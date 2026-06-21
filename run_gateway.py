"""
Standalone Windows Edge Gateway for Real-Time IoT IDS Monitoring.

Captures live network traffic using Scapy/Npcap, extracts IP flows,
sends them to the AI inference service, and writes to Elasticsearch
so Kibana shows real-time network flows and alerts.

Usage:
    python run_gateway.py                        # Auto-detect best interface
    python run_gateway.py --interface "Ethernet" # Use named interface
    python run_gateway.py --interface "Wi-Fi"
    python run_gateway.py --list                 # Show all interfaces
"""

import asyncio
import json
import logging
import sys
import time
import argparse
import uuid
from datetime import datetime, timezone

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("edge_gateway")

# ─── Configuration ─────────────────────────────────────────────────────────────
AI_SERVICE_URL = "http://localhost:8000/api/v1/detect"
ELASTICSEARCH_URL = "http://localhost:9200"
FLOWS_INDEX = "iot-ids-network-flows"
ALERTS_INDEX = "iot-ids-alerts"
FLUSH_INTERVAL = 3.0    # seconds between sending batches to ES
FLOW_TIMEOUT = 20       # seconds of inactivity before flow is exported
LOG_EVERY = 10          # log a status line every N packets captured

# ─── Elasticsearch helpers ──────────────────────────────────────────────────────

def ensure_index(index: str, mapping: dict) -> bool:
    try:
        r = requests.head(f"{ELASTICSEARCH_URL}/{index}", timeout=5)
        if r.status_code == 404:
            r2 = requests.put(f"{ELASTICSEARCH_URL}/{index}", json=mapping, timeout=10)
            if r2.status_code in (200, 201):
                logger.info(f"[OK] Created index: {index}")
            else:
                logger.warning(f"Could not create index {index}: {r2.text[:200]}")
        return True
    except Exception as e:
        logger.warning(f"[WARN] Elasticsearch not reachable at {ELASTICSEARCH_URL}: {e}")
        return False


def index_doc(index: str, doc: dict):
    try:
        requests.post(f"{ELASTICSEARCH_URL}/{index}/_doc", json=doc, timeout=5)
    except Exception:
        pass  # Silent fail — ES might be momentarily busy


FLOW_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "flow_id":          {"type": "keyword"},
            "source_ip":        {"type": "ip"},
            "destination_ip":   {"type": "ip"},
            "source_port":      {"type": "integer"},
            "destination_port": {"type": "integer"},
            "protocol":         {"type": "keyword"},
            "bytes_sent":       {"type": "long"},
            "packets_sent":     {"type": "integer"},
            "duration_ms":      {"type": "float"},
            "threat_score":     {"type": "float"},
            "is_anomaly":       {"type": "boolean"},
        }
    }
}

ALERT_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "alert_id":         {"type": "keyword"},
            "source_ip":        {"type": "ip"},
            "destination_ip":   {"type": "ip"},
            "source_port":      {"type": "integer"},
            "destination_port": {"type": "integer"},
            "protocol":         {"type": "keyword"},
            "threat_score":     {"type": "float"},
            "severity":         {"type": "keyword"},
            "attack_category":  {"type": "keyword"},
            "description":      {"type": "text"},
        }
    }
}


# ─── Windows Interface Resolution ──────────────────────────────────────────────

def resolve_windows_interface(name: str) -> str:
    """
    Resolve a friendly interface name (e.g. 'Ethernet', 'Wi-Fi') to the
    Npcap NPF device path that Scapy needs on Windows.
    Returns the NPF path if found, otherwise returns the original name.
    """
    import os
    if os.name != 'nt':
        return name
    try:
        from scapy.arch.windows import get_windows_if_list
        ifaces = get_windows_if_list()
        for i in ifaces:
            if i.get('name') == name or i.get('description') == name:
                guid = i.get('guid', '')
                if guid:
                    npf = f"\\Device\\NPF_{{{guid}}}" if not guid.startswith('{') else f"\\Device\\NPF_{guid}"
                    logger.info(f"Resolved '{name}' -> {npf} ({i.get('description','')})")
                    return npf
        logger.warning(f"Could not resolve '{name}' to an NPF device, using as-is")
    except Exception as e:
        logger.warning(f"Interface resolution failed: {e}")
    return name


def get_best_interface() -> str:
    """
    Auto-detect the best physical interface.
    Prefer physical adapters (Ethernet/Wi-Fi) over virtual ones.
    Returns the NPF device path on Windows.
    """
    import os
    try:
        from scapy.all import get_if_list, get_if_addr, conf

        if os.name == 'nt':
            from scapy.arch.windows import get_windows_if_list
            ifaces = get_windows_if_list()
            preferred_keywords = ['realtek', 'intel', 'ethernet', 'wi-fi', 'wifi', 'wireless', 'network']
            skip_keywords = ['virtual', 'loopback', 'vpn', 'vethernet', 'pseudo', 'miniport',
                             'bluetooth', 'teredo', 'isatap', '6to4', 'wan miniport', 'direct',
                             'vswitch', 'hyper-v', 'virtualbox', 'filter', 'scheduler', 'npcap driver',
                             'ndis']

            candidates = []
            for iface in ifaces:
                desc = (iface.get('description') or '').lower()
                name = (iface.get('name') or '').lower()
                guid = iface.get('guid', '')

                # Skip virtual/filter adapters
                if any(kw in desc for kw in skip_keywords):
                    continue
                if any(kw in name for kw in ['local area connection*', 'vethernet', 'loopback', 'bluetooth']):
                    continue
                if not guid:
                    continue

                # Score: prefer physical
                score = 0
                if any(kw in desc for kw in preferred_keywords):
                    score += 10
                if 'ethernet' in name or 'ethernet' in desc:
                    score += 5

                npf = f"\\Device\\NPF_{{{guid}}}" if not guid.startswith('{') else f"\\Device\\NPF_{guid}"
                # Check if interface has an IP
                try:
                    ip = get_if_addr(npf)
                    if ip and ip != '0.0.0.0':
                        score += 3
                        candidates.append((score, npf, iface.get('name', ''), desc, ip))
                except Exception:
                    candidates.append((score - 1, npf, iface.get('name', ''), desc, 'no-ip'))

            if candidates:
                candidates.sort(key=lambda x: -x[0])
                best = candidates[0]
                logger.info(f"Auto-selected interface: [{best[2]}] {best[3]} -> {best[3]} ({best[4]})")
                return best[1]

        # Linux/Mac fallback
        for iface in get_if_list():
            if iface.startswith('lo'):
                continue
            try:
                addr = get_if_addr(iface)
                if addr and addr != '0.0.0.0':
                    logger.info(f"Auto-detected interface: {iface} ({addr})")
                    return iface
            except Exception:
                continue

    except Exception as e:
        logger.error(f"Interface detection error: {e}")

    return "Ethernet"  # final fallback


def list_interfaces():
    """Print available interfaces."""
    import os
    print("\n" + "=" * 70)
    print("  Available Network Interfaces")
    print("=" * 70)
    try:
        from scapy.all import get_if_list, get_if_addr
        print("\nScapy Interface List:")
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                print(f"  {iface:<50} {addr}")
            except Exception:
                print(f"  {iface}")

        if os.name == 'nt':
            from scapy.arch.windows import get_windows_if_list
            print("\nWindows Friendly Names (use these with --interface):")
            print("-" * 70)
            skip = ['local area connection*', 'bluetooth', 'vethernet', 'filter', 'scheduler',
                    'loopback', 'pseudo', 'miniport', 'teredo', '6to4', 'wan miniport',
                    'isatap', 'direct', 'vswitch', 'hyper-v', 'virtualbox', 'npcap driver',
                    'ndis light']
            for i in get_windows_if_list():
                name = i.get('name', '')
                desc = i.get('description', '')
                if any(kw in name.lower() for kw in skip):
                    continue
                if any(kw in desc.lower() for kw in skip):
                    continue
                print(f"  --interface \"{name}\"   ({desc})")
    except ImportError:
        print("Scapy not installed! Run: pip install scapy")
    print()


# ─── Flow tracking ──────────────────────────────────────────────────────────────

class FlowRecord:
    __slots__ = ['flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                 'proto', 'bytes', 'packets', 'start', 'last_seen']

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.flow_id   = str(uuid.uuid4())
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port or 0
        self.dst_port  = dst_port or 0
        self.proto     = proto
        self.bytes     = 0
        self.packets   = 0
        self.start     = time.monotonic()
        self.last_seen = time.monotonic()

    def update(self, pkt_len: int):
        self.last_seen = time.monotonic()
        self.bytes    += pkt_len
        self.packets  += 1

    def to_network_flow(self) -> dict:
        duration_ms = max(1.0, (self.last_seen - self.start) * 1000)
        return {
            "flow_id":          self.flow_id,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "source_ip":        self.src_ip,
            "destination_ip":   self.dst_ip,
            "source_port":      self.src_port,
            "destination_port": self.dst_port,
            "protocol":         self.proto,
            "bytes_sent":       self.bytes,
            "bytes_received":   0,
            "packets_sent":     self.packets,
            "packets_received": 0,
            "duration_ms":      duration_ms,
            "inter_arrival_mean_ms": 0.0,
            "inter_arrival_std_ms":  0.0,
            "jitter_ms":        0.0,
            "tcp_flags":        [],
        }


# ─── Main Gateway ───────────────────────────────────────────────────────────────

class EdgeGateway:
    def __init__(self, npf_interface: str, friendly_name: str = ""):
        self.npf_interface   = npf_interface
        self.friendly_name   = friendly_name or npf_interface
        self.flows: dict     = {}          # key → FlowRecord
        self.running         = True
        self.packets_total   = 0
        self.packets_ip      = 0
        self.flows_exported  = 0
        self.alerts_generated = 0
        self._lock           = False

    # ── Packet handler ────────────────────────────────────────────────────────

    def handle_packet(self, pkt):
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP
            if not self.running:
                return

            self.packets_total += 1

            src_ip = dst_ip = src_port = dst_port = proto = None

            if pkt.haslayer(IP):
                ip = pkt[IP]
                src_ip, dst_ip = ip.src, ip.dst
                if pkt.haslayer(TCP):
                    t = pkt[TCP]; src_port, dst_port, proto = t.sport, t.dport, "TCP"
                elif pkt.haslayer(UDP):
                    u = pkt[UDP]; src_port, dst_port, proto = u.sport, u.dport, "UDP"
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"
                else:
                    proto = "IP"
            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]
                src_ip, dst_ip = ip.src, ip.dst
                if pkt.haslayer(TCP):
                    t = pkt[TCP]; src_port, dst_port, proto = t.sport, t.dport, "TCP"
                elif pkt.haslayer(UDP):
                    u = pkt[UDP]; src_port, dst_port, proto = u.sport, u.dport, "UDP"
                else:
                    proto = "IPv6"
            else:
                return  # Not IP — skip

            self.packets_ip += 1
            key = (src_ip, dst_ip, src_port or 0, dst_port or 0, proto)

            if key not in self.flows:
                self.flows[key] = FlowRecord(src_ip, dst_ip, src_port, dst_port, proto)
            self.flows[key].update(len(bytes(pkt)))

            if self.packets_ip % LOG_EVERY == 0:
                logger.info(
                    f"[CAPTURE] Packets: {self.packets_ip} IP / {self.packets_total} total | "
                    f"Active flows: {len(self.flows)} | "
                    f"Exported: {self.flows_exported} | "
                    f"Alerts: {self.alerts_generated}"
                )
                
            # Quick heuristic for Port Scans: if a single IP has > 20 active flows, flag it
            if self.packets_ip % 50 == 0:
                src_counts = {}
                dst_mappings = {}
                for f in self.flows.values():
                    src_counts[f.src_ip] = src_counts.get(f.src_ip, 0) + 1
                    if f.src_ip not in dst_mappings:
                        dst_mappings[f.src_ip] = f.dst_ip
                
                for sip, count in src_counts.items():
                    if count > 20:
                        # Prevent spamming the same alert
                        alert_key = f"portscan_{sip}"
                        if not hasattr(self, '_flagged_ips'): self._flagged_ips = set()
                        if alert_key not in self._flagged_ips:
                            self._flagged_ips.add(alert_key)
                            self.alerts_generated += 1
                            target_ip = dst_mappings.get(sip, dst_ip)
                            logger.warning(f"[ALERT] score=0.95 severity=critical category=reconnaissance - Port Scan detected from {sip} ({count} active flows)")
                            index_doc(ALERTS_INDEX, {
                                "@timestamp":       datetime.now(timezone.utc).isoformat(),
                                "alert_id":         f"ALERT-{int(time.time())}-{sip}",
                                "threat_score":     0.95,
                                "severity":         "critical",
                                "attack_category":  "reconnaissance",
                                "description":      f"Aggressive Port Scan detected from {sip}. Device rapidly scanning {count} different ports.",
                                "source_ip":        sip,
                                "destination_ip":   target_ip,
                                "source_port":      0,
                                "destination_port": 0,
                                "protocol":         "TCP"
                            })
        except Exception as e:
            logger.debug(f"Packet error: {e}")

    # ── Export flows to AI + ES ───────────────────────────────────────────────

    def _pop_expired_flows(self) -> list:
        now = time.monotonic()
        expired = [f for f in self.flows.values() if now - f.last_seen > FLOW_TIMEOUT]
        for f in expired:
            key = (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto)
            self.flows.pop(key, None)
        return expired

    def _sample_active_flows(self, n: int = 5) -> list:
        flows = sorted(self.flows.values(), key=lambda f: f.last_seen)
        return flows[:n]

    def _send_flows(self, flow_records: list):
        if not flow_records:
            return
        network_flows = [f.to_network_flow() for f in flow_records]

        # Try AI service first
        try:
            resp = requests.post(
                AI_SERVICE_URL,
                json={"flows": network_flows, "include_explanations": False},
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                detections = data.get("detections", [])

                for nf in network_flows:
                    index_doc(FLOWS_INDEX, {
                        "@timestamp":       nf["timestamp"],
                        "flow_id":          nf["flow_id"],
                        "source_ip":        nf["source_ip"],
                        "destination_ip":   nf["destination_ip"],
                        "source_port":      nf["source_port"],
                        "destination_port": nf["destination_port"],
                        "protocol":         nf["protocol"],
                        "bytes_sent":       nf["bytes_sent"],
                        "packets_sent":     nf["packets_sent"],
                        "duration_ms":      nf["duration_ms"],
                        "threat_score":     0.0,
                        "is_anomaly":       False,
                    })
                self.flows_exported += len(network_flows)

                for det in detections:
                    ts = det.get("threat_score", 0.0)
                    sev = det.get("severity", "low")
                    logger.warning(
                        f"[ALERT] score={ts:.2f} severity={sev} "
                        f"category={det.get('attack_category', 'unknown')}"
                    )
                    index_doc(ALERTS_INDEX, {
                        "@timestamp":       datetime.now(timezone.utc).isoformat(),
                        "alert_id":         det.get("detection_id", str(uuid.uuid4())),
                        "threat_score":     ts,
                        "severity":         sev,
                        "attack_category":  det.get("attack_category", "unknown"),
                        "description":      det.get("description", "Anomalous traffic detected"),
                        "source_ip":        network_flows[0]["source_ip"],
                        "destination_ip":   network_flows[0]["destination_ip"],
                        "source_port":      network_flows[0]["source_port"],
                        "destination_port": network_flows[0]["destination_port"],
                        "protocol":         network_flows[0]["protocol"],
                    })
                    self.alerts_generated += 1
                return

        except requests.exceptions.ConnectionError:
            logger.debug("AI service unreachable, writing flows directly to ES")
        except Exception as e:
            logger.debug(f"AI service error: {e}")

        # Fallback: write directly to ES without AI scoring
        for nf in network_flows:
            index_doc(FLOWS_INDEX, {
                "@timestamp":       nf["timestamp"],
                "flow_id":          nf["flow_id"],
                "source_ip":        nf["source_ip"],
                "destination_ip":   nf["destination_ip"],
                "source_port":      nf["source_port"],
                "destination_port": nf["destination_port"],
                "protocol":         nf["protocol"],
                "bytes_sent":       nf["bytes_sent"],
                "packets_sent":     nf["packets_sent"],
                "duration_ms":      nf["duration_ms"],
                "threat_score":     0.0,
                "is_anomaly":       False,
            })
        self.flows_exported += len(network_flows)

    # ── Flush loop ────────────────────────────────────────────────────────────

    async def _flush_loop(self):
        while self.running:
            await asyncio.sleep(FLUSH_INTERVAL)
            try:
                expired = self._pop_expired_flows()
                active  = self._sample_active_flows(5)
                all_flows = list({id(f): f for f in expired + active}.values())
                if all_flows:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self._send_flows, all_flows)
            except Exception as e:
                logger.debug(f"Flush error: {e}")

    # ── Packet capture thread ─────────────────────────────────────────────────

    def _run_capture(self):
        import threading
        from scapy.all import sniff

        logger.info(f"[CAPTURE] Starting capture on: {self.friendly_name}")
        logger.info(f"   NPF device: {self.npf_interface}")

        def _sniff_loop():
            while self.running:
                try:
                    sniff(
                        iface=self.npf_interface,
                        prn=self.handle_packet,
                        store=False,
                        timeout=2,
                        stop_filter=lambda p: not self.running,
                    )
                except Exception as e:
                    if self.running:
                        logger.warning(f"Sniff error (retrying): {e}")
                        time.sleep(1)

        t = threading.Thread(target=_sniff_loop, daemon=True, name="capture")
        t.start()
        return t

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run(self):
        logger.info("=" * 60)
        logger.info("  IoT IDS Edge Gateway — Real-Time Monitor")
        logger.info("=" * 60)
        logger.info(f"  Interface : {self.friendly_name}")
        logger.info(f"  AI Service: {AI_SERVICE_URL}")
        logger.info(f"  ES URL    : {ELASTICSEARCH_URL}")
        logger.info("=" * 60)

        # Setup ES indices
        es_ok = ensure_index(FLOWS_INDEX, FLOW_MAPPING)
        ensure_index(ALERTS_INDEX, ALERT_MAPPING)
        if not es_ok:
            logger.warning("Elasticsearch not available — flows will not be stored")

        # Start capture
        capture_thread = self._run_capture()

        logger.info("[OK] Capture running. Traffic will appear in Kibana at http://localhost:5601")
        logger.info("   Go to: Analytics > Discover > select 'iot-ids-network-flows'")
        logger.info("   Press Ctrl+C to stop.\n")

        try:
            await self._flush_loop()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            self.running = False
            await asyncio.sleep(0.5)
            logger.info(
                f"\n[SUMMARY] {self.packets_ip} IP packets | "
                f"{self.flows_exported} flows exported | "
                f"{self.alerts_generated} alerts"
            )


# ─── CLI ────────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="IoT IDS Edge Gateway — Real-Time Network Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_gateway.py                      # auto-detect best interface
  python run_gateway.py --interface Ethernet # use Ethernet adapter
  python run_gateway.py --interface Wi-Fi    # use Wi-Fi adapter
  python run_gateway.py --list               # show available interfaces
        """
    )
    parser.add_argument("--interface", "-i", type=str, help="Network interface friendly name")
    parser.add_argument("--list", "-l", action="store_true", help="List available interfaces and exit")
    args = parser.parse_args()

    # Verify scapy
    try:
        import scapy  # noqa
    except ImportError:
        logger.error("[ERROR] Scapy not installed! Run:  pip install scapy")
        sys.exit(1)

    if args.list:
        list_interfaces()
        return

    import os
    if args.interface:
        friendly_name = args.interface
        if os.name == 'nt':
            npf = resolve_windows_interface(args.interface)
        else:
            npf = args.interface
    else:
        npf = get_best_interface()
        # Extract friendly name from NPF path for display
        try:
            from scapy.arch.windows import get_windows_if_list
            for i in get_windows_if_list():
                guid = i.get('guid', '')
                if guid and guid in npf:
                    friendly_name = f"{i.get('name','')} ({i.get('description','')})"
                    break
            else:
                friendly_name = npf
        except Exception:
            friendly_name = npf

    gateway = EdgeGateway(npf_interface=npf, friendly_name=friendly_name)
    try:
        await gateway.run()
    except KeyboardInterrupt:
        gateway.running = False
        logger.info("Gateway stopped by user.")


if __name__ == "__main__":
    asyncio.run(main())
