"""
IoT IDS Demo - Simulates realistic IoT network traffic and threat detections
and pushes them directly to Elasticsearch for Kibana visualization.

Run AFTER starting ELK:
    docker-compose -f docker-compose.elk.yml up -d
    python demo_iot_alerts.py
Then open: http://localhost:5601
"""

import json
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone

ES_URL = "http://localhost:9200"
FLOWS_INDEX = "iot-ids-network-flows"
ALERTS_INDEX = "iot-ids-alerts"
DEVICES_INDEX = "iot-ids-devices"

# ── Simulated IoT device fleet ────────────────────────────────────────────────
DEVICES = [
    {"id": "aa:bb:cc:11:22:33", "type": "IP Camera",       "ip": "192.168.1.101", "vendor": "Hikvision"},
    {"id": "aa:bb:cc:11:22:44", "type": "Smart Thermostat","ip": "192.168.1.102", "vendor": "Nest"},
    {"id": "aa:bb:cc:11:22:55", "type": "Door Lock",       "ip": "192.168.1.103", "vendor": "August"},
    {"id": "aa:bb:cc:11:22:66", "type": "Motion Sensor",   "ip": "192.168.1.104", "vendor": "Philips"},
    {"id": "aa:bb:cc:11:22:77", "type": "Smart Speaker",   "ip": "192.168.1.105", "vendor": "Amazon"},
    {"id": "aa:bb:cc:11:22:88", "type": "IP Camera",       "ip": "192.168.1.106", "vendor": "Dahua"},
]

# ── Attack scenarios ──────────────────────────────────────────────────────────
ATTACK_SCENARIOS = [
    {
        "name": "Port Scan",
        "category": "reconnaissance",
        "severity": "medium",
        "mitre": "T1046",
        "description": "Device scanning multiple ports on internal network",
        "threat_score": 0.72,
        "dst_ports": list(range(20, 1025, 50)),
        "bytes": (40, 120),
    },
    {
        "name": "C2 Beacon",
        "category": "command_and_control",
        "severity": "critical",
        "mitre": "T1071",
        "description": "Periodic outbound connection to known C2 server",
        "threat_score": 0.95,
        "dst_ports": [4444, 8080, 443],
        "bytes": (200, 800),
    },
    {
        "name": "Data Exfiltration",
        "category": "exfiltration",
        "severity": "high",
        "mitre": "T1041",
        "description": "Unusually large outbound data transfer",
        "threat_score": 0.88,
        "dst_ports": [443, 80],
        "bytes": (50000, 200000),
    },
    {
        "name": "Brute Force SSH",
        "category": "credential_access",
        "severity": "high",
        "mitre": "T1110",
        "description": "Repeated failed SSH login attempts",
        "threat_score": 0.81,
        "dst_ports": [22],
        "bytes": (200, 500),
    },
    {
        "name": "DNS Tunneling",
        "category": "exfiltration",
        "severity": "high",
        "mitre": "T1048",
        "description": "Abnormal DNS query volume and payload size",
        "threat_score": 0.85,
        "dst_ports": [53],
        "bytes": (300, 1200),
    },
    {
        "name": "Lateral Movement",
        "category": "lateral_movement",
        "severity": "critical",
        "mitre": "T1021",
        "description": "Device attempting to connect to other IoT devices",
        "threat_score": 0.91,
        "dst_ports": [80, 8080, 554],
        "bytes": (500, 2000),
    },
]

NORMAL_PROTOCOLS = ["TCP", "UDP", "DNS", "HTTPS", "HTTP"]
EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "52.86.12.44",
    "185.220.101.5",   # Known Tor exit node
    "91.108.4.0",      # Telegram
    "203.0.113.99",    # Suspicious external
]


def es_request(method, path, body=None):
    """Simple Elasticsearch HTTP helper."""
    url = f"{ES_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())
    except Exception as e:
        print(f"  ES error: {e}")
        return {}


def wait_for_elasticsearch():
    print(" Waiting for Elasticsearch...")
    for attempt in range(30):
        try:
            resp = es_request("GET", "/_cluster/health")
            if resp.get("status") in ("green", "yellow"):
                print(f" Elasticsearch ready (status: {resp['status']})")
                return True
        except Exception:
            pass
        time.sleep(3)
        print(f"   Attempt {attempt + 1}/30...")
    print(" Elasticsearch not available after 90s")
    return False


def create_indices():
    """Create indices with proper mappings."""
    print("\n Creating indices...")

    # Network flows index
    es_request("DELETE", f"/{FLOWS_INDEX}")
    es_request("PUT", f"/{FLOWS_INDEX}", {
        "mappings": {"properties": {
            "@timestamp":     {"type": "date"},
            "device_id":      {"type": "keyword"},
            "device_type":    {"type": "keyword"},
            "device_vendor":  {"type": "keyword"},
            "src_ip":         {"type": "ip"},
            "dst_ip":         {"type": "ip"},
            "src_port":       {"type": "integer"},
            "dst_port":       {"type": "integer"},
            "protocol":       {"type": "keyword"},
            "bytes_sent":     {"type": "long"},
            "bytes_received": {"type": "long"},
            "duration_ms":    {"type": "long"},
            "packets":        {"type": "integer"},
            "is_threat":      {"type": "boolean"},
        }}
    })

    # Alerts index
    es_request("DELETE", f"/{ALERTS_INDEX}")
    es_request("PUT", f"/{ALERTS_INDEX}", {
        "mappings": {"properties": {
            "@timestamp":      {"type": "date"},
            "alert_id":        {"type": "keyword"},
            "device_id":       {"type": "keyword"},
            "device_type":     {"type": "keyword"},
            "device_ip":       {"type": "ip"},
            "attack_name":     {"type": "keyword"},
            "attack_category": {"type": "keyword"},
            "severity":        {"type": "keyword"},
            "threat_score":    {"type": "float"},
            "confidence":      {"type": "float"},
            "mitre_tactic":    {"type": "keyword"},
            "description":     {"type": "text"},
            "src_ip":          {"type": "ip"},
            "dst_ip":          {"type": "ip"},
            "dst_port":        {"type": "integer"},
            "bytes_sent":      {"type": "long"},
            "recommended_action": {"type": "text"},
            "model_used":      {"type": "keyword"},
            "anomaly_score":   {"type": "float"},
        }}
    })

    # Devices index
    es_request("DELETE", f"/{DEVICES_INDEX}")
    es_request("PUT", f"/{DEVICES_INDEX}", {
        "mappings": {"properties": {
            "@timestamp":    {"type": "date"},
            "device_id":     {"type": "keyword"},
            "device_type":   {"type": "keyword"},
            "vendor":        {"type": "keyword"},
            "ip":            {"type": "ip"},
            "status":        {"type": "keyword"},
            "risk_score":    {"type": "float"},
            "total_alerts":  {"type": "integer"},
        }}
    })

    print("    Indices created")


def bulk_index(index, docs):
    """Bulk index a list of documents."""
    lines = []
    for doc in docs:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(doc))
    body = "\n".join(lines) + "\n"
    data = body.encode("utf-8")
    req = urllib.request.Request(
        f"{ES_URL}/_bulk", data=data,
        headers={"Content-Type": "application/x-ndjson"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
        errors = [i for i in result.get("items", []) if i.get("index", {}).get("error")]
        return len(docs) - len(errors), len(errors)


def generate_normal_flows(device, base_time, count=20):
    """Generate normal background traffic for a device."""
    flows = []
    for i in range(count):
        ts = base_time + timedelta(seconds=random.randint(0, 3600))
        flows.append({
            "@timestamp":     ts.isoformat(),
            "device_id":      device["id"],
            "device_type":    device["type"],
            "device_vendor":  device["vendor"],
            "src_ip":         device["ip"],
            "dst_ip":         random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"]),
            "src_port":       random.randint(49152, 65535),
            "dst_port":       random.choice([53, 80, 443, 123]),
            "protocol":       random.choice(NORMAL_PROTOCOLS),
            "bytes_sent":     random.randint(64, 2048),
            "bytes_received": random.randint(64, 4096),
            "duration_ms":    random.randint(10, 500),
            "packets":        random.randint(1, 20),
            "is_threat":      False,
        })
    return flows


def generate_attack_flow(device, scenario, ts):
    """Generate a single attack flow."""
    dst_port = random.choice(scenario["dst_ports"])
    b_min, b_max = scenario["bytes"]
    return {
        "@timestamp":     ts.isoformat(),
        "device_id":      device["id"],
        "device_type":    device["type"],
        "device_vendor":  device["vendor"],
        "src_ip":         device["ip"],
        "dst_ip":         random.choice(EXTERNAL_IPS),
        "src_port":       random.randint(49152, 65535),
        "dst_port":       dst_port,
        "protocol":       "TCP" if dst_port != 53 else "UDP",
        "bytes_sent":     random.randint(b_min, b_max),
        "bytes_received": random.randint(64, 512),
        "duration_ms":    random.randint(100, 5000),
        "packets":        random.randint(5, 200),
        "is_threat":      True,
    }


def generate_alert(device, scenario, flow, ts):
    """Generate a threat detection alert."""
    score = scenario["threat_score"] + random.uniform(-0.05, 0.05)
    score = max(0.0, min(1.0, score))

    actions = {
        "reconnaissance":      "Block device from scanning internal network. Investigate for compromise.",
        "command_and_control": "ISOLATE DEVICE IMMEDIATELY. Block all outbound traffic. Forensic analysis required.",
        "exfiltration":        "Block outbound connection. Review data accessed. Notify security team.",
        "credential_access":   "Block SSH access. Reset credentials. Check for successful logins.",
        "lateral_movement":    "Isolate device. Check all connected devices for compromise.",
    }

    return {
        "@timestamp":        ts.isoformat(),
        "alert_id":          f"ALERT-{int(ts.timestamp())}-{random.randint(1000,9999)}",
        "device_id":         device["id"],
        "device_type":       device["type"],
        "device_ip":         device["ip"],
        "attack_name":       scenario["name"],
        "attack_category":   scenario["category"],
        "severity":          scenario["severity"],
        "threat_score":      round(score, 3),
        "confidence":        round(random.uniform(0.75, 0.99), 3),
        "mitre_tactic":      scenario["mitre"],
        "description":       scenario["description"],
        "src_ip":            flow["src_ip"],
        "dst_ip":            flow["dst_ip"],
        "dst_port":          flow["dst_port"],
        "bytes_sent":        flow["bytes_sent"],
        "recommended_action": actions.get(scenario["category"], "Investigate device."),
        "model_used":        random.choice(["IsolationForest", "XGBoost", "HybridDetector"]),
        "anomaly_score":     round(score, 3),
    }


def generate_device_status(device, alerts_count, risk):
    """Generate device status document."""
    status = "critical" if risk > 0.8 else "warning" if risk > 0.5 else "normal"
    return {
        "@timestamp":   datetime.now(timezone.utc).isoformat(),
        "device_id":    device["id"],
        "device_type":  device["type"],
        "vendor":       device["vendor"],
        "ip":           device["ip"],
        "status":       status,
        "risk_score":   round(risk, 3),
        "total_alerts": alerts_count,
    }


def main():
    print("=" * 60)
    print("  IoT IDS Demo — Simulated Threat Detection")
    print("=" * 60)

    if not wait_for_elasticsearch():
        return

    create_indices()

    # Generate data spread over the last 24 hours
    now = datetime.now(timezone.utc)
    base_time = now - timedelta(hours=24)

    all_flows = []
    all_alerts = []
    all_devices = []

    print("\n Generating simulated IoT traffic and threats...")

    device_alert_counts = {}

    for device in DEVICES:
        print(f"\n   Device: {device['type']} ({device['ip']})")

        # Normal background traffic
        flows = generate_normal_flows(device, base_time, count=30)
        all_flows.extend(flows)
        print(f"      {len(flows)} normal flows")

        # Pick 2-4 random attack scenarios for this device
        num_attacks = random.randint(2, 4)
        scenarios = random.sample(ATTACK_SCENARIOS, num_attacks)
        device_alerts = 0

        for scenario in scenarios:
            # Each attack has 3-8 events spread over the day
            num_events = random.randint(3, 8)
            for _ in range(num_events):
                attack_time = base_time + timedelta(
                    seconds=random.randint(0, 86400)
                )
                flow = generate_attack_flow(device, scenario, attack_time)
                alert = generate_alert(device, scenario, flow, attack_time)
                all_flows.append(flow)
                all_alerts.append(alert)
                device_alerts += 1

            print(f"       {scenario['name']} ({scenario['severity']}) — {num_events} events")

        device_alert_counts[device["id"]] = device_alerts
        risk = min(1.0, device_alerts * 0.12)
        all_devices.append(generate_device_status(device, device_alerts, risk))

    # Bulk index everything
    print("\n Indexing to Elasticsearch...")

    ok, err = bulk_index(FLOWS_INDEX, all_flows)
    print(f"   Network flows:  {ok} indexed, {err} errors")

    ok, err = bulk_index(ALERTS_INDEX, all_alerts)
    print(f"   Threat alerts:  {ok} indexed, {err} errors")

    ok, err = bulk_index(DEVICES_INDEX, all_devices)
    print(f"   Device status:  {ok} indexed, {err} errors")

    # Refresh indices so data is immediately searchable
    es_request("POST", f"/{FLOWS_INDEX}/_refresh")
    es_request("POST", f"/{ALERTS_INDEX}/_refresh")
    es_request("POST", f"/{DEVICES_INDEX}/_refresh")

    # Summary
    print("\n" + "=" * 60)
    print("   Demo data loaded successfully!")
    print("=" * 60)
    print(f"\n  Total flows:   {len(all_flows)}")
    print(f"  Total alerts:  {len(all_alerts)}")
    print(f"  Devices:       {len(DEVICES)}")

    # Severity breakdown
    critical = sum(1 for a in all_alerts if a["severity"] == "critical")
    high     = sum(1 for a in all_alerts if a["severity"] == "high")
    medium   = sum(1 for a in all_alerts if a["severity"] == "medium")
    print(f"\n  Alert severity breakdown:")
    print(f"     Critical: {critical}")
    print(f"     High:     {high}")
    print(f"     Medium:   {medium}")

    print("\n" + "=" * 60)
    print("   Open Kibana to explore the data:")
    print("     http://localhost:5601")
    print()
    print("  Kibana setup steps:")
    print("  1. Go to: Stack Management → Index Patterns")
    print("  2. Create pattern: iot-ids-*   (time field: @timestamp)")
    print("  3. Go to Discover → select iot-ids-alerts-*")
    print("  4. Filter by severity: critical or high")
    print("  5. Build a dashboard with:")
    print("     - Pie chart: alerts by attack_category")
    print("     - Bar chart: alerts by severity over time")
    print("     - Data table: device_ip, attack_name, threat_score")
    print("=" * 60)


if __name__ == "__main__":
    main()
