"""
Suricata protocol decoder implementation for the AI-driven IoT IDS system.

This module provides a concrete implementation of the ProtocolDecoderInterface
that integrates with Suricata for network protocol analysis, signature-based
detection, and metadata extraction.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, AsyncIterator
import aiofiles
import aiofiles.os
import yaml

from ..interfaces.protocol_decoder import (
    ProtocolDecoderInterface,
    ProtocolMetadata,
    ProtocolType,
    SignatureAlert
)
from ..interfaces.packet_capture import RawPacket
from ..utils.error_handling import IDSError


logger = logging.getLogger(__name__)


class SuricataDecoderError(IDSError):
    """Suricata-specific decoder errors."""
    pass


class SuricataDecoder(ProtocolDecoderInterface):
    """
    Suricata protocol decoder implementation.
    
    This decoder integrates with Suricata to analyze network packets and extract
    protocol-specific metadata while performing signature-based threat detection.
    It processes packets by writing them to pcap files and running Suricata analysis.
    """
    
    def __init__(
        self,
        suricata_binary_path: str = "/usr/bin/suricata",
        config_file: Optional[str] = None,
        rules_dir: Optional[str] = None,
        temp_dir: Optional[str] = None,
        batch_size: int = 100,
        timeout_seconds: int = 30
    ):
        """
        Initialize Suricata decoder.
        
        Args:
            suricata_binary_path: Path to Suricata binary executable
            config_file: Path to Suricata configuration file
            rules_dir: Directory containing Suricata rule files
            temp_dir: Directory for temporary files (uses system temp if None)
            batch_size: Number of packets to process in each batch
            timeout_seconds: Timeout for Suricata analysis operations
        """
        config = {
            "suricata_binary_path": suricata_binary_path,
            "config_file": config_file,
            "rules_dir": rules_dir,
            "temp_dir": temp_dir,
            "batch_size": batch_size,
            "timeout_seconds": timeout_seconds
        }
        super().__init__(config)
        self.suricata_binary_path = Path(suricata_binary_path)
        self.config_file = Path(config_file) if config_file else None
        self.rules_dir = Path(rules_dir) if rules_dir else None
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.batch_size = batch_size
        self.timeout_seconds = timeout_seconds
        
        # Statistics tracking
        self._packets_processed = 0
        self._protocols_detected = {}
        self._alerts_generated = 0
        self._enabled_protocols = set(ProtocolType)
        self._rule_count = 0
        
        # Default Suricata configuration template
        self._default_config = {
            "vars": {
                "address-groups": {
                    "HOME_NET": "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]",
                    "EXTERNAL_NET": "!$HOME_NET"
                },
                "port-groups": {
                    "HTTP_PORTS": "80",
                    "SHELLCODE_PORTS": "!80"
                }
            },
            "default-log-dir": "/tmp/suricata",
            "stats": {"enabled": True},
            "outputs": [
                {
                    "eve-log": {
                        "enabled": True,
                        "filetype": "regular",
                        "filename": "eve.json",
                        "types": [
                            {"alert": {"payload": True, "metadata": True}},
                            {"http": {"extended": True}},
                            {"dns": {"query": True, "answer": True}},
                            {"tls": {"extended": True}},
                            {"flow": {}},
                            {"netflow": {}}
                        ]
                    }
                }
            ],
            "app-layer": {
                "protocols": {
                    "http": {"enabled": True},
                    "tls": {"enabled": True},
                    "dns": {"enabled": True},
                    "ssh": {"enabled": True}
                }
            },
            "logging": {
                "default-log-level": "notice",
                "outputs": [
                    {"console": {"enabled": False}},
                    {"file": {"enabled": True, "level": "info", "filename": "suricata.log"}}
                ]
            }
        }
    
    async def initialize(self) -> None:
        """Initialize the Suricata decoder."""
        try:
            # Verify Suricata binary exists and is executable
            if not self.suricata_binary_path.exists():
                raise SuricataDecoderError(f"Suricata binary not found at {self.suricata_binary_path}")
            
            # Test Suricata installation
            result = await asyncio.create_subprocess_exec(
                str(self.suricata_binary_path), "--build-info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                raise SuricataDecoderError(f"Suricata build info check failed: {stderr.decode()}")
            
            logger.info(f"Suricata decoder initialized: {stdout.decode().strip()}")
            
            # Create temp directory if it doesn't exist
            await aiofiles.os.makedirs(self.temp_dir, exist_ok=True)
            
            # Create default config if none provided
            if not self.config_file:
                self.config_file = self.temp_dir / "suricata.yaml"
                await self._create_default_config()
            
            # Count rules if rules directory is provided
            if self.rules_dir and self.rules_dir.exists():
                self._rule_count = len(list(self.rules_dir.glob("*.rules")))
            
            self._initialized = True
            
        except Exception as e:
            logger.error(f"Failed to initialize Suricata decoder: {e}")
            raise SuricataDecoderError(f"Initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the Suricata decoder."""
        if not self._initialized:
            await self.initialize()
        
        self._running = True
        logger.info("Suricata decoder started")
    
    async def stop(self) -> None:
        """Stop the Suricata decoder."""
        self._running = False
        logger.info("Suricata decoder stopped")
    
    async def decode_packet(self, packet: RawPacket) -> Optional[ProtocolMetadata]:
        """
        Decode a single packet using Suricata.
        
        Args:
            packet: Raw packet data to decode
            
        Returns:
            ProtocolMetadata if packet could be decoded, None otherwise
        """
        if not self._running:
            raise SuricataDecoderError("Decoder not running")
        
        # For single packet, use batch processing with size 1
        results = await self.decode_packets_batch([packet])
        return results[0] if results else None
    
    async def decode_packets_batch(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """
        Decode multiple packets in batch using Suricata.
        
        Args:
            packets: List of raw packets to decode
            
        Returns:
            List of decoded protocol metadata
        """
        if not self._running:
            raise SuricataDecoderError("Decoder not running")
        
        if not packets:
            return []
        
        try:
            # Create temporary pcap file
            pcap_file = self.temp_dir / f"suricata_batch_{datetime.now().timestamp()}.pcap"
            
            # Write packets to pcap file
            await self._write_packets_to_pcap(packets, pcap_file)
            
            # Run Suricata analysis
            log_dir = await self._run_suricata_analysis(pcap_file)
            
            # Parse Suricata EVE JSON logs
            metadata_list = await self._parse_eve_logs(log_dir)
            
            # Update statistics
            self._packets_processed += len(packets)
            
            # Cleanup temporary files
            await self._cleanup_temp_files(pcap_file, log_dir)
            
            return metadata_list
            
        except Exception as e:
            logger.error(f"Batch decoding failed: {e}")
            raise SuricataDecoderError(f"Batch decoding failed: {e}")
    
    async def get_signature_alerts(self) -> AsyncIterator[SignatureAlert]:
        """
        Get signature-based security alerts from Suricata.
        
        Yields:
            SignatureAlert: Security alerts from Suricata rule matching
        """
        # This would typically read from a continuous Suricata alert log
        # For now, return empty iterator as this is batch-based processing
        return
        yield  # Make this an async generator
    
    async def load_custom_rules(self, rules_path: str) -> None:
        """
        Load custom Suricata rules from directory.
        
        Args:
            rules_path: Path to directory containing Suricata rule files
        """
        rules_dir = Path(rules_path)
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_path}")
        
        # Validate Suricata rules
        rule_files = list(rules_dir.glob("*.rules"))
        
        for rule_file in rule_files:
            # Basic syntax validation by testing rule loading
            result = await asyncio.create_subprocess_exec(
                str(self.suricata_binary_path), "-T", "-S", str(rule_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                raise ValueError(f"Invalid Suricata rule file {rule_file}: {stderr.decode()}")
        
        self.rules_dir = rules_dir
        self._rule_count = len(rule_files)
        logger.info(f"Loaded {len(rule_files)} custom Suricata rule files from {rules_path}")
    
    async def reload_rules(self) -> None:
        """
        Reload Suricata rules.
        
        Since this is a batch-based decoder, rules are loaded per analysis.
        This method validates that custom rules are still valid.
        """
        if self.rules_dir:
            await self.load_custom_rules(str(self.rules_dir))
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get list of protocols supported by Suricata."""
        return [
            ProtocolType.TCP,
            ProtocolType.UDP,
            ProtocolType.ICMP,
            ProtocolType.HTTP,
            ProtocolType.HTTPS,
            ProtocolType.DNS,
            ProtocolType.TLS,
            ProtocolType.SSH,
            ProtocolType.DHCP
        ]
    
    async def get_decoder_statistics(self) -> Dict[str, Any]:
        """Get Suricata decoder statistics."""
        return {
            "packets_processed": self._packets_processed,
            "protocols_detected": dict(self._protocols_detected),
            "alerts_generated": self._alerts_generated,
            "processing_rate_pps": 0,  # Would need time tracking for actual rate
            "rule_count": self._rule_count,
            "enabled_protocols": [p.value for p in self._enabled_protocols]
        }
    
    async def enable_protocol_analysis(self, protocols: List[ProtocolType]) -> None:
        """Enable analysis for specific protocols."""
        self._enabled_protocols.update(protocols)
        logger.info(f"Enabled protocol analysis for: {[p.value for p in protocols]}")
    
    async def disable_protocol_analysis(self, protocols: List[ProtocolType]) -> None:
        """Disable analysis for specific protocols."""
        self._enabled_protocols.difference_update(protocols)
        logger.info(f"Disabled protocol analysis for: {[p.value for p in protocols]}")
    
    async def _create_default_config(self) -> None:
        """Create default Suricata configuration file."""
        try:
            async with aiofiles.open(self.config_file, 'w') as f:
                yaml_content = yaml.dump(self._default_config, default_flow_style=False)
                await f.write(yaml_content)
            
            logger.debug(f"Created default Suricata config at {self.config_file}")
            
        except Exception as e:
            raise SuricataDecoderError(f"Failed to create default config: {e}")
    
    async def _write_packets_to_pcap(self, packets: List[RawPacket], pcap_file: Path) -> None:
        """Write raw packets to a pcap file for Suricata analysis."""
        try:
            # Use scapy to write packets to pcap format
            from scapy.all import wrpcap, Ether
            
            scapy_packets = []
            for packet in packets:
                # Convert raw packet data to scapy packet
                if packet.data:
                    try:
                        scapy_packet = Ether(packet.data)
                        scapy_packets.append(scapy_packet)
                    except Exception as e:
                        logger.warning(f"Failed to parse packet: {e}")
                        continue
            
            if scapy_packets:
                wrpcap(str(pcap_file), scapy_packets)
                logger.debug(f"Wrote {len(scapy_packets)} packets to {pcap_file}")
            
        except ImportError:
            raise SuricataDecoderError("Scapy is required for pcap file creation")
        except Exception as e:
            raise SuricataDecoderError(f"Failed to write pcap file: {e}")
    
    async def _run_suricata_analysis(self, pcap_file: Path) -> Path:
        """Run Suricata analysis on pcap file and return log directory."""
        log_dir = self.temp_dir / f"suricata_logs_{datetime.now().timestamp()}"
        await aiofiles.os.makedirs(log_dir, exist_ok=True)
        
        # Build Suricata command
        cmd = [
            str(self.suricata_binary_path),
            "-c", str(self.config_file),
            "-r", str(pcap_file),
            "-l", str(log_dir)
        ]
        
        # Add custom rules if available
        if self.rules_dir:
            cmd.extend(["-S", str(self.rules_dir)])
        
        try:
            # Run Suricata analysis
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=self.timeout_seconds
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                logger.error(f"Suricata analysis failed: {stderr.decode()}")
                raise SuricataDecoderError(f"Suricata analysis failed: {stderr.decode()}")
            
            logger.debug(f"Suricata analysis completed, logs in {log_dir}")
            return log_dir
            
        except asyncio.TimeoutError:
            raise SuricataDecoderError(f"Suricata analysis timed out after {self.timeout_seconds} seconds")
        except Exception as e:
            raise SuricataDecoderError(f"Suricata analysis failed: {e}")
    
    async def _parse_eve_logs(self, log_dir: Path) -> List[ProtocolMetadata]:
        """Parse Suricata EVE JSON logs and extract protocol metadata."""
        metadata_list = []
        eve_log_file = log_dir / "eve.json"
        
        if not eve_log_file.exists():
            logger.warning(f"EVE log file not found: {eve_log_file}")
            return metadata_list
        
        try:
            async with aiofiles.open(eve_log_file, 'r') as f:
                async for line in f:
                    if not line.strip():
                        continue
                    
                    try:
                        event = json.loads(line.strip())
                        metadata = await self._parse_eve_event(event)
                        if metadata:
                            metadata_list.append(metadata)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse EVE JSON line: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Failed to parse EVE logs: {e}")
        
        return metadata_list
    
    async def _parse_eve_event(self, event: Dict[str, Any]) -> Optional[ProtocolMetadata]:
        """Parse a single EVE JSON event into ProtocolMetadata."""
        try:
            event_type = event.get("event_type")
            timestamp = datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00"))
            
            # Extract basic network info
            src_ip = event.get("src_ip", "")
            dest_ip = event.get("dest_ip", "")
            src_port = event.get("src_port", 0)
            dest_port = event.get("dest_port", 0)
            proto = event.get("proto", "").upper()
            
            # Map protocol string to ProtocolType
            if proto == "TCP":
                protocol_type = ProtocolType.TCP
            elif proto == "UDP":
                protocol_type = ProtocolType.UDP
            elif proto == "ICMP":
                protocol_type = ProtocolType.ICMP
            else:
                protocol_type = ProtocolType.UNKNOWN
            
            # Check if protocol is enabled
            if protocol_type not in self._enabled_protocols:
                return None
            
            # Create base metadata
            metadata = ProtocolMetadata(
                protocol=protocol_type,
                timestamp=timestamp,
                source_ip=src_ip,
                destination_ip=dest_ip,
                source_port=src_port,
                destination_port=dest_port
            )
            
            # Parse event-specific data
            if event_type == "http":
                await self._parse_http_event(event, metadata)
            elif event_type == "dns":
                await self._parse_dns_event(event, metadata)
            elif event_type == "tls":
                await self._parse_tls_event(event, metadata)
            elif event_type == "flow":
                await self._parse_flow_event(event, metadata)
            elif event_type == "alert":
                # Handle alerts separately
                await self._parse_alert_event(event)
                return None  # Don't return metadata for alerts
            
            # Update protocol statistics
            self._protocols_detected[protocol_type.value] = \
                self._protocols_detected.get(protocol_type.value, 0) + 1
            
            return metadata
            
        except Exception as e:
            logger.warning(f"Failed to parse EVE event: {e}")
            return None
    
    async def _parse_http_event(self, event: Dict[str, Any], metadata: ProtocolMetadata) -> None:
        """Parse HTTP-specific fields from EVE event."""
        http_data = event.get("http", {})
        
        metadata.protocol = ProtocolType.HTTP
        metadata.http_method = http_data.get("http_method")
        metadata.http_uri = http_data.get("url")
        metadata.http_user_agent = http_data.get("http_user_agent")
        metadata.http_status_code = http_data.get("status")
        
        # Calculate payload size from length if available
        if "length" in http_data:
            metadata.payload_size = http_data["length"]
    
    async def _parse_dns_event(self, event: Dict[str, Any], metadata: ProtocolMetadata) -> None:
        """Parse DNS-specific fields from EVE event."""
        dns_data = event.get("dns", {})
        
        # Keep the base protocol (UDP/TCP) instead of overriding to DNS
        # metadata.protocol = ProtocolType.DNS
        metadata.dns_query = dns_data.get("rrname")
        metadata.dns_query_type = dns_data.get("rrtype")
        metadata.dns_response_code = dns_data.get("rcode")
        
        # Parse answers if available
        if "answers" in dns_data and dns_data["answers"]:
            answers = []
            for answer in dns_data["answers"]:
                if "rdata" in answer:
                    answers.append(answer["rdata"])
            metadata.dns_answers = answers if answers else []
        else:
            metadata.dns_answers = []
    
    async def _parse_tls_event(self, event: Dict[str, Any], metadata: ProtocolMetadata) -> None:
        """Parse TLS-specific fields from EVE event."""
        tls_data = event.get("tls", {})
        
        metadata.protocol = ProtocolType.TLS
        metadata.tls_version = tls_data.get("version")
        metadata.tls_sni = tls_data.get("sni")
        metadata.tls_ja3_fingerprint = tls_data.get("ja3", {}).get("hash")
        metadata.tls_ja3s_fingerprint = tls_data.get("ja3s", {}).get("hash")
    
    async def _parse_flow_event(self, event: Dict[str, Any], metadata: ProtocolMetadata) -> None:
        """Parse flow-specific fields from EVE event."""
        flow_data = event.get("flow", {})
        
        # Extract flow statistics
        bytes_toserver = flow_data.get("bytes_toserver", 0)
        bytes_toclient = flow_data.get("bytes_toclient", 0)
        metadata.payload_size = bytes_toserver + bytes_toclient
        
        # Extract TCP flags if available
        if "tcp" in event:
            tcp_data = event["tcp"]
            tcp_flags = []
            
            if tcp_data.get("syn"):
                tcp_flags.append("SYN")
            if tcp_data.get("ack"):
                tcp_flags.append("ACK")
            if tcp_data.get("fin"):
                tcp_flags.append("FIN")
            if tcp_data.get("rst"):
                tcp_flags.append("RST")
            if tcp_data.get("psh"):
                tcp_flags.append("PSH")
            if tcp_data.get("urg"):
                tcp_flags.append("URG")
            
            metadata.tcp_flags = tcp_flags if tcp_flags else None
    
    async def _parse_alert_event(self, event: Dict[str, Any]) -> None:
        """Parse alert event and update statistics."""
        alert_data = event.get("alert", {})
        
        # Create SignatureAlert (would be stored/yielded in real implementation)
        alert = SignatureAlert(
            rule_id=str(alert_data.get("gid", 0)) + ":" + str(alert_data.get("signature_id", 0)),
            rule_name=alert_data.get("signature", "Unknown"),
            severity=alert_data.get("severity", "medium"),
            category=alert_data.get("category", "unknown"),
            timestamp=datetime.fromisoformat(event.get("timestamp", "").replace("Z", "+00:00")),
            source_ip=event.get("src_ip", ""),
            destination_ip=event.get("dest_ip", ""),
            source_port=event.get("src_port", 0),
            destination_port=event.get("dest_port", 0),
            protocol=event.get("proto", ""),
            message=alert_data.get("signature", "")
        )
        
        self._alerts_generated += 1
        logger.debug(f"Generated alert: {alert.rule_name}")
    
    async def _cleanup_temp_files(self, pcap_file: Path, log_dir: Path) -> None:
        """Clean up temporary files after processing."""
        try:
            # Remove pcap file
            if pcap_file.exists():
                await aiofiles.os.remove(pcap_file)
            
            # Remove log directory and contents
            if log_dir.exists():
                import shutil
                shutil.rmtree(log_dir)
                
        except Exception as e:
            logger.warning(f"Failed to cleanup temp files: {e}")