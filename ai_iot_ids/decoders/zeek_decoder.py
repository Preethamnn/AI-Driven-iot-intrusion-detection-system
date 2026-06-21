"""
Zeek protocol decoder implementation for the AI-driven IoT IDS system.

This module provides a concrete implementation of the ProtocolDecoderInterface
that integrates with Zeek (formerly Bro) for network protocol analysis and
metadata extraction.
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

from ..interfaces.protocol_decoder import (
    ProtocolDecoderInterface,
    ProtocolMetadata,
    ProtocolType,
    SignatureAlert
)
from ..interfaces.packet_capture import RawPacket
from ..utils.error_handling import IDSError


logger = logging.getLogger(__name__)


class ZeekDecoderError(IDSError):
    """Zeek-specific decoder errors."""
    pass


class ZeekDecoder(ProtocolDecoderInterface):
    """
    Zeek protocol decoder implementation.
    
    This decoder integrates with Zeek to analyze network packets and extract
    protocol-specific metadata. It processes packets by writing them to pcap
    files and running Zeek analysis, then parsing the resulting log files.
    """
    
    def __init__(
        self,
        zeek_binary_path: str = "/usr/local/zeek/bin/zeek",
        scripts_dir: Optional[str] = None,
        temp_dir: Optional[str] = None,
        batch_size: int = 100,
        timeout_seconds: int = 30
    ):
        """
        Initialize Zeek decoder.
        
        Args:
            zeek_binary_path: Path to Zeek binary executable
            scripts_dir: Directory containing custom Zeek scripts
            temp_dir: Directory for temporary files (uses system temp if None)
            batch_size: Number of packets to process in each batch
            timeout_seconds: Timeout for Zeek analysis operations
        """
        config = {
            "zeek_binary_path": zeek_binary_path,
            "scripts_dir": scripts_dir,
            "temp_dir": temp_dir,
            "batch_size": batch_size,
            "timeout_seconds": timeout_seconds
        }
        super().__init__(config)
        self.zeek_binary_path = Path(zeek_binary_path)
        self.scripts_dir = Path(scripts_dir) if scripts_dir else None
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.batch_size = batch_size
        self.timeout_seconds = timeout_seconds
        
        # Statistics tracking
        self._packets_processed = 0
        self._protocols_detected = {}
        self._alerts_generated = 0
        self._enabled_protocols = set(ProtocolType)
        
        # Zeek log parsers
        self._log_parsers = {
            "conn.log": self._parse_conn_log,
            "http.log": self._parse_http_log,
            "dns.log": self._parse_dns_log,
            "ssl.log": self._parse_ssl_log,
            "notice.log": self._parse_notice_log
        }
    
    async def initialize(self) -> None:
        """Initialize the Zeek decoder."""
        try:
            # Verify Zeek binary exists and is executable
            if not self.zeek_binary_path.exists():
                raise ZeekDecoderError(f"Zeek binary not found at {self.zeek_binary_path}")
            
            # Test Zeek installation
            result = await asyncio.create_subprocess_exec(
                str(self.zeek_binary_path), "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                raise ZeekDecoderError(f"Zeek version check failed: {stderr.decode()}")
            
            logger.info(f"Zeek decoder initialized: {stdout.decode().strip()}")
            
            # Create temp directory if it doesn't exist
            await aiofiles.os.makedirs(self.temp_dir, exist_ok=True)
            
            self._initialized = True
            
        except Exception as e:
            logger.error(f"Failed to initialize Zeek decoder: {e}")
            raise ZeekDecoderError(f"Initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the Zeek decoder."""
        if not self._initialized:
            await self.initialize()
        
        self._running = True
        logger.info("Zeek decoder started")
    
    async def stop(self) -> None:
        """Stop the Zeek decoder."""
        self._running = False
        logger.info("Zeek decoder stopped")
    
    async def decode_packet(self, packet: RawPacket) -> Optional[ProtocolMetadata]:
        """
        Decode a single packet using Zeek.
        
        Args:
            packet: Raw packet data to decode
            
        Returns:
            ProtocolMetadata if packet could be decoded, None otherwise
        """
        if not self._running:
            raise ZeekDecoderError("Decoder not running")
        
        # For single packet, use batch processing with size 1
        results = await self.decode_packets_batch([packet])
        return results[0] if results else None
    
    async def decode_packets_batch(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """
        Decode multiple packets in batch using Zeek.
        
        Args:
            packets: List of raw packets to decode
            
        Returns:
            List of decoded protocol metadata
        """
        if not self._running:
            raise ZeekDecoderError("Decoder not running")
        
        if not packets:
            return []
        
        try:
            # Create temporary pcap file
            pcap_file = self.temp_dir / f"zeek_batch_{datetime.now().timestamp()}.pcap"
            
            # Write packets to pcap file
            await self._write_packets_to_pcap(packets, pcap_file)
            
            # Run Zeek analysis
            log_dir = await self._run_zeek_analysis(pcap_file)
            
            # Parse Zeek logs
            metadata_list = await self._parse_zeek_logs(log_dir)
            
            # Update statistics
            self._packets_processed += len(packets)
            
            # Cleanup temporary files
            await self._cleanup_temp_files(pcap_file, log_dir)
            
            return metadata_list
            
        except Exception as e:
            logger.error(f"Batch decoding failed: {e}")
            raise ZeekDecoderError(f"Batch decoding failed: {e}")
    
    async def get_signature_alerts(self) -> AsyncIterator[SignatureAlert]:
        """
        Get signature-based security alerts from Zeek notices.
        
        Yields:
            SignatureAlert: Security alerts from Zeek notice framework
        """
        # This would typically read from a continuous Zeek notice log
        # For now, return empty iterator as this is batch-based processing
        return
        yield  # Make this an async generator
    
    async def load_custom_rules(self, rules_path: str) -> None:
        """
        Load custom Zeek scripts from directory.
        
        Args:
            rules_path: Path to directory containing Zeek script files
        """
        rules_dir = Path(rules_path)
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_path}")
        
        # Validate Zeek scripts
        script_files = list(rules_dir.glob("*.zeek")) + list(rules_dir.glob("*.bro"))
        
        for script_file in script_files:
            # Basic syntax validation by running zeek -p
            result = await asyncio.create_subprocess_exec(
                str(self.zeek_binary_path), "-p", str(script_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                raise ValueError(f"Invalid Zeek script {script_file}: {stderr.decode()}")
        
        self.scripts_dir = rules_dir
        logger.info(f"Loaded {len(script_files)} custom Zeek scripts from {rules_path}")
    
    async def reload_rules(self) -> None:
        """
        Reload Zeek scripts.
        
        Since this is a batch-based decoder, rules are loaded per analysis.
        This method validates that custom scripts are still valid.
        """
        if self.scripts_dir:
            await self.load_custom_rules(str(self.scripts_dir))
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get list of protocols supported by Zeek."""
        return [
            ProtocolType.TCP,
            ProtocolType.UDP,
            ProtocolType.ICMP,
            ProtocolType.HTTP,
            ProtocolType.HTTPS,
            ProtocolType.DNS,
            ProtocolType.TLS,
            ProtocolType.SSH
        ]
    
    async def get_decoder_statistics(self) -> Dict[str, Any]:
        """Get Zeek decoder statistics."""
        return {
            "packets_processed": self._packets_processed,
            "protocols_detected": dict(self._protocols_detected),
            "alerts_generated": self._alerts_generated,
            "processing_rate_pps": 0,  # Would need time tracking for actual rate
            "rule_count": len(list(self.scripts_dir.glob("*.zeek"))) if self.scripts_dir else 0,
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
    
    async def _write_packets_to_pcap(self, packets: List[RawPacket], pcap_file: Path) -> None:
        """Write raw packets to a pcap file for Zeek analysis."""
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
            raise ZeekDecoderError("Scapy is required for pcap file creation")
        except Exception as e:
            raise ZeekDecoderError(f"Failed to write pcap file: {e}")
    
    async def _run_zeek_analysis(self, pcap_file: Path) -> Path:
        """Run Zeek analysis on pcap file and return log directory."""
        log_dir = self.temp_dir / f"zeek_logs_{datetime.now().timestamp()}"
        await aiofiles.os.makedirs(log_dir, exist_ok=True)
        
        # Build Zeek command
        cmd = [str(self.zeek_binary_path), "-r", str(pcap_file)]
        
        # Add custom scripts if available
        if self.scripts_dir:
            for script_file in self.scripts_dir.glob("*.zeek"):
                cmd.extend(["-s", str(script_file)])
        
        # Set log directory
        cmd.extend(["-C", "-d", str(log_dir)])
        
        try:
            # Run Zeek analysis
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(log_dir)
                ),
                timeout=self.timeout_seconds
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode != 0:
                logger.error(f"Zeek analysis failed: {stderr.decode()}")
                raise ZeekDecoderError(f"Zeek analysis failed: {stderr.decode()}")
            
            logger.debug(f"Zeek analysis completed, logs in {log_dir}")
            return log_dir
            
        except asyncio.TimeoutError:
            raise ZeekDecoderError(f"Zeek analysis timed out after {self.timeout_seconds} seconds")
        except Exception as e:
            raise ZeekDecoderError(f"Zeek analysis failed: {e}")
    
    async def _parse_zeek_logs(self, log_dir: Path) -> List[ProtocolMetadata]:
        """Parse Zeek log files and extract protocol metadata."""
        metadata_list = []
        
        for log_file in log_dir.glob("*.log"):
            if log_file.name in self._log_parsers:
                try:
                    parser = self._log_parsers[log_file.name]
                    log_metadata = await parser(log_file)
                    metadata_list.extend(log_metadata)
                except Exception as e:
                    logger.warning(f"Failed to parse {log_file.name}: {e}")
        
        return metadata_list
    
    async def _parse_conn_log(self, log_file: Path) -> List[ProtocolMetadata]:
        """Parse Zeek conn.log file."""
        metadata_list = []
        
        try:
            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    fields = line.strip().split('\t')
                    if len(fields) < 10:
                        continue
                    
                    # Parse basic connection info
                    timestamp = datetime.fromtimestamp(float(fields[0]))
                    uid = fields[1]
                    source_ip = fields[2]
                    source_port = int(fields[3]) if fields[3] != '-' else 0
                    dest_ip = fields[4]
                    dest_port = int(fields[5]) if fields[5] != '-' else 0
                    protocol = fields[6].upper()
                    
                    # Map protocol string to ProtocolType
                    protocol_type = ProtocolType.TCP if protocol == "TCP" else \
                                  ProtocolType.UDP if protocol == "UDP" else \
                                  ProtocolType.ICMP if protocol == "ICMP" else \
                                  ProtocolType.UNKNOWN
                    
                    if protocol_type not in self._enabled_protocols:
                        continue
                    
                    # Extract additional fields if available
                    duration = float(fields[8]) if len(fields) > 8 and fields[8] != '-' else 0
                    orig_bytes = int(fields[9]) if len(fields) > 9 and fields[9] != '-' else 0
                    resp_bytes = int(fields[10]) if len(fields) > 10 and fields[10] != '-' else 0
                    
                    metadata = ProtocolMetadata(
                        protocol=protocol_type,
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        source_port=source_port,
                        destination_port=dest_port,
                        payload_size=orig_bytes + resp_bytes
                    )
                    
                    metadata_list.append(metadata)
                    
                    # Update protocol statistics
                    self._protocols_detected[protocol_type.value] = \
                        self._protocols_detected.get(protocol_type.value, 0) + 1
        
        except Exception as e:
            logger.error(f"Failed to parse conn.log: {e}")
        
        return metadata_list
    
    async def _parse_http_log(self, log_file: Path) -> List[ProtocolMetadata]:
        """Parse Zeek http.log file."""
        metadata_list = []
        
        try:
            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    fields = line.strip().split('\t')
                    if len(fields) < 10:
                        continue
                    
                    timestamp = datetime.fromtimestamp(float(fields[0]))
                    source_ip = fields[2]
                    source_port = int(fields[3]) if fields[3] != '-' else 0
                    dest_ip = fields[4]
                    dest_port = int(fields[5]) if fields[5] != '-' else 0
                    
                    # HTTP-specific fields
                    method = fields[7] if len(fields) > 7 and fields[7] != '-' else None
                    host = fields[8] if len(fields) > 8 and fields[8] != '-' else None
                    uri = fields[9] if len(fields) > 9 and fields[9] != '-' else None
                    user_agent = fields[12] if len(fields) > 12 and fields[12] != '-' else None
                    status_code = int(fields[15]) if len(fields) > 15 and fields[15] != '-' else None
                    
                    metadata = ProtocolMetadata(
                        protocol=ProtocolType.HTTP,
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        source_port=source_port,
                        destination_port=dest_port,
                        http_method=method,
                        http_uri=f"{host}{uri}" if host and uri else uri,
                        http_user_agent=user_agent,
                        http_status_code=status_code
                    )
                    
                    metadata_list.append(metadata)
                    self._protocols_detected[ProtocolType.HTTP.value] = \
                        self._protocols_detected.get(ProtocolType.HTTP.value, 0) + 1
        
        except Exception as e:
            logger.error(f"Failed to parse http.log: {e}")
        
        return metadata_list
    
    async def _parse_dns_log(self, log_file: Path) -> List[ProtocolMetadata]:
        """Parse Zeek dns.log file."""
        metadata_list = []
        
        try:
            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    fields = line.strip().split('\t')
                    if len(fields) < 10:
                        continue
                    
                    timestamp = datetime.fromtimestamp(float(fields[0]))
                    source_ip = fields[2]
                    source_port = int(fields[3]) if fields[3] != '-' else 0
                    dest_ip = fields[4]
                    dest_port = int(fields[5]) if fields[5] != '-' else 0
                    
                    # DNS-specific fields
                    query = fields[9] if len(fields) > 9 and fields[9] != '-' else None
                    qtype = fields[11] if len(fields) > 11 and fields[11] != '-' else None
                    rcode = fields[15] if len(fields) > 15 and fields[15] != '-' else None
                    answers = fields[21].split(',') if len(fields) > 21 and fields[21] != '-' else None
                    
                    metadata = ProtocolMetadata(
                        protocol=ProtocolType.DNS,
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        source_port=source_port,
                        destination_port=dest_port,
                        dns_query=query,
                        dns_query_type=qtype,
                        dns_response_code=rcode,
                        dns_answers=answers
                    )
                    
                    metadata_list.append(metadata)
                    self._protocols_detected[ProtocolType.DNS.value] = \
                        self._protocols_detected.get(ProtocolType.DNS.value, 0) + 1
        
        except Exception as e:
            logger.error(f"Failed to parse dns.log: {e}")
        
        return metadata_list
    
    async def _parse_ssl_log(self, log_file: Path) -> List[ProtocolMetadata]:
        """Parse Zeek ssl.log file."""
        metadata_list = []
        
        try:
            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    fields = line.strip().split('\t')
                    if len(fields) < 10:
                        continue
                    
                    timestamp = datetime.fromtimestamp(float(fields[0]))
                    source_ip = fields[2]
                    source_port = int(fields[3]) if fields[3] != '-' else 0
                    dest_ip = fields[4]
                    dest_port = int(fields[5]) if fields[5] != '-' else 0
                    
                    # TLS/SSL-specific fields
                    version = fields[6] if len(fields) > 6 and fields[6] != '-' else None
                    server_name = fields[9] if len(fields) > 9 and fields[9] != '-' else None
                    ja3 = fields[16] if len(fields) > 16 and fields[16] != '-' else None
                    ja3s = fields[17] if len(fields) > 17 and fields[17] != '-' else None
                    
                    metadata = ProtocolMetadata(
                        protocol=ProtocolType.TLS,
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        source_port=source_port,
                        destination_port=dest_port,
                        tls_version=version,
                        tls_sni=server_name,
                        tls_ja3_fingerprint=ja3,
                        tls_ja3s_fingerprint=ja3s
                    )
                    
                    metadata_list.append(metadata)
                    self._protocols_detected[ProtocolType.TLS.value] = \
                        self._protocols_detected.get(ProtocolType.TLS.value, 0) + 1
        
        except Exception as e:
            logger.error(f"Failed to parse ssl.log: {e}")
        
        return metadata_list
    
    async def _parse_notice_log(self, log_file: Path) -> List[SignatureAlert]:
        """Parse Zeek notice.log file for security alerts."""
        alerts = []
        
        try:
            async with aiofiles.open(log_file, 'r') as f:
                async for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    
                    fields = line.strip().split('\t')
                    if len(fields) < 10:
                        continue
                    
                    timestamp = datetime.fromtimestamp(float(fields[0]))
                    source_ip = fields[2] if fields[2] != '-' else "unknown"
                    source_port = int(fields[3]) if fields[3] != '-' else 0
                    dest_ip = fields[4] if fields[4] != '-' else "unknown"
                    dest_port = int(fields[5]) if fields[5] != '-' else 0
                    
                    notice_type = fields[8] if len(fields) > 8 and fields[8] != '-' else "Unknown"
                    message = fields[9] if len(fields) > 9 and fields[9] != '-' else ""
                    
                    alert = SignatureAlert(
                        rule_id=f"zeek_{notice_type}",
                        rule_name=notice_type,
                        severity="medium",  # Default severity
                        category="protocol_violation",
                        timestamp=timestamp,
                        source_ip=source_ip,
                        destination_ip=dest_ip,
                        source_port=source_port,
                        destination_port=dest_port,
                        protocol="unknown",
                        message=message
                    )
                    
                    alerts.append(alert)
                    self._alerts_generated += 1
        
        except Exception as e:
            logger.error(f"Failed to parse notice.log: {e}")
        
        return alerts
    
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