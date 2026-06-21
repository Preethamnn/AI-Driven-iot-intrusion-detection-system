"""
Protocol Decoder interface for the AI-driven IoT IDS system.

This module defines the abstract interface for protocol decoding
components that parse network packets and extract protocol-specific
metadata using tools like Zeek and Suricata.
"""

from abc import abstractmethod
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from .base import BaseInterface
from .packet_capture import RawPacket


class ProtocolType(str, Enum):
    """Enumeration of supported network protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    DHCP = "DHCP"
    TLS = "TLS"
    SSH = "SSH"
    UNKNOWN = "UNKNOWN"


@dataclass
class ProtocolMetadata:
    """Protocol-specific metadata extracted from packets."""
    protocol: ProtocolType
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    
    # Protocol-specific fields
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_status_code: Optional[int] = None
    
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_response_code: Optional[str] = None
    dns_answers: Optional[List[str]] = None
    
    tls_sni: Optional[str] = None
    tls_ja3_fingerprint: Optional[str] = None
    tls_ja3s_fingerprint: Optional[str] = None
    tls_version: Optional[str] = None
    
    tcp_flags: Optional[List[str]] = None
    tcp_window_size: Optional[int] = None
    tcp_sequence_number: Optional[int] = None
    
    payload_size: int = 0
    raw_payload: Optional[bytes] = None


@dataclass
class SignatureAlert:
    """Security alert from signature-based detection."""
    rule_id: str
    rule_name: str
    severity: str
    category: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    message: str
    raw_packet: Optional[bytes] = None


class ProtocolDecoderInterface(BaseInterface):
    """
    Abstract interface for protocol decoding components.
    
    Implementations should integrate with protocol analysis tools
    like Zeek and Suricata to extract metadata and detect
    protocol violations or suspicious patterns.
    """
    
    @abstractmethod
    async def decode_packet(self, packet: RawPacket) -> Optional[ProtocolMetadata]:
        """
        Decode a single packet and extract protocol metadata.
        
        Args:
            packet: Raw packet data to decode
            
        Returns:
            ProtocolMetadata if packet could be decoded, None otherwise
            
        Raises:
            ValueError: If packet data is malformed
        """
        pass
    
    @abstractmethod
    async def decode_packets_batch(self, packets: List[RawPacket]) -> List[ProtocolMetadata]:
        """
        Decode multiple packets in batch for improved performance.
        
        Args:
            packets: List of raw packets to decode
            
        Returns:
            List of decoded protocol metadata (may be shorter than input
            if some packets could not be decoded)
        """
        pass
    
    @abstractmethod
    async def get_signature_alerts(self) -> AsyncIterator[SignatureAlert]:
        """
        Get signature-based security alerts from the decoder.
        
        Yields:
            SignatureAlert: Security alerts from signature matching
        """
        pass
    
    @abstractmethod
    async def load_custom_rules(self, rules_path: str) -> None:
        """
        Load custom detection rules from file system.
        
        Args:
            rules_path: Path to directory containing rule files
            
        Raises:
            FileNotFoundError: If rules path does not exist
            ValueError: If rules contain syntax errors
        """
        pass
    
    @abstractmethod
    async def reload_rules(self) -> None:
        """
        Reload detection rules without restarting the decoder.
        
        Supports hot-reloading of rules for operational flexibility.
        """
        pass
    
    @abstractmethod
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """
        Get list of protocols supported by this decoder.
        
        Returns:
            List of supported protocol types
        """
        pass
    
    @abstractmethod
    async def get_decoder_statistics(self) -> Dict[str, Any]:
        """
        Get protocol decoder statistics and performance metrics.
        
        Returns:
            Dictionary containing:
            - packets_processed: Total packets processed
            - protocols_detected: Count by protocol type
            - alerts_generated: Total signature alerts generated
            - processing_rate_pps: Current processing rate
            - rule_count: Number of loaded detection rules
        """
        pass
    
    @abstractmethod
    async def enable_protocol_analysis(self, protocols: List[ProtocolType]) -> None:
        """
        Enable analysis for specific protocols.
        
        Args:
            protocols: List of protocols to enable analysis for
        """
        pass
    
    @abstractmethod
    async def disable_protocol_analysis(self, protocols: List[ProtocolType]) -> None:
        """
        Disable analysis for specific protocols to improve performance.
        
        Args:
            protocols: List of protocols to disable analysis for
        """
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of protocol decoder component.
        
        Returns:
            Health status including processing statistics and rule status
        """
        try:
            stats = await self.get_decoder_statistics()
            supported_protocols = await self.get_supported_protocols()
            
            return {
                "status": "healthy" if self.is_running() else "stopped",
                "initialized": self.is_initialized(),
                "running": self.is_running(),
                "statistics": stats,
                "supported_protocols": [p.value for p in supported_protocols],
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }