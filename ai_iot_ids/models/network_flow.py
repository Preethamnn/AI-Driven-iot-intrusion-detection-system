"""
Network Flow data model for the AI-driven IoT IDS system.

This module defines the NetworkFlow Pydantic model that represents
network traffic flow features extracted from packet capture and
protocol decoding processes.
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator, model_validator
from ipaddress import IPv4Address, IPv6Address, AddressValueError
from typing import Union


class NetworkFlow(BaseModel):
    """
    Network flow feature representation for ML-based threat detection.
    
    This model captures flow-level statistics, timing features, protocol-specific
    information, and connection patterns extracted from network packet analysis.
    """
    
    # Core Flow Identification
    flow_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique flow identifier")
    timestamp: datetime = Field(description="Flow start timestamp in ISO 8601 format")
    source_ip: str = Field(description="Source IP address (IPv4 or IPv6)")
    destination_ip: str = Field(description="Destination IP address (IPv4 or IPv6)")
    source_port: int = Field(ge=0, le=65535, description="Source port number")
    destination_port: int = Field(ge=0, le=65535, description="Destination port number")
    protocol: str = Field(description="Network protocol (TCP/UDP/ICMP)")
    
    # Flow Statistics
    bytes_sent: int = Field(ge=0, description="Total bytes sent from source to destination")
    bytes_received: int = Field(ge=0, description="Total bytes received from destination to source")
    packets_sent: int = Field(ge=0, description="Total packets sent from source to destination")
    packets_received: int = Field(ge=0, description="Total packets received from destination to source")
    duration_ms: int = Field(ge=0, description="Flow duration in milliseconds")
    
    # Timing Features
    inter_arrival_mean_ms: float = Field(ge=0, description="Mean inter-arrival time in milliseconds")
    inter_arrival_std_ms: float = Field(ge=0, description="Standard deviation of inter-arrival times")
    jitter_ms: float = Field(ge=0, description="Packet jitter in milliseconds")
    
    # TCP-specific Features
    tcp_flags: List[str] = Field(default_factory=list, description="TCP flags observed (SYN, ACK, FIN, RST, PSH, URG)")
    retransmissions: int = Field(ge=0, default=0, description="Number of TCP retransmissions")
    syn_fin_ratio: float = Field(ge=0, default=0.0, description="Ratio of SYN to FIN packets")
    
    # Connection Patterns
    unique_destinations: int = Field(ge=0, default=1, description="Number of unique destination addresses")
    fan_out_ratio: float = Field(ge=0, default=0.0, description="Fan-out ratio for connection patterns")
    fan_in_ratio: float = Field(ge=0, default=0.0, description="Fan-in ratio for connection patterns")
    port_distribution_entropy: float = Field(ge=0, default=0.0, description="Entropy of port distribution")
    
    class Config:
        """Pydantic configuration for NetworkFlow model."""
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v)
        }
        schema_extra = {
            "example": {
                "flow_id": "550e8400-e29b-41d4-a716-446655440000",
                "timestamp": "2024-01-15T10:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "8.8.8.8",
                "source_port": 45123,
                "destination_port": 53,
                "protocol": "UDP",
                "bytes_sent": 64,
                "bytes_received": 128,
                "packets_sent": 1,
                "packets_received": 1,
                "duration_ms": 150,
                "inter_arrival_mean_ms": 0.0,
                "inter_arrival_std_ms": 0.0,
                "jitter_ms": 0.0,
                "tcp_flags": [],
                "retransmissions": 0,
                "syn_fin_ratio": 0.0,
                "unique_destinations": 1,
                "fan_out_ratio": 0.0,
                "fan_in_ratio": 0.0,
                "port_distribution_entropy": 0.0
            }
        }
    
    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def validate_ip_address(cls, v):
        """Validate that IP addresses are valid IPv4 or IPv6 addresses."""
        try:
            # Try IPv4 first
            IPv4Address(v)
            return v
        except AddressValueError:
            try:
                # Try IPv6
                IPv6Address(v)
                return v
            except AddressValueError:
                raise ValueError(f"Invalid IP address: {v}")
    
    @field_validator('protocol')
    @classmethod
    def validate_protocol(cls, v):
        """Validate that protocol is one of the supported types."""
        valid_protocols = {'TCP', 'UDP', 'ICMP', 'ICMPv6'}
        if v.upper() not in valid_protocols:
            raise ValueError(f"Protocol must be one of {valid_protocols}, got {v}")
        return v.upper()
    
    @field_validator('tcp_flags')
    @classmethod
    def validate_tcp_flags(cls, v):
        """Validate that TCP flags are from the allowed set."""
        valid_flags = {'SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG'}
        for flag in v:
            if flag.upper() not in valid_flags:
                raise ValueError(f"Invalid TCP flag: {flag}. Must be one of {valid_flags}")
        return [flag.upper() for flag in v]
    
    @model_validator(mode='after')
    def validate_flow_consistency(self):
        """Validate consistency between flow statistics and protocol type."""
        protocol = self.protocol.upper() if self.protocol else ''
        tcp_flags = self.tcp_flags or []
        retransmissions = self.retransmissions or 0
        syn_fin_ratio = self.syn_fin_ratio or 0.0
        
        # TCP-specific validations
        if protocol == 'TCP':
            # TCP flows should have reasonable flag combinations
            if tcp_flags and 'SYN' in tcp_flags and 'FIN' in tcp_flags:
                # This is valid - connection establishment and teardown
                pass
        elif protocol in ['UDP', 'ICMP', 'ICMPV6']:
            # Non-TCP protocols shouldn't have TCP-specific features
            if tcp_flags:
                raise ValueError(f"TCP flags not applicable for {protocol} protocol")
            if retransmissions > 0:
                raise ValueError(f"TCP retransmissions not applicable for {protocol} protocol")
        
        return self
    
    def total_bytes(self) -> int:
        """Calculate total bytes transferred in both directions."""
        return self.bytes_sent + self.bytes_received
    
    def total_packets(self) -> int:
        """Calculate total packets transferred in both directions."""
        return self.packets_sent + self.packets_received
    
    def bytes_per_packet_sent(self) -> float:
        """Calculate average bytes per packet sent."""
        return self.bytes_sent / self.packets_sent if self.packets_sent > 0 else 0.0
    
    def bytes_per_packet_received(self) -> float:
        """Calculate average bytes per packet received."""
        return self.bytes_received / self.packets_received if self.packets_received > 0 else 0.0
    
    def is_bidirectional(self) -> bool:
        """Check if flow has traffic in both directions."""
        return self.bytes_sent > 0 and self.bytes_received > 0