"""
Packet Capture interface for the AI-driven IoT IDS system.

This module defines the abstract interface for packet capture
components that handle network traffic monitoring and raw
packet collection from network interfaces.
"""

from abc import abstractmethod
from typing import AsyncIterator, Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

from .base import BaseInterface


@dataclass
class RawPacket:
    """Raw packet data structure from network capture."""
    timestamp: datetime
    length: int
    data: bytes
    interface: str
    protocol: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None


class PacketCaptureInterface(BaseInterface):
    """
    Abstract interface for packet capture components.
    
    Implementations should handle network packet capture using
    libpcap, af_packet, or similar low-level interfaces with
    configurable filtering and buffering capabilities.
    """
    
    @abstractmethod
    async def start_capture(self, interface: str, filter_expression: str = "") -> None:
        """
        Start packet capture on the specified network interface.
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'wlan0')
            filter_expression: BPF filter expression for packet filtering
            
        Raises:
            RuntimeError: If capture cannot be started
            ValueError: If interface or filter is invalid
        """
        pass
    
    @abstractmethod
    async def stop_capture(self) -> None:
        """
        Stop packet capture and release interface resources.
        
        Should gracefully stop capture and ensure no packets are lost
        from the current buffer.
        """
        pass
    
    @abstractmethod
    async def get_packets(self) -> AsyncIterator[RawPacket]:
        """
        Get captured packets as an async iterator.
        
        Yields:
            RawPacket: Individual captured packets with metadata
            
        Raises:
            RuntimeError: If capture is not active
        """
        pass
    
    @abstractmethod
    async def get_capture_statistics(self) -> Dict[str, Any]:
        """
        Get packet capture statistics and performance metrics.
        
        Returns:
            Dictionary containing:
            - packets_captured: Total packets captured
            - packets_dropped: Packets dropped due to buffer overflow
            - bytes_captured: Total bytes captured
            - capture_rate_pps: Current capture rate in packets per second
            - buffer_utilization: Current buffer utilization percentage
        """
        pass
    
    @abstractmethod
    async def set_buffer_size(self, size_mb: int) -> None:
        """
        Set the packet capture buffer size.
        
        Args:
            size_mb: Buffer size in megabytes
            
        Raises:
            ValueError: If buffer size is invalid
            RuntimeError: If buffer cannot be resized during capture
        """
        pass
    
    @abstractmethod
    async def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces for capture.
        
        Returns:
            List of interface names available for packet capture
        """
        pass
    
    @abstractmethod
    async def validate_filter(self, filter_expression: str) -> bool:
        """
        Validate a BPF filter expression without starting capture.
        
        Args:
            filter_expression: BPF filter to validate
            
        Returns:
            True if filter is valid, False otherwise
        """
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of packet capture component.
        
        Returns:
            Health status including capture statistics and interface status
        """
        try:
            stats = await self.get_capture_statistics()
            interfaces = await self.get_available_interfaces()
            
            return {
                "status": "healthy" if self.is_running() else "stopped",
                "initialized": self.is_initialized(),
                "running": self.is_running(),
                "statistics": stats,
                "available_interfaces": len(interfaces),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }