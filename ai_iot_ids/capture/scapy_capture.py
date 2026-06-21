"""
Scapy-based packet capture implementation for the AI-driven IoT IDS system.

This module provides a concrete implementation of the PacketCaptureInterface
using Scapy for network packet capture with support for both libpcap and
af_packet interfaces, configurable filters, and buffer management.
"""

import asyncio
import time
from typing import AsyncIterator, Dict, Any, Optional, List, Set
from datetime import datetime
from dataclasses import dataclass, field
from collections import deque
import threading
import socket
import struct

try:
    from scapy.all import (
        sniff, get_if_list, get_if_addr,
        Packet, IP, IPv6, TCP, UDP, ICMP,
        conf
    )
    from scapy.error import Scapy_Exception
    
    # Try to import ICMPv6, but don't fail if not available
    try:
        from scapy.all import ICMPv6
        HAS_ICMPV6 = True
    except ImportError:
        ICMPv6 = None
        HAS_ICMPV6 = False
        
except ImportError as e:
    raise ImportError(f"Scapy is required for packet capture: {e}")

from ..interfaces.packet_capture import PacketCaptureInterface, RawPacket
from ..utils.error_handling import IDSError


@dataclass
class CaptureStatistics:
    """Statistics for packet capture operations."""
    packets_captured: int = 0
    packets_dropped: int = 0
    bytes_captured: int = 0
    capture_start_time: Optional[datetime] = None
    last_packet_time: Optional[datetime] = None
    buffer_utilization: float = 0.0
    
    def get_capture_rate_pps(self) -> float:
        """Calculate current capture rate in packets per second."""
        if not self.capture_start_time or self.packets_captured == 0:
            return 0.0
        
        elapsed = (datetime.utcnow() - self.capture_start_time).total_seconds()
        if elapsed <= 0:
            return 0.0
        
        return self.packets_captured / elapsed


class ScapyPacketCapture(PacketCaptureInterface):
    """
    Scapy-based implementation of PacketCaptureInterface.
    
    Provides packet capture functionality using Scapy with support for:
    - Configurable BPF filters
    - Buffer management with size limits
    - Both libpcap and af_packet interfaces
    - Async packet iteration
    - Capture statistics and monitoring
    """
    
    def __init__(self, config: Dict[str, Any], logger=None):
        """
        Initialize the Scapy packet capture component.
        
        Args:
            config: Configuration dictionary containing:
                - buffer_size_mb: Buffer size in megabytes (default: 64)
                - max_packet_size: Maximum packet size to capture (default: 65535)
                - capture_timeout: Timeout for packet capture operations (default: 1.0)
                - promisc_mode: Enable promiscuous mode (default: True)
                - use_af_packet: Use AF_PACKET socket type on Linux (default: True)
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration parameters
        self.buffer_size_mb = self.get_config('buffer_size_mb', 64)
        self.max_packet_size = self.get_config('max_packet_size', 65535)
        self.capture_timeout = self.get_config('capture_timeout', 1.0)
        self.promisc_mode = self.get_config('promisc_mode', True)
        self.use_af_packet = self.get_config('use_af_packet', True)
        
        # Calculate buffer size in packets (approximate)
        avg_packet_size = 1500  # Typical Ethernet MTU
        self.max_buffer_packets = (self.buffer_size_mb * 1024 * 1024) // avg_packet_size
        
        # Internal state
        self.current_interface: Optional[str] = None
        self.current_filter: str = ""
        self.packet_buffer: deque = deque(maxlen=self.max_buffer_packets)
        self.statistics = CaptureStatistics()
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.packet_event = asyncio.Event()
        
        # Thread-safe access to packet buffer
        self.buffer_lock = threading.Lock()
        
        # Available interfaces cache
        self._available_interfaces: Optional[List[str]] = None
        self._interfaces_cache_time: Optional[datetime] = None
        self._cache_timeout = 30  # seconds
    
    async def initialize(self) -> None:
        """Initialize the packet capture component."""
        if self._initialized:
            return
        
        try:
            # Test Scapy functionality
            interfaces = await self.get_available_interfaces()
            if not interfaces:
                raise IDSError("No network interfaces available for packet capture")
            
            self.log_info(f"Initialized Scapy packet capture with {len(interfaces)} available interfaces")
            self.log_info(f"Buffer size: {self.buffer_size_mb}MB ({self.max_buffer_packets} packets)")
            
            # Configure Scapy settings
            import os
            if os.name == 'nt':
                conf.use_pcap = True
                try:
                    conf.use_npcap = True
                except AttributeError:
                    pass
                self.log_info("Using Npcap/Winpcap interface for Windows")
            elif self.use_af_packet:
                try:
                    conf.use_pcap = False  # Use native Linux sockets
                    self.log_info("Using AF_PACKET socket interface")
                except Exception as e:
                    self.log_warning(f"Could not configure AF_PACKET, falling back to libpcap: {e}")
                    conf.use_pcap = True
            else:
                conf.use_pcap = True
                self.log_info("Using libpcap interface")
            
            self._initialized = True
            
        except Exception as e:
            self.log_error("Failed to initialize packet capture", e)
            raise IDSError(f"Packet capture initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the packet capture component."""
        if not self._initialized:
            await self.initialize()
        
        if self._running:
            self.log_warning("Packet capture is already running")
            return
        
        self._running = True
        self.log_info("Packet capture component started")
    
    async def stop(self) -> None:
        """Stop the packet capture component."""
        if not self._running:
            return
        
        # Stop any active capture
        await self.stop_capture()
        
        self._running = False
        self.log_info("Packet capture component stopped")
    
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
        if not self._running:
            raise RuntimeError("Packet capture component is not running")
        
        # Stop any existing capture
        if self.capture_thread and self.capture_thread.is_alive():
            await self.stop_capture()
        
        # Resolve Windows interface names if needed
        import os
        if os.name == 'nt':
            try:
                from scapy.arch.windows import get_windows_if_list
                for win_if in get_windows_if_list():
                    if win_if['name'] == interface or win_if['description'] == interface:
                        resolved = f"\\Device\\NPF_{win_if['guid']}"
                        self.log_info(f"Resolved Windows interface '{interface}' to '{resolved}'")
                        interface = resolved
                        break
            except ImportError:
                pass
                
        # Validate interface
        available_interfaces = await self.get_available_interfaces()
        if interface not in available_interfaces:
            raise ValueError(f"Interface '{interface}' not available. Available: {available_interfaces}")
        
        # Validate filter
        if filter_expression and not await self.validate_filter(filter_expression):
            raise ValueError(f"Invalid BPF filter expression: '{filter_expression}'")
        
        # Clear previous state
        with self.buffer_lock:
            self.packet_buffer.clear()
            self.statistics = CaptureStatistics()
            self.statistics.capture_start_time = datetime.utcnow()
        
        self.current_interface = interface
        self.current_filter = filter_expression
        self.stop_event.clear()
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(interface, filter_expression),
            daemon=True
        )
        self.capture_thread.start()
        
        self.log_info(f"Started packet capture on interface '{interface}' with filter '{filter_expression}'")
    
    async def stop_capture(self) -> None:
        """Stop packet capture and release interface resources."""
        if not self.capture_thread:
            # No capture thread, but reset interface state anyway
            self.current_interface = None
            self.current_filter = ""
            return
        
        # Signal stop and wait for thread to finish
        self.stop_event.set()
        
        # Wait for capture thread to finish (with timeout)
        if self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5.0)
            if self.capture_thread.is_alive():
                self.log_warning("Capture thread did not stop gracefully")
        
        self.current_interface = None
        self.current_filter = ""
        self.capture_thread = None
        
        self.log_info("Stopped packet capture")
    
    def _capture_worker(self, interface: str, filter_expression: str) -> None:
        """
        Worker thread for packet capture using Scapy.
        
        Args:
            interface: Network interface to capture on
            filter_expression: BPF filter expression
        """
        try:
            def packet_handler(packet: Packet) -> None:
                """Handle captured packets."""
                if self.stop_event.is_set():
                    return
                
                try:
                    # Convert Scapy packet to RawPacket
                    raw_packet = self._convert_packet(packet, interface)
                    
                    # Add to buffer (thread-safe)
                    with self.buffer_lock:
                        if len(self.packet_buffer) >= self.max_buffer_packets:
                            # Buffer full, drop oldest packet
                            self.packet_buffer.popleft()
                            self.statistics.packets_dropped += 1
                        
                        self.packet_buffer.append(raw_packet)
                        self.statistics.packets_captured += 1
                        self.statistics.bytes_captured += raw_packet.length
                        self.statistics.last_packet_time = raw_packet.timestamp
                        
                        # Update buffer utilization
                        self.statistics.buffer_utilization = (
                            len(self.packet_buffer) / self.max_buffer_packets * 100.0
                        )
                    
                    # Signal that new packet is available
                    try:
                        # This is called from a different thread, so we need to be careful
                        # with asyncio event signaling
                        if hasattr(self.packet_event, '_loop') and self.packet_event._loop:
                            self.packet_event._loop.call_soon_threadsafe(self.packet_event.set)
                    except Exception:
                        pass  # Ignore asyncio event signaling errors
                        
                except Exception as e:
                    self.log_error(f"Error processing packet: {e}")
            
            # Start Scapy sniffing in a loop since it exits after timeout
            while not self.stop_event.is_set():
                sniff(
                    iface=interface,
                    filter=filter_expression if filter_expression else None,
                    prn=packet_handler,
                    store=False,  # Don't store packets in memory
                    stop_filter=lambda x: self.stop_event.is_set(),
                    timeout=self.capture_timeout,
                    promisc=self.promisc_mode
                )
            
        except Exception as e:
            self.log_error(f"Packet capture worker error: {e}")
        finally:
            self.log_info("Packet capture worker finished")
    
    def _convert_packet(self, packet: Packet, interface: str) -> RawPacket:
        """
        Convert a Scapy packet to RawPacket format.
        
        Args:
            packet: Scapy packet object
            interface: Interface name where packet was captured
            
        Returns:
            RawPacket object with extracted metadata
        """
        # Extract basic packet information
        timestamp = datetime.utcnow()
        data = bytes(packet)
        length = len(data)
        
        # Extract network layer information
        source_ip = None
        destination_ip = None
        protocol = None
        source_port = None
        destination_port = None
        
        # Check for IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            destination_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            # Check for transport layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                destination_port = tcp_layer.dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                destination_port = udp_layer.dport
                protocol = "UDP"
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
        
        # Check for IPv6 layer
        elif packet.haslayer(IPv6):
            ipv6_layer = packet[IPv6]
            source_ip = ipv6_layer.src
            destination_ip = ipv6_layer.dst
            protocol = ipv6_layer.nh
            
            # Check for transport layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                destination_port = tcp_layer.dport
                protocol = "TCP"
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                destination_port = udp_layer.dport
                protocol = "UDP"
            elif packet.haslayer(ICMPv6) if HAS_ICMPV6 and ICMPv6 else False:
                protocol = "ICMPv6"
        
        return RawPacket(
            timestamp=timestamp,
            length=length,
            data=data,
            interface=interface,
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port
        )
    
    async def get_packets(self) -> AsyncIterator[RawPacket]:
        """
        Get captured packets as an async iterator.
        
        Yields:
            RawPacket: Individual captured packets with metadata
            
        Raises:
            RuntimeError: If capture is not active
        """
        if not self.current_interface:
            raise RuntimeError("Packet capture is not active")
        
        while True:
            # Check if we have packets in buffer
            packet = None
            with self.buffer_lock:
                if self.packet_buffer:
                    packet = self.packet_buffer.popleft()
            
            if packet:
                yield packet
            else:
                # No packets available, wait for new ones
                if not self.capture_thread or not self.capture_thread.is_alive():
                    # Capture has stopped
                    break
                
                # Wait for packet event or timeout
                try:
                    await asyncio.wait_for(self.packet_event.wait(), timeout=1.0)
                    self.packet_event.clear()
                except asyncio.TimeoutError:
                    # Timeout is normal, continue checking
                    continue
    
    async def get_capture_statistics(self) -> Dict[str, Any]:
        """Get packet capture statistics and performance metrics."""
        with self.buffer_lock:
            stats = {
                "packets_captured": self.statistics.packets_captured,
                "packets_dropped": self.statistics.packets_dropped,
                "bytes_captured": self.statistics.bytes_captured,
                "capture_rate_pps": self.statistics.get_capture_rate_pps(),
                "buffer_utilization": self.statistics.buffer_utilization,
                "buffer_size_packets": self.max_buffer_packets,
                "current_buffer_count": len(self.packet_buffer),
                "capture_active": self.current_interface is not None,
                "current_interface": self.current_interface,
                "current_filter": self.current_filter
            }
            
            if self.statistics.capture_start_time:
                stats["capture_start_time"] = self.statistics.capture_start_time.isoformat()
            
            if self.statistics.last_packet_time:
                stats["last_packet_time"] = self.statistics.last_packet_time.isoformat()
        
        return stats
    
    async def set_buffer_size(self, size_mb: int) -> None:
        """
        Set the packet capture buffer size.
        
        Args:
            size_mb: Buffer size in megabytes
            
        Raises:
            ValueError: If buffer size is invalid
            RuntimeError: If buffer cannot be resized during capture
        """
        if size_mb < 1 or size_mb > 1024:
            raise ValueError("Buffer size must be between 1 and 1024 MB")
        
        if self.current_interface:
            raise RuntimeError("Cannot resize buffer during active capture")
        
        self.buffer_size_mb = size_mb
        avg_packet_size = 1500
        new_max_packets = (size_mb * 1024 * 1024) // avg_packet_size
        
        with self.buffer_lock:
            self.max_buffer_packets = new_max_packets
            # Create new deque with updated size
            old_buffer = list(self.packet_buffer)
            self.packet_buffer = deque(old_buffer[-new_max_packets:], maxlen=new_max_packets)
        
        self.log_info(f"Buffer size updated to {size_mb}MB ({new_max_packets} packets)")
    
    async def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces for capture."""
        # Use cached result if available and recent
        now = datetime.utcnow()
        if (self._available_interfaces and self._interfaces_cache_time and
            (now - self._interfaces_cache_time).total_seconds() < self._cache_timeout):
            return self._available_interfaces
        
        try:
            # Get interfaces from Scapy
            interfaces = get_if_list()
            
            # Filter out loopback and invalid interfaces
            valid_interfaces = []
            for iface in interfaces:
                try:
                    # Try to get interface address to verify it's valid
                    addr = get_if_addr(iface)
                    if addr and addr != "0.0.0.0" and not iface.startswith("lo"):
                        valid_interfaces.append(iface)
                    elif iface != "lo" and not iface.startswith("lo"):
                        # Include interface even if no IP (for monitoring mode)
                        valid_interfaces.append(iface)
                except Exception:
                    # Skip interfaces that cause errors
                    continue
            
            # Update cache
            self._available_interfaces = valid_interfaces
            self._interfaces_cache_time = now
            
            return valid_interfaces
            
        except Exception as e:
            self.log_error(f"Error getting available interfaces: {e}")
            return []
    
    async def validate_filter(self, filter_expression: str) -> bool:
        """
        Validate a BPF filter expression without starting capture.
        
        Args:
            filter_expression: BPF filter to validate
            
        Returns:
            True if filter is valid, False otherwise
        """
        if not filter_expression:
            return True
        
        try:
            # Try to compile the filter using Scapy
            # This is a simple validation - we attempt a very short sniff with the filter
            from scapy.all import compile_filter
            
            # Get a valid interface for testing
            interfaces = await self.get_available_interfaces()
            if not interfaces:
                return False
            
            test_interface = interfaces[0]
            
            # Try to compile the filter
            try:
                # Use Scapy's internal filter compilation if available
                compile_filter(filter_expression, test_interface)
                return True
            except (AttributeError, ImportError):
                # Fallback: try a very short sniff to test the filter
                try:
                    sniff(
                        iface=test_interface,
                        filter=filter_expression,
                        count=0,  # Don't capture any packets
                        timeout=0.1,  # Very short timeout
                        store=False
                    )
                    return True
                except Exception:
                    return False
            
        except Exception as e:
            self.log_warning(f"Filter validation error: {e}")
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of packet capture component."""
        try:
            stats = await self.get_capture_statistics()
            interfaces = await self.get_available_interfaces()
            
            # Check for potential issues
            issues = []
            if stats["buffer_utilization"] > 90:
                issues.append("High buffer utilization")
            
            if stats["packets_dropped"] > 0:
                issues.append(f"Packets dropped: {stats['packets_dropped']}")
            
            if not interfaces:
                issues.append("No network interfaces available")
            
            status = "healthy"
            if issues:
                status = "warning" if stats["capture_active"] else "unhealthy"
            
            return {
                "status": status,
                "initialized": self.is_initialized(),
                "running": self.is_running(),
                "capture_active": stats["capture_active"],
                "statistics": stats,
                "available_interfaces": len(interfaces),
                "interface_list": interfaces,
                "issues": issues,
                "timestamp": datetime.utcnow().isoformat(),
                "scapy_version": getattr(__import__('scapy'), '__version__', 'unknown'),
                "use_af_packet": self.use_af_packet,
                "buffer_size_mb": self.buffer_size_mb
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }