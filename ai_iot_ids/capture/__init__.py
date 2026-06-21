"""
Packet capture implementations for the AI-driven IoT IDS system.

This module provides concrete implementations of packet capture interfaces
using various backends like Scapy, libpcap, and af_packet.
"""

from .scapy_capture import ScapyPacketCapture

__all__ = [
    'ScapyPacketCapture',
]