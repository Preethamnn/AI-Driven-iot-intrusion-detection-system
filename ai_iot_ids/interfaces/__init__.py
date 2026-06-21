"""
Interface definitions for the AI-driven IoT IDS system.

This module contains abstract base classes and interface definitions
for all major system components, enabling modular design and
testability through dependency injection.
"""

from .base import BaseInterface
from .packet_capture import PacketCaptureInterface
from .protocol_decoder import ProtocolDecoderInterface
from .feature_extractor import FeatureExtractorInterface
from .secure_forwarder import SecureForwarderInterface
from .factory import create_packet_capture, get_available_packet_capture_types

__all__ = [
    "BaseInterface",
    "PacketCaptureInterface",
    "ProtocolDecoderInterface",
    "FeatureExtractorInterface",
    "SecureForwarderInterface",
    "create_packet_capture",
    "get_available_packet_capture_types",
]