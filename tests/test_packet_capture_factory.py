"""
Unit tests for packet capture factory functions.

Tests the factory functions for creating packet capture implementations.
"""

import pytest
from typing import Dict, Any

from ai_iot_ids.interfaces.factory import (
    create_packet_capture,
    get_available_packet_capture_types,
    PACKET_CAPTURE_IMPLEMENTATIONS
)
from ai_iot_ids.interfaces.packet_capture import PacketCaptureInterface
from ai_iot_ids.capture.scapy_capture import ScapyPacketCapture


class TestPacketCaptureFactory:
    """Test packet capture factory functions."""
    
    def test_create_packet_capture_scapy(self):
        """Test creating Scapy packet capture implementation."""
        config = {'buffer_size_mb': 10}
        capture = create_packet_capture("scapy", config)
        
        assert isinstance(capture, ScapyPacketCapture)
        assert isinstance(capture, PacketCaptureInterface)
        assert capture.buffer_size_mb == 10
    
    def test_create_packet_capture_scapy_case_insensitive(self):
        """Test creating Scapy implementation with different case."""
        capture = create_packet_capture("SCAPY")
        assert isinstance(capture, ScapyPacketCapture)
        
        capture = create_packet_capture("Scapy")
        assert isinstance(capture, ScapyPacketCapture)
    
    def test_create_packet_capture_default_config(self):
        """Test creating packet capture with default configuration."""
        capture = create_packet_capture("scapy")
        assert isinstance(capture, ScapyPacketCapture)
        # Should use default buffer size
        assert capture.buffer_size_mb == 64
    
    def test_create_packet_capture_invalid_type(self):
        """Test creating packet capture with invalid type."""
        with pytest.raises(ValueError, match="Unsupported packet capture type: invalid"):
            create_packet_capture("invalid")
    
    def test_get_available_packet_capture_types(self):
        """Test getting available packet capture types."""
        types = get_available_packet_capture_types()
        assert isinstance(types, list)
        assert "scapy" in types
        assert len(types) >= 1
    
    def test_packet_capture_implementations_registry(self):
        """Test the implementations registry."""
        assert "scapy" in PACKET_CAPTURE_IMPLEMENTATIONS
        assert PACKET_CAPTURE_IMPLEMENTATIONS["scapy"] == ScapyPacketCapture
    
    def test_create_packet_capture_with_logger(self):
        """Test creating packet capture with custom logger."""
        import logging
        logger = logging.getLogger("test_logger")
        
        capture = create_packet_capture("scapy", logger=logger)
        assert capture.logger == logger