"""
Factory functions for creating interface implementations.

This module provides factory functions to create concrete implementations
of the various system interfaces based on configuration.
"""

from typing import Dict, Any, Optional
import logging

from .packet_capture import PacketCaptureInterface
from .feature_extractor import FeatureExtractorInterface
from ..capture.scapy_capture import ScapyPacketCapture
from ..extractors.network_flow_extractor import NetworkFlowExtractor


def create_packet_capture(
    capture_type: str = "scapy",
    config: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None
) -> PacketCaptureInterface:
    """
    Create a packet capture interface implementation.
    
    Args:
        capture_type: Type of packet capture implementation to create.
                     Supported types: "scapy"
        config: Configuration dictionary for the implementation
        logger: Optional logger instance
        
    Returns:
        PacketCaptureInterface implementation
        
    Raises:
        ValueError: If capture_type is not supported
    """
    if config is None:
        config = {}
    
    if capture_type.lower() == "scapy":
        return ScapyPacketCapture(config, logger)
    else:
        raise ValueError(f"Unsupported packet capture type: {capture_type}")


def create_feature_extractor(
    extractor_type: str = "network_flow",
    config: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None
) -> FeatureExtractorInterface:
    """
    Create a feature extractor interface implementation.
    
    Args:
        extractor_type: Type of feature extractor implementation to create.
                       Supported types: "network_flow"
        config: Configuration dictionary for the implementation
        logger: Optional logger instance
        
    Returns:
        FeatureExtractorInterface implementation
        
    Raises:
        ValueError: If extractor_type is not supported
    """
    if config is None:
        config = {}
    
    if extractor_type.lower() == "network_flow":
        return NetworkFlowExtractor(config, logger)
    else:
        raise ValueError(f"Unsupported feature extractor type: {extractor_type}")


# Registry of available implementations
PACKET_CAPTURE_IMPLEMENTATIONS = {
    "scapy": ScapyPacketCapture,
}

FEATURE_EXTRACTOR_IMPLEMENTATIONS = {
    "network_flow": NetworkFlowExtractor,
}


def get_available_packet_capture_types() -> list[str]:
    """Get list of available packet capture implementation types."""
    return list(PACKET_CAPTURE_IMPLEMENTATIONS.keys())


def get_available_feature_extractor_types() -> list[str]:
    """Get list of available feature extractor implementation types."""
    return list(FEATURE_EXTRACTOR_IMPLEMENTATIONS.keys())