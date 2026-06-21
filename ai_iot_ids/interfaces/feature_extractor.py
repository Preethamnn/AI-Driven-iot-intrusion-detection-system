"""
Feature Extractor interface for the AI-driven IoT IDS system.

This module defines the abstract interface for feature extraction
components that convert raw network data into ML-ready features
for threat detection and anomaly analysis.
"""

from abc import abstractmethod
from typing import Dict, Any, List, Optional, AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timedelta

from .base import BaseInterface
from .protocol_decoder import ProtocolMetadata
from ..models.network_flow import NetworkFlow


@dataclass
class FlowWindow:
    """Time window for flow aggregation and feature extraction."""
    start_time: datetime
    end_time: datetime
    duration_seconds: int
    
    def contains(self, timestamp: datetime) -> bool:
        """Check if timestamp falls within this window."""
        return self.start_time <= timestamp <= self.end_time
    
    def overlaps(self, other: 'FlowWindow') -> bool:
        """Check if this window overlaps with another window."""
        return (self.start_time < other.end_time and 
                other.start_time < self.end_time)


@dataclass
class FeatureVector:
    """Feature vector for ML model input."""
    flow_id: str
    timestamp: datetime
    device_id: str
    features: Dict[str, float]
    feature_names: List[str]
    window: FlowWindow
    
    def to_array(self) -> List[float]:
        """Convert features to ordered array for ML models."""
        return [self.features.get(name, 0.0) for name in self.feature_names]
    
    def get_feature_count(self) -> int:
        """Get number of features in vector."""
        return len(self.feature_names)


class FeatureExtractorInterface(BaseInterface):
    """
    Abstract interface for feature extraction components.
    
    Implementations should convert protocol metadata and raw
    network flows into structured feature vectors suitable
    for machine learning-based threat detection.
    """
    
    @abstractmethod
    async def extract_flow_features(self, metadata_list: List[ProtocolMetadata]) -> NetworkFlow:
        """
        Extract network flow features from protocol metadata.
        
        Args:
            metadata_list: List of protocol metadata for the same flow
            
        Returns:
            NetworkFlow object with extracted features
            
        Raises:
            ValueError: If metadata is insufficient for feature extraction
        """
        pass
    
    @abstractmethod
    async def extract_temporal_features(self, flows: List[NetworkFlow], 
                                      window: FlowWindow) -> FeatureVector:
        """
        Extract temporal features from multiple flows within a time window.
        
        Args:
            flows: List of network flows within the time window
            window: Time window for feature aggregation
            
        Returns:
            FeatureVector with temporal features
        """
        pass
    
    @abstractmethod
    async def extract_device_features(self, device_id: str, 
                                    flows: List[NetworkFlow]) -> Dict[str, float]:
        """
        Extract device-specific behavioral features.
        
        Args:
            device_id: Device identifier (MAC address)
            flows: Historical flows for the device
            
        Returns:
            Dictionary of device behavioral features
        """
        pass
    
    @abstractmethod
    async def extract_dns_features(self, metadata: ProtocolMetadata) -> Dict[str, float]:
        """
        Extract DNS-specific features for threat detection.
        
        Args:
            metadata: Protocol metadata containing DNS information
            
        Returns:
            Dictionary of DNS-specific features including:
            - query_length: Length of DNS query
            - subdomain_count: Number of subdomains
            - entropy: Shannon entropy of domain name
            - nxdomain_rate: Rate of NXDOMAIN responses
        """
        pass
    
    @abstractmethod
    async def extract_tls_features(self, metadata: ProtocolMetadata) -> Dict[str, float]:
        """
        Extract TLS-specific features for threat detection.
        
        Args:
            metadata: Protocol metadata containing TLS information
            
        Returns:
            Dictionary of TLS-specific features including:
            - ja3_hash: JA3 fingerprint hash
            - ja3s_hash: JA3S fingerprint hash
            - cert_validity_days: Certificate validity period
            - cipher_strength: Cipher suite strength score
        """
        pass
    
    @abstractmethod
    async def calculate_directional_metrics(self, flows: List[NetworkFlow]) -> Dict[str, float]:
        """
        Calculate directional communication metrics.
        
        Args:
            flows: List of network flows for analysis
            
        Returns:
            Dictionary containing:
            - fan_out_ratio: Ratio of unique destinations to sources
            - fan_in_ratio: Ratio of unique sources to destinations
            - port_distribution_entropy: Entropy of port usage
            - protocol_diversity: Number of unique protocols used
        """
        pass
    
    @abstractmethod
    async def calculate_timing_features(self, flows: List[NetworkFlow]) -> Dict[str, float]:
        """
        Calculate timing-based features from flow data.
        
        Args:
            flows: List of network flows for timing analysis
            
        Returns:
            Dictionary containing:
            - inter_arrival_mean: Mean time between flows
            - inter_arrival_std: Standard deviation of inter-arrival times
            - periodicity_score: Score indicating periodic behavior
            - burst_ratio: Ratio of bursty to steady traffic
        """
        pass
    
    @abstractmethod
    async def normalize_features(self, feature_vector: FeatureVector) -> FeatureVector:
        """
        Normalize feature values for ML model consumption.
        
        Args:
            feature_vector: Raw feature vector to normalize
            
        Returns:
            Normalized feature vector with values scaled appropriately
        """
        pass
    
    @abstractmethod
    async def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance scores for explainability.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        pass
    
    @abstractmethod
    async def create_time_windows(self, start_time: datetime, 
                                end_time: datetime, 
                                window_size_minutes: int) -> List[FlowWindow]:
        """
        Create time windows for temporal feature extraction.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            window_size_minutes: Size of each window in minutes
            
        Returns:
            List of non-overlapping time windows
        """
        pass
    
    @abstractmethod
    async def get_extraction_statistics(self) -> Dict[str, Any]:
        """
        Get feature extraction statistics and performance metrics.
        
        Returns:
            Dictionary containing:
            - flows_processed: Total flows processed
            - features_extracted: Total feature vectors created
            - extraction_rate_fps: Current extraction rate (flows per second)
            - feature_dimensions: Number of features per vector
            - processing_latency_ms: Average processing latency
        """
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of feature extractor component.
        
        Returns:
            Health status including extraction statistics and performance
        """
        try:
            stats = await self.get_extraction_statistics()
            importance = await self.get_feature_importance()
            
            return {
                "status": "healthy" if self.is_running() else "stopped",
                "initialized": self.is_initialized(),
                "running": self.is_running(),
                "statistics": stats,
                "feature_count": len(importance),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }