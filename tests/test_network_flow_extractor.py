"""
Unit tests for NetworkFlowExtractor implementation.

Tests the feature extraction functionality including flow-level features,
directional metrics, DNS/TLS features, and temporal analysis.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import List

from ai_iot_ids.extractors.network_flow_extractor import NetworkFlowExtractor
from ai_iot_ids.interfaces.feature_extractor import FlowWindow, FeatureVector
from ai_iot_ids.interfaces.protocol_decoder import ProtocolMetadata, ProtocolType
from ai_iot_ids.models.network_flow import NetworkFlow


@pytest.fixture
def extractor_config():
    """Configuration for feature extractor tests."""
    return {
        'time_window_minutes': 5,
        'max_flows_per_window': 1000,
        'enable_dns_features': True,
        'enable_tls_features': True
    }


@pytest.fixture
def feature_extractor(extractor_config):
    """Create and initialize a feature extractor for testing."""
    return NetworkFlowExtractor(extractor_config)


@pytest.fixture
def sample_tcp_metadata():
    """Sample TCP protocol metadata for testing."""
    return ProtocolMetadata(
        protocol=ProtocolType.TCP,
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        source_port=45123,
        destination_port=80,
        tcp_flags=["SYN", "ACK"],
        tcp_window_size=65535,
        tcp_sequence_number=1000,
        payload_size=1024
    )


@pytest.fixture
def sample_dns_metadata():
    """Sample DNS protocol metadata for testing."""
    return ProtocolMetadata(
        protocol=ProtocolType.DNS,
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        source_port=45123,
        destination_port=53,
        dns_query="example.com",
        dns_query_type="A",
        dns_response_code="NOERROR",
        dns_answers=["93.184.216.34"],
        payload_size=64
    )


@pytest.fixture
def sample_tls_metadata():
    """Sample TLS protocol metadata for testing."""
    return ProtocolMetadata(
        protocol=ProtocolType.TLS,
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="93.184.216.34",
        source_port=45123,
        destination_port=443,
        tls_sni="example.com",
        tls_ja3_fingerprint="769,47-53-5-10-49161-49162-49171-49172-50-56-19-4",
        tls_ja3s_fingerprint="769,47,65281",
        tls_version="TLSv1.2",
        payload_size=512
    )


class TestNetworkFlowExtractor:
    """Test cases for NetworkFlowExtractor functionality."""
    
    @pytest.mark.asyncio
    async def test_initialization(self, extractor_config):
        """Test feature extractor initialization."""
        extractor = NetworkFlowExtractor(extractor_config)
        assert not extractor.is_initialized()
        assert not extractor.is_running()
        
        await extractor.initialize()
        assert extractor.is_initialized()
        assert not extractor.is_running()
        
        await extractor.start()
        assert extractor.is_running()
        
        await extractor.stop()
        assert not extractor.is_running()
    
    @pytest.mark.asyncio
    async def test_extract_flow_features_tcp(self, feature_extractor, sample_tcp_metadata):
        """Test extraction of TCP flow features."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        metadata_list = [sample_tcp_metadata]
        
        flow = await feature_extractor.extract_flow_features(metadata_list)
        
        assert isinstance(flow, NetworkFlow)
        assert flow.source_ip == "192.168.1.100"
        assert flow.destination_ip == "8.8.8.8"
        assert flow.source_port == 45123
        assert flow.destination_port == 80
        assert flow.protocol == "TCP"
        assert flow.bytes_sent == 1024
        assert flow.packets_sent == 1
        assert "SYN" in flow.tcp_flags
        assert "ACK" in flow.tcp_flags
    
    @pytest.mark.asyncio
    async def test_extract_dns_features(self, feature_extractor, sample_dns_metadata):
        """Test DNS-specific feature extraction."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        features = await feature_extractor.extract_dns_features(sample_dns_metadata)
        
        assert "dns_query_length" in features
        assert features["dns_query_length"] == 11.0  # len("example.com")
        assert "dns_subdomain_count" in features
        assert features["dns_subdomain_count"] == 1.0  # "example" subdomain
        assert "dns_query_entropy" in features
        assert features["dns_query_entropy"] > 0
        assert "dns_answer_count" in features
        assert features["dns_answer_count"] == 1.0
    
    @pytest.mark.asyncio
    async def test_extract_tls_features(self, feature_extractor, sample_tls_metadata):
        """Test TLS-specific feature extraction."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        features = await feature_extractor.extract_tls_features(sample_tls_metadata)
        
        assert "tls_sni_length" in features
        assert features["tls_sni_length"] == 11.0  # len("example.com")
        assert "tls_sni_entropy" in features
        assert features["tls_sni_entropy"] > 0
        assert "tls_ja3_present" in features
        assert features["tls_ja3_present"] == 1.0
        assert "tls_ja3s_present" in features
        assert features["tls_ja3s_present"] == 1.0
        assert "tls_version_score" in features
        assert features["tls_version_score"] == 0.8  # TLSv1.2 score
    
    @pytest.mark.asyncio
    async def test_calculate_directional_metrics(self, feature_extractor):
        """Test directional metrics calculation."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        flows = []
        
        # Create flows with different communication patterns
        for i in range(3):
            flow = NetworkFlow(
                timestamp=datetime.utcnow(),
                source_ip="192.168.1.100",
                destination_ip=f"8.8.8.{i+1}",
                source_port=45123,
                destination_port=80 + i,
                protocol="TCP",
                bytes_sent=1024,
                bytes_received=512,
                packets_sent=2,
                packets_received=1,
                duration_ms=1000,
                inter_arrival_mean_ms=0.0,
                inter_arrival_std_ms=0.0,
                jitter_ms=0.0
            )
            flows.append(flow)
        
        metrics = await feature_extractor.calculate_directional_metrics(flows)
        
        assert "avg_fan_out" in metrics
        assert metrics["avg_fan_out"] == 3.0  # One device talking to 3 destinations
        assert "dst_port_entropy" in metrics
        assert metrics["dst_port_entropy"] > 0  # Multiple destination ports
        assert "protocol_diversity" in metrics
        assert metrics["protocol_diversity"] == 1.0  # Only TCP
    
    @pytest.mark.asyncio
    async def test_calculate_timing_features(self, feature_extractor):
        """Test timing feature calculation."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        base_time = datetime.utcnow()
        flows = []
        
        # Create flows with regular timing pattern
        for i in range(4):
            flow = NetworkFlow(
                timestamp=base_time + timedelta(seconds=i*10),
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",
                source_port=45123,
                destination_port=80,
                protocol="TCP",
                bytes_sent=1024,
                bytes_received=512,
                packets_sent=2,
                packets_received=1,
                duration_ms=500 if i % 2 == 0 else 2000,  # Mix of short and long flows
                inter_arrival_mean_ms=0.0,
                inter_arrival_std_ms=0.0,
                jitter_ms=0.0
            )
            flows.append(flow)
        
        features = await feature_extractor.calculate_timing_features(flows)
        
        assert "inter_arrival_mean" in features
        assert features["inter_arrival_mean"] == 10.0  # 10 seconds between flows
        assert "inter_arrival_std" in features
        assert features["inter_arrival_std"] == 0.0  # Regular pattern
        assert "periodicity_score" in features
        assert features["periodicity_score"] > 0.5  # Regular pattern should have high score
        assert "burst_ratio" in features
        assert features["burst_ratio"] == 0.5  # Half are short flows (< 1 second)
    
    @pytest.mark.asyncio
    async def test_create_time_windows(self, feature_extractor):
        """Test time window creation."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        start_time = datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime(2024, 1, 1, 10, 15, 0)  # 15 minutes
        window_size = 5  # 5 minutes
        
        windows = await feature_extractor.create_time_windows(start_time, end_time, window_size)
        
        assert len(windows) == 3  # 15 minutes / 5 minutes = 3 windows
        
        # Check first window
        assert windows[0].start_time == start_time
        assert windows[0].end_time == datetime(2024, 1, 1, 10, 5, 0)
        assert windows[0].duration_seconds == 300
        
        # Check last window
        assert windows[2].start_time == datetime(2024, 1, 1, 10, 10, 0)
        assert windows[2].end_time == end_time
        
        # Check no overlaps
        for i in range(len(windows) - 1):
            assert not windows[i].overlaps(windows[i + 1])
    
    @pytest.mark.asyncio
    async def test_get_extraction_statistics(self, feature_extractor):
        """Test extraction statistics retrieval."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        # Process some flows to generate statistics
        metadata = ProtocolMetadata(
            protocol=ProtocolType.TCP,
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=45123,
            destination_port=80,
            payload_size=1024
        )
        
        await feature_extractor.extract_flow_features([metadata])
        
        stats = await feature_extractor.get_extraction_statistics()
        
        assert "flows_processed" in stats
        assert stats["flows_processed"] == 1
        assert "features_extracted" in stats
        assert "extraction_rate_fps" in stats
        assert "feature_dimensions" in stats
        assert stats["feature_dimensions"] > 0
        assert "dns_features_enabled" in stats
        assert "tls_features_enabled" in stats
    
    @pytest.mark.asyncio
    async def test_health_check(self, feature_extractor):
        """Test health check functionality."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        health = await feature_extractor.health_check()
        
        assert "status" in health
        assert health["status"] == "healthy"
        assert "initialized" in health
        assert health["initialized"] is True
        assert "running" in health
        assert health["running"] is True
        assert "statistics" in health
        assert "feature_count" in health
        assert "timestamp" in health


class TestFeatureExtractionEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.mark.asyncio
    async def test_extract_features_empty_list(self, feature_extractor):
        """Test handling of empty metadata list."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        with pytest.raises(ValueError, match="Empty metadata list"):
            await feature_extractor.extract_flow_features([])
    
    @pytest.mark.asyncio
    async def test_dns_features_non_dns_protocol(self, feature_extractor):
        """Test DNS feature extraction on non-DNS protocol."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        metadata = ProtocolMetadata(
            protocol=ProtocolType.TCP,  # Not DNS
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=45123,
            destination_port=80
        )
        
        features = await feature_extractor.extract_dns_features(metadata)
        assert len(features) == 0
    
    @pytest.mark.asyncio
    async def test_tls_features_non_tls_protocol(self, feature_extractor):
        """Test TLS feature extraction on non-TLS protocol."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        metadata = ProtocolMetadata(
            protocol=ProtocolType.UDP,  # Not TLS
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=45123,
            destination_port=53
        )
        
        features = await feature_extractor.extract_tls_features(metadata)
        assert len(features) == 0
    
    @pytest.mark.asyncio
    async def test_empty_flows_directional_metrics(self, feature_extractor):
        """Test directional metrics with empty flow list."""
        await feature_extractor.initialize()
        await feature_extractor.start()
        
        metrics = await feature_extractor.calculate_directional_metrics([])
        assert len(metrics) == 0


if __name__ == "__main__":
    pytest.main([__file__])