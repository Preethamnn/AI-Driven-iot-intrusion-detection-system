"""
Pytest configuration and shared fixtures for AI-driven IoT IDS tests.

This module provides common test fixtures, configuration, and utilities
used across all test modules in the system.
"""

import pytest
import tempfile
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import Mock

from ai_iot_ids.models.network_flow import NetworkFlow
from ai_iot_ids.models.device_profile import DeviceProfile, DeviceType, ActivitySchedule
from ai_iot_ids.models.threat_detection import ThreatDetection, SeverityLevel, AttackCategory
from ai_iot_ids.models.system_configuration import SystemConfiguration
from ai_iot_ids.utils.logging_config import setup_logging
from ai_iot_ids.utils.config_parser import YAMLConfigParser


@pytest.fixture(scope="session", autouse=True)
def setup_test_logging():
    """Set up logging for test sessions."""
    setup_logging(log_level="DEBUG", log_format="text")


@pytest.fixture
def sample_network_flow() -> NetworkFlow:
    """Create a sample NetworkFlow for testing."""
    return NetworkFlow(
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="8.8.8.8",
        source_port=45123,
        destination_port=53,
        protocol="UDP",
        bytes_sent=64,
        bytes_received=128,
        packets_sent=1,
        packets_received=1,
        duration_ms=150,
        inter_arrival_mean_ms=0.0,
        inter_arrival_std_ms=0.0,
        jitter_ms=0.0
    )


@pytest.fixture
def sample_device_profile() -> DeviceProfile:
    """Create a sample DeviceProfile for testing."""
    activity_schedule = ActivitySchedule(
        hour_of_day=[0.1] * 6 + [0.8] * 12 + [0.3] * 6,
        day_of_week=[0.9, 0.9, 0.9, 0.9, 0.9, 0.3, 0.2]  # Only weekdays >= 0.5
    )
    
    return DeviceProfile(
        device_id="aa:bb:cc:dd:ee:ff",
        vendor_oui="aa:bb:cc",
        device_type=DeviceType.CAMERA,
        firmware_version="1.2.3",
        normal_protocols=["TCP", "UDP", "ICMP"],
        allowed_destinations=["192.168.1.0/24", "8.8.8.8"],
        typical_bandwidth_bps=1048576,
        activity_schedule=activity_schedule,
        profile_created=datetime.utcnow() - timedelta(days=30),
        last_updated=datetime.utcnow(),
        confidence_score=0.85,
        observation_count=1000
    )


@pytest.fixture
def sample_threat_detection(sample_network_flow, sample_device_profile) -> ThreatDetection:
    """Create a sample ThreatDetection for testing."""
    from ai_iot_ids.models.threat_detection import SignatureMatch, MLPrediction
    
    signature_match = SignatureMatch(
        rule_id="SID:2001234",
        rule_name="Suspicious DNS Query Pattern",
        signature_score=0.95
    )
    
    ml_prediction = MLPrediction(
        model_name="isolation_forest_v1",
        model_version="1.2.0",
        anomaly_score=0.87,
        feature_importance={
            "bytes_per_packet": 0.35,
            "inter_arrival_time": 0.28
        }
    )
    
    return ThreatDetection(
        timestamp=datetime.utcnow(),
        source_flow_id=sample_network_flow.flow_id,
        device_id=sample_device_profile.device_id,
        threat_score=0.85,
        confidence=0.92,
        severity=SeverityLevel.HIGH,
        signature_matches=[signature_match],
        ml_predictions=[ml_prediction],
        attack_category=AttackCategory.RECONNAISSANCE,
        mitre_tactics=["T1046", "T1018"],
        recommended_actions=[
            "Block suspicious DNS queries",
            "Investigate device behavior"
        ]
    )


@pytest.fixture
def sample_system_configuration() -> SystemConfiguration:
    """Create a sample SystemConfiguration for testing."""
    from ai_iot_ids.models.system_configuration import (
        EdgeGatewayConfig, PacketCaptureConfig, ProtocolDecodersConfig,
        ForwardingConfig, AIInferenceConfig, StorageConfig, ElasticsearchConfig,
        RetentionConfig, ModelsConfig, IsolationForestConfig, XGBoostConfig,
        FeatureEngineeringConfig, DecisionEngineConfig, AggregationFunction
    )
    
    packet_capture = PacketCaptureConfig(
        interface="eth0",
        buffer_size_mb=64,
        capture_filter="not port 22"
    )
    
    protocol_decoders = ProtocolDecodersConfig(
        zeek_enabled=True,
        suricata_enabled=True,
        custom_rules_path="/etc/ids/rules"
    )
    
    forwarding = ForwardingConfig(
        upstream_endpoints=["https://ai-service:8080/api/v1/ingest"],
        batch_size=100,
        flush_interval_ms=5000,
        retry_attempts=3
    )
    
    edge_gateway = EdgeGatewayConfig(
        packet_capture=packet_capture,
        protocol_decoders=protocol_decoders,
        forwarding=forwarding
    )
    
    # AI Inference configuration
    isolation_forest = IsolationForestConfig(
        enabled=True,
        contamination=0.1,
        n_estimators=100
    )
    
    xgboost = XGBoostConfig(
        enabled=True,
        max_depth=6,
        learning_rate=0.1,
        n_estimators=100
    )
    
    models = ModelsConfig(
        isolation_forest=isolation_forest,
        xgboost=xgboost
    )
    
    feature_engineering = FeatureEngineeringConfig(
        time_window_minutes=5,
        aggregation_functions=[AggregationFunction.MEAN, AggregationFunction.STD]
    )
    
    decision_engine = DecisionEngineConfig(
        signature_weight=0.6,
        ml_weight=0.4,
        threshold_low=0.3,
        threshold_high=0.7
    )
    
    ai_inference = AIInferenceConfig(
        models=models,
        feature_engineering=feature_engineering,
        decision_engine=decision_engine
    )
    
    elasticsearch = ElasticsearchConfig(
        hosts=["http://elasticsearch:9200"],
        index_prefix="iot-ids",
        shard_count=1,
        replica_count=1
    )
    
    storage = StorageConfig(
        elasticsearch=elasticsearch,
        retention=RetentionConfig(
            raw_data_days=30,
            aggregated_data_days=365,
            alert_data_days=1095
        )
    )
    
    return SystemConfiguration(
        edge_gateway=edge_gateway,
        ai_inference=ai_inference,
        storage=storage
    )


@pytest.fixture
def yaml_config_parser() -> YAMLConfigParser:
    """Create a YAML configuration parser for testing."""
    return YAMLConfigParser()


@pytest.fixture
def temp_config_file(sample_system_configuration, yaml_config_parser) -> Path:
    """Create a temporary configuration file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        yaml_content = yaml_config_parser.serialize(sample_system_configuration)
        f.write(yaml_content)
        temp_path = Path(f.name)
    
    yield temp_path
    
    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    return Mock()


@pytest.fixture
def sample_config_dict() -> Dict[str, Any]:
    """Create a sample configuration dictionary for testing."""
    return {
        "edge_gateway": {
            "packet_capture": {
                "interface": "eth0",
                "buffer_size_mb": 64,
                "capture_filter": "not port 22"
            },
            "protocol_decoders": {
                "zeek_enabled": True,
                "suricata_enabled": True,
                "custom_rules_path": "/etc/ids/rules"
            },
            "forwarding": {
                "upstream_endpoints": ["https://ai-service:8080/api/v1/ingest"],
                "batch_size": 100,
                "flush_interval_ms": 5000,
                "retry_attempts": 3
            }
        },
        "storage": {
            "elasticsearch": {
                "hosts": ["http://elasticsearch:9200"],
                "index_prefix": "iot-ids",
                "shard_count": 1,
                "replica_count": 1
            }
        }
    }


@pytest.fixture
def invalid_config_dict() -> Dict[str, Any]:
    """Create an invalid configuration dictionary for testing."""
    return {
        "edge_gateway": {
            "packet_capture": {
                "interface": "eth0",
                "buffer_size_mb": -1,  # Invalid: negative value
                "capture_filter": "not port 22"
            },
            "forwarding": {
                "upstream_endpoints": [],  # Invalid: empty list
                "batch_size": 0,  # Invalid: zero value
                "flush_interval_ms": 50,  # Invalid: below minimum
                "retry_attempts": 15  # Invalid: above maximum
            }
        },
        "storage": {
            "elasticsearch": {
                "hosts": [],  # Invalid: empty list
                "shard_count": 0  # Invalid: zero value
            }
        }
    }


@pytest.fixture
def multiple_network_flows() -> List[NetworkFlow]:
    """Create multiple NetworkFlow instances for testing."""
    base_time = datetime.utcnow()
    flows = []
    
    for i in range(10):
        flow = NetworkFlow(
            timestamp=base_time + timedelta(seconds=i),
            source_ip=f"192.168.1.{100 + i}",
            destination_ip="8.8.8.8",
            source_port=45123 + i,
            destination_port=53,
            protocol="UDP",
            bytes_sent=64 + i * 10,
            bytes_received=128 + i * 5,
            packets_sent=1 + i,
            packets_received=1,
            duration_ms=150 + i * 20,
            inter_arrival_mean_ms=float(i * 10),
            inter_arrival_std_ms=float(i * 5),
            jitter_ms=float(i * 2)
        )
        flows.append(flow)
    
    return flows


@pytest.fixture
def performance_test_data() -> Dict[str, Any]:
    """Create performance test data for benchmarking."""
    return {
        "packet_count": 10000,
        "flow_count": 1000,
        "device_count": 100,
        "time_window_minutes": 5,
        "expected_processing_rate_pps": 1000,
        "max_memory_usage_mb": 512
    }