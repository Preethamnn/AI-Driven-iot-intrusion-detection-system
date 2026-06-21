"""
Unit tests for AI-driven IoT IDS data models.

This module contains unit tests for all Pydantic models including
NetworkFlow, DeviceProfile, ThreatDetection, and SystemConfiguration.
"""

import pytest
from datetime import datetime, timedelta
from typing import Dict, Any
from pydantic import ValidationError

from ai_iot_ids.models.network_flow import NetworkFlow
from ai_iot_ids.models.device_profile import DeviceProfile, DeviceType, ActivitySchedule
from ai_iot_ids.models.threat_detection import (
    ThreatDetection, SeverityLevel, AttackCategory, SignatureMatch, MLPrediction
)
from ai_iot_ids.models.system_configuration import SystemConfiguration


class TestNetworkFlow:
    """Test cases for NetworkFlow model."""
    
    def test_valid_network_flow_creation(self, sample_network_flow):
        """Test creation of valid NetworkFlow instance."""
        assert sample_network_flow.source_ip == "192.168.1.100"
        assert sample_network_flow.destination_ip == "8.8.8.8"
        assert sample_network_flow.protocol == "UDP"
        assert sample_network_flow.bytes_sent == 64
        assert sample_network_flow.bytes_received == 128
    
    def test_network_flow_validation_invalid_ip(self):
        """Test NetworkFlow validation with invalid IP addresses."""
        with pytest.raises(ValidationError) as exc_info:
            NetworkFlow(
                timestamp=datetime.utcnow(),
                source_ip="invalid.ip",
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
        assert "Invalid IP address" in str(exc_info.value)
    
    def test_network_flow_validation_invalid_protocol(self):
        """Test NetworkFlow validation with invalid protocol."""
        with pytest.raises(ValidationError) as exc_info:
            NetworkFlow(
                timestamp=datetime.utcnow(),
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",
                source_port=45123,
                destination_port=53,
                protocol="INVALID",
                bytes_sent=64,
                bytes_received=128,
                packets_sent=1,
                packets_received=1,
                duration_ms=150,
                inter_arrival_mean_ms=0.0,
                inter_arrival_std_ms=0.0,
                jitter_ms=0.0
            )
        assert "Protocol must be one of" in str(exc_info.value)
    
    def test_network_flow_tcp_flags_validation(self):
        """Test TCP flags validation."""
        flow = NetworkFlow(
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            source_port=45123,
            destination_port=80,
            protocol="TCP",
            bytes_sent=64,
            bytes_received=128,
            packets_sent=1,
            packets_received=1,
            duration_ms=150,
            inter_arrival_mean_ms=0.0,
            inter_arrival_std_ms=0.0,
            jitter_ms=0.0,
            tcp_flags=["SYN", "ACK"]
        )
        assert flow.tcp_flags == ["SYN", "ACK"]
    
    def test_network_flow_invalid_tcp_flags(self):
        """Test validation with invalid TCP flags."""
        with pytest.raises(ValidationError) as exc_info:
            NetworkFlow(
                timestamp=datetime.utcnow(),
                source_ip="192.168.1.100",
                destination_ip="8.8.8.8",
                source_port=45123,
                destination_port=80,
                protocol="TCP",
                bytes_sent=64,
                bytes_received=128,
                packets_sent=1,
                packets_received=1,
                duration_ms=150,
                inter_arrival_mean_ms=0.0,
                inter_arrival_std_ms=0.0,
                jitter_ms=0.0,
                tcp_flags=["INVALID"]
            )
        assert "Invalid TCP flag" in str(exc_info.value)
    
    def test_network_flow_protocol_consistency(self):
        """Test protocol consistency validation."""
        with pytest.raises(ValidationError) as exc_info:
            NetworkFlow(
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
                jitter_ms=0.0,
                tcp_flags=["SYN"],  # TCP flags on UDP protocol
                retransmissions=1
            )
        assert "TCP flags not applicable for UDP protocol" in str(exc_info.value)
    
    def test_network_flow_helper_methods(self, sample_network_flow):
        """Test NetworkFlow helper methods."""
        assert sample_network_flow.total_bytes() == 192
        assert sample_network_flow.total_packets() == 2
        assert sample_network_flow.bytes_per_packet_sent() == 64.0
        assert sample_network_flow.bytes_per_packet_received() == 128.0
        assert sample_network_flow.is_bidirectional() is True


class TestDeviceProfile:
    """Test cases for DeviceProfile model."""
    
    def test_valid_device_profile_creation(self, sample_device_profile):
        """Test creation of valid DeviceProfile instance."""
        assert sample_device_profile.device_id == "aa:bb:cc:dd:ee:ff"
        assert sample_device_profile.vendor_oui == "aa:bb:cc"
        assert sample_device_profile.device_type == DeviceType.CAMERA
        assert sample_device_profile.confidence_score == 0.85
        assert sample_device_profile.observation_count == 1000
    
    def test_device_profile_mac_validation(self):
        """Test MAC address validation."""
        with pytest.raises(ValidationError) as exc_info:
            DeviceProfile(
                device_id="invalid-mac",
                vendor_oui="aa:bb:cc",
                device_type=DeviceType.CAMERA,
                profile_created=datetime.utcnow(),
                last_updated=datetime.utcnow(),
                confidence_score=0.5,
                observation_count=100
            )
        assert "Invalid MAC address format" in str(exc_info.value)
    
    def test_device_profile_oui_validation(self):
        """Test OUI validation."""
        with pytest.raises(ValidationError) as exc_info:
            DeviceProfile(
                device_id="aa:bb:cc:dd:ee:ff",
                vendor_oui="invalid-oui",
                device_type=DeviceType.CAMERA,
                profile_created=datetime.utcnow(),
                last_updated=datetime.utcnow(),
                confidence_score=0.5,
                observation_count=100
            )
        assert "Invalid OUI format" in str(exc_info.value)
    
    def test_device_profile_protocol_validation(self):
        """Test protocol validation."""
        with pytest.raises(ValidationError) as exc_info:
            DeviceProfile(
                device_id="aa:bb:cc:dd:ee:ff",
                vendor_oui="aa:bb:cc",
                device_type=DeviceType.CAMERA,
                normal_protocols=["INVALID_PROTOCOL"],
                profile_created=datetime.utcnow(),
                last_updated=datetime.utcnow(),
                confidence_score=0.5,
                observation_count=100
            )
        assert "Unknown protocol" in str(exc_info.value)
    
    def test_device_profile_destination_validation(self):
        """Test destination validation."""
        valid_profile = DeviceProfile(
            device_id="aa:bb:cc:dd:ee:ff",
            vendor_oui="aa:bb:cc",
            device_type=DeviceType.CAMERA,
            allowed_destinations=["192.168.1.0/24", "8.8.8.8", "*.example.com"],
            profile_created=datetime.utcnow(),
            last_updated=datetime.utcnow(),
            confidence_score=0.5,
            observation_count=100
        )
        assert len(valid_profile.allowed_destinations) == 3
    
    def test_device_profile_invalid_destination(self):
        """Test validation with invalid destination."""
        with pytest.raises(ValidationError) as exc_info:
            DeviceProfile(
                device_id="aa:bb:cc:dd:ee:ff",
                vendor_oui="aa:bb:cc",
                device_type=DeviceType.CAMERA,
                allowed_destinations=["invalid-destination"],
                profile_created=datetime.utcnow(),
                last_updated=datetime.utcnow(),
                confidence_score=0.5,
                observation_count=100
            )
        assert "Invalid destination format" in str(exc_info.value)
    
    def test_device_profile_consistency_validation(self):
        """Test profile consistency validation."""
        now = datetime.utcnow()
        with pytest.raises(ValidationError) as exc_info:
            DeviceProfile(
                device_id="aa:bb:cc:dd:ee:ff",
                vendor_oui="aa:bb:cc",
                device_type=DeviceType.CAMERA,
                profile_created=now,
                last_updated=now - timedelta(hours=1),  # Invalid: before creation
                confidence_score=0.5,
                observation_count=100
            )
        assert "last_updated cannot be before profile_created" in str(exc_info.value)
    
    def test_device_profile_helper_methods(self, sample_device_profile):
        """Test DeviceProfile helper methods."""
        assert sample_device_profile.is_mature_profile() is True
        active_hours = sample_device_profile.get_active_hours()
        assert len(active_hours) == 12  # Hours 6-17 have activity >= 0.5
        active_days = sample_device_profile.get_active_days()
        assert len(active_days) == 5  # Weekdays have activity >= 0.5


class TestActivitySchedule:
    """Test cases for ActivitySchedule model."""
    
    def test_valid_activity_schedule(self):
        """Test creation of valid ActivitySchedule."""
        schedule = ActivitySchedule(
            hour_of_day=[0.5] * 24,
            day_of_week=[0.8] * 7
        )
        assert len(schedule.hour_of_day) == 24
        assert len(schedule.day_of_week) == 7
    
    def test_activity_schedule_invalid_length(self):
        """Test ActivitySchedule with invalid array lengths."""
        with pytest.raises(ValidationError):
            ActivitySchedule(
                hour_of_day=[0.5] * 23,  # Invalid: should be 24
                day_of_week=[0.8] * 7
            )
    
    def test_activity_schedule_invalid_values(self):
        """Test ActivitySchedule with invalid activity values."""
        with pytest.raises(ValidationError) as exc_info:
            ActivitySchedule(
                hour_of_day=[1.5] * 24,  # Invalid: > 1.0
                day_of_week=[0.8] * 7
            )
        assert "Activity level must be between 0.0 and 1.0" in str(exc_info.value)


class TestThreatDetection:
    """Test cases for ThreatDetection model."""
    
    def test_valid_threat_detection_creation(self, sample_threat_detection):
        """Test creation of valid ThreatDetection instance."""
        assert sample_threat_detection.threat_score == 0.85
        assert sample_threat_detection.confidence == 0.92
        assert sample_threat_detection.severity == SeverityLevel.HIGH
        assert sample_threat_detection.attack_category == AttackCategory.RECONNAISSANCE
        assert len(sample_threat_detection.signature_matches) == 1
        assert len(sample_threat_detection.ml_predictions) == 1
    
    def test_threat_detection_mitre_validation(self):
        """Test MITRE ATT&CK tactic validation."""
        detection = ThreatDetection(
            timestamp=datetime.utcnow(),
            source_flow_id="test-flow-id",
            device_id="aa:bb:cc:dd:ee:ff",
            threat_score=0.5,
            confidence=0.8,
            severity=SeverityLevel.MEDIUM,
            attack_category=AttackCategory.RECONNAISSANCE,
            mitre_tactics=["T1046", "T1018"],
            signature_matches=[SignatureMatch(
                rule_id="SID:123",
                rule_name="Test Rule",
                signature_score=0.5
            )]
        )
        assert detection.mitre_tactics == ["T1046", "T1018"]
    
    def test_threat_detection_invalid_mitre(self):
        """Test validation with invalid MITRE tactic format."""
        with pytest.raises(ValidationError) as exc_info:
            ThreatDetection(
                timestamp=datetime.utcnow(),
                source_flow_id="test-flow-id",
                device_id="aa:bb:cc:dd:ee:ff",
                threat_score=0.5,
                confidence=0.8,
                severity=SeverityLevel.MEDIUM,
                attack_category=AttackCategory.RECONNAISSANCE,
                mitre_tactics=["INVALID"],
                signature_matches=[SignatureMatch(
                    rule_id="SID:123",
                    rule_name="Test Rule",
                    signature_score=0.5
                )]
            )
        assert "Invalid MITRE ATT&CK tactic format" in str(exc_info.value)
    
    def test_threat_detection_consistency_validation(self):
        """Test threat detection consistency validation."""
        with pytest.raises(ValidationError) as exc_info:
            ThreatDetection(
                timestamp=datetime.utcnow(),
                source_flow_id="test-flow-id",
                device_id="aa:bb:cc:dd:ee:ff",
                threat_score=0.2,  # Low score
                confidence=0.8,
                severity=SeverityLevel.CRITICAL,  # But critical severity
                attack_category=AttackCategory.RECONNAISSANCE
                # No signature matches or ML predictions
            )
        assert "Detection must have at least one signature match or ML prediction" in str(exc_info.value)
    
    def test_threat_detection_helper_methods(self, sample_threat_detection):
        """Test ThreatDetection helper methods."""
        assert sample_threat_detection.get_max_signature_score() == 0.95
        assert sample_threat_detection.get_max_ml_score() == 0.87
        assert sample_threat_detection.get_contributing_models() == ["isolation_forest_v1"]
        assert sample_threat_detection.get_triggered_rules() == ["Suspicious DNS Query Pattern"]
        assert sample_threat_detection.is_high_confidence() is True
        assert sample_threat_detection.requires_immediate_action() is True
        
        top_features = sample_threat_detection.get_top_features(2)
        assert len(top_features) == 2
        assert "bytes_per_packet" in top_features


class TestSignatureMatch:
    """Test cases for SignatureMatch model."""
    
    def test_valid_signature_match(self):
        """Test creation of valid SignatureMatch."""
        match = SignatureMatch(
            rule_id="SID:2001234",
            rule_name="Test Rule",
            signature_score=0.95
        )
        assert match.rule_id == "SID:2001234"
        assert match.signature_score == 0.95


class TestMLPrediction:
    """Test cases for MLPrediction model."""
    
    def test_valid_ml_prediction(self):
        """Test creation of valid MLPrediction."""
        prediction = MLPrediction(
            model_name="test_model",
            model_version="1.0.0",
            anomaly_score=0.87,
            feature_importance={"feature1": 0.5, "feature2": 0.3}
        )
        assert prediction.model_name == "test_model"
        assert prediction.anomaly_score == 0.87
        assert len(prediction.feature_importance) == 2
    
    def test_ml_prediction_feature_importance_validation(self):
        """Test feature importance validation."""
        with pytest.raises(ValidationError) as exc_info:
            MLPrediction(
                model_name="test_model",
                model_version="1.0.0",
                anomaly_score=0.87,
                feature_importance={"feature1": 1.5}  # Invalid: > 1.0
            )
        assert "Feature importance must be between 0.0 and 1.0" in str(exc_info.value)


class TestSystemConfiguration:
    """Test cases for SystemConfiguration model."""
    
    def test_valid_system_configuration_creation(self, sample_system_configuration):
        """Test creation of valid SystemConfiguration instance."""
        assert sample_system_configuration.edge_gateway.packet_capture.interface == "eth0"
        assert sample_system_configuration.storage.elasticsearch.hosts == ["http://elasticsearch:9200"]
        assert sample_system_configuration.validate_configuration() is True
    
    def test_system_configuration_helper_methods(self, sample_system_configuration):
        """Test SystemConfiguration helper methods."""
        enabled_models = sample_system_configuration.get_enabled_models()
        assert "isolation_forest" in enabled_models
        assert "xgboost" in enabled_models
        
        retention_days = sample_system_configuration.get_total_retention_days()
        assert retention_days > 0
        
        # Default configuration should not be high performance mode
        assert sample_system_configuration.is_high_performance_mode() is False