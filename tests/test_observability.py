"""
Tests for observability stack integration components.

This module tests the Elasticsearch client, Logstash pipeline,
and alerting system functionality.
"""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from dataclasses import asdict

from ai_iot_ids.observability.elasticsearch_client import ElasticsearchClient, IndexConfig, ILMPolicy
from ai_iot_ids.observability.logstash_pipeline import LogstashPipeline, LogstashConfig, StructuredLogger
from ai_iot_ids.observability.alerting_system import (
    AlertingSystem, EmailConfig, SlackConfig, WebhookConfig, KibanaConfig,
    EmailAlerter, SlackAlerter, WebhookAlerter, AlertRule
)
from ai_iot_ids.models.threat_detection import ThreatDetection, SeverityLevel, AttackCategory, SignatureMatch, MLPrediction
from ai_iot_ids.models.network_flow import NetworkFlow
from ai_iot_ids.models.device_profile import DeviceProfile, DeviceType


class TestElasticsearchClient:
    """Test Elasticsearch client functionality."""
    
    @patch('ai_iot_ids.observability.elasticsearch_client.Elasticsearch')
    def test_client_initialization(self, mock_es):
        """Test Elasticsearch client initialization."""
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_es.return_value = mock_client
        
        client = ElasticsearchClient(
            hosts=["localhost:9200"],
            username="test",
            password="test"
        )
        
        assert client.client == mock_client
        mock_es.assert_called_once()
        mock_client.ping.assert_called_once()
    
    @patch('ai_iot_ids.observability.elasticsearch_client.Elasticsearch')
    def test_create_index_template(self, mock_es):
        """Test index template creation."""
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.indices.put_index_template.return_value = {"acknowledged": True}
        mock_es.return_value = mock_client
        
        client = ElasticsearchClient(hosts=["localhost:9200"])
        
        mappings = {
            "properties": {
                "timestamp": {"type": "date"},
                "message": {"type": "text"}
            }
        }
        
        result = client.create_index_template("test-template", "test-*", mappings)
        
        assert result is True
        mock_client.indices.put_index_template.assert_called_once()
    
    @patch('ai_iot_ids.observability.elasticsearch_client.Elasticsearch')
    def test_create_ilm_policy(self, mock_es):
        """Test ILM policy creation."""
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.ilm.put_lifecycle.return_value = {"acknowledged": True}
        mock_es.return_value = mock_client
        
        client = ElasticsearchClient(hosts=["localhost:9200"])
        
        policy = ILMPolicy(name="test-policy")
        result = client.create_ilm_policy(policy)
        
        assert result is True
        mock_client.ilm.put_lifecycle.assert_called_once()
    
    @patch('ai_iot_ids.observability.elasticsearch_client.Elasticsearch')
    def test_index_document(self, mock_es):
        """Test document indexing."""
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.index.return_value = {"result": "created"}
        mock_es.return_value = mock_client
        
        client = ElasticsearchClient(hosts=["localhost:9200"])
        
        document = {"timestamp": "2024-01-01T00:00:00Z", "message": "test"}
        result = client.index_document("test-index", document)
        
        assert result is True
        mock_client.index.assert_called_once()
    
    @patch('ai_iot_ids.observability.elasticsearch_client.Elasticsearch')
    def test_search_documents(self, mock_es):
        """Test document searching."""
        mock_client = Mock()
        mock_client.ping.return_value = True
        mock_client.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"message": "test1"}},
                    {"_source": {"message": "test2"}}
                ]
            }
        }
        mock_es.return_value = mock_client
        
        client = ElasticsearchClient(hosts=["localhost:9200"])
        
        query = {"match_all": {}}
        results = client.search_documents("test-index", query)
        
        assert len(results) == 2
        assert results[0]["message"] == "test1"
        assert results[1]["message"] == "test2"


class TestLogstashPipeline:
    """Test Logstash pipeline functionality."""
    
    def test_pipeline_config_generation(self):
        """Test Logstash pipeline configuration generation."""
        config = LogstashConfig(
            pipeline_name="test-pipeline",
            output_elasticsearch_hosts=["localhost:9200"]
        )
        
        pipeline = LogstashPipeline(config)
        config_str = pipeline.generate_pipeline_config()
        
        assert "test-pipeline" in config_str
        assert "localhost:9200" in config_str
        assert "input {" in config_str
        assert "filter {" in config_str
        assert "output {" in config_str
    
    def test_event_validation(self):
        """Test event validation."""
        config = LogstashConfig(pipeline_name="test")
        pipeline = LogstashPipeline(config)
        
        # Valid event
        valid_event = {
            "timestamp": "2024-01-01T00:00:00Z",
            "event_type": "network_flow",
            "source_ip": "192.168.1.1"
        }
        
        assert pipeline.validate_event(valid_event) is True
        
        # Invalid event - missing timestamp
        invalid_event = {
            "event_type": "network_flow",
            "source_ip": "192.168.1.1"
        }
        
        assert pipeline.validate_event(invalid_event) is False
        errors = pipeline.get_validation_errors()
        assert "Missing required field: timestamp" in errors
    
    def test_event_enrichment(self):
        """Test event enrichment."""
        config = LogstashConfig(pipeline_name="test")
        pipeline = LogstashPipeline(config)
        
        event = {
            "timestamp": "2024-01-01T00:00:00Z",
            "event_type": "network_flow",
            "bytes_sent": 1000,
            "bytes_received": 500,
            "packets_sent": 10,
            "packets_received": 5,
            "duration_ms": 1000
        }
        
        enriched = pipeline.enrich_event(event)
        
        assert enriched["bytes_total"] == 1500
        assert enriched["packets_total"] == 15
        assert enriched["bytes_per_second"] == 1500.0
        assert enriched["packets_per_second"] == 15.0
        assert "processed_at" in enriched
        assert "pipeline_name" in enriched
    
    def test_batch_processing(self):
        """Test batch event processing."""
        config = LogstashConfig(pipeline_name="test")
        pipeline = LogstashPipeline(config)
        
        events = [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "event_type": "network_flow"
            },
            {
                "timestamp": "2024-01-01T00:00:01Z",
                "event_type": "threat_detection",
                "threat_score": 0.8
            },
            {
                "event_type": "invalid_event"  # Missing timestamp
            }
        ]
        
        results = pipeline.process_batch(events)
        
        assert results["total_events"] == 3
        assert results["valid_events"] == 2
        assert results["invalid_events"] == 1
        assert len(results["enriched_events"]) == 2
        assert len(results["validation_errors"]) == 1


class TestStructuredLogger:
    """Test structured logging functionality."""
    
    def test_logger_initialization(self):
        """Test structured logger initialization."""
        logger = StructuredLogger("test_logger", "DEBUG")
        
        assert logger.logger_name == "test_logger"
        assert logger.logger.level == 10  # DEBUG level
    
    @patch('ai_iot_ids.observability.logstash_pipeline.logging.getLogger')
    def test_network_flow_logging(self, mock_get_logger):
        """Test network flow event logging."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        
        logger = StructuredLogger("test")
        
        flow = NetworkFlow(
            flow_id="test-flow-1",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.1",
            destination_ip="192.168.1.2",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            bytes_sent=1000,
            bytes_received=500,
            packets_sent=10,
            packets_received=5,
            duration_ms=1000,
            inter_arrival_mean_ms=50.0,
            inter_arrival_std_ms=10.0,
            jitter_ms=5.0
        )
        
        logger.log_network_flow(flow)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        assert "Network flow processed" in call_args[0][0]
        assert "event_type" in call_args[1]["extra"]
        assert call_args[1]["extra"]["event_type"] == "network_flow"


class TestAlertingSystem:
    """Test alerting system functionality."""
    
    def test_alert_rule_management(self):
        """Test alert rule management."""
        alerting = AlertingSystem()
        
        rule = AlertRule(
            name="test-rule",
            severity_threshold=SeverityLevel.MEDIUM,
            threat_score_threshold=0.7
        )
        
        alerting.add_alert_rule(rule)
        assert "test-rule" in alerting.alert_rules
        
        alerting.remove_alert_rule("test-rule")
        assert "test-rule" not in alerting.alert_rules
    
    def test_should_alert_logic(self):
        """Test alert decision logic."""
        alerting = AlertingSystem()
        
        rule = AlertRule(
            name="test-rule",
            severity_threshold=SeverityLevel.MEDIUM,
            threat_score_threshold=0.7,
            confidence_threshold=0.8
        )
        alerting.add_alert_rule(rule)
        
        # Create test detection
        detection = ThreatDetection(
            detection_id="test-detection-1",
            timestamp=datetime.utcnow(),
            source_flow_id="test-flow-1",
            device_id="test-device-1",
            threat_score=0.8,
            confidence=0.9,
            severity=SeverityLevel.HIGH,
            signature_matches=[
                SignatureMatch(
                    rule_id="SID:2001234",
                    rule_name="Test Rule",
                    signature_score=0.9
                )
            ],
            ml_predictions=[
                MLPrediction(
                    model_name="isolation_forest_v1",
                    model_version="1.0.0",
                    anomaly_score=0.8,
                    feature_importance={"bytes_per_packet": 0.5}
                )
            ],
            attack_category=AttackCategory.RECONNAISSANCE,
            mitre_tactics=[],
            recommended_actions=[]
        )
        
        # Should alert - meets all thresholds
        assert alerting.should_alert(detection, "test-rule") is True
        
        # Should not alert - below threat score threshold
        detection.threat_score = 0.5
        assert alerting.should_alert(detection, "test-rule") is False
        
        # Should not alert - below confidence threshold
        detection.threat_score = 0.8
        detection.confidence = 0.5
        assert alerting.should_alert(detection, "test-rule") is False
        
        # Should not alert - below severity threshold
        detection.confidence = 0.9
        detection.severity = SeverityLevel.LOW
        assert alerting.should_alert(detection, "test-rule") is False
    
    def test_cooldown_logic(self):
        """Test alert cooldown functionality."""
        alerting = AlertingSystem()
        
        rule = AlertRule(
            name="test-rule",
            severity_threshold=SeverityLevel.LOW,
            threat_score_threshold=0.5,
            confidence_threshold=0.5,
            cooldown_minutes=5
        )
        alerting.add_alert_rule(rule)
        
        detection = ThreatDetection(
            detection_id="test-detection-1",
            timestamp=datetime.utcnow(),
            source_flow_id="test-flow-1",
            device_id="test-device-1",
            threat_score=0.8,
            confidence=0.9,
            severity=SeverityLevel.HIGH,
            signature_matches=[
                SignatureMatch(
                    rule_id="SID:1",
                    rule_name="Test Rule",
                    signature_score=0.8
                )
            ],
            ml_predictions=[
                MLPrediction(
                    model_name="test_model",
                    model_version="1.0.0",
                    anomaly_score=0.9,
                    feature_importance={"test": 0.5}
                )
            ],
            attack_category=AttackCategory.RECONNAISSANCE,
            mitre_tactics=[],
            recommended_actions=[]
        )
        
        # First alert should be allowed
        assert alerting.should_alert(detection, "test-rule") is True
        
        # Simulate sending alert
        alerting._alert_history[f"test-rule_{detection.device_id}"] = datetime.utcnow()
        
        # Second alert should be blocked by cooldown
        assert alerting.should_alert(detection, "test-rule") is False
        
        # Alert should be allowed after cooldown period
        alerting._alert_history[f"test-rule_{detection.device_id}"] = datetime.utcnow() - timedelta(minutes=10)
        assert alerting.should_alert(detection, "test-rule") is True


class TestEmailAlerter:
    """Test email alerting functionality."""
    
    def test_email_config(self):
        """Test email configuration."""
        config = EmailConfig(
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="test@example.com",
            password="password",
            sender_email="alerts@example.com",
            recipients=["admin@example.com"]
        )
        
        alerter = EmailAlerter(config)
        assert alerter.config.smtp_server == "smtp.example.com"
        assert alerter.config.recipients == ["admin@example.com"]
    
    @patch('ai_iot_ids.observability.alerting_system.smtplib.SMTP')
    def test_send_threat_alert_email(self, mock_smtp):
        """Test sending threat alert email."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server
        
        config = EmailConfig(
            smtp_server="smtp.example.com",
            sender_email="alerts@example.com",
            recipients=["admin@example.com"]
        )
        
        alerter = EmailAlerter(config)
        
        detection = ThreatDetection(
            detection_id="test-detection-1",
            timestamp=datetime.utcnow(),
            source_flow_id="test-flow-1",
            device_id="test-device-1",
            threat_score=0.8,
            confidence=0.9,
            severity=SeverityLevel.HIGH,
            signature_matches=[
                SignatureMatch(
                    rule_id="SID:1",
                    rule_name="Test Rule",
                    signature_score=0.8
                )
            ],
            ml_predictions=[
                MLPrediction(
                    model_name="test_model",
                    model_version="1.0.0",
                    anomaly_score=0.9,
                    feature_importance={"test": 0.5}
                )
            ],
            attack_category=AttackCategory.RECONNAISSANCE,
            mitre_tactics=[],
            recommended_actions=[]
        )
        
        result = alerter.send_threat_alert(detection)
        
        assert result is True
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()


class TestWebhookAlerter:
    """Test webhook alerting functionality."""
    
    @patch('ai_iot_ids.observability.alerting_system.requests.Session')
    def test_send_threat_alert_webhook(self, mock_session_class):
        """Test sending threat alert via webhook."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_session.request.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        config = WebhookConfig(
            url="https://example.com/webhook",
            auth_token="test-token"
        )
        
        alerter = WebhookAlerter(config)
        
        detection = ThreatDetection(
            detection_id="test-detection-1",
            timestamp=datetime.utcnow(),
            source_flow_id="test-flow-1",
            device_id="test-device-1",
            threat_score=0.8,
            confidence=0.9,
            severity=SeverityLevel.HIGH,
            signature_matches=[
                SignatureMatch(
                    rule_id="SID:1",
                    rule_name="Test Rule",
                    signature_score=0.8
                )
            ],
            ml_predictions=[
                MLPrediction(
                    model_name="test_model",
                    model_version="1.0.0",
                    anomaly_score=0.9,
                    feature_importance={"test": 0.5}
                )
            ],
            attack_category=AttackCategory.RECONNAISSANCE,
            mitre_tactics=[],
            recommended_actions=[]
        )
        
        result = alerter.send_threat_alert(detection)
        
        assert result is True
        mock_session.request.assert_called_once()
        
        # Check that auth header was added
        call_args = mock_session.request.call_args
        headers = call_args[1]["headers"]
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test-token"


if __name__ == "__main__":
    pytest.main([__file__])
