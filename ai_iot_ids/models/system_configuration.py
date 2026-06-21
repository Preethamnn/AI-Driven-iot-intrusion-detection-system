"""
System Configuration data model for the AI-driven IoT IDS system.

This module defines the SystemConfiguration Pydantic model that represents
all configurable parameters for edge gateways, AI inference services,
and storage components.
"""

from typing import List, Dict, Any, Optional
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator


class AggregationFunction(str, Enum):
    """Enumeration of supported aggregation functions."""
    MEAN = "mean"
    STD = "std"
    MIN = "min"
    MAX = "max"
    COUNT = "count"
    MEDIAN = "median"
    PERCENTILE_95 = "percentile_95"


class PacketCaptureConfig(BaseModel):
    """Configuration for packet capture on edge gateways."""
    interface: str = Field(description="Network interface for packet capture")
    buffer_size_mb: int = Field(ge=1, le=1024, description="Capture buffer size in MB")
    capture_filter: str = Field(default="", description="BPF filter expression for packet capture")
    
    class Config:
        schema_extra = {
            "example": {
                "interface": "eth0",
                "buffer_size_mb": 64,
                "capture_filter": "not port 22"
            }
        }


class ProtocolDecodersConfig(BaseModel):
    """Configuration for protocol decoders (Zeek/Suricata)."""
    zeek_enabled: bool = Field(default=True, description="Enable Zeek protocol analysis")
    suricata_enabled: bool = Field(default=True, description="Enable Suricata intrusion detection")
    custom_rules_path: str = Field(default="/etc/ids/rules", description="Path to custom detection rules")
    
    class Config:
        schema_extra = {
            "example": {
                "zeek_enabled": True,
                "suricata_enabled": True,
                "custom_rules_path": "/etc/ids/rules"
            }
        }


class ForwardingConfig(BaseModel):
    """Configuration for data forwarding from edge gateways."""
    upstream_endpoints: List[str] = Field(description="List of upstream service URLs")
    batch_size: int = Field(ge=1, le=10000, description="Number of events per batch")
    flush_interval_ms: int = Field(ge=100, le=60000, description="Maximum time to wait before flushing batch")
    retry_attempts: int = Field(ge=1, le=10, description="Number of retry attempts for failed transmissions")
    
    class Config:
        schema_extra = {
            "example": {
                "upstream_endpoints": ["https://ai-service:8080/api/v1/ingest"],
                "batch_size": 100,
                "flush_interval_ms": 5000,
                "retry_attempts": 3
            }
        }


class EdgeGatewayConfig(BaseModel):
    """Configuration for edge gateway components."""
    packet_capture: PacketCaptureConfig
    protocol_decoders: ProtocolDecodersConfig
    forwarding: ForwardingConfig


class IsolationForestConfig(BaseModel):
    """Configuration for Isolation Forest anomaly detection model."""
    enabled: bool = Field(default=True, description="Enable Isolation Forest model")
    contamination: float = Field(default=0.1, ge=0.0, le=0.5, description="Expected proportion of anomalies")
    n_estimators: int = Field(default=100, ge=50, le=1000, description="Number of isolation trees")
    
    class Config:
        schema_extra = {
            "example": {
                "enabled": True,
                "contamination": 0.1,
                "n_estimators": 100
            }
        }


class XGBoostConfig(BaseModel):
    """Configuration for XGBoost supervised learning model."""
    enabled: bool = Field(default=True, description="Enable XGBoost model")
    max_depth: int = Field(default=6, ge=3, le=20, description="Maximum tree depth")
    learning_rate: float = Field(default=0.1, ge=0.01, le=1.0, description="Learning rate for gradient boosting")
    n_estimators: int = Field(default=100, ge=50, le=1000, description="Number of boosting rounds")
    
    class Config:
        schema_extra = {
            "example": {
                "enabled": True,
                "max_depth": 6,
                "learning_rate": 0.1,
                "n_estimators": 100
            }
        }


class ModelsConfig(BaseModel):
    """Configuration for AI/ML models."""
    isolation_forest: IsolationForestConfig = Field(default_factory=IsolationForestConfig)
    xgboost: XGBoostConfig = Field(default_factory=XGBoostConfig)


class FeatureEngineeringConfig(BaseModel):
    """Configuration for feature engineering pipeline."""
    time_window_minutes: int = Field(default=5, ge=1, le=60, description="Time window for feature aggregation")
    aggregation_functions: List[AggregationFunction] = Field(
        default=[AggregationFunction.MEAN, AggregationFunction.STD, AggregationFunction.MAX],
        description="Statistical functions for feature aggregation"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "time_window_minutes": 5,
                "aggregation_functions": ["mean", "std", "max", "count"]
            }
        }


class DecisionEngineConfig(BaseModel):
    """Configuration for hybrid decision engine."""
    signature_weight: float = Field(default=0.7, ge=0.0, le=1.0, description="Weight for signature-based detection")
    ml_weight: float = Field(default=0.3, ge=0.0, le=1.0, description="Weight for ML-based detection")
    threshold_low: float = Field(default=0.3, ge=0.0, le=1.0, description="Threshold for low severity alerts")
    threshold_high: float = Field(default=0.7, ge=0.0, le=1.0, description="Threshold for high severity alerts")
    
    class Config:
        schema_extra = {
            "example": {
                "signature_weight": 0.7,
                "ml_weight": 0.3,
                "threshold_low": 0.3,
                "threshold_high": 0.7
            }
        }
    
    @model_validator(mode='after')
    def validate_weights_and_thresholds(self):
        """Validate that weights sum to 1.0 and thresholds are ordered correctly."""
        signature_weight = self.signature_weight or 0.0
        ml_weight = self.ml_weight or 0.0
        threshold_low = self.threshold_low or 0.0
        threshold_high = self.threshold_high or 1.0
        
        # Weights should sum to 1.0 (with small tolerance for floating point)
        weight_sum = signature_weight + ml_weight
        if abs(weight_sum - 1.0) > 0.001:
            raise ValueError(f"Signature and ML weights must sum to 1.0, got {weight_sum}")
        
        # Thresholds should be ordered correctly
        if threshold_low >= threshold_high:
            raise ValueError("threshold_low must be less than threshold_high")
        
        return self


class AIInferenceConfig(BaseModel):
    """Configuration for AI inference service."""
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    feature_engineering: FeatureEngineeringConfig = Field(default_factory=FeatureEngineeringConfig)
    decision_engine: DecisionEngineConfig = Field(default_factory=DecisionEngineConfig)


class ElasticsearchConfig(BaseModel):
    """Configuration for Elasticsearch storage."""
    hosts: List[str] = Field(default_factory=lambda: ["http://elasticsearch:9200"], description="List of Elasticsearch host URLs")
    index_prefix: str = Field(default="iot-ids", description="Prefix for Elasticsearch indices")
    shard_count: int = Field(default=1, ge=1, le=10, description="Number of primary shards per index")
    replica_count: int = Field(default=1, ge=0, le=5, description="Number of replica shards per index")
    
    class Config:
        schema_extra = {
            "example": {
                "hosts": ["http://elasticsearch:9200"],
                "index_prefix": "iot-ids",
                "shard_count": 1,
                "replica_count": 1
            }
        }


class RetentionConfig(BaseModel):
    """Configuration for data retention policies."""
    raw_data_days: int = Field(default=30, ge=1, le=365, description="Retention period for raw network data")
    aggregated_data_days: int = Field(default=365, ge=1, le=1095, description="Retention period for aggregated data")
    alert_data_days: int = Field(default=1095, ge=1, le=2555, description="Retention period for alert data")
    
    class Config:
        schema_extra = {
            "example": {
                "raw_data_days": 30,
                "aggregated_data_days": 365,
                "alert_data_days": 1095
            }
        }


class StorageConfig(BaseModel):
    """Configuration for data storage components."""
    elasticsearch: ElasticsearchConfig
    retention: RetentionConfig = Field(default_factory=RetentionConfig)


class SystemConfiguration(BaseModel):
    """
    Complete system configuration for AI-driven IoT IDS.
    
    This model represents all configurable parameters across
    edge gateways, AI inference services, and storage components,
    supporting hot-reloading and validation of configuration changes.
    """
    
    # Component Configurations
    edge_gateway: EdgeGatewayConfig
    ai_inference: AIInferenceConfig = Field(default_factory=AIInferenceConfig)
    storage: StorageConfig
    
    class Config:
        """Pydantic configuration for SystemConfiguration model."""
        schema_extra = {
            "example": {
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
                "ai_inference": {
                    "models": {
                        "isolation_forest": {
                            "enabled": True,
                            "contamination": 0.1,
                            "n_estimators": 100
                        },
                        "xgboost": {
                            "enabled": True,
                            "max_depth": 6,
                            "learning_rate": 0.1,
                            "n_estimators": 100
                        }
                    },
                    "feature_engineering": {
                        "time_window_minutes": 5,
                        "aggregation_functions": ["mean", "std", "max"]
                    },
                    "decision_engine": {
                        "signature_weight": 0.7,
                        "ml_weight": 0.3,
                        "threshold_low": 0.3,
                        "threshold_high": 0.7
                    }
                },
                "storage": {
                    "elasticsearch": {
                        "hosts": ["http://elasticsearch:9200"],
                        "index_prefix": "iot-ids",
                        "shard_count": 1,
                        "replica_count": 1
                    },
                    "retention": {
                        "raw_data_days": 30,
                        "aggregated_data_days": 365,
                        "alert_data_days": 1095
                    }
                }
            }
        }
    
    def validate_configuration(self) -> bool:
        """Validate the complete configuration for consistency."""
        # Check that at least one ML model is enabled
        models = self.ai_inference.models
        if not (models.isolation_forest.enabled or models.xgboost.enabled):
            raise ValueError("At least one ML model must be enabled")
        
        # Check that upstream endpoints are configured
        if not self.edge_gateway.forwarding.upstream_endpoints:
            raise ValueError("At least one upstream endpoint must be configured")
        
        # Check that Elasticsearch hosts are configured
        if not self.storage.elasticsearch.hosts:
            raise ValueError("At least one Elasticsearch host must be configured")
        
        return True
    
    def get_enabled_models(self) -> List[str]:
        """Get list of enabled ML models."""
        enabled = []
        if self.ai_inference.models.isolation_forest.enabled:
            enabled.append("isolation_forest")
        #if self.ai_inference.models.xgboost.enabled:
        #    enabled.append("xgboost")
        return enabled
    
    def get_total_retention_days(self) -> int:
        """Get maximum retention period across all data types."""
        return max(
            self.storage.retention.raw_data_days,
            self.storage.retention.aggregated_data_days,
            self.storage.retention.alert_data_days
        )
    
    def is_high_performance_mode(self) -> bool:
        """Check if configuration is optimized for high performance."""
        return (
            self.edge_gateway.packet_capture.buffer_size_mb >= 128 and
            self.edge_gateway.forwarding.batch_size >= 500 and
            self.storage.elasticsearch.shard_count > 1
        )