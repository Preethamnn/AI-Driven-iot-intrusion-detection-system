"""
Threat Detection data model for the AI-driven IoT IDS system.

This module defines the ThreatDetection Pydantic model that represents
security threats detected through hybrid signature-based and ML-based
detection methods.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


class SeverityLevel(str, Enum):
    """Enumeration of threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackCategory(str, Enum):
    """Enumeration of attack categories based on common threat types."""
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    DOS = "dos"
    MALWARE = "malware"
    UNKNOWN = "unknown"


class SignatureMatch(BaseModel):
    """Signature-based detection match information."""
    rule_id: str = Field(description="Unique identifier for the detection rule")
    rule_name: str = Field(description="Human-readable name of the detection rule")
    signature_score: float = Field(ge=0.0, le=1.0, description="Confidence score for signature match")
    
    class Config:
        schema_extra = {
            "example": {
                "rule_id": "SID:2001234",
                "rule_name": "Suspicious DNS Query Pattern",
                "signature_score": 0.95
            }
        }


class MLPrediction(BaseModel):
    """Machine learning model prediction information."""
    model_name: str = Field(description="Name of the ML model that generated the prediction")
    model_version: str = Field(description="Version of the ML model")
    anomaly_score: float = Field(ge=0.0, le=1.0, description="Anomaly score from ML model")
    feature_importance: Dict[str, float] = Field(
        default_factory=dict,
        description="Feature importance scores for explainability"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "model_name": "isolation_forest_v1",
                "model_version": "1.2.0",
                "anomaly_score": 0.87,
                "feature_importance": {
                    "bytes_per_packet": 0.35,
                    "inter_arrival_time": 0.28,
                    "port_distribution": 0.22,
                    "protocol_deviation": 0.15
                }
            }
        }
    
    @field_validator('feature_importance')
    @classmethod
    def validate_feature_importance(cls, v):
        """Validate that feature importance scores are between 0 and 1."""
        for feature, importance in v.items():
            if not 0.0 <= importance <= 1.0:
                raise ValueError(f"Feature importance must be between 0.0 and 1.0, got {importance} for {feature}")
        return v


class ThreatDetection(BaseModel):
    """
    Threat detection result from hybrid detection engine.
    
    This model represents a security threat detected through combination
    of signature-based rules and machine learning anomaly detection,
    including context, severity assessment, and recommended actions.
    """
    
    # Detection Identification
    detection_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique detection identifier")
    timestamp: datetime = Field(description="Detection timestamp in ISO 8601 format")
    source_flow_id: str = Field(description="Reference to the NetworkFlow that triggered detection")
    device_id: str = Field(description="Reference to the DeviceProfile associated with detection")
    
    # Detection Results
    threat_score: float = Field(ge=0.0, le=1.0, description="Combined threat score from hybrid detection")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence level in the detection")
    severity: SeverityLevel = Field(description="Threat severity level")
    
    # Detection Methods
    signature_matches: List[SignatureMatch] = Field(
        default_factory=list,
        description="List of signature-based detection matches"
    )
    ml_predictions: List[MLPrediction] = Field(
        default_factory=list,
        description="List of ML model predictions"
    )
    
    # Context and Classification
    attack_category: AttackCategory = Field(description="Categorization of the attack type")
    mitre_tactics: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactic IDs associated with the threat"
    )
    recommended_actions: List[str] = Field(
        default_factory=list,
        description="Recommended response actions for the threat"
    )
    
    class Config:
        """Pydantic configuration for ThreatDetection model."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "detection_id": "550e8400-e29b-41d4-a716-446655440001",
                "timestamp": "2024-01-15T10:35:00Z",
                "source_flow_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_id": "aa:bb:cc:dd:ee:ff",
                "threat_score": 0.85,
                "confidence": 0.92,
                "severity": "high",
                "signature_matches": [
                    {
                        "rule_id": "SID:2001234",
                        "rule_name": "Suspicious DNS Query Pattern",
                        "signature_score": 0.95
                    }
                ],
                "ml_predictions": [
                    {
                        "model_name": "isolation_forest_v1",
                        "model_version": "1.2.0",
                        "anomaly_score": 0.87,
                        "feature_importance": {
                            "bytes_per_packet": 0.35,
                            "inter_arrival_time": 0.28
                        }
                    }
                ],
                "attack_category": "reconnaissance",
                "mitre_tactics": ["T1046", "T1018"],
                "recommended_actions": [
                    "Block suspicious DNS queries",
                    "Investigate device behavior",
                    "Review network segmentation"
                ]
            }
        }
    
    @field_validator('mitre_tactics')
    @classmethod
    def validate_mitre_tactics(cls, v):
        """Validate MITRE ATT&CK tactic ID format."""
        import re
        mitre_pattern = re.compile(r'^T\d{4}(\.\d{3})?$')
        for tactic in v:
            if not mitre_pattern.match(tactic):
                raise ValueError(f"Invalid MITRE ATT&CK tactic format: {tactic}")
        return v
    
    @model_validator(mode='after')
    def validate_detection_consistency(self):
        """Validate consistency between detection fields."""
        threat_score = self.threat_score or 0.0
        severity = self.severity
        signature_matches = self.signature_matches or []
        ml_predictions = self.ml_predictions or []
        confidence = self.confidence or 0.0
        
        # Ensure at least one detection method produced results
        if not signature_matches and not ml_predictions:
            raise ValueError("Detection must have at least one signature match or ML prediction")
        
        # Validate severity aligns with threat score
        severity_thresholds = {
            SeverityLevel.LOW: (0.0, 0.3),
            SeverityLevel.MEDIUM: (0.3, 0.6),
            SeverityLevel.HIGH: (0.6, 0.9),
            SeverityLevel.CRITICAL: (0.9, 1.0)
        }
        
        if severity:
            min_score, max_score = severity_thresholds[severity]
            if not (min_score <= threat_score <= max_score):
                raise ValueError(f"Threat score {threat_score} inconsistent with severity {severity}")
        
        # Confidence should be reasonable given the evidence
        evidence_count = len(signature_matches) + len(ml_predictions)
        if evidence_count == 1 and confidence > 0.8:
            raise ValueError("High confidence requires multiple sources of evidence")
        
        return self
    
    def get_max_signature_score(self) -> float:
        """Get the highest signature match score."""
        if not self.signature_matches:
            return 0.0
        return max(match.signature_score for match in self.signature_matches)
    
    def get_max_ml_score(self) -> float:
        """Get the highest ML anomaly score."""
        if not self.ml_predictions:
            return 0.0
        return max(pred.anomaly_score for pred in self.ml_predictions)
    
    def get_contributing_models(self) -> List[str]:
        """Get list of ML models that contributed to this detection."""
        return [pred.model_name for pred in self.ml_predictions]
    
    def get_triggered_rules(self) -> List[str]:
        """Get list of signature rules that triggered for this detection."""
        return [match.rule_name for match in self.signature_matches]
    
    def is_high_confidence(self, threshold: float = 0.8) -> bool:
        """Check if detection has high confidence."""
        return self.confidence >= threshold
    
    def requires_immediate_action(self) -> bool:
        """Check if detection requires immediate response."""
        return (self.severity == SeverityLevel.CRITICAL or 
                (self.severity == SeverityLevel.HIGH and self.confidence >= 0.9))
    
    def get_top_features(self, n: int = 5) -> Dict[str, float]:
        """Get top N most important features across all ML predictions."""
        all_features = {}
        
        for pred in self.ml_predictions:
            for feature, importance in pred.feature_importance.items():
                if feature in all_features:
                    all_features[feature] = max(all_features[feature], importance)
                else:
                    all_features[feature] = importance
        
        # Sort by importance and return top N
        sorted_features = sorted(all_features.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_features[:n])