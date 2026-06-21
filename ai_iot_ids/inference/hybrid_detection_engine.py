"""
Hybrid Detection Engine for combining signature-based and ML-based threat detection.

This module provides the core detection engine that fuses signature rule matching
with machine learning anomaly detection to produce unified threat assessments.
"""

from typing import Dict, List, Optional, Union, Any, Tuple
import logging
import asyncio
from datetime import datetime
from enum import Enum
import re
import json
import numpy as np

from ..interfaces.base import BaseInterface
from ..models.network_flow import NetworkFlow
from ..models.threat_detection import ThreatDetection, SignatureMatch, MLPrediction, SeverityLevel, AttackCategory
from .model_manager import ModelManager


class RuleEngine:
    """
    Simple rule engine for signature-based detection.
    
    Processes network flows against signature rules to identify
    known threats and protocol violations.
    """
    
    def __init__(self, rules_config: Dict[str, Any]):
        """
        Initialize the rule engine.
        
        Args:
            rules_config: Configuration containing signature rules
        """
        self.rules = rules_config.get('rules', [])
        self.enabled_rules = set(rules_config.get('enabled_rules', []))
        self.rule_weights = rules_config.get('rule_weights', {})
        
    def match_rules(self, flow: NetworkFlow) -> List[SignatureMatch]:
        """
        Match network flow against signature rules.
        
        Args:
            flow: NetworkFlow to analyze
            
        Returns:
            List of signature matches
        """
        matches = []
        
        for rule in self.rules:
            rule_id = rule.get('id')
            
            # Skip disabled rules
            if self.enabled_rules and rule_id not in self.enabled_rules:
                continue
            
            if self._evaluate_rule(flow, rule):
                confidence = self.rule_weights.get(rule_id, 1.0)
                match = SignatureMatch(
                    rule_id=rule_id,
                    rule_name=rule.get('name', f'Rule {rule_id}'),
                    signature_score=min(confidence, 1.0)
                )
                matches.append(match)
        
        return matches
    
    def _evaluate_rule(self, flow: NetworkFlow, rule: Dict[str, Any]) -> bool:
        """
        Evaluate a single rule against a network flow.
        
        Args:
            flow: NetworkFlow to evaluate
            rule: Rule definition
            
        Returns:
            True if rule matches, False otherwise
        """
        conditions = rule.get('conditions', [])
        
        for condition in conditions:
            if not self._evaluate_condition(flow, condition):
                return False
        
        return len(conditions) > 0
    
    def _evaluate_condition(self, flow: NetworkFlow, condition: Dict[str, Any]) -> bool:
        """
        Evaluate a single condition against a network flow.
        
        Args:
            flow: NetworkFlow to evaluate
            condition: Condition definition
            
        Returns:
            True if condition matches, False otherwise
        """
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')
        
        if not all([field, operator, value]):
            return False
        
        # Get field value from flow
        flow_value = getattr(flow, field, None)
        if flow_value is None:
            return False
        
        # Evaluate based on operator
        if operator == 'eq':
            return flow_value == value
        elif operator == 'ne':
            return flow_value != value
        elif operator == 'gt':
            return flow_value > value
        elif operator == 'lt':
            return flow_value < value
        elif operator == 'gte':
            return flow_value >= value
        elif operator == 'lte':
            return flow_value <= value
        elif operator == 'in':
            return flow_value in value
        elif operator == 'contains':
            return str(value).lower() in str(flow_value).lower()
        elif operator == 'regex':
            return bool(re.search(value, str(flow_value)))
        else:
            return False


class ThreatScoreCalculator:
    """
    Calculator for combining signature and ML scores into unified threat scores.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the threat score calculator.
        
        Args:
            config: Configuration for score calculation
        """
        self.signature_weight = config.get('signature_weight', 0.6)
        self.ml_weight = config.get('ml_weight', 0.4)
        self.threshold_low = config.get('threshold_low', 0.3)
        self.threshold_medium = config.get('threshold_medium', 0.6)
        self.threshold_high = config.get('threshold_high', 0.8)
        self.confidence_boost = config.get('confidence_boost', 0.1)
        
        # Ensure weights sum to 1
        total_weight = self.signature_weight + self.ml_weight
        if total_weight > 0:
            self.signature_weight /= total_weight
            self.ml_weight /= total_weight
    
    def calculate_threat_score(self, signature_matches: List[SignatureMatch], 
                             ml_predictions: List[MLPrediction]) -> Tuple[float, float, SeverityLevel]:
        """
        Calculate unified threat score from signature matches and ML predictions.
        
        Args:
            signature_matches: List of signature-based matches
            ml_predictions: List of ML model predictions
            
        Returns:
            Tuple of (threat_score, confidence, severity_level)
        """
        # Calculate signature score
        signature_score = self._calculate_signature_score(signature_matches)
        
        # Calculate ML score
        ml_score = self._calculate_ml_score(ml_predictions)
        
        # Combine scores
        threat_score = (self.signature_weight * signature_score + 
                       self.ml_weight * ml_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(signature_matches, ml_predictions, threat_score)
        
        # Determine severity
        severity = self._determine_severity(threat_score, confidence)
        
        return threat_score, confidence, severity
    
    def _calculate_signature_score(self, matches: List[SignatureMatch]) -> float:
        """Calculate aggregated signature score."""
        if not matches:
            return 0.0
        
        # Use maximum score approach (most severe match)
        max_score = max(match.signature_score for match in matches)
        
        # Apply boost for multiple matches
        if len(matches) > 1:
            boost = min(0.2, (len(matches) - 1) * 0.05)
            max_score = min(1.0, max_score + boost)
        
        return max_score
    
    def _calculate_ml_score(self, predictions: List[MLPrediction]) -> float:
        """Calculate aggregated ML score."""
        if not predictions:
            return 0.0
        
        # Use weighted average of all model predictions
        total_score = 0.0
        total_weight = 0.0
        
        for pred in predictions:
            # Weight could be based on model performance/confidence
            weight = 1.0  # Equal weight for now
            total_score += pred.anomaly_score * weight
            total_weight += weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _calculate_confidence(self, signature_matches: List[SignatureMatch], 
                            ml_predictions: List[MLPrediction], threat_score: float) -> float:
        """Calculate confidence in the threat assessment."""
        base_confidence = 0.5
        
        # Boost confidence for signature matches (high confidence)
        if signature_matches:
            signature_boost = min(0.3, len(signature_matches) * 0.1)
            base_confidence += signature_boost
        
        # Boost confidence for multiple ML models agreeing
        if len(ml_predictions) > 1:
            scores = [pred.anomaly_score for pred in ml_predictions]
            score_std = float(np.std(scores)) if len(scores) > 1 else 0.0
            
            # Lower standard deviation = higher agreement = higher confidence
            agreement_boost = max(0.0, 0.2 - score_std)
            base_confidence += agreement_boost
        
        # Boost confidence for extreme scores
        if threat_score > 0.8 or threat_score < 0.2:
            base_confidence += self.confidence_boost
        
        return min(1.0, base_confidence)
    
    def _determine_severity(self, threat_score: float, confidence: float) -> SeverityLevel:
        """Determine severity level based on threat score and confidence."""
        # Adjust thresholds based on confidence
        confidence_factor = 0.8 + 0.2 * confidence  # Scale between 0.8 and 1.0
        
        adjusted_low = self.threshold_low * confidence_factor
        adjusted_medium = self.threshold_medium * confidence_factor
        adjusted_high = self.threshold_high * confidence_factor
        
        if threat_score >= adjusted_high:
            return SeverityLevel.CRITICAL
        elif threat_score >= adjusted_medium:
            return SeverityLevel.HIGH
        elif threat_score >= adjusted_low:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW


class HybridDetectionEngine(BaseInterface):
    """
    Hybrid detection engine combining signature-based and ML-based threat detection.
    
    Processes network flows through both signature rule matching and machine learning
    models to produce unified threat assessments with confidence scores.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the hybrid detection engine.
        
        Args:
            config: Engine configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.enable_signature_detection = config.get('enable_signature_detection', True)
        self.enable_ml_detection = config.get('enable_ml_detection', True)
        self.require_both_methods = config.get('require_both_methods', False)
        self.max_concurrent_detections = config.get('max_concurrent_detections', 10)
        
        # Components
        self.rule_engine = None
        self.model_manager = None
        self.score_calculator = None
        
        # Statistics
        self.detection_count = 0
        self.signature_detection_count = 0
        self.ml_detection_count = 0
        self.hybrid_detection_count = 0
        self.error_count = 0
        
        # Attack category mapping
        self.attack_category_rules = config.get('attack_category_rules', {})
        self.mitre_tactic_mapping = config.get('mitre_tactic_mapping', {})
        self.response_actions = config.get('response_actions', {})
    
    async def initialize(self) -> None:
        """Initialize the hybrid detection engine."""
        try:
            # Initialize rule engine
            if self.enable_signature_detection:
                rules_config = self.config.get('signature_rules', {})
                self.rule_engine = RuleEngine(rules_config)
                self.log_info(f"Rule engine initialized with {len(self.rule_engine.rules)} rules")
            
            # Initialize model manager
            if self.enable_ml_detection:
                manager_or_config = self.config.get('model_manager')
                if isinstance(manager_or_config, ModelManager):
                    self.model_manager = manager_or_config
                else:
                    self.model_manager = ModelManager(manager_or_config or {}, self.logger)
                
                if not getattr(self.model_manager, '_initialized', False):
                    await self.model_manager.initialize()
                self.log_info("Model manager initialized")
            
            # Initialize score calculator
            score_config = self.config.get('score_calculation', {})
            self.score_calculator = ThreatScoreCalculator(score_config)
            
            self._initialized = True
            self.log_info("Hybrid detection engine initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize hybrid detection engine", e)
            raise
    
    async def start(self) -> None:
        """Start the hybrid detection engine."""
        if not self._initialized:
            await self.initialize()
        
        # Start model manager
        if self.model_manager:
            await self.model_manager.start()
        
        self._running = True
        self.log_info("Hybrid detection engine started")
    
    async def stop(self) -> None:
        """Stop the hybrid detection engine."""
        self._running = False
        
        # Stop model manager
        if self.model_manager:
            await self.model_manager.stop()
        
        self.log_info("Hybrid detection engine stopped")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the detection engine.
        
        Returns:
            Dictionary containing engine health status
        """
        model_manager_health = None
        if self.model_manager:
            try:
                model_manager_health = await self.model_manager.health_check()
            except Exception as e:
                model_manager_health = {'error': str(e)}
        
        return {
            'initialized': self._initialized,
            'running': self._running,
            'signature_detection_enabled': self.enable_signature_detection,
            'ml_detection_enabled': self.enable_ml_detection,
            'rule_count': len(self.rule_engine.rules) if self.rule_engine else 0,
            'loaded_models': self.model_manager.get_loaded_models() if self.model_manager else [],
            'detection_count': self.detection_count,
            'signature_detection_count': self.signature_detection_count,
            'ml_detection_count': self.ml_detection_count,
            'hybrid_detection_count': self.hybrid_detection_count,
            'error_count': self.error_count,
            'model_manager_health': model_manager_health
        }
    
    async def detect_threats(self, flows: List[NetworkFlow]) -> List[ThreatDetection]:
        """
        Detect threats in network flows using hybrid approach.
        
        Args:
            flows: List of network flows to analyze
            
        Returns:
            List of threat detections
        """
        if not self._running:
            raise RuntimeError("Detection engine is not running")
        
        detections = []
        
        try:
            # Process flows concurrently with limit
            semaphore = asyncio.Semaphore(self.max_concurrent_detections)
            
            async def process_flow(flow):
                async with semaphore:
                    return await self._detect_single_flow(flow)
            
            # Create tasks for all flows
            tasks = [process_flow(flow) for flow in flows]
            
            # Wait for all detections
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect valid detections
            for result in results:
                if isinstance(result, Exception):
                    self.error_count += 1
                    self.log_error("Flow detection failed", result)
                elif result is not None:
                    detections.append(result)
            
            self.detection_count += len(flows)
            self.log_info(f"Processed {len(flows)} flows, generated {len(detections)} detections")
            
        except Exception as e:
            self.error_count += 1
            self.log_error("Batch threat detection failed", e)
            raise
        
        return detections
    
    async def _detect_single_flow(self, flow: NetworkFlow) -> Optional[ThreatDetection]:
        """
        Detect threats in a single network flow.
        
        Args:
            flow: NetworkFlow to analyze
            
        Returns:
            ThreatDetection if threats found, None otherwise
        """
        signature_matches = []
        ml_predictions = []
        
        try:
            # Signature-based detection
            if self.enable_signature_detection and self.rule_engine:
                signature_matches = self.rule_engine.match_rules(flow)
                if signature_matches:
                    self.signature_detection_count += 1
            
            # ML-based detection
            if self.enable_ml_detection and self.model_manager:
                try:
                    ml_predictions = await self.model_manager.predict_ensemble([flow])
                    if ml_predictions:
                        self.ml_detection_count += 1
                except Exception as e:
                    self.log_warning(f"ML detection failed for flow {flow.flow_id}: {e}")
            
            # Check if we have any detections
            has_signature = len(signature_matches) > 0
            has_ml = len(ml_predictions) > 0
            
            if self.require_both_methods and not (has_signature and has_ml):
                return None
            
            if not has_signature and not has_ml:
                return None
            
            # Calculate threat score
            threat_score, confidence, severity = self.score_calculator.calculate_threat_score(
                signature_matches, ml_predictions
            )
            
            # Skip low-confidence, low-severity detections
            if severity == SeverityLevel.LOW and confidence < 0.6:
                return None
            
            # Determine attack category and MITRE tactics
            attack_category = self._determine_attack_category(signature_matches, ml_predictions)
            mitre_tactics = self._get_mitre_tactics(signature_matches, attack_category)
            
            # Generate recommended actions
            recommended_actions = self._generate_recommended_actions(
                severity, attack_category, signature_matches, ml_predictions
            )
            
            # Create threat detection
            detection = ThreatDetection(
                timestamp=datetime.utcnow(),
                source_flow_id=flow.flow_id,
                device_id=f"{flow.source_ip}",  # Simplified device ID
                threat_score=threat_score,
                confidence=confidence,
                severity=severity,
                signature_matches=signature_matches,
                ml_predictions=ml_predictions,
                attack_category=attack_category,
                mitre_tactics=mitre_tactics,
                recommended_actions=recommended_actions
            )
            
            if has_signature and has_ml:
                self.hybrid_detection_count += 1
            
            return detection
            
        except Exception as e:
            self.log_error(f"Single flow detection failed for {flow.flow_id}", e)
            return None
    
    def _determine_attack_category(self, signature_matches: List[SignatureMatch], 
                                 ml_predictions: List[MLPrediction]) -> AttackCategory:
        """Determine attack category based on detections."""
        # Check signature matches first
        for match in signature_matches:
            rule_id = match.rule_id
            if rule_id in self.attack_category_rules:
                category_name = self.attack_category_rules[rule_id]
                try:
                    return AttackCategory(category_name)
                except ValueError:
                    pass
        
        # Fallback based on ML predictions (simplified)
        if ml_predictions:
            max_score = max(pred.anomaly_score for pred in ml_predictions)
            if max_score > 0.8:
                return AttackCategory.MALWARE
            elif max_score > 0.6:
                return AttackCategory.LATERAL_MOVEMENT
            else:
                return AttackCategory.RECONNAISSANCE
        
        return AttackCategory.UNKNOWN
    
    def _get_mitre_tactics(self, signature_matches: List[SignatureMatch], 
                          attack_category: AttackCategory) -> List[str]:
        """Get MITRE ATT&CK tactics for the detection."""
        tactics = []
        
        # Check signature-specific mappings
        for match in signature_matches:
            rule_id = match.rule_id
            if rule_id in self.mitre_tactic_mapping:
                tactics.extend(self.mitre_tactic_mapping[rule_id])
        
        # Add category-based tactics
        category_tactics = {
            AttackCategory.RECONNAISSANCE: ["T1046", "T1018"],
            AttackCategory.LATERAL_MOVEMENT: ["T1021", "T1570"],
            AttackCategory.EXFILTRATION: ["T1041", "T1048"],
            AttackCategory.DOS: ["T1499", "T1498"],
            AttackCategory.MALWARE: ["T1059", "T1055"]
        }
        
        if attack_category in category_tactics:
            tactics.extend(category_tactics[attack_category])
        
        return list(set(tactics))  # Remove duplicates
    
    def _generate_recommended_actions(self, severity: SeverityLevel, 
                                    attack_category: AttackCategory,
                                    signature_matches: List[SignatureMatch],
                                    ml_predictions: List[MLPrediction]) -> List[str]:
        """Generate recommended response actions."""
        actions = []
        
        # Severity-based actions
        if severity == SeverityLevel.CRITICAL:
            actions.extend([
                "Immediately isolate affected device",
                "Escalate to security team",
                "Begin incident response procedure"
            ])
        elif severity == SeverityLevel.HIGH:
            actions.extend([
                "Monitor device closely",
                "Review network logs",
                "Consider device isolation"
            ])
        elif severity == SeverityLevel.MEDIUM:
            actions.extend([
                "Log for investigation",
                "Monitor for pattern escalation"
            ])
        
        # Category-specific actions
        category_actions = {
            AttackCategory.RECONNAISSANCE: [
                "Review firewall rules",
                "Check for unauthorized scanning"
            ],
            AttackCategory.LATERAL_MOVEMENT: [
                "Audit network segmentation",
                "Review access controls"
            ],
            AttackCategory.EXFILTRATION: [
                "Monitor data flows",
                "Check for data loss prevention alerts"
            ],
            AttackCategory.DOS: [
                "Implement rate limiting",
                "Check network capacity"
            ],
            AttackCategory.MALWARE: [
                "Run antivirus scan",
                "Check for indicators of compromise"
            ]
        }
        
        if attack_category in category_actions:
            actions.extend(category_actions[attack_category])
        
        # Custom actions from configuration
        for match in signature_matches:
            rule_id = match.rule_id
            if rule_id in self.response_actions:
                actions.extend(self.response_actions[rule_id])
        
        return list(set(actions))  # Remove duplicates
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection engine statistics."""
        return {
            'total_detections': self.detection_count,
            'signature_detections': self.signature_detection_count,
            'ml_detections': self.ml_detection_count,
            'hybrid_detections': self.hybrid_detection_count,
            'error_count': self.error_count,
            'signature_detection_rate': self.signature_detection_count / max(1, self.detection_count),
            'ml_detection_rate': self.ml_detection_count / max(1, self.detection_count),
            'hybrid_detection_rate': self.hybrid_detection_count / max(1, self.detection_count)
        }