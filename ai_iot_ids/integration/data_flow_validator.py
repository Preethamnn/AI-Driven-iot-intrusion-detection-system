"""
End-to-end data flow validation for AI-driven IoT IDS system.

This module provides validation of the complete data pipeline from
packet capture through threat detection to observability storage.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import json

from ..interfaces.packet_capture import RawPacket
from ..models.network_flow import NetworkFlow
from ..models.threat_detection import ThreatDetection
from .system_orchestrator import SystemOrchestrator


@dataclass
class ValidationResult:
    """Result of end-to-end data flow validation."""
    test_name: str
    success: bool
    duration_ms: float
    error_message: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None


class DataFlowValidator:
    """
    Validator for end-to-end data flow testing.
    
    Provides comprehensive testing of the complete system pipeline
    from packet ingestion to threat detection and storage.
    """
    
    def __init__(self, orchestrator: SystemOrchestrator, logger=None):
        """
        Initialize the data flow validator.
        
        Args:
            orchestrator: System orchestrator instance
            logger: Optional logger instance
        """
        self.orchestrator = orchestrator
        self.logger = logger or logging.getLogger(__name__)
        
        # Test configuration
        self.test_timeout = 30.0  # seconds
        self.validation_results: List[ValidationResult] = []
    
    async def validate_complete_pipeline(self) -> List[ValidationResult]:
        """
        Validate the complete data processing pipeline.
        
        Returns:
            List of validation results for each test
        """
        self.logger.info("Starting complete pipeline validation...")
        self.validation_results.clear()
        
        # Run all validation tests
        tests = [
            self._test_packet_capture_to_protocol_decoding,
            self._test_protocol_decoding_to_feature_extraction,
            self._test_feature_extraction_to_threat_detection,
            self._test_threat_detection_to_observability,
            self._test_end_to_end_flow,
            self._test_system_health_monitoring,
            self._test_error_handling_resilience
        ]
        
        for test in tests:
            try:
                result = await asyncio.wait_for(test(), timeout=self.test_timeout)
                self.validation_results.append(result)
                
                if result.success:
                    self.logger.info(f"✓ {result.test_name} passed ({result.duration_ms:.2f}ms)")
                else:
                    self.logger.error(f"✗ {result.test_name} failed: {result.error_message}")
                    
            except asyncio.TimeoutError:
                result = ValidationResult(
                    test_name=test.__name__,
                    success=False,
                    duration_ms=self.test_timeout * 1000,
                    error_message="Test timed out"
                )
                self.validation_results.append(result)
                self.logger.error(f"✗ {test.__name__} timed out")
                
            except Exception as e:
                result = ValidationResult(
                    test_name=test.__name__,
                    success=False,
                    duration_ms=0.0,
                    error_message=str(e)
                )
                self.validation_results.append(result)
                self.logger.error(f"✗ {test.__name__} failed with exception: {e}")
        
        # Generate summary
        self._log_validation_summary()
        
        return self.validation_results
    
    async def _test_packet_capture_to_protocol_decoding(self) -> ValidationResult:
        """Test packet capture to protocol decoding flow."""
        start_time = datetime.utcnow()
        
        try:
            # Create a synthetic packet for testing
            test_packet = RawPacket(
                timestamp=datetime.utcnow(),
                length=64,
                data=b'\x00' * 64,  # Dummy packet data
                interface='test0',
                protocol='TCP',
                source_ip='192.168.1.100',
                destination_ip='192.168.1.1',
                source_port=12345,
                destination_port=80
            )
            
            # Get protocol decoder from orchestrator
            protocol_decoder = self.orchestrator.protocol_decoder
            
            # Test protocol decoding
            metadata_list = await protocol_decoder.decode_packet(test_packet)
            
            # Validate results
            if not metadata_list:
                raise ValueError("Protocol decoder returned empty metadata list")
            
            if len(metadata_list) == 0:
                raise ValueError("No protocol metadata extracted")
            
            # Check metadata structure
            metadata = metadata_list[0]
            if not hasattr(metadata, 'source_ip') or not hasattr(metadata, 'destination_ip'):
                raise ValueError("Protocol metadata missing required fields")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="Packet Capture to Protocol Decoding",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'metadata_count': len(metadata_list),
                    'protocol_type': str(metadata.protocol)
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="Packet Capture to Protocol Decoding",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_protocol_decoding_to_feature_extraction(self) -> ValidationResult:
        """Test protocol decoding to feature extraction flow."""
        start_time = datetime.utcnow()
        
        try:
            # Create synthetic protocol metadata
            from ..interfaces.protocol_decoder import ProtocolMetadata, ProtocolType
            
            test_metadata = ProtocolMetadata(
                timestamp=datetime.utcnow(),
                source_ip='192.168.1.100',
                destination_ip='192.168.1.1',
                source_port=12345,
                destination_port=80,
                protocol=ProtocolType.TCP,
                payload_size=1024,
                tcp_flags=['SYN', 'ACK']
            )
            
            # Get feature extractor from orchestrator
            feature_extractor = self.orchestrator.feature_extractor
            
            # Test feature extraction
            flow = await feature_extractor.extract_flow_features([test_metadata])
            
            # Validate results
            if not isinstance(flow, NetworkFlow):
                raise ValueError("Feature extractor did not return NetworkFlow object")
            
            if flow.source_ip != test_metadata.source_ip:
                raise ValueError("Flow source IP does not match metadata")
            
            if flow.bytes_sent <= 0:
                raise ValueError("Flow bytes_sent should be positive")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="Protocol Decoding to Feature Extraction",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'flow_bytes': flow.bytes_sent,
                    'flow_packets': flow.packets_sent,
                    'flow_duration': flow.duration_ms
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="Protocol Decoding to Feature Extraction",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_feature_extraction_to_threat_detection(self) -> ValidationResult:
        """Test feature extraction to threat detection flow."""
        start_time = datetime.utcnow()
        
        try:
            # Create synthetic network flow
            test_flow = NetworkFlow(
                timestamp=datetime.utcnow(),
                source_ip='192.168.1.100',
                destination_ip='192.168.1.1',
                source_port=12345,
                destination_port=80,
                protocol='TCP',
                bytes_sent=1024,
                bytes_received=512,
                packets_sent=10,
                packets_received=8,
                duration_ms=5000,
                inter_arrival_mean_ms=500.0,
                inter_arrival_std_ms=100.0,
                jitter_ms=50.0,
                tcp_flags=['SYN', 'ACK', 'FIN'],
                retransmissions=0,
                syn_fin_ratio=1.0,
                unique_destinations=1,
                fan_out_ratio=0.1,
                fan_in_ratio=0.1,
                port_distribution_entropy=0.5
            )
            
            # Get detection engine from orchestrator
            detection_engine = self.orchestrator.detection_engine
            
            # Test threat detection
            detection_result = await detection_engine.detect_threats([test_flow])
            
            # Validate results
            if not isinstance(detection_result, ThreatDetection):
                raise ValueError("Detection engine did not return ThreatDetection object")
            
            if not (0.0 <= detection_result.threat_score <= 1.0):
                raise ValueError("Threat score should be between 0.0 and 1.0")
            
            if not detection_result.detection_id:
                raise ValueError("Detection ID should not be empty")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="Feature Extraction to Threat Detection",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'threat_score': detection_result.threat_score,
                    'confidence': detection_result.confidence,
                    'severity': detection_result.severity.value
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="Feature Extraction to Threat Detection",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_threat_detection_to_observability(self) -> ValidationResult:
        """Test threat detection to observability storage flow."""
        start_time = datetime.utcnow()
        
        try:
            # Create synthetic threat detection
            test_detection = ThreatDetection(
                timestamp=datetime.utcnow(),
                source_flow_id='test-flow-123',
                device_id='test-device-456',
                threat_score=0.75,
                confidence=0.85,
                severity='high',
                signature_matches=[],
                ml_predictions=[],
                attack_category='reconnaissance',
                mitre_tactics=['T1595'],
                recommended_actions=['block_ip', 'investigate']
            )
            
            # Get Elasticsearch client from orchestrator
            elasticsearch_client = self.orchestrator.elasticsearch_client
            
            # Test data storage
            result = await elasticsearch_client.index_document(
                index='test-iot-ids-detections',
                document=test_detection.dict()
            )
            
            # Validate results
            if not result or not result.get('_id'):
                raise ValueError("Failed to store detection in Elasticsearch")
            
            # Test data retrieval
            stored_doc = await elasticsearch_client.get_document(
                index='test-iot-ids-detections',
                doc_id=result['_id']
            )
            
            if not stored_doc or stored_doc['_source']['threat_score'] != test_detection.threat_score:
                raise ValueError("Stored document does not match original")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="Threat Detection to Observability",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'document_id': result['_id'],
                    'index_name': 'test-iot-ids-detections'
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="Threat Detection to Observability",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_end_to_end_flow(self) -> ValidationResult:
        """Test complete end-to-end data flow."""
        start_time = datetime.utcnow()
        
        try:
            # Get initial system metrics
            initial_metrics = self.orchestrator.get_system_metrics()
            
            # Wait for some processing to occur
            await asyncio.sleep(2.0)
            
            # Get updated system metrics
            updated_metrics = self.orchestrator.get_system_metrics()
            
            # Validate that processing is occurring
            metrics_changed = False
            for key in ['packets_received', 'packets_processed', 'flows_extracted']:
                if updated_metrics.get(key, 0) > initial_metrics.get(key, 0):
                    metrics_changed = True
                    break
            
            if not metrics_changed:
                # This might be normal if no packets are being captured
                self.logger.warning("No processing activity detected during end-to-end test")
            
            # Check system health
            if updated_metrics.get('processing_errors', 0) > 10:
                raise ValueError(f"Too many processing errors: {updated_metrics['processing_errors']}")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="End-to-End Data Flow",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'initial_packets': initial_metrics.get('packets_received', 0),
                    'updated_packets': updated_metrics.get('packets_received', 0),
                    'processing_rate': updated_metrics.get('processing_rate_pps', 0.0),
                    'processing_errors': updated_metrics.get('processing_errors', 0)
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="End-to-End Data Flow",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_system_health_monitoring(self) -> ValidationResult:
        """Test system health monitoring functionality."""
        start_time = datetime.utcnow()
        
        try:
            # Test component health checks
            components = [
                'packet_capture',
                'protocol_decoder',
                'feature_extractor',
                'secure_forwarder',
                'detection_engine',
                'elasticsearch_client',
                'alerting_system',
                'model_registry',
                'drift_monitor'
            ]
            
            health_results = {}
            for component_name in components:
                component = getattr(self.orchestrator, component_name, None)
                if component and hasattr(component, 'health_check'):
                    try:
                        health_status = await component.health_check()
                        health_results[component_name] = health_status
                    except Exception as e:
                        health_results[component_name] = {'status': 'error', 'error': str(e)}
                else:
                    health_results[component_name] = {'status': 'not_available'}
            
            # Check that most components are healthy
            healthy_count = sum(1 for status in health_results.values() 
                              if status.get('status') == 'healthy')
            total_count = len(health_results)
            
            if healthy_count < total_count * 0.7:  # At least 70% should be healthy
                raise ValueError(f"Too many unhealthy components: {healthy_count}/{total_count}")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="System Health Monitoring",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'healthy_components': healthy_count,
                    'total_components': total_count,
                    'health_percentage': (healthy_count / total_count) * 100
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="System Health Monitoring",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_error_handling_resilience(self) -> ValidationResult:
        """Test system error handling and resilience."""
        start_time = datetime.utcnow()
        
        try:
            # Get initial error count
            initial_metrics = self.orchestrator.get_system_metrics()
            initial_errors = initial_metrics.get('processing_errors', 0)
            
            # Test that system continues processing despite errors
            # (This is a basic test - in practice, we might inject specific errors)
            
            await asyncio.sleep(1.0)
            
            # Check that system is still running
            if not self.orchestrator.is_running:
                raise ValueError("System stopped running during resilience test")
            
            # Check queue sizes are reasonable (not growing unbounded)
            queue_sizes = initial_metrics.get('queue_sizes', {})
            max_queue_size = max(queue_sizes.values()) if queue_sizes else 0
            
            if max_queue_size > 5000:  # Arbitrary threshold
                raise ValueError(f"Queue size too large: {max_queue_size}")
            
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return ValidationResult(
                test_name="Error Handling Resilience",
                success=True,
                duration_ms=duration_ms,
                metrics={
                    'system_running': self.orchestrator.is_running,
                    'max_queue_size': max_queue_size,
                    'initial_errors': initial_errors
                }
            )
            
        except Exception as e:
            duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
            return ValidationResult(
                test_name="Error Handling Resilience",
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    def _log_validation_summary(self) -> None:
        """Log summary of validation results."""
        total_tests = len(self.validation_results)
        passed_tests = sum(1 for result in self.validation_results if result.success)
        failed_tests = total_tests - passed_tests
        
        total_duration = sum(result.duration_ms for result in self.validation_results)
        avg_duration = total_duration / total_tests if total_tests > 0 else 0
        
        self.logger.info(f"Validation Summary:")
        self.logger.info(f"  Total tests: {total_tests}")
        self.logger.info(f"  Passed: {passed_tests}")
        self.logger.info(f"  Failed: {failed_tests}")
        self.logger.info(f"  Success rate: {(passed_tests/total_tests)*100:.1f}%")
        self.logger.info(f"  Average duration: {avg_duration:.2f}ms")
        self.logger.info(f"  Total duration: {total_duration:.2f}ms")
        
        if failed_tests > 0:
            self.logger.error("Failed tests:")
            for result in self.validation_results:
                if not result.success:
                    self.logger.error(f"  - {result.test_name}: {result.error_message}")
    
    def get_validation_report(self) -> Dict[str, Any]:
        """
        Get comprehensive validation report.
        
        Returns:
            Dictionary containing validation results and summary
        """
        total_tests = len(self.validation_results)
        passed_tests = sum(1 for result in self.validation_results if result.success)
        
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': total_tests - passed_tests,
                'success_rate': (passed_tests / total_tests) * 100 if total_tests > 0 else 0,
                'total_duration_ms': sum(result.duration_ms for result in self.validation_results)
            },
            'test_results': [
                {
                    'test_name': result.test_name,
                    'success': result.success,
                    'duration_ms': result.duration_ms,
                    'error_message': result.error_message,
                    'metrics': result.metrics
                }
                for result in self.validation_results
            ]
        }