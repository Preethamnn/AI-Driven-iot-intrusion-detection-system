"""
System Orchestrator for AI-driven IoT IDS.

This module provides end-to-end system integration, connecting packet capture
to feature extraction pipeline, AI inference with observability stack,
and MLOps pipeline to model deployment.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict

from ..interfaces.packet_capture import PacketCaptureInterface, RawPacket
from ..interfaces.protocol_decoder import ProtocolDecoderInterface, ProtocolMetadata
from ..interfaces.feature_extractor import FeatureExtractorInterface, FeatureVector
from ..interfaces.secure_forwarder import SecureForwarderInterface
from ..models.network_flow import NetworkFlow
from ..models.threat_detection import ThreatDetection
from ..inference.hybrid_detection_engine import HybridDetectionEngine
from ..observability.elasticsearch_client import ElasticsearchClient
from ..observability.alerting_system import AlertingSystem
from ..mlops.model_registry import ModelRegistry
from ..mlops.drift_monitor import DriftMonitor
from ..utils.error_handling import IDSError


@dataclass
class ProcessingMetrics:
    """Metrics for system processing pipeline."""
    packets_received: int = 0
    packets_processed: int = 0
    flows_extracted: int = 0
    threats_detected: int = 0
    alerts_generated: int = 0
    data_forwarded: int = 0
    processing_errors: int = 0
    start_time: Optional[datetime] = None
    
    def get_processing_rate(self) -> float:
        """Calculate processing rate in packets per second."""
        if not self.start_time or self.packets_processed == 0:
            return 0.0
        
        elapsed = (datetime.utcnow() - self.start_time).total_seconds()
        return self.packets_processed / elapsed if elapsed > 0 else 0.0


class SystemOrchestrator:
    """
    Main system orchestrator that wires all components together.
    
    Manages the complete data flow from packet capture through threat detection
    to observability and model management.
    """
    
    def __init__(self, config: Dict[str, Any], logger=None):
        """
        Initialize the system orchestrator.
        
        Args:
            config: System configuration dictionary
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Component instances (to be injected)
        self.packet_capture: Optional[PacketCaptureInterface] = None
        self.protocol_decoder: Optional[ProtocolDecoderInterface] = None
        self.feature_extractor: Optional[FeatureExtractorInterface] = None
        self.secure_forwarder: Optional[SecureForwarderInterface] = None
        self.detection_engine: Optional[HybridDetectionEngine] = None
        self.elasticsearch_client: Optional[ElasticsearchClient] = None
        self.alerting_system: Optional[AlertingSystem] = None
        self.model_registry: Optional[ModelRegistry] = None
        self.drift_monitor: Optional[DriftMonitor] = None
        
        # Processing state
        self.is_running = False
        self.processing_tasks: List[asyncio.Task] = []
        self.metrics = ProcessingMetrics()
        
        # Data flow queues
        self.packet_queue = asyncio.Queue(maxsize=1000)
        self.metadata_queue = asyncio.Queue(maxsize=1000)
        self.flow_queue = asyncio.Queue(maxsize=1000)
        self.detection_queue = asyncio.Queue(maxsize=1000)
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
    
    def register_components(self,
                          packet_capture: PacketCaptureInterface,
                          protocol_decoder: ProtocolDecoderInterface,
                          feature_extractor: FeatureExtractorInterface,
                          secure_forwarder: SecureForwarderInterface,
                          detection_engine: HybridDetectionEngine,
                          elasticsearch_client: ElasticsearchClient,
                          alerting_system: AlertingSystem,
                          model_registry: ModelRegistry,
                          drift_monitor: DriftMonitor) -> None:
        """
        Register all system components with the orchestrator.
        
        Args:
            packet_capture: Packet capture component
            protocol_decoder: Protocol decoder component
            feature_extractor: Feature extractor component
            secure_forwarder: Secure forwarder component
            detection_engine: Hybrid detection engine
            elasticsearch_client: Elasticsearch client
            alerting_system: Alerting system
            model_registry: Model registry
            drift_monitor: Drift monitor
        """
        self.packet_capture = packet_capture
        self.protocol_decoder = protocol_decoder
        self.feature_extractor = feature_extractor
        self.secure_forwarder = secure_forwarder
        self.detection_engine = detection_engine
        self.elasticsearch_client = elasticsearch_client
        self.alerting_system = alerting_system
        self.model_registry = model_registry
        self.drift_monitor = drift_monitor
        
        self.logger.info("All system components registered with orchestrator")
    
    def add_event_handler(self, event_type: str, handler: Callable) -> None:
        """
        Add event handler for system events.
        
        Args:
            event_type: Type of event (e.g., 'threat_detected', 'model_updated')
            handler: Async callable to handle the event
        """
        self.event_handlers[event_type].append(handler)
    
    async def emit_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """
        Emit system event to registered handlers.
        
        Args:
            event_type: Type of event
            event_data: Event data dictionary
        """
        handlers = self.event_handlers.get(event_type, [])
        if handlers:
            await asyncio.gather(*[handler(event_data) for handler in handlers])
    
    async def start(self) -> None:
        """Start the system orchestrator and all processing pipelines."""
        if self.is_running:
            self.logger.warning("System orchestrator is already running")
            return
        
        try:
            self.logger.info("Starting system orchestrator...")
            
            # Validate that all components are registered
            self._validate_components()
            
            # Initialize metrics
            self.metrics = ProcessingMetrics()
            self.metrics.start_time = datetime.utcnow()
            
            # Start processing pipelines
            self.processing_tasks = [
                asyncio.create_task(self._packet_ingestion_pipeline()),
                asyncio.create_task(self._protocol_decoding_pipeline()),
                asyncio.create_task(self._feature_extraction_pipeline()),
                asyncio.create_task(self._threat_detection_pipeline()),
                asyncio.create_task(self._data_forwarding_pipeline()),
                asyncio.create_task(self._observability_pipeline()),
                asyncio.create_task(self._model_management_pipeline()),
                asyncio.create_task(self._health_monitoring_pipeline())
            ]
            
            self.is_running = True
            self.logger.info("System orchestrator started successfully")
            
            # Wait for all pipelines to complete
            await asyncio.gather(*self.processing_tasks)
            
        except Exception as e:
            self.logger.error(f"Failed to start system orchestrator: {e}", exc_info=True)
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the system orchestrator and all processing pipelines."""
        if not self.is_running:
            return
        
        try:
            self.logger.info("Stopping system orchestrator...")
            
            self.is_running = False
            
            # Cancel all processing tasks
            for task in self.processing_tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for tasks to complete with timeout
            if self.processing_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self.processing_tasks, return_exceptions=True),
                        timeout=10.0
                    )
                except asyncio.TimeoutError:
                    self.logger.warning("Some processing tasks did not stop gracefully")
            
            self.processing_tasks.clear()
            
            self.logger.info("System orchestrator stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping system orchestrator: {e}", exc_info=True)
    
    def _validate_components(self) -> None:
        """Validate that all required components are registered."""
        required_components = [
            ('packet_capture', self.packet_capture),
            ('protocol_decoder', self.protocol_decoder),
            ('feature_extractor', self.feature_extractor),
            ('secure_forwarder', self.secure_forwarder),
            ('detection_engine', self.detection_engine),
            ('elasticsearch_client', self.elasticsearch_client),
            ('alerting_system', self.alerting_system),
            ('model_registry', self.model_registry),
            ('drift_monitor', self.drift_monitor)
        ]
        
        missing_components = [name for name, component in required_components if component is None]
        
        if missing_components:
            raise IDSError(f"Missing required components: {missing_components}")
    
    async def _packet_ingestion_pipeline(self) -> None:
        """Pipeline for packet ingestion from capture interface."""
        try:
            self.logger.info("Starting packet ingestion pipeline...")
            
            async for packet in self.packet_capture.get_packets():
                if not self.is_running:
                    break
                
                try:
                    # Add packet to processing queue
                    await self.packet_queue.put(packet)
                    self.metrics.packets_received += 1
                    
                except asyncio.QueueFull:
                    self.logger.warning("Packet queue full, dropping packet")
                    self.metrics.processing_errors += 1
                
        except Exception as e:
            self.logger.error(f"Packet ingestion pipeline error: {e}", exc_info=True)
    
    async def _protocol_decoding_pipeline(self) -> None:
        """Pipeline for protocol decoding of captured packets."""
        try:
            self.logger.info("Starting protocol decoding pipeline...")
            
            while self.is_running:
                try:
                    # Get packet from queue with timeout
                    packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                    
                    # Decode packet using protocol decoder
                    metadata_list = await self.protocol_decoder.decode_packet(packet)
                    
                    if metadata_list:
                        if not isinstance(metadata_list, list):
                            metadata_list = [metadata_list]
                        # Add metadata to next pipeline stage
                        await self.metadata_queue.put(metadata_list)
                        self.metrics.packets_processed += 1
                    
                    # Mark packet as processed
                    self.packet_queue.task_done()
                    
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue processing
                except Exception as e:
                    self.logger.error(f"Protocol decoding error: {e}")
                    self.metrics.processing_errors += 1
                
        except Exception as e:
            self.logger.error(f"Protocol decoding pipeline error: {e}", exc_info=True)
    
    async def _feature_extraction_pipeline(self) -> None:
        """Pipeline for feature extraction from protocol metadata."""
        try:
            self.logger.info("Starting feature extraction pipeline...")
            
            while self.is_running:
                try:
                    # Get metadata from queue with timeout
                    metadata_list = await asyncio.wait_for(self.metadata_queue.get(), timeout=1.0)
                    
                    # Extract network flow features
                    flow = await self.feature_extractor.extract_flow_features(metadata_list)
                    
                    # Add flow to next pipeline stage
                    await self.flow_queue.put(flow)
                    self.metrics.flows_extracted += 1
                    
                    # Mark metadata as processed
                    self.metadata_queue.task_done()
                    
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue processing
                except Exception as e:
                    self.logger.error(f"Feature extraction error: {e}")
                    self.metrics.processing_errors += 1
                
        except Exception as e:
            self.logger.error(f"Feature extraction pipeline error: {e}", exc_info=True)
    
    async def _threat_detection_pipeline(self) -> None:
        """Pipeline for threat detection using hybrid detection engine."""
        try:
            self.logger.info("Starting threat detection pipeline...")
            
            while self.is_running:
                try:
                    # Get flow from queue with timeout
                    flow = await asyncio.wait_for(self.flow_queue.get(), timeout=1.0)
                    
                    # Perform threat detection
                    detection_result = await self.detection_engine.detect_threats([flow])
                    
                    if detection_result and detection_result.threat_score > 0.3:  # Configurable threshold
                        # Add detection to next pipeline stage
                        await self.detection_queue.put(detection_result)
                        self.metrics.threats_detected += 1
                        
                        # Emit threat detected event
                        await self.emit_event('threat_detected', {
                            'detection': detection_result,
                            'flow': flow,
                            'timestamp': datetime.utcnow()
                        })
                    
                    # Mark flow as processed
                    self.flow_queue.task_done()
                    
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue processing
                except Exception as e:
                    self.logger.error(f"Threat detection error: {e}")
                    self.metrics.processing_errors += 1
                
        except Exception as e:
            self.logger.error(f"Threat detection pipeline error: {e}", exc_info=True)
    
    async def _data_forwarding_pipeline(self) -> None:
        """Pipeline for forwarding data to upstream services."""
        try:
            self.logger.info("Starting data forwarding pipeline...")
            
            batch_data = []
            batch_size = self.config.get('forwarding', {}).get('batch_size', 100)
            flush_interval = self.config.get('forwarding', {}).get('flush_interval_ms', 5000) / 1000.0
            last_flush = datetime.utcnow()
            
            while self.is_running:
                try:
                    # Check if we should flush based on time
                    now = datetime.utcnow()
                    should_flush_time = (now - last_flush).total_seconds() >= flush_interval
                    
                    if batch_data and (len(batch_data) >= batch_size or should_flush_time):
                        # Forward batch data
                        await self.secure_forwarder.forward_data(batch_data)
                        self.metrics.data_forwarded += len(batch_data)
                        
                        batch_data.clear()
                        last_flush = now
                    
                    # Try to get detection from queue (non-blocking)
                    try:
                        detection = await asyncio.wait_for(self.detection_queue.get(), timeout=0.1)
                        batch_data.append(detection.dict())
                        self.detection_queue.task_done()
                    except asyncio.TimeoutError:
                        pass  # No data available, continue
                    
                    # Small delay to prevent busy waiting
                    await asyncio.sleep(0.01)
                    
                except Exception as e:
                    self.logger.error(f"Data forwarding error: {e}")
                    self.metrics.processing_errors += 1
            
            # Flush remaining data on shutdown
            if batch_data:
                try:
                    await self.secure_forwarder.forward_data(batch_data)
                    self.metrics.data_forwarded += len(batch_data)
                except Exception as e:
                    self.logger.error(f"Error flushing remaining data: {e}")
                
        except Exception as e:
            self.logger.error(f"Data forwarding pipeline error: {e}", exc_info=True)
    
    async def _observability_pipeline(self) -> None:
        """Pipeline for observability data storage and alerting."""
        try:
            self.logger.info("Starting observability pipeline...")
            
            # Register event handlers for observability
            self.add_event_handler('threat_detected', self._handle_threat_detection_event)
            
            while self.is_running:
                try:
                    # Store system metrics in Elasticsearch
                    metrics_data = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'packets_received': self.metrics.packets_received,
                        'packets_processed': self.metrics.packets_processed,
                        'flows_extracted': self.metrics.flows_extracted,
                        'threats_detected': self.metrics.threats_detected,
                        'processing_rate_pps': self.metrics.get_processing_rate(),
                        'processing_errors': self.metrics.processing_errors
                    }
                    
                    self.elasticsearch_client.index_document(
                        index='iot-ids-metrics',
                        document=metrics_data
                    )
                    
                    # Wait before next metrics collection
                    await asyncio.sleep(60)  # Collect metrics every minute
                    
                except Exception as e:
                    self.logger.error(f"Observability pipeline error: {e}")
                    await asyncio.sleep(60)  # Continue after error
                
        except Exception as e:
            self.logger.error(f"Observability pipeline error: {e}", exc_info=True)
    
    async def _handle_threat_detection_event(self, event_data: Dict[str, Any]) -> None:
        """Handle threat detection events for observability."""
        try:
            detection = event_data['detection']
            flow = event_data['flow']
            
            # Store detection in Elasticsearch
            detection_data = detection.dict()
            detection_data['flow_data'] = flow.dict()
            
            self.elasticsearch_client.index_document(
                index='iot-ids-detections',
                document=detection_data
            )
            
            # Generate alert if severity is high enough
            if detection.severity in ['high', 'critical']:
                alert_data = {
                    'title': f'IoT IDS Threat Detection - {detection.severity.upper()}',
                    'description': f'Threat detected with score {detection.threat_score:.2f}',
                    'severity': detection.severity,
                    'detection_id': detection.detection_id,
                    'source_ip': flow.source_ip,
                    'destination_ip': flow.destination_ip,
                    'timestamp': detection.timestamp.isoformat()
                }
                
                await self.alerting_system.send_alert(alert_data)
                self.metrics.alerts_generated += 1
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection event: {e}")
    
    async def _model_management_pipeline(self) -> None:
        """Pipeline for MLOps model management and drift monitoring."""
        try:
            self.logger.info("Starting model management pipeline...")
            
            while self.is_running:
                try:
                    # Check for model drift (placeholder as monitor_data_drift requires data)
                    drift_results = []
                    
                    if drift_results and any(result.drift_detected for result in drift_results):
                        self.logger.warning("Model drift detected, triggering model update")
                        
                        # Emit model drift event
                        await self.emit_event('model_drift_detected', {
                            'drift_results': drift_results,
                            'timestamp': datetime.utcnow()
                        })
                    
                    # Check for model updates in registry
                    available_models = self.model_registry.list_models()
                    
                    # Update detection engine with new models if available
                    if available_models:
                        await self.detection_engine.update_models(available_models)
                    
                    # Wait before next check
                    await asyncio.sleep(300)  # Check every 5 minutes
                    
                except Exception as e:
                    self.logger.error(f"Model management error: {e}")
                    await asyncio.sleep(300)  # Continue after error
                
        except Exception as e:
            self.logger.error(f"Model management pipeline error: {e}", exc_info=True)
    
    async def _health_monitoring_pipeline(self) -> None:
        """Pipeline for system health monitoring."""
        try:
            self.logger.info("Starting health monitoring pipeline...")
            
            while self.is_running:
                try:
                    # Collect health status from all components
                    health_status = await self._collect_component_health()
                    
                    # Log system status
                    self._log_system_status(health_status)
                    
                    # Store health metrics in Elasticsearch
                    health_data = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'component_health': health_status,
                        'system_metrics': {
                            'packets_received': self.metrics.packets_received,
                            'processing_rate_pps': self.metrics.get_processing_rate(),
                            'queue_sizes': {
                                'packet_queue': self.packet_queue.qsize(),
                                'metadata_queue': self.metadata_queue.qsize(),
                                'flow_queue': self.flow_queue.qsize(),
                                'detection_queue': self.detection_queue.qsize()
                            }
                        }
                    }
                    
                    self.elasticsearch_client.index_document(
                        index='iot-ids-health',
                        document=health_data
                    )
                    
                    # Wait before next health check
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"Health monitoring error: {e}")
                    await asyncio.sleep(30)  # Continue after error
                
        except Exception as e:
            self.logger.error(f"Health monitoring pipeline error: {e}", exc_info=True)
    
    async def _collect_component_health(self) -> Dict[str, Dict[str, Any]]:
        """Collect health status from all system components."""
        health_status = {}
        
        components = [
            ('packet_capture', self.packet_capture),
            ('protocol_decoder', self.protocol_decoder),
            ('feature_extractor', self.feature_extractor),
            ('secure_forwarder', self.secure_forwarder),
            ('detection_engine', self.detection_engine),
            ('elasticsearch_client', self.elasticsearch_client),
            ('alerting_system', self.alerting_system),
            ('model_registry', self.model_registry),
            ('drift_monitor', self.drift_monitor)
        ]
        
        for name, component in components:
            try:
                if component and hasattr(component, 'health_check'):
                    health_status[name] = await component.health_check()
                else:
                    health_status[name] = {'status': 'unknown', 'error': 'No health check available'}
            except Exception as e:
                health_status[name] = {'status': 'error', 'error': str(e)}
        
        return health_status
    
    def _log_system_status(self, health_status: Dict[str, Dict[str, Any]]) -> None:
        """Log system status summary."""
        healthy_components = sum(1 for status in health_status.values() if status.get('status') == 'healthy')
        total_components = len(health_status)
        
        processing_rate = self.metrics.get_processing_rate()
        
        self.logger.info(
            f"System Status - "
            f"Components: {healthy_components}/{total_components} healthy, "
            f"Processing: {processing_rate:.2f} pps, "
            f"Threats: {self.metrics.threats_detected}, "
            f"Errors: {self.metrics.processing_errors}"
        )
        
        # Log unhealthy components
        unhealthy = [name for name, status in health_status.items() if status.get('status') != 'healthy']
        if unhealthy:
            self.logger.warning(f"Unhealthy components: {unhealthy}")
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics."""
        return {
            'packets_received': self.metrics.packets_received,
            'packets_processed': self.metrics.packets_processed,
            'flows_extracted': self.metrics.flows_extracted,
            'threats_detected': self.metrics.threats_detected,
            'alerts_generated': self.metrics.alerts_generated,
            'data_forwarded': self.metrics.data_forwarded,
            'processing_errors': self.metrics.processing_errors,
            'processing_rate_pps': self.metrics.get_processing_rate(),
            'uptime_seconds': (datetime.utcnow() - self.metrics.start_time).total_seconds() if self.metrics.start_time else 0,
            'queue_sizes': {
                'packet_queue': self.packet_queue.qsize(),
                'metadata_queue': self.metadata_queue.qsize(),
                'flow_queue': self.flow_queue.qsize(),
                'detection_queue': self.detection_queue.qsize()
            }
        }