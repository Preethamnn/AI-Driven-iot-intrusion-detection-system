"""
Component Factory for AI-driven IoT IDS system integration.

This module provides a factory for creating and wiring all system components
together based on configuration, enabling easy system setup and testing.
"""

import logging
from typing import Dict, Any, Optional, Tuple

from ..models.system_configuration import SystemConfiguration
from ..capture.scapy_capture import ScapyPacketCapture
from ..decoders.hybrid_decoder import HybridDecoder
from ..extractors.network_flow_extractor import NetworkFlowExtractor
from ..transport.secure_forwarder_impl import SecureForwarderImpl
from ..inference.hybrid_detection_engine import HybridDetectionEngine
from ..inference.model_manager import ModelManager
from ..observability.elasticsearch_client import ElasticsearchClient
from ..observability.alerting_system import AlertingSystem
from ..mlops.model_registry import ModelRegistry
from ..mlops.drift_monitor import DriftMonitor
from .system_orchestrator import SystemOrchestrator


class ComponentFactory:
    """
    Factory for creating and configuring all system components.
    
    Provides a centralized way to create components with proper configuration
    and dependency injection for system integration.
    """
    
    def __init__(self, config: SystemConfiguration, logger=None):
        """
        Initialize the component factory.
        
        Args:
            config: System configuration object
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
    
    def create_packet_capture(self) -> ScapyPacketCapture:
        """Create and configure packet capture component."""
        capture_config = {
            'buffer_size_mb': self.config.edge_gateway.packet_capture.buffer_size_mb,
            'max_packet_size': 65535,
            'capture_timeout': 1.0,
            'promisc_mode': True,
            'use_af_packet': True
        }
        
        return ScapyPacketCapture(capture_config, self.logger)
    
    def create_protocol_decoder(self) -> HybridDecoder:
        """Create and configure protocol decoder component."""
        # Zeek-specific configuration
        zeek_config = {
            'zeek_binary_path': '/usr/local/zeek/bin/zeek',
            'scripts_dir': None,
            'temp_dir': None,
            'batch_size': 100,
            'timeout_seconds': 30
        }
        
        # Suricata-specific configuration
        suricata_config = {
            'suricata_binary_path': '/usr/bin/suricata',
            'config_file': '/etc/suricata/suricata.yaml',
            'rules_dir': self.config.edge_gateway.protocol_decoders.custom_rules_path,
            'temp_dir': None,
            'batch_size': 100,
            'timeout_seconds': 30
        }
        
        # Determine mode based on enabled decoders
        zeek_enabled = self.config.edge_gateway.protocol_decoders.zeek_enabled
        suricata_enabled = self.config.edge_gateway.protocol_decoders.suricata_enabled
        
        if zeek_enabled and suricata_enabled:
            mode = "both"
        elif zeek_enabled:
            mode = "zeek"
        elif suricata_enabled:
            mode = "suricata"
        else:
            mode = "both"  # Default fallback
        
        return HybridDecoder(
            zeek_config=zeek_config if zeek_enabled else None,
            suricata_config=suricata_config if suricata_enabled else None,
            mode=mode,
            primary_decoder="suricata",
            merge_metadata=True
        )
    
    def create_feature_extractor(self) -> NetworkFlowExtractor:
        """Create and configure feature extractor component."""
        extractor_config = {
            'time_window_minutes': self.config.ai_inference.feature_engineering.time_window_minutes,
            'max_flows_per_window': 10000,
            'enable_dns_features': True,
            'enable_tls_features': True,
            'aggregation_functions': [func.value for func in self.config.ai_inference.feature_engineering.aggregation_functions]
        }
        
        return NetworkFlowExtractor(extractor_config, self.logger)
    
    def create_secure_forwarder(self) -> SecureForwarderImpl:
        """Create and configure secure forwarder component."""
        forwarder_config = {
            'upstream_endpoints': self.config.edge_gateway.forwarding.upstream_endpoints,
            'batch_size': self.config.edge_gateway.forwarding.batch_size,
            'flush_interval_ms': self.config.edge_gateway.forwarding.flush_interval_ms,
            'retry_attempts': self.config.edge_gateway.forwarding.retry_attempts,
            'enable_tls': True,
            'verify_certificates': True,
            'connection_timeout': 30.0,
            'read_timeout': 60.0
        }
        
        return SecureForwarderImpl(forwarder_config)
    
    def create_model_manager(self) -> ModelManager:
        """Create and configure model manager component."""
        model_config = {
            'model_base_path': 'models/',
            'enable_isolation_forest': self.config.ai_inference.models.isolation_forest.enabled,
            'enable_xgboost': self.config.ai_inference.models.xgboost.enabled,
            'isolation_forest_config': {
                'contamination': self.config.ai_inference.models.isolation_forest.contamination,
                'n_estimators': self.config.ai_inference.models.isolation_forest.n_estimators
            },
            'xgboost_config': {
                'max_depth': self.config.ai_inference.models.xgboost.max_depth,
                'learning_rate': self.config.ai_inference.models.xgboost.learning_rate,
                'n_estimators': self.config.ai_inference.models.xgboost.n_estimators
            }
        }
        
        return ModelManager(model_config, self.logger)
    
    def create_detection_engine(self, model_manager: ModelManager) -> HybridDetectionEngine:
        """Create and configure hybrid detection engine."""
        engine_config = {
            'enable_signature_detection': True,
            'enable_ml_detection': True,
            'signature_rules': {
                'rules': [],  # Would be loaded from configuration
                'enabled_rules': []
            },
            'score_calculation': {
                'signature_weight': self.config.ai_inference.decision_engine.signature_weight,
                'ml_weight': self.config.ai_inference.decision_engine.ml_weight,
                'threshold_low': self.config.ai_inference.decision_engine.threshold_low,
                'threshold_high': self.config.ai_inference.decision_engine.threshold_high
            },
            'model_manager': model_manager
        }
        
        return HybridDetectionEngine(engine_config, self.logger)
    
    def create_elasticsearch_client(self) -> ElasticsearchClient:
        """Create and configure Elasticsearch client."""
        # Note: using localhost since Edge Gateway runs natively on Windows
        return ElasticsearchClient(
            hosts=["http://localhost:9200"],
            username=None,
            password=None,
            ca_certs=None,
            verify_certs=False,
            timeout=30
        )
    
    def create_alerting_system(self, elasticsearch_client: ElasticsearchClient) -> AlertingSystem:
        """Create and configure alerting system."""
        # Disable all external alerting for local edge gateway demo
        return AlertingSystem(
            email_config=None,
            slack_config=None,
            webhook_config=None,
            kibana_config=None
        )
    
    def create_model_registry(self) -> ModelRegistry:
        """Create and configure model registry."""
        registry_config = {
            'storage_backend': 'filesystem',
            'storage_path': 'models/registry',
            'enable_versioning': True,
            'enable_metadata_tracking': True,
            'max_versions_per_model': 10
        }
        
        return ModelRegistry(registry_config, self.logger)
    
    def create_drift_monitor(self, model_registry: ModelRegistry) -> DriftMonitor:
        """Create and configure drift monitor."""
        drift_config = {
            'monitoring_enabled': True,
            'drift_detection_method': 'statistical',
            'drift_threshold': 0.05,
            'monitoring_window_hours': 24,
            'model_registry': model_registry
        }
        
        return DriftMonitor(drift_config, self.logger)
    
    def create_system_orchestrator(self) -> Tuple[SystemOrchestrator, Dict[str, Any]]:
        """
        Create complete system with all components wired together.
        
        Returns:
            Tuple of (SystemOrchestrator, components_dict)
        """
        self.logger.info("Creating complete system with all components...")
        
        # Create all components
        packet_capture = self.create_packet_capture()
        protocol_decoder = self.create_protocol_decoder()
        feature_extractor = self.create_feature_extractor()
        secure_forwarder = self.create_secure_forwarder()
        
        model_manager = self.create_model_manager()
        detection_engine = self.create_detection_engine(model_manager)
        
        elasticsearch_client = self.create_elasticsearch_client()
        alerting_system = self.create_alerting_system(elasticsearch_client)
        
        model_registry = self.create_model_registry()
        drift_monitor = self.create_drift_monitor(model_registry)
        
        # Create orchestrator configuration
        orchestrator_config = {
            'forwarding': {
                'batch_size': self.config.edge_gateway.forwarding.batch_size,
                'flush_interval_ms': self.config.edge_gateway.forwarding.flush_interval_ms
            }
        }
        
        # Create system orchestrator
        orchestrator = SystemOrchestrator(orchestrator_config, self.logger)
        
        # Register all components with orchestrator
        orchestrator.register_components(
            packet_capture=packet_capture,
            protocol_decoder=protocol_decoder,
            feature_extractor=feature_extractor,
            secure_forwarder=secure_forwarder,
            detection_engine=detection_engine,
            elasticsearch_client=elasticsearch_client,
            alerting_system=alerting_system,
            model_registry=model_registry,
            drift_monitor=drift_monitor
        )
        
        # Components dictionary for external access
        components = {
            'packet_capture': packet_capture,
            'protocol_decoder': protocol_decoder,
            'feature_extractor': feature_extractor,
            'secure_forwarder': secure_forwarder,
            'model_manager': model_manager,
            'detection_engine': detection_engine,
            'elasticsearch_client': elasticsearch_client,
            'alerting_system': alerting_system,
            'model_registry': model_registry,
            'drift_monitor': drift_monitor,
            'orchestrator': orchestrator
        }
        
        self.logger.info("Complete system created successfully")
        return orchestrator, components
    
    async def initialize_all_components(self, components: Dict[str, Any]) -> None:
        """
        Initialize all system components.
        
        Args:
            components: Dictionary of components to initialize
        """
        self.logger.info("Initializing all system components...")
        
        # Initialize components in dependency order
        initialization_order = [
            'elasticsearch_client',
            'model_registry',
            'model_manager',
            'packet_capture',
            'protocol_decoder',
            'feature_extractor',
            'secure_forwarder',
            'detection_engine',
            'alerting_system',
            'drift_monitor'
        ]
        
        for component_name in initialization_order:
            component = components.get(component_name)
            if component and hasattr(component, 'initialize'):
                try:
                    await component.initialize()
                    self.logger.info(f"Initialized {component_name}")
                except Exception as e:
                    self.logger.error(f"Failed to initialize {component_name}: {e}")
                    raise
        
        self.logger.info("All components initialized successfully")
    
    async def start_all_components(self, components: Dict[str, Any]) -> None:
        """
        Start all system components.
        
        Args:
            components: Dictionary of components to start
        """
        self.logger.info("Starting all system components...")
        
        # Start components in dependency order
        start_order = [
            'elasticsearch_client',
            'model_registry',
            'model_manager',
            'packet_capture',
            'protocol_decoder',
            'feature_extractor',
            'secure_forwarder',
            'detection_engine',
            'alerting_system',
            'drift_monitor'
        ]
        
        for component_name in start_order:
            component = components.get(component_name)
            if component and hasattr(component, 'start'):
                try:
                    await component.start()
                    self.logger.info(f"Started {component_name}")
                except Exception as e:
                    self.logger.error(f"Failed to start {component_name}: {e}")
                    raise
        
        self.logger.info("All components started successfully")
    
    async def stop_all_components(self, components: Dict[str, Any]) -> None:
        """
        Stop all system components.
        
        Args:
            components: Dictionary of components to stop
        """
        self.logger.info("Stopping all system components...")
        
        # Stop components in reverse dependency order
        stop_order = [
            'drift_monitor',
            'alerting_system',
            'detection_engine',
            'secure_forwarder',
            'feature_extractor',
            'protocol_decoder',
            'packet_capture',
            'model_manager',
            'model_registry',
            'elasticsearch_client'
        ]
        
        for component_name in stop_order:
            component = components.get(component_name)
            if component and hasattr(component, 'stop'):
                try:
                    await component.stop()
                    self.logger.info(f"Stopped {component_name}")
                except Exception as e:
                    self.logger.error(f"Error stopping {component_name}: {e}")
        
        self.logger.info("All components stopped")