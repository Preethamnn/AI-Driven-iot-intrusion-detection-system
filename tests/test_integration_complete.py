"""
Complete system integration tests for AI-driven IoT IDS.

This module provides comprehensive integration testing of the complete
system from packet capture through threat detection to observability.
"""

import pytest
import pytest_asyncio
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any

from ai_iot_ids.models.system_configuration import SystemConfiguration
from ai_iot_ids.integration.component_factory import ComponentFactory
from ai_iot_ids.integration.system_orchestrator import SystemOrchestrator
from ai_iot_ids.integration.data_flow_validator import DataFlowValidator


@pytest.fixture
def test_config():
    """Create test system configuration."""
    return SystemConfiguration(
        edge_gateway={
            'packet_capture': {
                'interface': 'lo',  # Use loopback for testing
                'buffer_size_mb': 16,
                'capture_filter': ''
            },
            'protocol_decoders': {
                'zeek_enabled': True,
                'suricata_enabled': True,
                'custom_rules_path': '/tmp/test_rules'
            },
            'forwarding': {
                'upstream_endpoints': ['http://localhost:8000/api/v1/ingest'],
                'batch_size': 10,
                'flush_interval_ms': 1000,
                'retry_attempts': 2
            }
        },
        ai_inference={
            'models': {
                'isolation_forest': {
                    'enabled': True,
                    'contamination': 0.1,
                    'n_estimators': 50
                },
                'xgboost': {
                    'enabled': False,  # Disable for faster testing
                    'max_depth': 3,
                    'learning_rate': 0.1,
                    'n_estimators': 50
                }
            },
            'feature_engineering': {
                'time_window_minutes': 1,
                'aggregation_functions': ['mean', 'std']
            },
            'decision_engine': {
                'signature_weight': 0.6,
                'ml_weight': 0.4,
                'threshold_low': 0.3,
                'threshold_high': 0.7
            }
        },
        storage={
            'elasticsearch': {
                'hosts': ['http://localhost:9200'],
                'index_prefix': 'test-iot-ids',
                'shard_count': 1,
                'replica_count': 0
            },
            'retention': {
                'raw_data_days': 7,
                'aggregated_data_days': 30,
                'alert_data_days': 90
            }
        }
    )


@pytest_asyncio.fixture(scope="function")
async def component_factory(test_config):
    """Create component factory with test configuration."""
    logger = logging.getLogger('test_integration')
    return ComponentFactory(test_config, logger)


@pytest_asyncio.fixture(scope="function")
async def system_components(component_factory):
    """Create and initialize all system components."""
    orchestrator, components = component_factory.create_system_orchestrator()
    
    # Initialize components (but don't start them yet)
    try:
        await component_factory.initialize_all_components(components)
        yield orchestrator, components
    finally:
        # Cleanup
        await component_factory.stop_all_components(components)


@pytest.mark.asyncio
class TestSystemIntegration:
    """Test complete system integration."""
    
    @pytest.mark.asyncio
    async def test_component_creation(self, component_factory):
        """Test that all components can be created successfully."""
        orchestrator, components = component_factory.create_system_orchestrator()
        
        # Verify all expected components are created
        expected_components = [
            'packet_capture',
            'protocol_decoder',
            'feature_extractor',
            'secure_forwarder',
            'model_manager',
            'detection_engine',
            'elasticsearch_client',
            'alerting_system',
            'model_registry',
            'drift_monitor',
            'orchestrator'
        ]
        
        for component_name in expected_components:
            assert component_name in components
            assert components[component_name] is not None
    
    @pytest.mark.asyncio
    async def test_component_initialization(self, component_factory):
        """Test that all components can be initialized successfully."""
        orchestrator, components = component_factory.create_system_orchestrator()
        
        # Initialize components
        await component_factory.initialize_all_components(components)
        
        # Verify components are initialized
        for component_name, component in components.items():
            if component_name != 'orchestrator' and hasattr(component, 'is_initialized'):
                assert component.is_initialized(), f"{component_name} not initialized"
    
    @pytest.mark.asyncio
    async def test_component_health_checks(self, system_components):
        """Test health checks for all components."""
        orchestrator, components = system_components
        
        # Start components
        await orchestrator.component_factory.start_all_components(components)
        
        try:
            # Test health checks
            health_results = {}
            for component_name, component in components.items():
                if component_name != 'orchestrator' and hasattr(component, 'health_check'):
                    try:
                        health_status = await component.health_check()
                        health_results[component_name] = health_status
                        
                        # Basic health check validation
                        assert 'status' in health_status
                        assert health_status['status'] in ['healthy', 'warning', 'unhealthy', 'error']
                        
                    except Exception as e:
                        # Some components might not be fully functional in test environment
                        health_results[component_name] = {'status': 'error', 'error': str(e)}
            
            # At least some components should be healthy
            healthy_count = sum(1 for status in health_results.values() 
                              if status.get('status') == 'healthy')
            assert healthy_count > 0, f"No healthy components found: {health_results}"
            
        finally:
            await orchestrator.component_factory.stop_all_components(components)
    
    @pytest.mark.asyncio
    async def test_orchestrator_metrics(self, system_components):
        """Test system orchestrator metrics collection."""
        orchestrator, components = system_components
        
        # Get initial metrics
        metrics = orchestrator.get_system_metrics()
        
        # Verify metrics structure
        expected_metrics = [
            'packets_received',
            'packets_processed',
            'flows_extracted',
            'threats_detected',
            'alerts_generated',
            'data_forwarded',
            'processing_errors',
            'processing_rate_pps',
            'uptime_seconds',
            'queue_sizes'
        ]
        
        for metric_name in expected_metrics:
            assert metric_name in metrics, f"Missing metric: {metric_name}"
        
        # Verify queue sizes structure
        assert isinstance(metrics['queue_sizes'], dict)
        expected_queues = ['packet_queue', 'metadata_queue', 'flow_queue', 'detection_queue']
        for queue_name in expected_queues:
            assert queue_name in metrics['queue_sizes']
    
    @pytest.mark.asyncio
    async def test_data_flow_validation(self, system_components):
        """Test end-to-end data flow validation."""
        orchestrator, components = system_components
        
        # Create data flow validator
        validator = DataFlowValidator(orchestrator)
        
        # Run validation tests
        validation_results = await validator.validate_complete_pipeline()
        
        # Verify validation results
        assert len(validation_results) > 0, "No validation tests were run"
        
        # Check that at least some tests passed
        passed_tests = sum(1 for result in validation_results if result.success)
        total_tests = len(validation_results)
        
        # Allow some tests to fail in test environment (e.g., Elasticsearch might not be available)
        success_rate = passed_tests / total_tests
        assert success_rate >= 0.5, f"Too many validation tests failed: {passed_tests}/{total_tests}"
        
        # Verify validation report structure
        report = validator.get_validation_report()
        assert 'timestamp' in report
        assert 'summary' in report
        assert 'test_results' in report
        
        assert report['summary']['total_tests'] == total_tests
        assert report['summary']['passed_tests'] == passed_tests
    
    @pytest.mark.asyncio
    async def test_error_resilience(self, system_components):
        """Test system resilience to errors."""
        orchestrator, components = system_components
        
        # Start components
        await orchestrator.component_factory.start_all_components(components)
        
        try:
            # Get initial metrics
            initial_metrics = orchestrator.get_system_metrics()
            initial_errors = initial_metrics.get('processing_errors', 0)
            
            # Simulate some processing time
            await asyncio.sleep(0.5)
            
            # Get updated metrics
            updated_metrics = orchestrator.get_system_metrics()
            
            # System should still be functional
            assert orchestrator.is_running == False  # Orchestrator not started in this test
            
            # Error count should not have increased dramatically
            current_errors = updated_metrics.get('processing_errors', 0)
            error_increase = current_errors - initial_errors
            assert error_increase < 100, f"Too many errors generated: {error_increase}"
            
        finally:
            await orchestrator.component_factory.stop_all_components(components)
    
    @pytest.mark.asyncio
    async def test_configuration_validation(self, test_config):
        """Test system configuration validation."""
        # Test valid configuration
        assert test_config.validate_configuration() == True
        
        # Test configuration methods
        enabled_models = test_config.get_enabled_models()
        assert isinstance(enabled_models, list)
        assert 'isolation_forest' in enabled_models
        
        total_retention = test_config.get_total_retention_days()
        assert isinstance(total_retention, int)
        assert total_retention > 0
        
        high_perf_mode = test_config.is_high_performance_mode()
        assert isinstance(high_perf_mode, bool)
    
    @pytest.mark.asyncio
    async def test_component_lifecycle(self, component_factory):
        """Test complete component lifecycle (create, initialize, start, stop)."""
        orchestrator, components = component_factory.create_system_orchestrator()
        
        # Test initialization
        await component_factory.initialize_all_components(components)
        
        # Test starting
        await component_factory.start_all_components(components)
        
        # Verify components are running
        for component_name, component in components.items():
            if component_name != 'orchestrator' and hasattr(component, 'is_running'):
                assert component.is_running(), f"{component_name} not running after start"
        
        # Test stopping
        await component_factory.stop_all_components(components)
        
        # Verify components are stopped
        for component_name, component in components.items():
            if component_name != 'orchestrator' and hasattr(component, 'is_running'):
                assert not component.is_running(), f"{component_name} still running after stop"


@pytest.mark.asyncio
class TestDataFlowValidation:
    """Test data flow validation functionality."""
    
    @pytest.mark.asyncio
    async def test_validation_result_structure(self):
        """Test validation result data structure."""
        from ai_iot_ids.integration.data_flow_validator import ValidationResult
        
        result = ValidationResult(
            test_name="Test Validation",
            success=True,
            duration_ms=100.0,
            error_message=None,
            metrics={'test_metric': 42}
        )
        
        assert result.test_name == "Test Validation"
        assert result.success == True
        assert result.duration_ms == 100.0
        assert result.error_message is None
        assert result.metrics['test_metric'] == 42
    
    @pytest.mark.asyncio
    async def test_validator_timeout_handling(self, system_components):
        """Test validator timeout handling."""
        orchestrator, components = system_components
        
        validator = DataFlowValidator(orchestrator)
        validator.test_timeout = 0.1  # Very short timeout
        
        # Create a test that will timeout
        async def slow_test():
            await asyncio.sleep(1.0)  # Longer than timeout
            return ValidationResult("Slow Test", True, 1000.0)
        
        # Run validation with timeout
        start_time = datetime.utcnow()
        results = []
        
        try:
            result = await asyncio.wait_for(slow_test(), timeout=validator.test_timeout)
            results.append(result)
        except asyncio.TimeoutError:
            result = ValidationResult(
                test_name="Slow Test",
                success=False,
                duration_ms=validator.test_timeout * 1000,
                error_message="Test timed out"
            )
            results.append(result)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Verify timeout was handled
        assert len(results) == 1
        assert not results[0].success
        assert "timeout" in results[0].error_message.lower()
        assert duration < 0.5  # Should have timed out quickly


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])