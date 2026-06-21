"""
Tests for MLOps pipeline components.

This module tests the model registry, drift monitoring, and deployment
management components of the MLOps pipeline.
"""

import pytest
import pytest_asyncio
import asyncio
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
import numpy as np
from unittest.mock import Mock, AsyncMock, patch

from ai_iot_ids.mlops.model_registry import (
    ModelRegistry, ModelMetadata, ModelVersion, ModelStatus, ModelType
)
from ai_iot_ids.mlops.drift_monitor import (
    DriftMonitor, PerformanceTracker, DriftAlert, DriftType, AlertSeverity,
    PerformanceMetrics
)
from ai_iot_ids.mlops.deployment_manager import (
    DeploymentManager, DeploymentConfig, DeploymentStrategy, DeploymentStatus
)
from ai_iot_ids.mlops.cicd_integration import (
    CICDPipeline, PipelineConfig, PipelineStatus, BuildStage
)


@pytest.mark.asyncio
class TestModelRegistry:
    """Test cases for ModelRegistry."""
    
    @pytest_asyncio.fixture(scope="function")
    async def registry(self):
        """Create a test model registry."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'registry_path': f"{temp_dir}/registry",
                'models_path': f"{temp_dir}/models",
                'max_versions_per_model': 5,
                'auto_cleanup': True
            }
            
            registry = ModelRegistry(config)
            await registry.initialize()
            await registry.start()
            
            yield registry
            
            await registry.stop()
    
    @pytest.fixture
    def sample_metadata(self):
        """Create sample model metadata."""
        return ModelMetadata(
            name="test_model",
            version="1.0.0",
            model_type=ModelType.SUPERVISED,
            framework="sklearn",
            created_at=datetime.utcnow(),
            created_by="test_user",
            description="Test model for unit testing",
            tags=["test", "sklearn"],
            training_metrics={"accuracy": 0.95, "f1_score": 0.92},
            validation_metrics={"accuracy": 0.93, "f1_score": 0.90},
            model_path="",
            config_path=""
        )
    
    @pytest.fixture
    def mock_model(self):
        """Create a mock model object."""
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        
        # Create dummy training data
        X = np.random.rand(100, 4)
        y = np.random.randint(0, 2, 100)
        model.fit(X, y)
        
        return model
    
    async def test_model_registration(self, registry, sample_metadata, mock_model):
        """Test model registration."""
        model_version = await registry.register_model(
            model_name="test_model",
            model_version="1.0.0",
            model_artifact=mock_model,
            metadata=sample_metadata,
            config={"n_estimators": 10},
            requirements=["scikit-learn>=1.0.0"]
        )
        
        assert model_version.version == "1.0.0"
        assert model_version.metadata.name == "test_model"
        assert model_version.checksum is not None
        assert model_version.size_bytes > 0
        
        # Verify model is in registry
        assert "test_model" in registry.list_models()
        assert "1.0.0" in registry.list_versions("test_model")
    
    async def test_model_loading(self, registry, sample_metadata, mock_model):
        """Test model loading."""
        # Register model first
        await registry.register_model(
            model_name="test_model",
            model_version="1.0.0",
            model_artifact=mock_model,
            metadata=sample_metadata
        )
        
        # Load model
        loaded_model = await registry.load_model_artifact("test_model", "1.0.0")
        
        assert loaded_model is not None
        assert hasattr(loaded_model, 'predict')
        
        # Test prediction to ensure model works
        X_test = np.random.rand(5, 4)
        predictions = loaded_model.predict(X_test)
        assert len(predictions) == 5
    
    async def test_model_promotion(self, registry, sample_metadata, mock_model):
        """Test model promotion workflow."""
        # Register model
        await registry.register_model(
            model_name="test_model",
            model_version="1.0.0",
            model_artifact=mock_model,
            metadata=sample_metadata
        )
        
        # Promote to staging
        await registry.promote_to_staging("test_model", "1.0.0")
        assert registry.get_staging_version("test_model") == "1.0.0"
        
        # Promote to production
        await registry.promote_to_production("test_model", "1.0.0")
        assert registry.get_production_version("test_model") == "1.0.0"
    
    async def test_model_rollback(self, registry, sample_metadata, mock_model):
        """Test model rollback."""
        # Register two versions
        await registry.register_model(
            model_name="test_model",
            model_version="1.0.0",
            model_artifact=mock_model,
            metadata=sample_metadata
        )
        
        sample_metadata.version = "1.1.0"
        await registry.register_model(
            model_name="test_model",
            model_version="1.1.0",
            model_artifact=mock_model,
            metadata=sample_metadata
        )
        
        # Promote both versions
        await registry.promote_to_production("test_model", "1.0.0")
        await registry.promote_to_production("test_model", "1.1.0")
        
        # Rollback to previous version
        rolled_back_version = await registry.rollback_model("test_model", target_version="1.0.0")
        assert rolled_back_version == "1.0.0"
        assert registry.get_production_version("test_model") == "1.0.0"


@pytest.mark.asyncio
class TestDriftMonitor:
    """Test cases for DriftMonitor."""
    
    @pytest_asyncio.fixture(scope="function")
    async def drift_monitor(self):
        """Create a test drift monitor."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'alerts_path': f"{temp_dir}/alerts",
                'metrics_path': f"{temp_dir}/metrics",
                'monitoring_window_hours': 24,
                'drift_threshold': 0.05,
                'min_samples': 50
            }
            
            monitor = DriftMonitor(config)
            await monitor.initialize()
            await monitor.start()
            
            yield monitor
            
            await monitor.stop()
    
    @pytest.fixture
    def baseline_data(self):
        """Create baseline data for drift detection."""
        np.random.seed(42)
        return pd.DataFrame({
            'feature1': np.random.normal(0, 1, 1000),
            'feature2': np.random.normal(5, 2, 1000),
            'feature3': np.random.exponential(1, 1000),
            'category': np.random.choice(['A', 'B', 'C'], 1000)
        })
    
    @pytest.fixture
    def drifted_data(self):
        """Create drifted data for drift detection."""
        np.random.seed(123)
        return pd.DataFrame({
            'feature1': np.random.normal(1, 1, 500),  # Mean shift
            'feature2': np.random.normal(5, 3, 500),  # Variance shift
            'feature3': np.random.exponential(2, 500),  # Distribution shift
            'category': np.random.choice(['A', 'B', 'C', 'D'], 500)  # New category
        })
    
    async def test_baseline_update(self, drift_monitor, baseline_data):
        """Test baseline data update."""
        await drift_monitor.update_baseline("test_model", baseline_data)
        
        assert "test_model" in drift_monitor.baseline_data
        assert len(drift_monitor.baseline_data["test_model"]) == len(baseline_data)
        assert "test_model" in drift_monitor.feature_scalers
    
    async def test_data_drift_detection(self, drift_monitor, baseline_data, drifted_data):
        """Test data drift detection."""
        # Set baseline
        await drift_monitor.update_baseline("test_model", baseline_data)
        
        # Monitor for drift
        alerts = await drift_monitor.monitor_data_drift("test_model", drifted_data)
        
        # Should detect drift in multiple features
        assert len(alerts) > 0
        
        # Check alert properties
        for alert in alerts:
            assert alert.model_name == "test_model"
            assert alert.drift_type == DriftType.DATA_DRIFT
            assert alert.severity in [AlertSeverity.LOW, AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL]
    
    async def test_prediction_drift_detection(self, drift_monitor):
        """Test prediction drift detection."""
        # Create baseline and current predictions
        np.random.seed(42)
        baseline_predictions = np.random.beta(2, 5, 1000)  # Skewed distribution
        
        np.random.seed(123)
        current_predictions = np.random.beta(5, 2, 500)   # Different distribution
        
        # Monitor for prediction drift
        alerts = await drift_monitor.monitor_prediction_drift(
            "test_model", current_predictions, baseline_predictions
        )
        
        # Should detect prediction drift
        assert len(alerts) > 0
        
        # Check alert properties
        for alert in alerts:
            assert alert.model_name == "test_model"
            assert alert.drift_type == DriftType.PREDICTION_DRIFT
    
    async def test_alert_callbacks(self, drift_monitor, baseline_data, drifted_data):
        """Test alert callback functionality."""
        callback_called = False
        received_alert = None
        
        def alert_callback(alert: DriftAlert):
            nonlocal callback_called, received_alert
            callback_called = True
            received_alert = alert
        
        # Add callback
        drift_monitor.add_alert_callback(alert_callback)
        
        # Set baseline and detect drift
        await drift_monitor.update_baseline("test_model", baseline_data)
        alerts = await drift_monitor.monitor_data_drift("test_model", drifted_data)
        
        # Verify callback was called
        if alerts:
            assert callback_called
            assert received_alert is not None
            assert received_alert.model_name == "test_model"


@pytest.mark.asyncio
class TestPerformanceTracker:
    """Test cases for PerformanceTracker."""
    
    @pytest_asyncio.fixture(scope="function")
    async def performance_tracker(self):
        """Create a test performance tracker."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'metrics_path': f"{temp_dir}/performance",
                'tracking_window_hours': 24,
                'performance_threshold': 0.1
            }
            
            tracker = PerformanceTracker(config)
            await tracker.initialize()
            await tracker.start()
            
            yield tracker
            
            await tracker.stop()
    
    @pytest.fixture
    def sample_metrics(self):
        """Create sample performance metrics."""
        return PerformanceMetrics(
            model_name="test_model",
            timestamp=datetime.utcnow(),
            accuracy=0.95,
            precision=0.93,
            recall=0.92,
            f1_score=0.925,
            threat_detection_rate=0.88,
            false_positive_rate=0.05,
            response_time_ms=150.0
        )
    
    async def test_performance_recording(self, performance_tracker, sample_metrics):
        """Test performance metrics recording."""
        await performance_tracker.record_performance("test_model", sample_metrics)
        
        # Check that metrics were recorded
        recent_metrics = performance_tracker.get_recent_performance("test_model", hours=1)
        assert len(recent_metrics) == 1
        assert recent_metrics[0].accuracy == 0.95
    
    async def test_baseline_setting(self, performance_tracker, sample_metrics):
        """Test baseline performance setting."""
        await performance_tracker.set_baseline_performance("test_model", sample_metrics)
        
        assert "test_model" in performance_tracker.baseline_performance
        assert performance_tracker.baseline_performance["test_model"].accuracy == 0.95
    
    async def test_performance_degradation_detection(self, performance_tracker, sample_metrics):
        """Test performance degradation detection."""
        # Set baseline
        await performance_tracker.set_baseline_performance("test_model", sample_metrics)
        
        # Create degraded metrics
        degraded_metrics = PerformanceMetrics(
            model_name="test_model",
            timestamp=datetime.utcnow(),
            accuracy=0.80,  # 15.8% degradation
            f1_score=0.78,  # 15.7% degradation
            threat_detection_rate=0.70  # 20.5% degradation
        )
        
        # Record degraded performance (should trigger alerts)
        await performance_tracker.record_performance("test_model", degraded_metrics)
        
        # Check that alerts were generated
        assert performance_tracker.performance_alerts > 0


@pytest.mark.asyncio
class TestDeploymentManager:
    """Test cases for DeploymentManager."""
    
    @pytest_asyncio.fixture(scope="function")
    async def deployment_manager(self):
        """Create a test deployment manager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'deployments_path': f"{temp_dir}/deployments",
                'docker_registry': 'localhost:5000',
                'kubernetes_namespace': 'test',
                'default_strategy': 'canary'
            }
            
            manager = DeploymentManager(config)
            
            # Mock dependencies
            mock_registry = Mock()
            mock_registry.get_model = AsyncMock(return_value=Mock(
                metadata=Mock(
                    model_path="/tmp/model.pkl",
                    config_path="/tmp/config.json",
                    framework="sklearn"
                )
            ))
            manager.set_model_registry(mock_registry)
            
            await manager.initialize()
            await manager.start()
            
            yield manager
            
            await manager.stop()
    
    async def test_deployment_creation(self, deployment_manager):
        """Test deployment creation."""
        deployment_id = await deployment_manager.deploy_model(
            model_name="test_model",
            model_version="1.0.0",
            target_environment="staging",
            strategy=DeploymentStrategy.CANARY
        )
        
        assert deployment_id is not None
        assert deployment_id in deployment_manager.active_deployments
        
        deployment_record = deployment_manager.active_deployments[deployment_id]
        assert deployment_record.config.model_name == "test_model"
        assert deployment_record.config.model_version == "1.0.0"
        assert deployment_record.config.strategy == DeploymentStrategy.CANARY
    
    async def test_deployment_rollback(self, deployment_manager):
        """Test deployment rollback."""
        # Create deployment
        deployment_id = await deployment_manager.deploy_model(
            model_name="test_model",
            model_version="1.0.0",
            target_environment="staging"
        )
        
        # Rollback deployment
        await deployment_manager.rollback_deployment(deployment_id, "Test rollback")
        
        deployment_record = deployment_manager.active_deployments[deployment_id]
        assert deployment_record.status == DeploymentStatus.ROLLED_BACK
        assert deployment_record.rollback_reason == "Test rollback"


@pytest.mark.asyncio
class TestCICDPipeline:
    """Test cases for CICDPipeline."""
    
    @pytest_asyncio.fixture(scope="function")
    async def cicd_pipeline(self):
        """Create a test CI/CD pipeline."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'pipelines_path': f"{temp_dir}/pipelines",
                'builds_path': f"{temp_dir}/builds",
                'max_concurrent_builds': 2
            }
            
            pipeline = CICDPipeline(config)
            await pipeline.initialize()
            await pipeline.start()
            
            yield pipeline
            
            await pipeline.stop()
    
    @pytest.fixture
    def sample_pipeline_config(self):
        """Create sample pipeline configuration."""
        return PipelineConfig(
            pipeline_name="test_pipeline",
            model_name="test_model",
            model_version="1.0.0",
            run_tests=False,  # Skip tests for unit testing
            auto_deploy=False,  # Skip deployment for unit testing
            registry_url="localhost:5000"
        )
    
    async def test_pipeline_config_creation(self, cicd_pipeline, sample_pipeline_config):
        """Test pipeline configuration creation."""
        await cicd_pipeline.create_pipeline_config(sample_pipeline_config)
        
        assert "test_pipeline" in cicd_pipeline.pipeline_configs
        config = cicd_pipeline.pipeline_configs["test_pipeline"]
        assert config.model_name == "test_model"
        assert config.model_version == "1.0.0"
    
    async def test_pipeline_trigger(self, cicd_pipeline, sample_pipeline_config):
        """Test pipeline triggering."""
        # Create pipeline config
        await cicd_pipeline.create_pipeline_config(sample_pipeline_config)
        
        run_id = await cicd_pipeline.trigger_pipeline("test_pipeline")
        
        assert run_id is not None
        assert run_id in cicd_pipeline.active_runs
        
        pipeline_run = cicd_pipeline.active_runs[run_id]
        assert pipeline_run.config.model_name == "test_model"
        assert pipeline_run.status == PipelineStatus.PENDING
    
    async def test_pipeline_cancellation(self, cicd_pipeline, sample_pipeline_config):
        """Test pipeline cancellation."""
        # Create and trigger pipeline
        await cicd_pipeline.create_pipeline_config(sample_pipeline_config)
        
        run_id = await cicd_pipeline.trigger_pipeline("test_pipeline")
        
        # Cancel pipeline
        await cicd_pipeline.cancel_pipeline_run(run_id)
        
        # Check that pipeline was cancelled
        assert run_id not in cicd_pipeline.active_runs
        
        # Find in history
        cancelled_run = None
        for run in cicd_pipeline.run_history:
            if run.run_id == run_id:
                cancelled_run = run
                break
        
        assert cancelled_run is not None
        assert cancelled_run.status == PipelineStatus.CANCELLED


# Integration tests
@pytest.mark.asyncio
class TestMLOpsIntegration:
    """Integration tests for MLOps components."""
    
    @pytest_asyncio.fixture(scope="function")
    async def mlops_system(self):
        """Create integrated MLOps system."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Model Registry
            registry_config = {
                'registry_path': f"{temp_dir}/registry",
                'models_path': f"{temp_dir}/models"
            }
            model_registry = ModelRegistry(registry_config)
            
            # Drift Monitor
            drift_config = {
                'alerts_path': f"{temp_dir}/alerts",
                'metrics_path': f"{temp_dir}/metrics"
            }
            drift_monitor = DriftMonitor(drift_config)
            
            # Performance Tracker
            perf_config = {
                'metrics_path': f"{temp_dir}/performance"
            }
            performance_tracker = PerformanceTracker(perf_config)
            
            # Deployment Manager
            deploy_config = {
                'deployments_path': f"{temp_dir}/deployments"
            }
            deployment_manager = DeploymentManager(deploy_config)
            deployment_manager.set_model_registry(model_registry)
            deployment_manager.set_performance_tracker(performance_tracker)
            
            # CI/CD Pipeline
            cicd_config = {
                'pipelines_path': f"{temp_dir}/pipelines",
                'builds_path': f"{temp_dir}/builds"
            }
            cicd_pipeline = CICDPipeline(cicd_config)
            cicd_pipeline.set_model_registry(model_registry)
            cicd_pipeline.set_deployment_manager(deployment_manager)
            
            # Initialize all components
            await model_registry.initialize()
            await drift_monitor.initialize()
            await performance_tracker.initialize()
            await deployment_manager.initialize()
            await cicd_pipeline.initialize()
            
            # Start all components
            await model_registry.start()
            await drift_monitor.start()
            await performance_tracker.start()
            await deployment_manager.start()
            await cicd_pipeline.start()
            
            yield {
                'model_registry': model_registry,
                'drift_monitor': drift_monitor,
                'performance_tracker': performance_tracker,
                'deployment_manager': deployment_manager,
                'cicd_pipeline': cicd_pipeline
            }
            
            # Stop all components
            await cicd_pipeline.stop()
            await deployment_manager.stop()
            await performance_tracker.stop()
            await drift_monitor.stop()
            await model_registry.stop()
    
    async def test_end_to_end_workflow(self, mlops_system):
        """Test end-to-end MLOps workflow."""
        registry = mlops_system['model_registry']
        drift_monitor = mlops_system['drift_monitor']
        performance_tracker = mlops_system['performance_tracker']
        
        # 1. Register a model
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        X = np.random.rand(100, 4)
        y = np.random.randint(0, 2, 100)
        model.fit(X, y)
        
        metadata = ModelMetadata(
            name="integration_test_model",
            version="1.0.0",
            model_type=ModelType.SUPERVISED,
            framework="sklearn",
            created_at=datetime.utcnow(),
            created_by="integration_test",
            description="Integration test model",
            tags=["test"],
            training_metrics={"accuracy": 0.95},
            validation_metrics={"accuracy": 0.93},
            model_path="",
            config_path=""
        )
        
        model_version = await registry.register_model(
            model_name="integration_test_model",
            model_version="1.0.0",
            model_artifact=model,
            metadata=metadata
        )
        
        assert model_version is not None
        
        # 2. Set up drift monitoring
        baseline_data = pd.DataFrame({
            'feature1': np.random.normal(0, 1, 200),
            'feature2': np.random.normal(5, 2, 200)
        })
        
        await drift_monitor.update_baseline("integration_test_model", baseline_data)
        
        # 3. Record performance metrics
        metrics = PerformanceMetrics(
            model_name="integration_test_model",
            timestamp=datetime.utcnow(),
            accuracy=0.95,
            f1_score=0.92
        )
        
        await performance_tracker.record_performance("integration_test_model", metrics)
        await performance_tracker.set_baseline_performance("integration_test_model", metrics)
        
        # 4. Verify all components are working
        assert "integration_test_model" in registry.list_models()
        assert "integration_test_model" in drift_monitor.baseline_data
        assert "integration_test_model" in performance_tracker.baseline_performance
        
        # 5. Test health checks
        registry_health = await registry.health_check()
        drift_health = await drift_monitor.health_check()
        perf_health = await performance_tracker.health_check()
        
        assert registry_health['initialized']
        assert registry_health['running']
        assert drift_health['initialized']
        assert drift_health['running']
        assert perf_health['initialized']
        assert perf_health['running']