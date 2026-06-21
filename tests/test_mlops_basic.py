"""
Basic tests for MLOps pipeline components.

This module tests the basic functionality of MLOps components
without requiring external dependencies.
"""

import pytest
import asyncio
import tempfile
from datetime import datetime
from pathlib import Path

from ai_iot_ids.mlops.model_registry import (
    ModelRegistry, ModelMetadata, ModelStatus, ModelType
)
from ai_iot_ids.mlops.deployment_manager import (
    DeploymentManager, DeploymentStrategy
)


class TestBasicMLOps:
    """Basic tests for MLOps components."""
    
    @pytest.mark.asyncio
    async def test_model_registry_initialization(self):
        """Test model registry initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'registry_path': f"{temp_dir}/registry",
                'models_path': f"{temp_dir}/models"
            }
            
            registry = ModelRegistry(config)
            await registry.initialize()
            await registry.start()
            
            # Test health check
            health = await registry.health_check()
            assert health['initialized']
            assert health['running']
            
            await registry.stop()
    
    @pytest.mark.asyncio
    async def test_deployment_manager_initialization(self):
        """Test deployment manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'deployments_path': f"{temp_dir}/deployments"
            }
            
            manager = DeploymentManager(config)
            await manager.initialize()
            await manager.start()
            
            # Test health check
            health = await manager.health_check()
            assert health['initialized']
            assert health['running']
            
            await manager.stop()
    
    def test_model_metadata_creation(self):
        """Test model metadata creation."""
        metadata = ModelMetadata(
            name="test_model",
            version="1.0.0",
            model_type=ModelType.SUPERVISED,
            framework="sklearn",
            created_at=datetime.utcnow(),
            created_by="test_user",
            description="Test model",
            tags=["test"],
            model_path="/tmp/model.pkl",
            config_path="/tmp/config.json",
            training_metrics={"accuracy": 0.95},
            validation_metrics={"accuracy": 0.93}
        )
        
        assert metadata.name == "test_model"
        assert metadata.version == "1.0.0"
        assert metadata.model_type == ModelType.SUPERVISED
        assert metadata.status == ModelStatus.REGISTERED
        
        # Test serialization
        data = metadata.to_dict()
        assert data['name'] == "test_model"
        assert data['model_type'] == "supervised"
        
        # Test deserialization
        restored = ModelMetadata.from_dict(data)
        assert restored.name == metadata.name
        assert restored.model_type == metadata.model_type


# Run the tests
if __name__ == "__main__":
    async def run_tests():
        test_instance = TestBasicMLOps()
        
        print("Testing model registry initialization...")
        await test_instance.test_model_registry_initialization()
        print("✓ Model registry initialization test passed")
        
        print("Testing deployment manager initialization...")
        await test_instance.test_deployment_manager_initialization()
        print("✓ Deployment manager initialization test passed")
        
        print("Testing model metadata creation...")
        await test_instance.test_model_metadata_creation()
        print("✓ Model metadata creation test passed")
        
        print("\nAll basic MLOps tests passed!")
    
    asyncio.run(run_tests())