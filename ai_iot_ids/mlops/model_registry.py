"""
Model registry and versioning system for MLOps pipeline.

This module provides comprehensive model lifecycle management including
versioning, metadata tracking, deployment capabilities, and rollback support.
"""

from typing import Dict, List, Optional, Any, Union
import logging
import json
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import pickle
import joblib
import asyncio
import aiofiles
from packaging import version

from ..interfaces.base import BaseInterface
from ..utils.error_handling import MLOpsError, ValidationError


class ModelStatus(Enum):
    """Model deployment status."""
    REGISTERED = "registered"
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"


class ModelType(Enum):
    """Model type classification."""
    UNSUPERVISED = "unsupervised"
    SUPERVISED = "supervised"
    SEQUENCE = "sequence"
    ENSEMBLE = "ensemble"


@dataclass
class ModelMetadata:
    """Model metadata container."""
    name: str
    version: str
    model_type: ModelType
    framework: str  # sklearn, xgboost, tensorflow, pytorch, etc.
    created_at: datetime
    created_by: str
    description: str
    tags: List[str]
    
    # Model artifacts
    model_path: str
    config_path: str
    
    # Performance metrics
    training_metrics: Dict[str, float]
    validation_metrics: Dict[str, float]
    
    # Optional fields with defaults
    test_metrics: Optional[Dict[str, float]] = None
    requirements_path: Optional[str] = None
    status: ModelStatus = ModelStatus.REGISTERED
    deployment_config: Optional[Dict[str, Any]] = None
    parent_models: List[str] = None
    training_data_hash: Optional[str] = None
    feature_schema: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.parent_models is None:
            self.parent_models = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['model_type'] = self.model_type.value
        data['status'] = self.status.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelMetadata':
        """Create from dictionary."""
        data = data.copy()
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['model_type'] = ModelType(data['model_type'])
        data['status'] = ModelStatus(data['status'])
        return cls(**data)


@dataclass
class ModelVersion:
    """Model version information."""
    version: str
    metadata: ModelMetadata
    checksum: str
    size_bytes: int
    registered_at: datetime
    
    def is_compatible_with(self, other_version: str) -> bool:
        """Check if this version is compatible with another version."""
        try:
            current = version.parse(self.version)
            other = version.parse(other_version)
            
            # Compatible if major version is the same
            return current.major == other.major
        except Exception:
            return False
    
    def is_newer_than(self, other_version: str) -> bool:
        """Check if this version is newer than another version."""
        try:
            current = version.parse(self.version)
            other = version.parse(other_version)
            return current > other
        except Exception:
            return False


class ModelRegistry(BaseInterface):
    """
    Comprehensive model registry with versioning and metadata tracking.
    
    Provides model storage, versioning, metadata management, and deployment
    capabilities for the MLOps pipeline.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the model registry.
        
        Args:
            config: Registry configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.registry_path = Path(config.get('registry_path', 'models/registry'))
        self.models_path = Path(config.get('models_path', 'models/artifacts'))
        self.metadata_file = self.registry_path / 'metadata.json'
        self.max_versions_per_model = config.get('max_versions_per_model', 10)
        self.auto_cleanup = config.get('auto_cleanup', True)
        self.backup_enabled = config.get('backup_enabled', True)
        
        # Internal state
        self.models: Dict[str, Dict[str, ModelVersion]] = {}  # model_name -> {version -> ModelVersion}
        self.production_models: Dict[str, str] = {}  # model_name -> production_version
        self.staging_models: Dict[str, str] = {}  # model_name -> staging_version
        
        # Statistics
        self.registration_count = 0
        self.deployment_count = 0
        self.rollback_count = 0
        
        # Create directories
        self.registry_path.mkdir(parents=True, exist_ok=True)
        self.models_path.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize the model registry."""
        try:
            # Load existing metadata
            await self._load_metadata()
            
            # Validate model artifacts
            await self._validate_artifacts()
            
            # Cleanup old versions if enabled
            if self.auto_cleanup:
                await self._cleanup_old_versions()
            
            self._initialized = True
            self.log_info(f"Model registry initialized with {len(self.models)} models")
            
        except Exception as e:
            self.log_error("Failed to initialize model registry", e)
            raise MLOpsError(f"Registry initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the model registry service."""
        if not self._initialized:
            await self.initialize()
        
        self._running = True
        self.log_info("Model registry started")
    
    async def stop(self) -> None:
        """Stop the model registry and save metadata."""
        self._running = False
        
        # Save metadata
        await self._save_metadata()
        
        self.log_info("Model registry stopped")
    
    async def register_model(
        self,
        model_name: str,
        model_version: str,
        model_artifact: Any,
        metadata: ModelMetadata,
        config: Optional[Dict[str, Any]] = None,
        requirements: Optional[List[str]] = None
    ) -> ModelVersion:
        """
        Register a new model version.
        
        Args:
            model_name: Name of the model
            model_version: Version string (semantic versioning)
            model_artifact: Trained model object
            metadata: Model metadata
            config: Optional model configuration
            requirements: Optional Python requirements
            
        Returns:
            ModelVersion object
        """
        if not self._running:
            raise MLOpsError("Registry is not running")
        
        try:
            # Validate version format
            version.parse(model_version)
        except Exception as e:
            raise ValidationError(f"Invalid version format: {model_version}")
        
        # Check if version already exists
        if model_name in self.models and model_version in self.models[model_name]:
            raise ValidationError(f"Model {model_name} version {model_version} already exists")
        
        try:
            # Create model directory
            model_dir = self.models_path / model_name / model_version
            model_dir.mkdir(parents=True, exist_ok=True)
            
            # Save model artifact
            model_path = model_dir / 'model.pkl'
            await self._save_model_artifact(model_artifact, model_path)
            
            # Save configuration
            config_path = model_dir / 'config.json'
            if config:
                async with aiofiles.open(config_path, 'w') as f:
                    await f.write(json.dumps(config, indent=2))
            
            # Save requirements
            requirements_path = None
            if requirements:
                requirements_path = model_dir / 'requirements.txt'
                async with aiofiles.open(requirements_path, 'w') as f:
                    await f.write('\n'.join(requirements))
            
            # Calculate checksum
            checksum = await self._calculate_checksum(model_path)
            
            # Get file size
            size_bytes = model_path.stat().st_size
            
            # Update metadata paths
            metadata.model_path = str(model_path)
            metadata.config_path = str(config_path)
            metadata.requirements_path = str(requirements_path) if requirements_path else None
            
            # Create model version
            model_version_obj = ModelVersion(
                version=model_version,
                metadata=metadata,
                checksum=checksum,
                size_bytes=size_bytes,
                registered_at=datetime.utcnow()
            )
            
            # Store in registry
            if model_name not in self.models:
                self.models[model_name] = {}
            
            self.models[model_name][model_version] = model_version_obj
            
            # Save metadata
            await self._save_metadata()
            
            # Cleanup old versions if needed
            if self.auto_cleanup:
                await self._cleanup_model_versions(model_name)
            
            self.registration_count += 1
            self.log_info(f"Registered model {model_name} version {model_version}")
            
            return model_version_obj
            
        except Exception as e:
            self.log_error(f"Failed to register model {model_name} version {model_version}", e)
            raise MLOpsError(f"Model registration failed: {e}")
    
    async def get_model(self, model_name: str, model_version: Optional[str] = None) -> Optional[ModelVersion]:
        """
        Get a specific model version.
        
        Args:
            model_name: Name of the model
            model_version: Version string (latest if None)
            
        Returns:
            ModelVersion object or None if not found
        """
        if model_name not in self.models:
            return None
        
        if model_version is None:
            # Get latest version
            model_version = self.get_latest_version(model_name)
            if model_version is None:
                return None
        
        return self.models[model_name].get(model_version)
    
    async def load_model_artifact(self, model_name: str, model_version: Optional[str] = None) -> Any:
        """
        Load model artifact from storage.
        
        Args:
            model_name: Name of the model
            model_version: Version string (latest if None)
            
        Returns:
            Loaded model artifact
        """
        model_version_obj = await self.get_model(model_name, model_version)
        if model_version_obj is None:
            raise MLOpsError(f"Model {model_name} version {model_version} not found")
        
        try:
            model_path = Path(model_version_obj.metadata.model_path)
            return await self._load_model_artifact(model_path)
        except Exception as e:
            self.log_error(f"Failed to load model {model_name} version {model_version}", e)
            raise MLOpsError(f"Model loading failed: {e}")
    
    async def promote_to_staging(self, model_name: str, model_version: str) -> None:
        """
        Promote a model version to staging.
        
        Args:
            model_name: Name of the model
            model_version: Version to promote
        """
        model_version_obj = await self.get_model(model_name, model_version)
        if model_version_obj is None:
            raise MLOpsError(f"Model {model_name} version {model_version} not found")
        
        # Update status
        model_version_obj.metadata.status = ModelStatus.STAGING
        self.staging_models[model_name] = model_version
        
        # Save metadata
        await self._save_metadata()
        
        self.log_info(f"Promoted model {model_name} version {model_version} to staging")
    
    async def promote_to_production(self, model_name: str, model_version: str) -> None:
        """
        Promote a model version to production.
        
        Args:
            model_name: Name of the model
            model_version: Version to promote
        """
        model_version_obj = await self.get_model(model_name, model_version)
        if model_version_obj is None:
            raise MLOpsError(f"Model {model_name} version {model_version} not found")
        
        # Demote current production model if exists
        if model_name in self.production_models:
            old_version = self.production_models[model_name]
            old_model = await self.get_model(model_name, old_version)
            if old_model:
                old_model.metadata.status = ModelStatus.ARCHIVED
        
        # Update status
        model_version_obj.metadata.status = ModelStatus.PRODUCTION
        self.production_models[model_name] = model_version
        
        # Save metadata
        await self._save_metadata()
        
        self.deployment_count += 1
        self.log_info(f"Promoted model {model_name} version {model_version} to production")
    
    async def rollback_model(self, model_name: str, target_version: Optional[str] = None) -> str:
        """
        Rollback a model to a previous version.
        
        Args:
            model_name: Name of the model
            target_version: Version to rollback to (previous production if None)
            
        Returns:
            Version that was rolled back to
        """
        if model_name not in self.models:
            raise MLOpsError(f"Model {model_name} not found")
        
        if target_version is None:
            # Find previous production version
            production_versions = [
                v for v, mv in self.models[model_name].items()
                if mv.metadata.status == ModelStatus.ARCHIVED
            ]
            
            if not production_versions:
                raise MLOpsError(f"No previous production version found for {model_name}")
            
            # Get latest archived version
            production_versions.sort(key=lambda v: version.parse(v), reverse=True)
            target_version = production_versions[0]
        
        # Promote target version to production
        await self.promote_to_production(model_name, target_version)
        
        self.rollback_count += 1
        self.log_info(f"Rolled back model {model_name} to version {target_version}")
        
        return target_version
    
    async def delete_model_version(self, model_name: str, model_version: str) -> None:
        """
        Delete a specific model version.
        
        Args:
            model_name: Name of the model
            model_version: Version to delete
        """
        if model_name not in self.models or model_version not in self.models[model_name]:
            raise MLOpsError(f"Model {model_name} version {model_version} not found")
        
        model_version_obj = self.models[model_name][model_version]
        
        # Prevent deletion of production models
        if model_version_obj.metadata.status == ModelStatus.PRODUCTION:
            raise MLOpsError("Cannot delete production model version")
        
        try:
            # Delete model directory
            model_dir = Path(model_version_obj.metadata.model_path).parent
            if model_dir.exists():
                shutil.rmtree(model_dir)
            
            # Remove from registry
            del self.models[model_name][model_version]
            
            # Remove from staging if applicable
            if self.staging_models.get(model_name) == model_version:
                del self.staging_models[model_name]
            
            # Save metadata
            await self._save_metadata()
            
            self.log_info(f"Deleted model {model_name} version {model_version}")
            
        except Exception as e:
            self.log_error(f"Failed to delete model {model_name} version {model_version}", e)
            raise MLOpsError(f"Model deletion failed: {e}")
    
    def list_models(self) -> List[str]:
        """List all registered model names."""
        return list(self.models.keys())
    
    def list_versions(self, model_name: str) -> List[str]:
        """List all versions of a model."""
        if model_name not in self.models:
            return []
        
        versions = list(self.models[model_name].keys())
        versions.sort(key=lambda v: version.parse(v), reverse=True)
        return versions
    
    def get_latest_version(self, model_name: str) -> Optional[str]:
        """Get the latest version of a model."""
        versions = self.list_versions(model_name)
        return versions[0] if versions else None
    
    def get_production_version(self, model_name: str) -> Optional[str]:
        """Get the production version of a model."""
        return self.production_models.get(model_name)
    
    def get_staging_version(self, model_name: str) -> Optional[str]:
        """Get the staging version of a model."""
        return self.staging_models.get(model_name)
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the model registry.
        
        Returns:
            Dictionary containing registry health status
        """
        model_counts = {}
        for model_name, versions in self.models.items():
            model_counts[model_name] = {
                'total_versions': len(versions),
                'production_version': self.get_production_version(model_name),
                'staging_version': self.get_staging_version(model_name),
                'latest_version': self.get_latest_version(model_name)
            }
        
        return {
            'initialized': self._initialized,
            'running': self._running,
            'total_models': len(self.models),
            'production_models': len(self.production_models),
            'staging_models': len(self.staging_models),
            'registration_count': self.registration_count,
            'deployment_count': self.deployment_count,
            'rollback_count': self.rollback_count,
            'model_counts': model_counts,
            'registry_path': str(self.registry_path),
            'models_path': str(self.models_path)
        }
    
    async def _load_metadata(self) -> None:
        """Load metadata from disk."""
        if not self.metadata_file.exists():
            self.log_info("No existing metadata found, starting with empty registry")
            return
        
        try:
            async with aiofiles.open(self.metadata_file, 'r') as f:
                content = await f.read()
                data = json.loads(content)
            
            # Load models
            for model_name, versions_data in data.get('models', {}).items():
                self.models[model_name] = {}
                for version_str, version_data in versions_data.items():
                    metadata = ModelMetadata.from_dict(version_data['metadata'])
                    model_version = ModelVersion(
                        version=version_str,
                        metadata=metadata,
                        checksum=version_data['checksum'],
                        size_bytes=version_data['size_bytes'],
                        registered_at=datetime.fromisoformat(version_data['registered_at'])
                    )
                    self.models[model_name][version_str] = model_version
            
            # Load deployment status
            self.production_models = data.get('production_models', {})
            self.staging_models = data.get('staging_models', {})
            
            # Load statistics
            self.registration_count = data.get('registration_count', 0)
            self.deployment_count = data.get('deployment_count', 0)
            self.rollback_count = data.get('rollback_count', 0)
            
            self.log_info(f"Loaded metadata for {len(self.models)} models")
            
        except Exception as e:
            self.log_error("Failed to load metadata", e)
            raise MLOpsError(f"Metadata loading failed: {e}")
    
    async def _save_metadata(self) -> None:
        """Save metadata to disk."""
        try:
            # Prepare data for serialization
            models_data = {}
            for model_name, versions in self.models.items():
                models_data[model_name] = {}
                for version_str, model_version in versions.items():
                    models_data[model_name][version_str] = {
                        'metadata': model_version.metadata.to_dict(),
                        'checksum': model_version.checksum,
                        'size_bytes': model_version.size_bytes,
                        'registered_at': model_version.registered_at.isoformat()
                    }
            
            data = {
                'models': models_data,
                'production_models': self.production_models,
                'staging_models': self.staging_models,
                'registration_count': self.registration_count,
                'deployment_count': self.deployment_count,
                'rollback_count': self.rollback_count,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            # Create backup if enabled
            if self.backup_enabled and self.metadata_file.exists():
                backup_file = self.metadata_file.with_suffix('.json.bak')
                shutil.copy2(self.metadata_file, backup_file)
            
            # Write metadata
            async with aiofiles.open(self.metadata_file, 'w') as f:
                await f.write(json.dumps(data, indent=2))
            
        except Exception as e:
            self.log_error("Failed to save metadata", e)
            raise MLOpsError(f"Metadata saving failed: {e}")
    
    async def _save_model_artifact(self, model_artifact: Any, model_path: Path) -> None:
        """Save model artifact to disk."""
        try:
            # Try different serialization methods based on model type
            if hasattr(model_artifact, 'save'):
                # TensorFlow/Keras models
                model_artifact.save(str(model_path.with_suffix('')))
            elif hasattr(model_artifact, 'save_model'):
                # XGBoost/LightGBM models
                model_artifact.save_model(str(model_path))
            else:
                # Use joblib for sklearn and other models
                await asyncio.get_event_loop().run_in_executor(
                    None, joblib.dump, model_artifact, str(model_path)
                )
        except Exception as e:
            self.log_error(f"Failed to save model artifact to {model_path}", e)
            raise
    
    async def _load_model_artifact(self, model_path: Path) -> Any:
        """Load model artifact from disk."""
        try:
            if model_path.is_dir():
                # TensorFlow/Keras model directory
                import tensorflow as tf
                return tf.keras.models.load_model(str(model_path))
            else:
                # Use joblib for other models
                return await asyncio.get_event_loop().run_in_executor(
                    None, joblib.load, str(model_path)
                )
        except Exception as e:
            self.log_error(f"Failed to load model artifact from {model_path}", e)
            raise
    
    async def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of a file."""
        hash_sha256 = hashlib.sha256()
        
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                hash_sha256.update(chunk)
        
        return hash_sha256.hexdigest()
    
    async def _validate_artifacts(self) -> None:
        """Validate that all registered model artifacts exist."""
        invalid_models = []
        
        for model_name, versions in self.models.items():
            for version_str, model_version in versions.items():
                model_path = Path(model_version.metadata.model_path)
                if not model_path.exists():
                    invalid_models.append((model_name, version_str))
                    self.log_warning(f"Model artifact missing: {model_path}")
        
        # Remove invalid models
        for model_name, version_str in invalid_models:
            del self.models[model_name][version_str]
            if not self.models[model_name]:
                del self.models[model_name]
        
        if invalid_models:
            self.log_warning(f"Removed {len(invalid_models)} invalid model entries")
    
    async def _cleanup_old_versions(self) -> None:
        """Cleanup old model versions based on retention policy."""
        for model_name in list(self.models.keys()):
            await self._cleanup_model_versions(model_name)
    
    async def _cleanup_model_versions(self, model_name: str) -> None:
        """Cleanup old versions of a specific model."""
        if model_name not in self.models:
            return
        
        versions = self.list_versions(model_name)
        
        if len(versions) <= self.max_versions_per_model:
            return
        
        # Keep production, staging, and latest versions
        protected_versions = set()
        
        if model_name in self.production_models:
            protected_versions.add(self.production_models[model_name])
        
        if model_name in self.staging_models:
            protected_versions.add(self.staging_models[model_name])
        
        # Keep the latest version
        if versions:
            protected_versions.add(versions[0])
        
        # Remove old versions
        versions_to_remove = versions[self.max_versions_per_model:]
        for version_str in versions_to_remove:
            if version_str not in protected_versions:
                try:
                    await self.delete_model_version(model_name, version_str)
                    self.log_info(f"Cleaned up old version {model_name}:{version_str}")
                except Exception as e:
                    self.log_error(f"Failed to cleanup version {model_name}:{version_str}", e)