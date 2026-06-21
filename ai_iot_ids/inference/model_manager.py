"""
Model management and versioning infrastructure for ML models.

This module provides model loading, versioning, hot-swapping,
and lifecycle management capabilities for the AI inference service.
"""

from typing import Dict, List, Optional, Any, Union, Type
import logging
import asyncio
from pathlib import Path
from datetime import datetime
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
import threading

from ..interfaces.base import BaseInterface
from .base_model import BaseMLModel, UnsupervisedModel, SupervisedModel, SequenceModel
from .feature_preprocessor import FeaturePreprocessor
from ..models.network_flow import NetworkFlow
from ..models.threat_detection import MLPrediction


class ModelRegistry:
    """
    Registry for tracking model metadata and versions.
    """
    
    def __init__(self):
        self.models = {}  # model_name -> model_info
        self.versions = {}  # model_name -> {version -> version_info}
    
    def register_model(self, model_name: str, model_info: Dict[str, Any]) -> None:
        """Register a new model in the registry."""
        self.models[model_name] = model_info
        if model_name not in self.versions:
            self.versions[model_name] = {}
    
    def register_version(self, model_name: str, version: str, version_info: Dict[str, Any]) -> None:
        """Register a new version of a model."""
        if model_name not in self.versions:
            self.versions[model_name] = {}
        self.versions[model_name][version] = version_info
    
    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get model information."""
        return self.models.get(model_name)
    
    def get_version_info(self, model_name: str, version: str) -> Optional[Dict[str, Any]]:
        """Get version information."""
        return self.versions.get(model_name, {}).get(version)
    
    def get_latest_version(self, model_name: str) -> Optional[str]:
        """Get the latest version of a model."""
        if model_name not in self.versions:
            return None
        
        versions = list(self.versions[model_name].keys())
        if not versions:
            return None
        
        # Simple version sorting (assumes semantic versioning)
        versions.sort(key=lambda v: [int(x) for x in v.split('.')])
        return versions[-1]
    
    def list_models(self) -> List[str]:
        """List all registered models."""
        return list(self.models.keys())
    
    def list_versions(self, model_name: str) -> List[str]:
        """List all versions of a model."""
        return list(self.versions.get(model_name, {}).keys())


class ModelManager(BaseInterface):
    """
    Model manager for loading, versioning, and managing ML models.
    
    Provides centralized model lifecycle management including loading,
    hot-swapping, version control, and health monitoring.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the model manager.
        
        Args:
            config: Model manager configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.model_registry_path = config.get('model_registry_path', 'models/registry.json')
        self.model_base_path = config.get('model_base_path', 'models/')
        self.max_concurrent_models = config.get('max_concurrent_models', 5)
        self.model_timeout_seconds = config.get('model_timeout_seconds', 30)
        self.enable_hot_swapping = config.get('enable_hot_swapping', True)
        
        # Model registry and storage
        self.registry = ModelRegistry()
        self.loaded_models: Dict[str, BaseMLModel] = {}
        self.model_configs: Dict[str, Dict[str, Any]] = {}
        self.preprocessor: Optional[FeaturePreprocessor] = None
        
        # Threading and concurrency
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_models)
        self.model_locks: Dict[str, threading.Lock] = {}
        self.loading_status: Dict[str, str] = {}  # model_name -> status
        
        # Statistics
        self.load_count = 0
        self.inference_count = 0
        self.error_count = 0
        self.last_registry_update = None
    
    async def initialize(self) -> None:
        """Initialize the model manager."""
        try:
            # Load model registry
            await self._load_registry()
            
            # Initialize feature preprocessor
            preprocessor_config = self.config.get('preprocessor', {})
            self.preprocessor = FeaturePreprocessor(preprocessor_config, self.logger)
            await self.preprocessor.initialize()
            
            # Load default models if configured
            default_models = self.config.get('default_models', [])
            for model_config in default_models:
                await self.load_model(model_config['name'], model_config)
            
            self._initialized = True
            self.log_info("Model manager initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize model manager", e)
            raise
    
    async def start(self) -> None:
        """Start the model manager service."""
        if not self._initialized:
            await self.initialize()
        
        # Start preprocessor
        if self.preprocessor:
            await self.preprocessor.start()
        
        self._running = True
        self.log_info("Model manager started")
    
    async def stop(self) -> None:
        """Stop the model manager and clean up resources."""
        self._running = False
        
        # Stop all loaded models
        for model_name in list(self.loaded_models.keys()):
            await self.unload_model(model_name)
        
        # Stop preprocessor
        if self.preprocessor:
            await self.preprocessor.stop()
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.log_info("Model manager stopped")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the model manager.
        
        Returns:
            Dictionary containing model manager health status
        """
        model_health = {}
        for model_name, model in self.loaded_models.items():
            try:
                model_health[model_name] = await model.health_check()
            except Exception as e:
                model_health[model_name] = {'error': str(e)}
        
        return {
            'initialized': self._initialized,
            'running': self._running,
            'loaded_models_count': len(self.loaded_models),
            'registered_models_count': len(self.registry.list_models()),
            'preprocessor_health': await self.preprocessor.health_check() if self.preprocessor else None,
            'load_count': self.load_count,
            'inference_count': self.inference_count,
            'error_count': self.error_count,
            'last_registry_update': self.last_registry_update.isoformat() if self.last_registry_update else None,
            'model_health': model_health
        }
    
    async def load_model(self, model_name: str, model_config: Dict[str, Any]) -> None:
        """
        Load a model into memory.
        
        Args:
            model_name: Name of the model to load
            model_config: Model configuration
        """
        if model_name in self.loading_status:
            raise RuntimeError(f"Model {model_name} is already being loaded")
        
        try:
            self.loading_status[model_name] = 'loading'
            self.log_info(f"Loading model {model_name}")
            
            # Create model lock
            if model_name not in self.model_locks:
                self.model_locks[model_name] = threading.Lock()
            
            # Determine model class and create instance
            model_type = model_config.get('type', 'unsupervised')
            model_class = self._get_model_class(model_name)
            
            # Create model instance
            model = model_class(model_config, self.logger)
            
            # Initialize and start model
            await model.initialize()
            await model.start()
            
            # Store model and config
            self.loaded_models[model_name] = model
            self.model_configs[model_name] = model_config
            
            # Register in registry
            model_info = {
                'name': model_name,
                'type': model_type,
                'version': model_config.get('model_version', '1.0.0'),
                'loaded_at': datetime.utcnow().isoformat(),
                'config': model_config
            }
            self.registry.register_model(model_name, model_info)
            
            self.load_count += 1
            self.loading_status.pop(model_name, None)
            self.log_info(f"Model {model_name} loaded successfully")
            
        except Exception as e:
            self.loading_status.pop(model_name, None)
            self.error_count += 1
            self.log_error(f"Failed to load model {model_name}", e)
            raise
    
    async def unload_model(self, model_name: str) -> None:
        """
        Unload a model from memory.
        
        Args:
            model_name: Name of the model to unload
        """
        if model_name not in self.loaded_models:
            self.log_warning(f"Model {model_name} is not loaded")
            return
        
        try:
            model = self.loaded_models[model_name]
            await model.stop()
            
            # Remove from loaded models
            del self.loaded_models[model_name]
            del self.model_configs[model_name]
            
            # Remove lock
            if model_name in self.model_locks:
                del self.model_locks[model_name]
            
            self.log_info(f"Model {model_name} unloaded successfully")
            
        except Exception as e:
            self.error_count += 1
            self.log_error(f"Failed to unload model {model_name}", e)
            raise
    
    async def reload_model(self, model_name: str, new_config: Optional[Dict[str, Any]] = None) -> None:
        """
        Reload a model with optional new configuration.
        
        Args:
            model_name: Name of the model to reload
            new_config: Optional new configuration
        """
        if model_name not in self.loaded_models:
            raise ValueError(f"Model {model_name} is not loaded")
        
        # Use existing config if no new config provided
        config = new_config or self.model_configs[model_name]
        
        # Unload and reload
        await self.unload_model(model_name)
        await self.load_model(model_name, config)
        
        self.log_info(f"Model {model_name} reloaded successfully")
    
    async def predict(self, model_name: str, flows: List[NetworkFlow]) -> MLPrediction:
        """
        Generate predictions using a specific model.
        
        Args:
            model_name: Name of the model to use
            flows: List of network flows to analyze
            
        Returns:
            MLPrediction from the specified model
        """
        if model_name not in self.loaded_models:
            raise ValueError(f"Model {model_name} is not loaded")
        
        try:
            model = self.loaded_models[model_name]
            
            # Preprocess features if preprocessor is available
            if self.preprocessor and self.preprocessor.is_fitted:
                features = await self.preprocessor.transform(flows)
            else:
                # Convert flows to basic feature format
                features = self._flows_to_basic_features(flows)
            
            # Generate prediction
            prediction = await model.predict(features)
            
            self.inference_count += 1
            return prediction
            
        except Exception as e:
            self.error_count += 1
            self.log_error(f"Prediction failed for model {model_name}", e)
            raise
    
    async def predict_ensemble(self, flows: List[NetworkFlow], model_names: Optional[List[str]] = None) -> List[MLPrediction]:
        """
        Generate predictions using multiple models (ensemble).
        
        Args:
            flows: List of network flows to analyze
            model_names: Optional list of model names to use (uses all if None)
            
        Returns:
            List of MLPredictions from all specified models
        """
        if model_names is None:
            model_names = list(self.loaded_models.keys())
        
        if not model_names:
            raise ValueError("No models available for ensemble prediction")
        
        predictions = []
        
        # Run predictions concurrently
        tasks = []
        for model_name in model_names:
            if model_name in self.loaded_models:
                task = self.predict(model_name, flows)
                tasks.append(task)
        
        if not tasks:
            raise ValueError("No valid models found for ensemble prediction")
        
        # Wait for all predictions
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and collect valid predictions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.log_error(f"Ensemble prediction failed for model {model_names[i]}", result)
            else:
                predictions.append(result)
        
        if not predictions:
            raise RuntimeError("All ensemble predictions failed")
        
        return predictions
    
    def get_loaded_models(self) -> List[str]:
        """Get list of currently loaded model names."""
        return list(self.loaded_models.keys())
    
    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific model."""
        if model_name in self.loaded_models:
            model = self.loaded_models[model_name]
            return model.get_model_info()
        return self.registry.get_model_info(model_name)
    
    def is_model_loaded(self, model_name: str) -> bool:
        """Check if a model is currently loaded."""
        return model_name in self.loaded_models
    
    async def _load_registry(self) -> None:
        """Load model registry from disk."""
        registry_path = Path(self.model_registry_path)
        
        if registry_path.exists():
            try:
                with open(registry_path, 'r') as f:
                    registry_data = json.load(f)
                
                # Load models and versions
                for model_name, model_info in registry_data.get('models', {}).items():
                    self.registry.register_model(model_name, model_info)
                
                for model_name, versions in registry_data.get('versions', {}).items():
                    for version, version_info in versions.items():
                        self.registry.register_version(model_name, version, version_info)
                
                self.last_registry_update = datetime.utcnow()
                self.log_info(f"Model registry loaded from {registry_path}")
                
            except Exception as e:
                self.log_error(f"Failed to load registry from {registry_path}", e)
                # Continue with empty registry
        else:
            self.log_info("No existing registry found, starting with empty registry")
    
    async def _save_registry(self) -> None:
        """Save model registry to disk."""
        registry_path = Path(self.model_registry_path)
        registry_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            registry_data = {
                'models': self.registry.models,
                'versions': self.registry.versions,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            with open(registry_path, 'w') as f:
                json.dump(registry_data, f, indent=2)
            
            self.last_registry_update = datetime.utcnow()
            self.log_info(f"Model registry saved to {registry_path}")
            
        except Exception as e:
            self.log_error(f"Failed to save registry to {registry_path}", e)
            raise
    
    def _get_model_class(self, model_name: str) -> Type[BaseMLModel]:
        """
        Get model class based on model name.
        
        Args:
            model_name: Name of the model
            
        Returns:
            Model class
        """
        if model_name == 'isolation_forest':
            from .models.isolation_forest_model import IsolationForestModel
            return IsolationForestModel
        elif model_name == 'xgboost':
            from .models.xgboost_model import XGBoostModel
            return XGBoostModel
        elif model_name == 'catboost':
            from .models.catboost_model import CatBoostModel
            return CatBoostModel
        elif model_name == 'lstm' or model_name == 'gru':
            from .models.sequence_models import LSTMModel
            return LSTMModel # Or GRU if split
        else:
            # Fallback to base classes if type is passed instead of name
            if model_name == 'unsupervised':
                from .models.isolation_forest_model import IsolationForestModel
                return IsolationForestModel
            raise ValueError(f"Unknown model name: {model_name}")
    
    def _flows_to_basic_features(self, flows: List[NetworkFlow]) -> List[Dict[str, Any]]:
        """
        Convert flows to basic feature format when preprocessor is not available.
        
        Args:
            flows: List of NetworkFlow objects
            
        Returns:
            List of feature dictionaries
        """
        features = []
        for flow in flows:
            flow_dict = flow.model_dump()
            # Remove non-numeric fields
            exclude_fields = ['flow_id', 'timestamp', 'source_ip', 'destination_ip', 'tcp_flags']
            for field in exclude_fields:
                flow_dict.pop(field, None)
            
            # Add TCP flags count
            flow_dict['tcp_flags_count'] = len(flow.tcp_flags)
            
            features.append(flow_dict)
        
        return features