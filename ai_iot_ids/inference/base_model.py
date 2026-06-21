"""
Base ML model interfaces and abstract classes for the AI inference service.

This module provides the foundational abstract base classes that all
machine learning models inherit from, ensuring consistent interfaces
for model loading, inference, and lifecycle management.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime
import logging
import numpy as np
import pandas as pd
from pathlib import Path

from ..interfaces.base import BaseInterface
from ..models.network_flow import NetworkFlow
from ..models.threat_detection import MLPrediction


class BaseMLModel(BaseInterface):
    """
    Abstract base class for all ML models in the system.
    
    Provides common functionality for model loading, versioning,
    feature preprocessing, and inference operations.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the base ML model.
        
        Args:
            config: Model configuration including paths, parameters, and metadata
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        self.model_name = config.get('model_name', self.__class__.__name__)
        self.model_version = config.get('model_version', '1.0.0')
        self.model_path = config.get('model_path')
        self.feature_columns = config.get('feature_columns', [])
        self.model = None
        self.metadata = {}
        self.last_inference_time = None
        self.inference_count = 0
    
    @abstractmethod
    async def load_model(self, model_path: Optional[str] = None) -> None:
        """
        Load the ML model from disk or remote storage.
        
        Args:
            model_path: Optional path to model file, uses config path if not provided
        """
        pass
    
    @abstractmethod
    async def predict(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> MLPrediction:
        """
        Generate predictions for input features.
        
        Args:
            features: Input features in various supported formats
            
        Returns:
            MLPrediction object with scores and explanations
        """
        pass
    
    @abstractmethod
    async def validate_features(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> bool:
        """
        Validate that input features match model expectations.
        
        Args:
            features: Input features to validate
            
        Returns:
            True if features are valid, False otherwise
        """
        pass
    
    async def initialize(self) -> None:
        """Initialize the model by loading it from storage."""
        try:
            await self.load_model()
            self._initialized = True
            self.log_info(f"Model {self.model_name} v{self.model_version} initialized successfully")
        except Exception as e:
            self.log_error(f"Failed to initialize model {self.model_name}", e)
            raise
    
    async def start(self) -> None:
        """Start the model service."""
        if not self._initialized:
            await self.initialize()
        self._running = True
        self.log_info(f"Model {self.model_name} started")
    
    async def stop(self) -> None:
        """Stop the model service and clean up resources."""
        self._running = False
        self.model = None
        self.log_info(f"Model {self.model_name} stopped")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the model.
        
        Returns:
            Dictionary containing model health status and metrics
        """
        return {
            'model_name': self.model_name,
            'model_version': self.model_version,
            'initialized': self._initialized,
            'running': self._running,
            'model_loaded': self.model is not None,
            'inference_count': self.inference_count,
            'last_inference_time': self.last_inference_time.isoformat() if self.last_inference_time else None,
            'feature_columns_count': len(self.feature_columns),
            'metadata': self.metadata
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get model information and metadata.
        
        Returns:
            Dictionary containing model information
        """
        return {
            'name': self.model_name,
            'version': self.model_version,
            'type': self.__class__.__name__,
            'feature_columns': self.feature_columns,
            'metadata': self.metadata,
            'inference_count': self.inference_count
        }
    
    def _update_inference_stats(self) -> None:
        """Update inference statistics."""
        self.inference_count += 1
        self.last_inference_time = datetime.utcnow()
    
    def _prepare_features(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> pd.DataFrame:
        """
        Convert input features to standardized DataFrame format.
        
        Args:
            features: Input features in various formats
            
        Returns:
            Standardized DataFrame with expected columns
        """
        if isinstance(features, pd.DataFrame):
            return features
        elif isinstance(features, np.ndarray):
            if len(self.feature_columns) != features.shape[1]:
                raise ValueError(f"Feature array has {features.shape[1]} columns, expected {len(self.feature_columns)}")
            return pd.DataFrame(features, columns=self.feature_columns)
        elif isinstance(features, list):
            return pd.DataFrame(features)
        else:
            raise ValueError(f"Unsupported feature format: {type(features)}")


class UnsupervisedModel(BaseMLModel):
    """
    Abstract base class for unsupervised learning models.
    
    Provides specialized functionality for anomaly detection models
    like Isolation Forest and Autoencoders.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the unsupervised model.
        
        Args:
            config: Model configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        self.contamination = config.get('contamination', 0.1)
        self.threshold = config.get('anomaly_threshold', 0.5)
    
    @abstractmethod
    async def fit(self, features: Union[pd.DataFrame, np.ndarray]) -> None:
        """
        Train the unsupervised model on normal data.
        
        Args:
            features: Training features (assumed to be mostly normal data)
        """
        pass
    
    @abstractmethod
    async def predict_anomaly_score(self, features: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Predict anomaly scores for input features.
        
        Args:
            features: Input features
            
        Returns:
            Array of anomaly scores between 0 and 1
        """
        pass
    
    async def predict(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> MLPrediction:
        """
        Generate anomaly predictions for input features.
        
        Args:
            features: Input features
            
        Returns:
            MLPrediction with anomaly scores
        """
        if not self.model:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Validate and prepare features
        if not await self.validate_features(features):
            raise ValueError("Invalid features provided")
        
        df_features = self._prepare_features(features)
        
        # Get anomaly scores
        anomaly_scores = await self.predict_anomaly_score(df_features.values)
        
        # For unsupervised models, we typically return the max score for a batch
        max_score = float(np.max(anomaly_scores))
        
        # Calculate feature importance (simplified for base class)
        feature_importance = self._calculate_feature_importance(df_features)
        
        self._update_inference_stats()
        
        return MLPrediction(
            model_name=self.model_name,
            model_version=self.model_version,
            anomaly_score=max_score,
            feature_importance=feature_importance
        )
    
    def _calculate_feature_importance(self, features: pd.DataFrame) -> Dict[str, float]:
        """
        Calculate basic feature importance based on variance.
        
        Args:
            features: Input features DataFrame
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        # Simple variance-based importance for base class
        variances = features.var()
        total_variance = variances.sum()
        
        if total_variance == 0:
            return {col: 0.0 for col in features.columns}
        
        importance = {}
        for col in features.columns:
            importance[col] = float(variances[col] / total_variance)
        
        return importance


class SupervisedModel(BaseMLModel):
    """
    Abstract base class for supervised learning models.
    
    Provides specialized functionality for classification models
    like XGBoost and CatBoost that use labeled training data.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the supervised model.
        
        Args:
            config: Model configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        self.num_classes = config.get('num_classes', 2)
        self.class_names = config.get('class_names', ['normal', 'threat'])
        self.probability_threshold = config.get('probability_threshold', 0.5)
    
    @abstractmethod
    async def fit(self, features: Union[pd.DataFrame, np.ndarray], labels: Union[pd.Series, np.ndarray]) -> None:
        """
        Train the supervised model on labeled data.
        
        Args:
            features: Training features
            labels: Training labels
        """
        pass
    
    @abstractmethod
    async def predict_proba(self, features: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Predict class probabilities for input features.
        
        Args:
            features: Input features
            
        Returns:
            Array of class probabilities
        """
        pass
    
    @abstractmethod
    async def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance from the trained model.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        pass
    
    async def predict(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> MLPrediction:
        """
        Generate threat predictions for input features.
        
        Args:
            features: Input features
            
        Returns:
            MLPrediction with threat probabilities
        """
        if not self.model:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Validate and prepare features
        if not await self.validate_features(features):
            raise ValueError("Invalid features provided")
        
        df_features = self._prepare_features(features)
        
        # Get class probabilities
        probabilities = await self.predict_proba(df_features.values)
        
        # For binary classification, use threat class probability
        if self.num_classes == 2:
            threat_score = float(np.max(probabilities[:, 1]))  # Threat class
        else:
            # For multi-class, use max probability as anomaly score
            threat_score = float(np.max(probabilities))
        
        # Get feature importance from model
        feature_importance = await self.get_feature_importance()
        
        self._update_inference_stats()
        
        return MLPrediction(
            model_name=self.model_name,
            model_version=self.model_version,
            anomaly_score=threat_score,
            feature_importance=feature_importance
        )


class SequenceModel(BaseMLModel):
    """
    Abstract base class for sequence models.
    
    Provides specialized functionality for temporal pattern analysis
    using models like GRU, LSTM, or Transformers.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the sequence model.
        
        Args:
            config: Model configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        self.sequence_length = config.get('sequence_length', 10)
        self.time_window_minutes = config.get('time_window_minutes', 5)
        self.feature_dim = config.get('feature_dim', len(self.feature_columns))
    
    @abstractmethod
    async def predict_sequence(self, sequences: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for input sequences.
        
        Args:
            sequences: Input sequences with shape (batch_size, sequence_length, feature_dim)
            
        Returns:
            Array of anomaly scores
        """
        pass
    
    async def predict(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> MLPrediction:
        """
        Generate predictions for sequential features.
        
        Args:
            features: Input features (should contain temporal sequences)
            
        Returns:
            MLPrediction with temporal anomaly scores
        """
        if not self.model:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Validate and prepare features
        if not await self.validate_features(features):
            raise ValueError("Invalid features provided")
        
        df_features = self._prepare_features(features)
        
        # Convert to sequences (this is a simplified version)
        sequences = self._create_sequences(df_features.values)
        
        # Get sequence predictions
        sequence_scores = await self.predict_sequence(sequences)
        
        # Use max score across sequences
        max_score = float(np.max(sequence_scores))
        
        # Calculate feature importance for sequences
        feature_importance = self._calculate_sequence_importance(df_features)
        
        self._update_inference_stats()
        
        return MLPrediction(
            model_name=self.model_name,
            model_version=self.model_version,
            anomaly_score=max_score,
            feature_importance=feature_importance
        )
    
    def _create_sequences(self, features: np.ndarray) -> np.ndarray:
        """
        Create sequences from feature array.
        
        Args:
            features: Input features array
            
        Returns:
            Sequences array with shape (num_sequences, sequence_length, feature_dim)
        """
        if len(features) < self.sequence_length:
            # Pad with zeros if not enough data
            padded = np.zeros((self.sequence_length, features.shape[1]))
            padded[:len(features)] = features
            return padded.reshape(1, self.sequence_length, -1)
        
        # Create sliding window sequences
        sequences = []
        for i in range(len(features) - self.sequence_length + 1):
            sequences.append(features[i:i + self.sequence_length])
        
        return np.array(sequences)
    
    def _calculate_sequence_importance(self, features: pd.DataFrame) -> Dict[str, float]:
        """
        Calculate feature importance for sequence models.
        
        Args:
            features: Input features DataFrame
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        # Simplified importance based on temporal variance
        temporal_variance = {}
        
        for col in features.columns:
            values = features[col].values
            if len(values) > 1:
                # Calculate variance of differences (temporal change)
                diffs = np.diff(values)
                temporal_variance[col] = float(np.var(diffs))
            else:
                temporal_variance[col] = 0.0
        
        # Normalize to sum to 1
        total_variance = sum(temporal_variance.values())
        if total_variance == 0:
            return {col: 0.0 for col in features.columns}
        
        return {col: var / total_variance for col, var in temporal_variance.items()}