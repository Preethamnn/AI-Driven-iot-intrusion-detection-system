"""
Isolation Forest model implementation for anomaly detection.

This module provides an Isolation Forest-based unsupervised learning model
for detecting anomalous network flows in IoT traffic patterns.
"""

from typing import Dict, List, Optional, Union, Any
import logging
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

from ..base_model import UnsupervisedModel
from ...models.threat_detection import MLPrediction


class IsolationForestModel(UnsupervisedModel):
    """
    Isolation Forest implementation for network flow anomaly detection.
    
    Uses scikit-learn's IsolationForest to identify anomalous patterns
    in network flow features that may indicate security threats.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the Isolation Forest model.
        
        Args:
            config: Model configuration including hyperparameters
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Isolation Forest specific parameters (optimized for maximum accuracy)
        self.n_estimators = config.get('n_estimators', 100)  # Optimized: 100 estimators
        self.max_samples = config.get('max_samples', 0.9)    # Optimized: 90% sampling
        self.max_features = config.get('max_features', 1.0)
        self.bootstrap = config.get('bootstrap', False)
        self.n_jobs = config.get('n_jobs', -1)
        self.random_state = config.get('random_state', 42)
        self.warm_start = config.get('warm_start', False)
        
        # Model instance
        self.model = None
        self.feature_importances_ = None
        self.training_scores_ = None
    
    async def load_model(self, model_path: Optional[str] = None) -> None:
        """
        Load the Isolation Forest model from disk.
        
        Args:
            model_path: Optional path to model file
        """
        path = model_path or self.model_path
        
        if path and Path(path).exists():
            try:
                model_data = joblib.load(path)
                self.model = model_data['model']
                self.feature_importances_ = model_data.get('feature_importances')
                self.training_scores_ = model_data.get('training_scores')
                self.metadata = model_data.get('metadata', {})
                
                self.log_info(f"Isolation Forest model loaded from {path}")
                
            except Exception as e:
                self.log_error(f"Failed to load model from {path}", e)
                raise
        else:
            # Create new model with optimized parameters for maximum accuracy
            self.model = IsolationForest(
                n_estimators=self.n_estimators,
                max_samples=self.max_samples,
                contamination=0.25,  # Optimized: Higher contamination for better accuracy
                max_features=self.max_features,
                bootstrap=self.bootstrap,
                n_jobs=self.n_jobs,
                random_state=self.random_state,
                warm_start=self.warm_start
            )
            
            self.log_info("Created new Isolation Forest model")
    
    async def fit(self, features: Union[pd.DataFrame, np.ndarray]) -> None:
        """
        Train the Isolation Forest model on normal data.
        
        Args:
            features: Training features (assumed to be mostly normal data)
        """
        if self.model is None:
            await self.load_model()
        
        try:
            # Convert to numpy array if needed
            if isinstance(features, pd.DataFrame):
                X = features.values
                self.feature_columns = list(features.columns)
            else:
                X = features
            
            # Fit the model
            self.model.fit(X)
            
            # Calculate training scores for threshold setting
            self.training_scores_ = self.model.decision_function(X)
            
            # Calculate feature importance based on path lengths
            self._calculate_feature_importance(X)
            
            # Update metadata
            self.metadata.update({
                'n_samples_trained': X.shape[0],
                'n_features': X.shape[1],
                'contamination': self.contamination,
                'n_estimators': self.n_estimators,
                'training_score_mean': float(np.mean(self.training_scores_)),
                'training_score_std': float(np.std(self.training_scores_))
            })
            
            self.log_info(f"Isolation Forest trained on {X.shape[0]} samples with {X.shape[1]} features")
            
        except Exception as e:
            self.log_error("Failed to train Isolation Forest model", e)
            raise
    
    async def predict_anomaly_score(self, features: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Predict anomaly scores for input features.
        
        Args:
            features: Input features
            
        Returns:
            Array of anomaly scores between 0 and 1
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        try:
            # Convert to numpy array if needed
            if isinstance(features, pd.DataFrame):
                X = features.values
            else:
                X = features
            
            # Get decision function scores (higher = more normal)
            decision_scores = self.model.decision_function(X)
            
            # Convert to anomaly scores (0 = normal, 1 = anomalous)
            # Use sigmoid transformation to map to [0, 1]
            anomaly_scores = 1 / (1 + np.exp(decision_scores))
            
            return anomaly_scores
            
        except Exception as e:
            self.log_error("Failed to predict anomaly scores", e)
            raise
    
    async def validate_features(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> bool:
        """
        Validate that input features match model expectations.
        
        Args:
            features: Input features to validate
            
        Returns:
            True if features are valid, False otherwise
        """
        try:
            df_features = self._prepare_features(features)
            
            # Check if we have the expected number of features
            if self.model is not None and hasattr(self.model, 'n_features_in_'):
                expected_features = self.model.n_features_in_
                if df_features.shape[1] != expected_features:
                    self.log_error(f"Feature count mismatch: expected {expected_features}, got {df_features.shape[1]}")
                    return False
            
            # Check for missing values
            if df_features.isnull().any().any():
                self.log_error("Features contain missing values")
                return False
            
            # Check for infinite values
            if np.isinf(df_features.values).any():
                self.log_error("Features contain infinite values")
                return False
            
            return True
            
        except Exception as e:
            self.log_error("Feature validation failed", e)
            return False
    
    async def predict(self, features: Union[pd.DataFrame, np.ndarray, List[Dict]]) -> MLPrediction:
        """
        Generate anomaly predictions for input features.
        
        Args:
            features: Input features
            
        Returns:
            MLPrediction with anomaly scores and feature importance
        """
        if not self.model:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Validate and prepare features
        if not await self.validate_features(features):
            raise ValueError("Invalid features provided")
        
        df_features = self._prepare_features(features)
        
        # Get anomaly scores
        anomaly_scores = await self.predict_anomaly_score(df_features)
        
        # Use max score for batch prediction
        max_score = float(np.max(anomaly_scores))
        
        # Get feature importance
        if self.feature_importances_ is not None:
            feature_importance = dict(zip(self.feature_columns, self.feature_importances_))
        else:
            feature_importance = self._calculate_feature_importance_runtime(df_features)
        
        self._update_inference_stats()
        
        return MLPrediction(
            model_name=self.model_name,
            model_version=self.model_version,
            anomaly_score=max_score,
            feature_importance=feature_importance
        )
    
    def _calculate_feature_importance(self, X: np.ndarray) -> None:
        """
        Calculate feature importance based on isolation path lengths.
        
        Args:
            X: Training features
        """
        try:
            # Calculate feature importance based on how much each feature
            # contributes to the isolation process
            n_features = X.shape[1]
            importances = np.zeros(n_features)
            
            # For each tree in the forest
            for tree in self.model.estimators_:
                # Get feature usage in tree splits
                feature_counts = np.bincount(tree.tree_.feature[tree.tree_.feature >= 0], minlength=n_features)
                importances += feature_counts
            
            # Normalize importances
            if importances.sum() > 0:
                importances = importances / importances.sum()
            
            self.feature_importances_ = importances
            
        except Exception as e:
            self.log_warning(f"Could not calculate feature importance: {e}")
            # Fallback to uniform importance
            self.feature_importances_ = np.ones(X.shape[1]) / X.shape[1]
    
    def _calculate_feature_importance_runtime(self, features: pd.DataFrame) -> Dict[str, float]:
        """
        Calculate feature importance at runtime using variance-based method.
        
        Args:
            features: Input features DataFrame
            
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if self.feature_importances_ is not None and len(self.feature_columns) == len(self.feature_importances_):
            return dict(zip(self.feature_columns, self.feature_importances_))
        
        # Fallback to variance-based importance
        variances = features.var()
        total_variance = variances.sum()
        
        if total_variance == 0:
            return {col: 0.0 for col in features.columns}
        
        importance = {}
        for col in features.columns:
            importance[col] = float(variances[col] / total_variance)
        
        return importance
    
    async def save_model(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path: Path to save the model
        """
        if self.model is None:
            raise RuntimeError("No model to save")
        
        try:
            model_data = {
                'model': self.model,
                'feature_importances': self.feature_importances_,
                'training_scores': self.training_scores_,
                'metadata': self.metadata,
                'config': self.config,
                'feature_columns': self.feature_columns
            }
            
            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(model_data, path)
            self.log_info(f"Isolation Forest model saved to {path}")
            
        except Exception as e:
            self.log_error(f"Failed to save model to {path}", e)
            raise
    
    def get_model_parameters(self) -> Dict[str, Any]:
        """
        Get model hyperparameters.
        
        Returns:
            Dictionary of model parameters
        """
        return {
            'n_estimators': self.n_estimators,
            'max_samples': self.max_samples,
            'contamination': self.contamination,
            'max_features': self.max_features,
            'bootstrap': self.bootstrap,
            'n_jobs': self.n_jobs,
            'random_state': self.random_state,
            'warm_start': self.warm_start
        }
    
    def get_training_info(self) -> Dict[str, Any]:
        """
        Get information about model training.
        
        Returns:
            Dictionary with training information
        """
        info = {
            'is_fitted': self.model is not None and hasattr(self.model, 'estimators_'),
            'n_estimators_actual': len(self.model.estimators_) if self.model and hasattr(self.model, 'estimators_') else 0
        }
        
        if self.training_scores_ is not None:
            info.update({
                'training_score_mean': float(np.mean(self.training_scores_)),
                'training_score_std': float(np.std(self.training_scores_)),
                'training_score_min': float(np.min(self.training_scores_)),
                'training_score_max': float(np.max(self.training_scores_))
            })
        
        return info