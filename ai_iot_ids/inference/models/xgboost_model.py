"""
XGBoost model implementation for supervised threat detection.

This module provides an XGBoost-based supervised learning model
for classifying network flows as normal or threatening.
"""

from typing import Dict, List, Optional, Union, Any
import logging
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    xgb = None

from ..base_model import SupervisedModel
from ...models.threat_detection import MLPrediction


class XGBoostModel(SupervisedModel):
    """
    XGBoost implementation for network flow threat classification.
    
    Uses XGBoost gradient boosting for supervised learning on labeled
    network flow data to classify threats vs normal traffic.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the XGBoost model.
        
        Args:
            config: Model configuration including hyperparameters
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        if not XGBOOST_AVAILABLE:
            raise ImportError("XGBoost is not installed. Install with: pip install xgboost")
        
        # XGBoost specific parameters
        self.max_depth = config.get('max_depth', 6)
        self.learning_rate = config.get('learning_rate', 0.1)
        self.n_estimators = config.get('n_estimators', 100)
        self.subsample = config.get('subsample', 1.0)
        self.colsample_bytree = config.get('colsample_bytree', 1.0)
        self.reg_alpha = config.get('reg_alpha', 0)
        self.reg_lambda = config.get('reg_lambda', 1)
        self.random_state = config.get('random_state', 42)
        self.n_jobs = config.get('n_jobs', -1)
        self.early_stopping_rounds = config.get('early_stopping_rounds', 10)
        self.eval_metric = config.get('eval_metric', 'logloss')
        
        # Model instance
        self.model = None
        self.feature_importance_dict = {}
        self.training_history = {}
    
    async def load_model(self, model_path: Optional[str] = None) -> None:
        """
        Load the XGBoost model from disk.
        
        Args:
            model_path: Optional path to model file
        """
        path = model_path or self.model_path
        
        if path and Path(path).exists():
            try:
                model_data = joblib.load(path)
                self.model = model_data['model']
                self.feature_importance_dict = model_data.get('feature_importance', {})
                self.training_history = model_data.get('training_history', {})
                self.metadata = model_data.get('metadata', {})
                self.feature_columns = model_data.get('feature_columns', [])
                
                self.log_info(f"XGBoost model loaded from {path}")
                
            except Exception as e:
                self.log_error(f"Failed to load model from {path}", e)
                raise
        else:
            # Create new model if no saved model exists
            self.model = xgb.XGBClassifier(
                max_depth=self.max_depth,
                learning_rate=self.learning_rate,
                n_estimators=self.n_estimators,
                subsample=self.subsample,
                colsample_bytree=self.colsample_bytree,
                reg_alpha=self.reg_alpha,
                reg_lambda=self.reg_lambda,
                random_state=self.random_state,
                n_jobs=self.n_jobs,
                eval_metric=self.eval_metric,
                use_label_encoder=False
            )
            
            self.log_info("Created new XGBoost model")
    
    async def fit(self, features: Union[pd.DataFrame, np.ndarray], labels: Union[pd.Series, np.ndarray]) -> None:
        """
        Train the XGBoost model on labeled data.
        
        Args:
            features: Training features
            labels: Training labels (0=normal, 1=threat)
        """
        if self.model is None:
            await self.load_model()
        
        try:
            # Convert to appropriate formats
            if isinstance(features, pd.DataFrame):
                X = features.values
                self.feature_columns = list(features.columns)
            else:
                X = features
            
            if isinstance(labels, pd.Series):
                y = labels.values
            else:
                y = labels
            
            # Validate labels
            unique_labels = np.unique(y)
            if len(unique_labels) != 2 or not all(label in [0, 1] for label in unique_labels):
                raise ValueError("Labels must be binary (0=normal, 1=threat)")
            
            # Split for validation if early stopping is enabled
            if self.early_stopping_rounds > 0:
                from sklearn.model_selection import train_test_split
                X_train, X_val, y_train, y_val = train_test_split(
                    X, y, test_size=0.2, random_state=self.random_state, stratify=y
                )
                
                # Fit with validation
                self.model.fit(
                    X_train, y_train,
                    eval_set=[(X_val, y_val)],
                    early_stopping_rounds=self.early_stopping_rounds,
                    verbose=False
                )
                
                # Store validation results
                self.training_history = {
                    'validation_scores': self.model.evals_result()
                }
            else:
                # Fit without validation
                self.model.fit(X, y)
            
            # Calculate and store feature importance
            await self._calculate_feature_importance()
            
            # Update metadata
            self.metadata.update({
                'n_samples_trained': X.shape[0],
                'n_features': X.shape[1],
                'n_classes': len(unique_labels),
                'class_distribution': {
                    'normal': int(np.sum(y == 0)),
                    'threat': int(np.sum(y == 1))
                },
                'best_iteration': getattr(self.model, 'best_iteration', self.n_estimators)
            })
            
            self.log_info(f"XGBoost trained on {X.shape[0]} samples with {X.shape[1]} features")
            
        except Exception as e:
            self.log_error("Failed to train XGBoost model", e)
            raise
    
    async def predict_proba(self, features: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """
        Predict class probabilities for input features.
        
        Args:
            features: Input features
            
        Returns:
            Array of class probabilities [P(normal), P(threat)]
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        try:
            # Convert to numpy array if needed
            if isinstance(features, pd.DataFrame):
                X = features.values
            else:
                X = features
            
            # Get class probabilities
            probabilities = self.model.predict_proba(X)
            
            return probabilities
            
        except Exception as e:
            self.log_error("Failed to predict probabilities", e)
            raise
    
    async def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance from the trained model.
        
        Returns:
            Dictionary mapping feature names to importance scores
        """
        if not self.feature_importance_dict:
            await self._calculate_feature_importance()
        
        return self.feature_importance_dict.copy()
    
    async def _calculate_feature_importance(self) -> None:
        """Calculate and store feature importance."""
        if self.model is None or not hasattr(self.model, 'feature_importances_'):
            return
        
        try:
            importances = self.model.feature_importances_
            
            if len(self.feature_columns) == len(importances):
                self.feature_importance_dict = dict(zip(self.feature_columns, importances.astype(float)))
            else:
                # Fallback to indexed names
                self.feature_importance_dict = {
                    f'feature_{i}': float(imp) for i, imp in enumerate(importances)
                }
                
        except Exception as e:
            self.log_warning(f"Could not calculate feature importance: {e}")
            self.feature_importance_dict = {}
    
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
        Generate threat predictions for input features.
        
        Args:
            features: Input features
            
        Returns:
            MLPrediction with threat probabilities and feature importance
        """
        if not self.model:
            raise RuntimeError(f"Model {self.model_name} not loaded")
        
        # Validate and prepare features
        if not await self.validate_features(features):
            raise ValueError("Invalid features provided")
        
        df_features = self._prepare_features(features)
        
        # Get class probabilities
        probabilities = await self.predict_proba(df_features)
        
        # Use threat class probability (class 1) as anomaly score
        threat_scores = probabilities[:, 1]
        max_threat_score = float(np.max(threat_scores))
        
        # Get feature importance
        feature_importance = await self.get_feature_importance()
        
        self._update_inference_stats()
        
        return MLPrediction(
            model_name=self.model_name,
            model_version=self.model_version,
            anomaly_score=max_threat_score,
            feature_importance=feature_importance
        )
    
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
                'feature_importance': self.feature_importance_dict,
                'training_history': self.training_history,
                'metadata': self.metadata,
                'config': self.config,
                'feature_columns': self.feature_columns
            }
            
            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(model_data, path)
            self.log_info(f"XGBoost model saved to {path}")
            
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
            'max_depth': self.max_depth,
            'learning_rate': self.learning_rate,
            'n_estimators': self.n_estimators,
            'subsample': self.subsample,
            'colsample_bytree': self.colsample_bytree,
            'reg_alpha': self.reg_alpha,
            'reg_lambda': self.reg_lambda,
            'random_state': self.random_state,
            'n_jobs': self.n_jobs,
            'early_stopping_rounds': self.early_stopping_rounds,
            'eval_metric': self.eval_metric
        }
    
    def get_training_info(self) -> Dict[str, Any]:
        """
        Get information about model training.
        
        Returns:
            Dictionary with training information
        """
        info = {
            'is_fitted': self.model is not None and hasattr(self.model, 'feature_importances_'),
            'best_iteration': getattr(self.model, 'best_iteration', None) if self.model else None,
            'n_features': getattr(self.model, 'n_features_in_', None) if self.model else None
        }
        
        if self.training_history:
            info['training_history'] = self.training_history
        
        return info
    
    async def evaluate(self, features: Union[pd.DataFrame, np.ndarray], labels: Union[pd.Series, np.ndarray]) -> Dict[str, Any]:
        """
        Evaluate model performance on test data.
        
        Args:
            features: Test features
            labels: True labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        try:
            # Convert to appropriate formats
            if isinstance(features, pd.DataFrame):
                X = features.values
            else:
                X = features
            
            if isinstance(labels, pd.Series):
                y_true = labels.values
            else:
                y_true = labels
            
            # Get predictions
            y_pred = self.model.predict(X)
            y_pred_proba = self.model.predict_proba(X)
            
            # Calculate metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
            
            metrics = {
                'accuracy': float(accuracy_score(y_true, y_pred)),
                'precision': float(precision_score(y_true, y_pred)),
                'recall': float(recall_score(y_true, y_pred)),
                'f1_score': float(f1_score(y_true, y_pred)),
                'roc_auc': float(roc_auc_score(y_true, y_pred_proba[:, 1]))
            }
            
            return metrics
            
        except Exception as e:
            self.log_error("Failed to evaluate model", e)
            raise