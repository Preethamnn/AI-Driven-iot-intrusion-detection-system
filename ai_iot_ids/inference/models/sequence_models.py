"""
Sequence model implementations for temporal pattern analysis.

This module provides GRU and LSTM-based sequence models for analyzing
temporal patterns in network flow data using TensorFlow/Keras.
"""

from typing import Dict, List, Optional, Union, Any, Tuple
import logging
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None
    keras = None
    layers = None

from ..base_model import SequenceModel
from ...models.threat_detection import MLPrediction


class GRUModel(SequenceModel):
    """
    GRU-based sequence model for temporal network flow analysis.
    
    Uses Gated Recurrent Units to analyze temporal patterns in
    network flow sequences for anomaly detection.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the GRU model.
        
        Args:
            config: Model configuration including hyperparameters
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is not installed. Install with: pip install tensorflow")
        
        # GRU specific parameters
        self.hidden_units = config.get('hidden_units', 64)
        self.num_layers = config.get('num_layers', 2)
        self.dropout_rate = config.get('dropout_rate', 0.2)
        self.learning_rate = config.get('learning_rate', 0.001)
        self.batch_size = config.get('batch_size', 32)
        self.epochs = config.get('epochs', 50)
        self.validation_split = config.get('validation_split', 0.2)
        self.early_stopping_patience = config.get('early_stopping_patience', 10)
        
        # Model architecture
        self.model = None
        self.training_history = {}
        self.scaler = None
    
    async def load_model(self, model_path: Optional[str] = None) -> None:
        """
        Load the GRU model from disk.
        
        Args:
            model_path: Optional path to model file
        """
        path = model_path or self.model_path
        
        if path and Path(path).exists():
            try:
                # Load model components
                model_data = joblib.load(path)
                
                # Load Keras model
                model_path_h5 = str(Path(path).with_suffix('.h5'))
                if Path(model_path_h5).exists():
                    self.model = keras.models.load_model(model_path_h5)
                
                self.training_history = model_data.get('training_history', {})
                self.metadata = model_data.get('metadata', {})
                self.feature_columns = model_data.get('feature_columns', [])
                self.scaler = model_data.get('scaler')
                
                self.log_info(f"GRU model loaded from {path}")
                
            except Exception as e:
                self.log_error(f"Failed to load model from {path}", e)
                raise
        else:
            # Create new model if no saved model exists
            await self._build_model()
            self.log_info("Created new GRU model")
    
    async def _build_model(self) -> None:
        """Build the GRU model architecture."""
        try:
            # Input layer
            inputs = keras.Input(shape=(self.sequence_length, self.feature_dim))
            
            # GRU layers
            x = inputs
            for i in range(self.num_layers):
                return_sequences = i < self.num_layers - 1
                x = layers.GRU(
                    self.hidden_units,
                    return_sequences=return_sequences,
                    dropout=self.dropout_rate,
                    recurrent_dropout=self.dropout_rate,
                    name=f'gru_{i+1}'
                )(x)
            
            # Dense layers for anomaly detection
            x = layers.Dense(32, activation='relu', name='dense_1')(x)
            x = layers.Dropout(self.dropout_rate, name='dropout_final')(x)
            outputs = layers.Dense(1, activation='sigmoid', name='output')(x)
            
            # Create model
            self.model = keras.Model(inputs=inputs, outputs=outputs, name='gru_anomaly_detector')
            
            # Compile model
            self.model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            self.log_info(f"GRU model built with {self.model.count_params()} parameters")
            
        except Exception as e:
            self.log_error("Failed to build GRU model", e)
            raise
    
    async def fit(self, sequences: np.ndarray, labels: Optional[np.ndarray] = None) -> None:
        """
        Train the GRU model on sequence data.
        
        Args:
            sequences: Training sequences with shape (n_samples, sequence_length, n_features)
            labels: Optional labels for supervised training (0=normal, 1=anomaly)
        """
        if self.model is None:
            await self._build_model()
        
        try:
            # Prepare data
            X = sequences
            
            if labels is not None:
                # Supervised training
                y = labels
            else:
                # Unsupervised training - use reconstruction loss
                # For simplicity, we'll create pseudo-labels based on reconstruction error
                y = np.zeros(X.shape[0])  # Assume all normal for initial training
            
            # Setup callbacks
            callbacks = [
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=self.early_stopping_patience,
                    restore_best_weights=True
                ),
                keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=5,
                    min_lr=1e-7
                )
            ]
            
            # Train model
            history = self.model.fit(
                X, y,
                batch_size=self.batch_size,
                epochs=self.epochs,
                validation_split=self.validation_split,
                callbacks=callbacks,
                verbose=0
            )
            
            # Store training history
            self.training_history = {
                'loss': history.history['loss'],
                'val_loss': history.history['val_loss'],
                'accuracy': history.history.get('accuracy', []),
                'val_accuracy': history.history.get('val_accuracy', [])
            }
            
            # Update metadata
            self.metadata.update({
                'n_samples_trained': X.shape[0],
                'sequence_length': X.shape[1],
                'n_features': X.shape[2],
                'epochs_trained': len(history.history['loss']),
                'final_loss': float(history.history['loss'][-1]),
                'final_val_loss': float(history.history['val_loss'][-1])
            })
            
            self.log_info(f"GRU trained on {X.shape[0]} sequences for {len(history.history['loss'])} epochs")
            
        except Exception as e:
            self.log_error("Failed to train GRU model", e)
            raise
    
    async def predict_sequence(self, sequences: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for input sequences.
        
        Args:
            sequences: Input sequences with shape (batch_size, sequence_length, feature_dim)
            
        Returns:
            Array of anomaly scores between 0 and 1
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        try:
            # Get predictions
            predictions = self.model.predict(sequences, verbose=0)
            
            # Convert to anomaly scores
            anomaly_scores = predictions.flatten()
            
            return anomaly_scores
            
        except Exception as e:
            self.log_error("Failed to predict sequence anomalies", e)
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
            
            # Check minimum sequence length
            if len(df_features) < self.sequence_length:
                self.log_error(f"Insufficient data: need at least {self.sequence_length} samples, got {len(df_features)}")
                return False
            
            # Check feature dimensions
            if df_features.shape[1] != self.feature_dim:
                self.log_error(f"Feature dimension mismatch: expected {self.feature_dim}, got {df_features.shape[1]}")
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
    
    async def save_model(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path: Path to save the model
        """
        if self.model is None:
            raise RuntimeError("No model to save")
        
        try:
            # Save Keras model
            model_path_h5 = str(Path(path).with_suffix('.h5'))
            self.model.save(model_path_h5)
            
            # Save additional data
            model_data = {
                'training_history': self.training_history,
                'metadata': self.metadata,
                'config': self.config,
                'feature_columns': self.feature_columns,
                'scaler': self.scaler
            }
            
            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(model_data, path)
            self.log_info(f"GRU model saved to {path}")
            
        except Exception as e:
            self.log_error(f"Failed to save model to {path}", e)
            raise


class LSTMModel(SequenceModel):
    """
    LSTM-based sequence model for temporal network flow analysis.
    
    Uses Long Short-Term Memory networks to analyze temporal patterns
    in network flow sequences for anomaly detection.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the LSTM model.
        
        Args:
            config: Model configuration including hyperparameters
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        if not TENSORFLOW_AVAILABLE:
            raise ImportError("TensorFlow is not installed. Install with: pip install tensorflow")
        
        # LSTM specific parameters
        self.hidden_units = config.get('hidden_units', 64)
        self.num_layers = config.get('num_layers', 2)
        self.dropout_rate = config.get('dropout_rate', 0.2)
        self.learning_rate = config.get('learning_rate', 0.001)
        self.batch_size = config.get('batch_size', 32)
        self.epochs = config.get('epochs', 50)
        self.validation_split = config.get('validation_split', 0.2)
        self.early_stopping_patience = config.get('early_stopping_patience', 10)
        
        # Model architecture
        self.model = None
        self.training_history = {}
        self.scaler = None
    
    async def load_model(self, model_path: Optional[str] = None) -> None:
        """
        Load the LSTM model from disk.
        
        Args:
            model_path: Optional path to model file
        """
        path = model_path or self.model_path
        
        if path and Path(path).exists():
            try:
                # Load model components
                model_data = joblib.load(path)
                
                # Load Keras model
                model_path_h5 = str(Path(path).with_suffix('.h5'))
                if Path(model_path_h5).exists():
                    self.model = keras.models.load_model(model_path_h5)
                
                self.training_history = model_data.get('training_history', {})
                self.metadata = model_data.get('metadata', {})
                self.feature_columns = model_data.get('feature_columns', [])
                self.scaler = model_data.get('scaler')
                
                self.log_info(f"LSTM model loaded from {path}")
                
            except Exception as e:
                self.log_error(f"Failed to load model from {path}", e)
                raise
        else:
            # Create new model if no saved model exists
            await self._build_model()
            self.log_info("Created new LSTM model")
    
    async def _build_model(self) -> None:
        """Build the LSTM model architecture."""
        try:
            # Input layer
            inputs = keras.Input(shape=(self.sequence_length, self.feature_dim))
            
            # LSTM layers
            x = inputs
            for i in range(self.num_layers):
                return_sequences = i < self.num_layers - 1
                x = layers.LSTM(
                    self.hidden_units,
                    return_sequences=return_sequences,
                    dropout=self.dropout_rate,
                    recurrent_dropout=self.dropout_rate,
                    name=f'lstm_{i+1}'
                )(x)
            
            # Dense layers for anomaly detection
            x = layers.Dense(32, activation='relu', name='dense_1')(x)
            x = layers.Dropout(self.dropout_rate, name='dropout_final')(x)
            outputs = layers.Dense(1, activation='sigmoid', name='output')(x)
            
            # Create model
            self.model = keras.Model(inputs=inputs, outputs=outputs, name='lstm_anomaly_detector')
            
            # Compile model
            self.model.compile(
                optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
                loss='binary_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            self.log_info(f"LSTM model built with {self.model.count_params()} parameters")
            
        except Exception as e:
            self.log_error("Failed to build LSTM model", e)
            raise
    
    async def fit(self, sequences: np.ndarray, labels: Optional[np.ndarray] = None) -> None:
        """
        Train the LSTM model on sequence data.
        
        Args:
            sequences: Training sequences with shape (n_samples, sequence_length, n_features)
            labels: Optional labels for supervised training (0=normal, 1=anomaly)
        """
        if self.model is None:
            await self._build_model()
        
        try:
            # Prepare data
            X = sequences
            
            if labels is not None:
                # Supervised training
                y = labels
            else:
                # Unsupervised training - use reconstruction loss
                # For simplicity, we'll create pseudo-labels based on reconstruction error
                y = np.zeros(X.shape[0])  # Assume all normal for initial training
            
            # Setup callbacks
            callbacks = [
                keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=self.early_stopping_patience,
                    restore_best_weights=True
                ),
                keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=5,
                    min_lr=1e-7
                )
            ]
            
            # Train model
            history = self.model.fit(
                X, y,
                batch_size=self.batch_size,
                epochs=self.epochs,
                validation_split=self.validation_split,
                callbacks=callbacks,
                verbose=0
            )
            
            # Store training history
            self.training_history = {
                'loss': history.history['loss'],
                'val_loss': history.history['val_loss'],
                'accuracy': history.history.get('accuracy', []),
                'val_accuracy': history.history.get('val_accuracy', [])
            }
            
            # Update metadata
            self.metadata.update({
                'n_samples_trained': X.shape[0],
                'sequence_length': X.shape[1],
                'n_features': X.shape[2],
                'epochs_trained': len(history.history['loss']),
                'final_loss': float(history.history['loss'][-1]),
                'final_val_loss': float(history.history['val_loss'][-1])
            })
            
            self.log_info(f"LSTM trained on {X.shape[0]} sequences for {len(history.history['loss'])} epochs")
            
        except Exception as e:
            self.log_error("Failed to train LSTM model", e)
            raise
    
    async def predict_sequence(self, sequences: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for input sequences.
        
        Args:
            sequences: Input sequences with shape (batch_size, sequence_length, feature_dim)
            
        Returns:
            Array of anomaly scores between 0 and 1
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        try:
            # Get predictions
            predictions = self.model.predict(sequences, verbose=0)
            
            # Convert to anomaly scores
            anomaly_scores = predictions.flatten()
            
            return anomaly_scores
            
        except Exception as e:
            self.log_error("Failed to predict sequence anomalies", e)
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
            
            # Check minimum sequence length
            if len(df_features) < self.sequence_length:
                self.log_error(f"Insufficient data: need at least {self.sequence_length} samples, got {len(df_features)}")
                return False
            
            # Check feature dimensions
            if df_features.shape[1] != self.feature_dim:
                self.log_error(f"Feature dimension mismatch: expected {self.feature_dim}, got {df_features.shape[1]}")
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
    
    async def save_model(self, path: str) -> None:
        """
        Save the trained model to disk.
        
        Args:
            path: Path to save the model
        """
        if self.model is None:
            raise RuntimeError("No model to save")
        
        try:
            # Save Keras model
            model_path_h5 = str(Path(path).with_suffix('.h5'))
            self.model.save(model_path_h5)
            
            # Save additional data
            model_data = {
                'training_history': self.training_history,
                'metadata': self.metadata,
                'config': self.config,
                'feature_columns': self.feature_columns,
                'scaler': self.scaler
            }
            
            # Ensure directory exists
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            
            joblib.dump(model_data, path)
            self.log_info(f"LSTM model saved to {path}")
            
        except Exception as e:
            self.log_error(f"Failed to save model to {path}", e)
            raise