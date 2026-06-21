"""
Feature preprocessing and normalization pipelines for ML models.

This module provides feature preprocessing capabilities including
normalization, scaling, encoding, and feature engineering for
network flow data used in threat detection models.
"""

from typing import Dict, List, Optional, Union, Tuple, Any
import logging
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
import joblib
from pathlib import Path

from ..models.network_flow import NetworkFlow
from ..interfaces.base import BaseInterface


class FeaturePreprocessor(BaseInterface):
    """
    Feature preprocessing pipeline for network flow data.
    
    Handles normalization, scaling, encoding, and feature engineering
    to prepare raw network flow features for ML model consumption.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the feature preprocessor.
        
        Args:
            config: Preprocessor configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.scaler_type = config.get('scaler_type', 'standard')  # standard, minmax, robust
        self.handle_missing = config.get('handle_missing', 'mean')  # mean, median, most_frequent
        self.categorical_encoding = config.get('categorical_encoding', 'onehot')  # onehot, label
        self.feature_selection = config.get('feature_selection', True)
        self.outlier_detection = config.get('outlier_detection', True)
        self.feature_engineering = config.get('feature_engineering', True)
        
        # Preprocessing components
        self.scaler = None
        self.imputer = None
        self.categorical_encoder = None
        self.feature_selector = None
        self.preprocessor_pipeline = None
        
        # Feature metadata
        self.numerical_features = []
        self.categorical_features = []
        self.engineered_features = []
        self.selected_features = []
        self.feature_stats = {}
        
        # State
        self.is_fitted = False
    
    async def initialize(self) -> None:
        """Initialize the preprocessor components."""
        try:
            self._setup_feature_lists()
            self._create_preprocessing_pipeline()
            self._initialized = True
            self.log_info("Feature preprocessor initialized successfully")
        except Exception as e:
            self.log_error("Failed to initialize feature preprocessor", e)
            raise
    
    async def start(self) -> None:
        """Start the preprocessor service."""
        if not self._initialized:
            await self.initialize()
        self._running = True
        self.log_info("Feature preprocessor started")
    
    async def stop(self) -> None:
        """Stop the preprocessor service."""
        self._running = False
        self.log_info("Feature preprocessor stopped")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the preprocessor.
        
        Returns:
            Dictionary containing preprocessor health status
        """
        return {
            'initialized': self._initialized,
            'running': self._running,
            'fitted': self.is_fitted,
            'numerical_features_count': len(self.numerical_features),
            'categorical_features_count': len(self.categorical_features),
            'engineered_features_count': len(self.engineered_features),
            'selected_features_count': len(self.selected_features),
            'scaler_type': self.scaler_type,
            'categorical_encoding': self.categorical_encoding
        }
    
    def _setup_feature_lists(self) -> None:
        """Setup lists of numerical and categorical features."""
        # Numerical features from NetworkFlow model
        self.numerical_features = [
            'source_port', 'destination_port',
            'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
            'duration_ms', 'inter_arrival_mean_ms', 'inter_arrival_std_ms', 'jitter_ms',
            'retransmissions', 'syn_fin_ratio',
            'unique_destinations', 'fan_out_ratio', 'fan_in_ratio', 'port_distribution_entropy'
        ]
        
        # Categorical features
        self.categorical_features = [
            'protocol'
        ]
        
        # Features that will be engineered
        self.engineered_features = [
            'total_bytes', 'total_packets', 'bytes_per_packet_sent', 'bytes_per_packet_received',
            'is_bidirectional', 'port_ratio', 'time_of_day', 'day_of_week'
        ]
    
    def _create_preprocessing_pipeline(self) -> None:
        """Create the preprocessing pipeline."""
        # Create scaler based on configuration
        if self.scaler_type == 'standard':
            self.scaler = StandardScaler()
        elif self.scaler_type == 'minmax':
            self.scaler = MinMaxScaler()
        elif self.scaler_type == 'robust':
            self.scaler = RobustScaler()
        else:
            raise ValueError(f"Unknown scaler type: {self.scaler_type}")
        
        # Create imputer
        self.imputer = SimpleImputer(strategy=self.handle_missing)
        
        # Create categorical encoder
        if self.categorical_encoding == 'onehot':
            self.categorical_encoder = OneHotEncoder(drop='first', sparse_output=False)
        elif self.categorical_encoding == 'label':
            self.categorical_encoder = LabelEncoder()
        else:
            raise ValueError(f"Unknown categorical encoding: {self.categorical_encoding}")
        
        # Create column transformer for different feature types
        self.preprocessor_pipeline = ColumnTransformer([
            ('numerical', Pipeline([
                ('imputer', self.imputer),
                ('scaler', self.scaler)
            ]), self.numerical_features),
            ('categorical', self.categorical_encoder, self.categorical_features)
        ], remainder='passthrough')
    
    async def fit(self, flows: List[NetworkFlow]) -> None:
        """
        Fit the preprocessor on training data.
        
        Args:
            flows: List of NetworkFlow objects for training
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Convert flows to DataFrame
            df = self._flows_to_dataframe(flows)
            
            # Engineer features
            if self.feature_engineering:
                df = self._engineer_features(df)
            
            # Fit the preprocessing pipeline
            self.preprocessor_pipeline.fit(df)
            
            # Calculate feature statistics
            self._calculate_feature_stats(df)
            
            # Select features if enabled
            if self.feature_selection:
                self.selected_features = self._select_features(df)
            else:
                self.selected_features = list(df.columns)
            
            self.is_fitted = True
            self.log_info(f"Preprocessor fitted on {len(flows)} flows with {len(self.selected_features)} features")
            
        except Exception as e:
            self.log_error("Failed to fit preprocessor", e)
            raise
    
    async def transform(self, flows: List[NetworkFlow]) -> pd.DataFrame:
        """
        Transform network flows into preprocessed features.
        
        Args:
            flows: List of NetworkFlow objects to transform
            
        Returns:
            DataFrame with preprocessed features
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transform")
        
        try:
            # Convert flows to DataFrame
            df = self._flows_to_dataframe(flows)
            
            # Engineer features
            if self.feature_engineering:
                df = self._engineer_features(df)
            
            # Apply preprocessing pipeline
            transformed = self.preprocessor_pipeline.transform(df)
            
            # Convert back to DataFrame with proper column names
            feature_names = self._get_feature_names()
            df_transformed = pd.DataFrame(transformed, columns=feature_names)
            
            # Select features if configured
            if self.feature_selection and self.selected_features:
                df_transformed = df_transformed[self.selected_features]
            
            # Handle outliers if enabled
            if self.outlier_detection:
                df_transformed = self._handle_outliers(df_transformed)
            
            return df_transformed
            
        except Exception as e:
            self.log_error("Failed to transform features", e)
            raise
    
    async def fit_transform(self, flows: List[NetworkFlow]) -> pd.DataFrame:
        """
        Fit the preprocessor and transform the data in one step.
        
        Args:
            flows: List of NetworkFlow objects
            
        Returns:
            DataFrame with preprocessed features
        """
        await self.fit(flows)
        return await self.transform(flows)
    
    def _flows_to_dataframe(self, flows: List[NetworkFlow]) -> pd.DataFrame:
        """
        Convert list of NetworkFlow objects to DataFrame.
        
        Args:
            flows: List of NetworkFlow objects
            
        Returns:
            DataFrame with flow features
        """
        data = []
        for flow in flows:
            # Convert flow to dictionary, excluding non-feature fields
            flow_dict = flow.model_dump()
            
            # Remove non-feature fields
            exclude_fields = ['flow_id', 'timestamp', 'source_ip', 'destination_ip', 'tcp_flags']
            for field in exclude_fields:
                flow_dict.pop(field, None)
            
            # Handle TCP flags as count
            flow_dict['tcp_flags_count'] = len(flow.tcp_flags)
            
            data.append(flow_dict)
        
        return pd.DataFrame(data)
    
    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Engineer additional features from raw flow data.
        
        Args:
            df: DataFrame with raw features
            
        Returns:
            DataFrame with engineered features added
        """
        df_eng = df.copy()
        
        # Total bytes and packets
        df_eng['total_bytes'] = df_eng['bytes_sent'] + df_eng['bytes_received']
        df_eng['total_packets'] = df_eng['packets_sent'] + df_eng['packets_received']
        
        # Bytes per packet ratios
        df_eng['bytes_per_packet_sent'] = df_eng['bytes_sent'] / (df_eng['packets_sent'] + 1e-8)
        df_eng['bytes_per_packet_received'] = df_eng['bytes_received'] / (df_eng['packets_received'] + 1e-8)
        
        # Bidirectional communication indicator
        df_eng['is_bidirectional'] = ((df_eng['bytes_sent'] > 0) & (df_eng['bytes_received'] > 0)).astype(int)
        
        # Port ratio (source/destination)
        df_eng['port_ratio'] = df_eng['source_port'] / (df_eng['destination_port'] + 1e-8)
        
        # Time-based features (simplified - would need actual timestamps)
        # For now, create dummy time features
        df_eng['time_of_day'] = np.random.randint(0, 24, len(df_eng))  # Hour of day
        df_eng['day_of_week'] = np.random.randint(0, 7, len(df_eng))   # Day of week
        
        return df_eng
    
    def _calculate_feature_stats(self, df: pd.DataFrame) -> None:
        """
        Calculate feature statistics for monitoring and validation.
        
        Args:
            df: DataFrame with features
        """
        self.feature_stats = {}
        
        for col in df.select_dtypes(include=[np.number]).columns:
            self.feature_stats[col] = {
                'mean': float(df[col].mean()),
                'std': float(df[col].std()),
                'min': float(df[col].min()),
                'max': float(df[col].max()),
                'median': float(df[col].median()),
                'missing_count': int(df[col].isnull().sum())
            }
    
    def _select_features(self, df: pd.DataFrame) -> List[str]:
        """
        Select most important features based on variance and correlation.
        
        Args:
            df: DataFrame with features
            
        Returns:
            List of selected feature names
        """
        # Simple feature selection based on variance
        numerical_cols = df.select_dtypes(include=[np.number]).columns
        variances = df[numerical_cols].var()
        
        # Remove features with very low variance
        low_variance_threshold = 0.01
        selected = variances[variances > low_variance_threshold].index.tolist()
        
        # Add categorical features back
        categorical_cols = df.select_dtypes(exclude=[np.number]).columns
        selected.extend(categorical_cols.tolist())
        
        return selected
    
    def _get_feature_names(self) -> List[str]:
        """
        Get feature names after preprocessing pipeline transformation.
        
        Returns:
            List of feature names
        """
        feature_names = []
        
        # Numerical features (same names)
        feature_names.extend(self.numerical_features)
        
        # Categorical features (depends on encoding)
        if self.categorical_encoding == 'onehot':
            # OneHotEncoder creates multiple columns
            if hasattr(self.categorical_encoder, 'get_feature_names_out'):
                cat_names = self.categorical_encoder.get_feature_names_out(self.categorical_features)
                feature_names.extend(cat_names)
            else:
                # Fallback for older sklearn versions
                feature_names.extend(self.categorical_features)
        else:
            # Label encoding keeps same names
            feature_names.extend(self.categorical_features)
        
        return feature_names
    
    def _handle_outliers(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Handle outliers in the transformed features.
        
        Args:
            df: DataFrame with transformed features
            
        Returns:
            DataFrame with outliers handled
        """
        df_clean = df.copy()
        
        # Use IQR method to cap outliers
        for col in df_clean.select_dtypes(include=[np.number]).columns:
            Q1 = df_clean[col].quantile(0.25)
            Q3 = df_clean[col].quantile(0.75)
            IQR = Q3 - Q1
            
            lower_bound = Q1 - 1.5 * IQR
            upper_bound = Q3 + 1.5 * IQR
            
            # Cap outliers
            df_clean[col] = df_clean[col].clip(lower=lower_bound, upper=upper_bound)
        
        return df_clean
    
    async def save_preprocessor(self, path: str) -> None:
        """
        Save the fitted preprocessor to disk.
        
        Args:
            path: Path to save the preprocessor
        """
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before saving")
        
        try:
            preprocessor_data = {
                'pipeline': self.preprocessor_pipeline,
                'feature_stats': self.feature_stats,
                'selected_features': self.selected_features,
                'numerical_features': self.numerical_features,
                'categorical_features': self.categorical_features,
                'engineered_features': self.engineered_features,
                'config': self.config
            }
            
            joblib.dump(preprocessor_data, path)
            self.log_info(f"Preprocessor saved to {path}")
            
        except Exception as e:
            self.log_error(f"Failed to save preprocessor to {path}", e)
            raise
    
    async def load_preprocessor(self, path: str) -> None:
        """
        Load a fitted preprocessor from disk.
        
        Args:
            path: Path to load the preprocessor from
        """
        try:
            preprocessor_data = joblib.load(path)
            
            self.preprocessor_pipeline = preprocessor_data['pipeline']
            self.feature_stats = preprocessor_data['feature_stats']
            self.selected_features = preprocessor_data['selected_features']
            self.numerical_features = preprocessor_data['numerical_features']
            self.categorical_features = preprocessor_data['categorical_features']
            self.engineered_features = preprocessor_data['engineered_features']
            
            self.is_fitted = True
            self.log_info(f"Preprocessor loaded from {path}")
            
        except Exception as e:
            self.log_error(f"Failed to load preprocessor from {path}", e)
            raise
    
    def get_feature_info(self) -> Dict[str, Any]:
        """
        Get information about features and preprocessing.
        
        Returns:
            Dictionary with feature information
        """
        return {
            'numerical_features': self.numerical_features,
            'categorical_features': self.categorical_features,
            'engineered_features': self.engineered_features,
            'selected_features': self.selected_features,
            'feature_stats': self.feature_stats,
            'scaler_type': self.scaler_type,
            'categorical_encoding': self.categorical_encoding,
            'is_fitted': self.is_fitted
        }