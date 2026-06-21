"""
Drift monitoring and performance tracking for MLOps pipeline.

This module provides statistical drift detection, model performance monitoring,
and automated retraining triggers for maintaining model effectiveness.
"""

from typing import Dict, List, Optional, Any, Tuple, Callable
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
import json
from pathlib import Path
import warnings
from collections import deque, defaultdict

# Statistical libraries
try:
    from scipy import stats
    from scipy.spatial.distance import jensenshannon
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    SCIPY_AVAILABLE = True
except ImportError:
    stats = None
    jensenshannon = None
    StandardScaler = None
    PCA = None
    SCIPY_AVAILABLE = False

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    aiofiles = None
    AIOFILES_AVAILABLE = False

from ..interfaces.base import BaseInterface
from ..utils.error_handling import MLOpsError, ValidationError
from ..models.network_flow import NetworkFlow
from ..models.threat_detection import ThreatDetection


class DriftType(Enum):
    """Types of drift detection."""
    DATA_DRIFT = "data_drift"
    CONCEPT_DRIFT = "concept_drift"
    PREDICTION_DRIFT = "prediction_drift"


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DriftAlert:
    """Drift detection alert."""
    alert_id: str
    model_name: str
    drift_type: DriftType
    severity: AlertSeverity
    detected_at: datetime
    metric_name: str
    current_value: float
    baseline_value: float
    threshold: float
    confidence: float
    description: str
    recommended_actions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['detected_at'] = self.detected_at.isoformat()
        data['drift_type'] = self.drift_type.value
        data['severity'] = self.severity.value
        return data


@dataclass
class PerformanceMetrics:
    """Model performance metrics container."""
    model_name: str
    timestamp: datetime
    
    # Classification metrics
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    
    # Regression metrics
    mse: Optional[float] = None
    mae: Optional[float] = None
    r2_score: Optional[float] = None
    
    # Custom metrics
    threat_detection_rate: Optional[float] = None
    false_positive_rate: Optional[float] = None
    response_time_ms: Optional[float] = None
    
    # Drift metrics
    data_drift_score: Optional[float] = None
    concept_drift_score: Optional[float] = None
    prediction_drift_score: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class DriftMonitor(BaseInterface):
    """
    Statistical drift detection and monitoring system.
    
    Monitors data drift, concept drift, and prediction drift using various
    statistical tests and machine learning techniques.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the drift monitor.
        
        Args:
            config: Drift monitor configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.monitoring_window_hours = config.get('monitoring_window_hours', 24)
        self.baseline_window_days = config.get('baseline_window_days', 7)
        self.drift_threshold = config.get('drift_threshold', 0.05)
        self.alert_threshold = config.get('alert_threshold', 0.1)
        self.min_samples = config.get('min_samples', 100)
        self.max_features_pca = config.get('max_features_pca', 50)
        
        # Drift detection methods
        self.enable_ks_test = config.get('enable_ks_test', True)
        self.enable_js_divergence = config.get('enable_js_divergence', True)
        self.enable_psi = config.get('enable_psi', True)
        self.enable_pca_drift = config.get('enable_pca_drift', True)
        
        # Storage
        self.alerts_path = Path(config.get('alerts_path', 'monitoring/alerts'))
        self.metrics_path = Path(config.get('metrics_path', 'monitoring/metrics'))
        
        # Internal state
        self.baseline_data: Dict[str, pd.DataFrame] = {}  # model_name -> baseline_data
        self.current_data: Dict[str, deque] = {}  # model_name -> current_window_data
        self.feature_scalers: Dict[str, StandardScaler] = {}  # model_name -> scaler
        self.pca_models: Dict[str, PCA] = {}  # model_name -> PCA
        self.alerts: List[DriftAlert] = []
        self.alert_callbacks: List[Callable[[DriftAlert], None]] = []
        
        # Statistics
        self.drift_detections = 0
        self.alerts_sent = 0
        
        # Create directories
        self.alerts_path.mkdir(parents=True, exist_ok=True)
        self.metrics_path.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize the drift monitor."""
        try:
            if not SCIPY_AVAILABLE:
                self.log_warning("SciPy not available - drift detection will be limited")
            
            # Load existing baselines and alerts
            await self._load_baselines()
            await self._load_alerts()
            
            self._initialized = True
            self.log_info("Drift monitor initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize drift monitor", e)
            raise MLOpsError(f"Drift monitor initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the drift monitoring service."""
        if not self._initialized:
            await self.initialize()
        
        self._running = True
        
        # Start monitoring loop
        asyncio.create_task(self._monitoring_loop())
        
        self.log_info("Drift monitor started")
    
    async def stop(self) -> None:
        """Stop the drift monitor."""
        self._running = False
        
        # Save current state
        await self._save_baselines()
        await self._save_alerts()
        
        self.log_info("Drift monitor stopped")
    
    async def update_baseline(self, model_name: str, features: pd.DataFrame) -> None:
        """
        Update baseline data for a model.
        
        Args:
            model_name: Name of the model
            features: Feature data for baseline
        """
        if features.empty or len(features) < self.min_samples:
            raise ValidationError(f"Insufficient samples for baseline: {len(features)}")
        
        try:
            # Store baseline data
            self.baseline_data[model_name] = features.copy()
            
            # Fit feature scaler
            scaler = StandardScaler()
            scaled_features = scaler.fit_transform(features.select_dtypes(include=[np.number]))
            self.feature_scalers[model_name] = scaler
            
            # Fit PCA if enabled and features are high-dimensional
            if self.enable_pca_drift and scaled_features.shape[1] > self.max_features_pca:
                pca = PCA(n_components=min(self.max_features_pca, scaled_features.shape[1]))
                pca.fit(scaled_features)
                self.pca_models[model_name] = pca
            
            # Initialize current data window
            if model_name not in self.current_data:
                self.current_data[model_name] = deque(maxlen=self.min_samples * 2)
            
            await self._save_baselines()
            
            self.log_info(f"Updated baseline for model {model_name} with {len(features)} samples")
            
        except Exception as e:
            self.log_error(f"Failed to update baseline for model {model_name}", e)
            raise MLOpsError(f"Baseline update failed: {e}")
    
    async def monitor_data_drift(self, model_name: str, new_features: pd.DataFrame) -> List[DriftAlert]:
        """
        Monitor for data drift in new features.
        
        Args:
            model_name: Name of the model
            new_features: New feature data to monitor
            
        Returns:
            List of drift alerts if drift is detected
        """
        if model_name not in self.baseline_data:
            raise ValidationError(f"No baseline data found for model {model_name}")
        
        if new_features.empty:
            return []
        
        alerts = []
        baseline = self.baseline_data[model_name]
        
        try:
            # Add to current data window
            for _, row in new_features.iterrows():
                self.current_data[model_name].append(row.to_dict())
            
            # Check if we have enough samples for drift detection
            if len(self.current_data[model_name]) < self.min_samples:
                return []
            
            # Convert current window to DataFrame
            current_df = pd.DataFrame(list(self.current_data[model_name]))
            
            # Align columns
            common_cols = list(set(baseline.columns) & set(current_df.columns))
            baseline_aligned = baseline[common_cols]
            current_aligned = current_df[common_cols]
            
            # Detect drift for each feature
            for col in common_cols:
                if baseline_aligned[col].dtype in ['int64', 'float64']:
                    drift_alerts = await self._detect_numerical_drift(
                        model_name, col, baseline_aligned[col], current_aligned[col]
                    )
                    alerts.extend(drift_alerts)
                else:
                    drift_alerts = await self._detect_categorical_drift(
                        model_name, col, baseline_aligned[col], current_aligned[col]
                    )
                    alerts.extend(drift_alerts)
            
            # Detect multivariate drift using PCA
            if self.enable_pca_drift and model_name in self.pca_models:
                pca_alerts = await self._detect_pca_drift(
                    model_name, baseline_aligned, current_aligned
                )
                alerts.extend(pca_alerts)
            
            # Store alerts
            for alert in alerts:
                self.alerts.append(alert)
                await self._trigger_alert(alert)
            
            if alerts:
                self.drift_detections += 1
                self.log_warning(f"Data drift detected for model {model_name}: {len(alerts)} alerts")
            
            return alerts
            
        except Exception as e:
            self.log_error(f"Failed to monitor data drift for model {model_name}", e)
            raise MLOpsError(f"Data drift monitoring failed: {e}")
    
    async def monitor_prediction_drift(
        self, 
        model_name: str, 
        predictions: np.ndarray, 
        baseline_predictions: Optional[np.ndarray] = None
    ) -> List[DriftAlert]:
        """
        Monitor for prediction drift.
        
        Args:
            model_name: Name of the model
            predictions: New predictions to monitor
            baseline_predictions: Baseline predictions (if None, uses stored baseline)
            
        Returns:
            List of drift alerts if drift is detected
        """
        alerts = []
        
        try:
            if baseline_predictions is None:
                # Use stored baseline predictions if available
                baseline_key = f"{model_name}_predictions"
                if baseline_key not in self.baseline_data:
                    self.log_warning(f"No baseline predictions found for model {model_name}")
                    return []
                baseline_predictions = self.baseline_data[baseline_key].values.flatten()
            
            # Detect distribution shift in predictions
            if len(predictions) >= self.min_samples and len(baseline_predictions) >= self.min_samples:
                # KS test for prediction distributions
                if self.enable_ks_test:
                    ks_stat, p_value = stats.ks_2samp(baseline_predictions, predictions)
                    
                    if p_value < self.drift_threshold:
                        alert = DriftAlert(
                            alert_id=f"pred_drift_{model_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                            model_name=model_name,
                            drift_type=DriftType.PREDICTION_DRIFT,
                            severity=self._get_severity(p_value, self.drift_threshold),
                            detected_at=datetime.utcnow(),
                            metric_name="ks_test_predictions",
                            current_value=ks_stat,
                            baseline_value=0.0,
                            threshold=self.drift_threshold,
                            confidence=1.0 - p_value,
                            description=f"Prediction distribution drift detected (KS statistic: {ks_stat:.4f})",
                            recommended_actions=[
                                "Review recent model predictions",
                                "Check for changes in input data distribution",
                                "Consider model retraining",
                                "Investigate potential concept drift"
                            ]
                        )
                        alerts.append(alert)
                
                # Jensen-Shannon divergence
                if self.enable_js_divergence:
                    js_div = self._calculate_js_divergence(baseline_predictions, predictions)
                    
                    if js_div > self.alert_threshold:
                        alert = DriftAlert(
                            alert_id=f"pred_js_drift_{model_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                            model_name=model_name,
                            drift_type=DriftType.PREDICTION_DRIFT,
                            severity=self._get_severity(js_div, self.alert_threshold),
                            detected_at=datetime.utcnow(),
                            metric_name="js_divergence_predictions",
                            current_value=js_div,
                            baseline_value=0.0,
                            threshold=self.alert_threshold,
                            confidence=min(js_div / self.alert_threshold, 1.0),
                            description=f"Prediction distribution divergence detected (JS divergence: {js_div:.4f})",
                            recommended_actions=[
                                "Analyze prediction distribution changes",
                                "Check model performance metrics",
                                "Consider prediction calibration",
                                "Evaluate need for model update"
                            ]
                        )
                        alerts.append(alert)
            
            # Store alerts
            for alert in alerts:
                self.alerts.append(alert)
                await self._trigger_alert(alert)
            
            if alerts:
                self.drift_detections += 1
                self.log_warning(f"Prediction drift detected for model {model_name}: {len(alerts)} alerts")
            
            return alerts
            
        except Exception as e:
            self.log_error(f"Failed to monitor prediction drift for model {model_name}", e)
            raise MLOpsError(f"Prediction drift monitoring failed: {e}")
    
    def add_alert_callback(self, callback: Callable[[DriftAlert], None]) -> None:
        """
        Add callback function for drift alerts.
        
        Args:
            callback: Function to call when drift is detected
        """
        self.alert_callbacks.append(callback)
    
    def get_recent_alerts(self, hours: int = 24) -> List[DriftAlert]:
        """
        Get recent drift alerts.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of recent alerts
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [alert for alert in self.alerts if alert.detected_at >= cutoff_time]
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the drift monitor.
        
        Returns:
            Dictionary containing drift monitor health status
        """
        recent_alerts = self.get_recent_alerts(24)
        
        return {
            'initialized': self._initialized,
            'running': self._running,
            'monitored_models': len(self.baseline_data),
            'total_alerts': len(self.alerts),
            'recent_alerts_24h': len(recent_alerts),
            'drift_detections': self.drift_detections,
            'alerts_sent': self.alerts_sent,
            'alert_callbacks': len(self.alert_callbacks),
            'monitoring_window_hours': self.monitoring_window_hours,
            'drift_threshold': self.drift_threshold
        }
    
    async def _detect_numerical_drift(
        self, 
        model_name: str, 
        feature_name: str, 
        baseline: pd.Series, 
        current: pd.Series
    ) -> List[DriftAlert]:
        """Detect drift in numerical features."""
        alerts = []
        
        # Remove NaN values
        baseline_clean = baseline.dropna()
        current_clean = current.dropna()
        
        if len(baseline_clean) < self.min_samples or len(current_clean) < self.min_samples:
            return alerts
        
        # Kolmogorov-Smirnov test
        if self.enable_ks_test:
            ks_stat, p_value = stats.ks_2samp(baseline_clean, current_clean)
            
            if p_value < self.drift_threshold:
                alert = DriftAlert(
                    alert_id=f"ks_drift_{model_name}_{feature_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                    model_name=model_name,
                    drift_type=DriftType.DATA_DRIFT,
                    severity=self._get_severity(p_value, self.drift_threshold),
                    detected_at=datetime.utcnow(),
                    metric_name=f"ks_test_{feature_name}",
                    current_value=ks_stat,
                    baseline_value=0.0,
                    threshold=self.drift_threshold,
                    confidence=1.0 - p_value,
                    description=f"Data drift detected in feature '{feature_name}' (KS statistic: {ks_stat:.4f})",
                    recommended_actions=[
                        f"Investigate changes in feature '{feature_name}'",
                        "Check data collection pipeline",
                        "Consider feature engineering updates",
                        "Evaluate model retraining"
                    ]
                )
                alerts.append(alert)
        
        # Population Stability Index (PSI)
        if self.enable_psi:
            psi_score = self._calculate_psi(baseline_clean, current_clean)
            
            if psi_score > self.alert_threshold:
                alert = DriftAlert(
                    alert_id=f"psi_drift_{model_name}_{feature_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                    model_name=model_name,
                    drift_type=DriftType.DATA_DRIFT,
                    severity=self._get_severity(psi_score, self.alert_threshold),
                    detected_at=datetime.utcnow(),
                    metric_name=f"psi_{feature_name}",
                    current_value=psi_score,
                    baseline_value=0.0,
                    threshold=self.alert_threshold,
                    confidence=min(psi_score / self.alert_threshold, 1.0),
                    description=f"Population stability drift in feature '{feature_name}' (PSI: {psi_score:.4f})",
                    recommended_actions=[
                        f"Analyze distribution changes in '{feature_name}'",
                        "Check for data quality issues",
                        "Review feature preprocessing",
                        "Consider model recalibration"
                    ]
                )
                alerts.append(alert)
        
        return alerts
    
    async def _detect_categorical_drift(
        self, 
        model_name: str, 
        feature_name: str, 
        baseline: pd.Series, 
        current: pd.Series
    ) -> List[DriftAlert]:
        """Detect drift in categorical features."""
        alerts = []
        
        # Remove NaN values
        baseline_clean = baseline.dropna()
        current_clean = current.dropna()
        
        if len(baseline_clean) < self.min_samples or len(current_clean) < self.min_samples:
            return alerts
        
        # Chi-square test for categorical distributions
        try:
            # Get value counts
            baseline_counts = baseline_clean.value_counts()
            current_counts = current_clean.value_counts()
            
            # Align categories
            all_categories = set(baseline_counts.index) | set(current_counts.index)
            baseline_aligned = [baseline_counts.get(cat, 0) for cat in all_categories]
            current_aligned = [current_counts.get(cat, 0) for cat in all_categories]
            
            # Chi-square test
            chi2_stat, p_value = stats.chisquare(current_aligned, baseline_aligned)
            
            if p_value < self.drift_threshold:
                alert = DriftAlert(
                    alert_id=f"chi2_drift_{model_name}_{feature_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                    model_name=model_name,
                    drift_type=DriftType.DATA_DRIFT,
                    severity=self._get_severity(p_value, self.drift_threshold),
                    detected_at=datetime.utcnow(),
                    metric_name=f"chi2_test_{feature_name}",
                    current_value=chi2_stat,
                    baseline_value=0.0,
                    threshold=self.drift_threshold,
                    confidence=1.0 - p_value,
                    description=f"Categorical drift detected in feature '{feature_name}' (Chi-square: {chi2_stat:.4f})",
                    recommended_actions=[
                        f"Review category distribution changes in '{feature_name}'",
                        "Check for new categories or missing values",
                        "Validate data encoding consistency",
                        "Consider feature mapping updates"
                    ]
                )
                alerts.append(alert)
                
        except Exception as e:
            self.log_warning(f"Failed to perform chi-square test for {feature_name}: {e}")
        
        return alerts
    
    async def _detect_pca_drift(
        self, 
        model_name: str, 
        baseline: pd.DataFrame, 
        current: pd.DataFrame
    ) -> List[DriftAlert]:
        """Detect multivariate drift using PCA."""
        alerts = []
        
        if model_name not in self.pca_models or model_name not in self.feature_scalers:
            return alerts
        
        try:
            pca = self.pca_models[model_name]
            scaler = self.feature_scalers[model_name]
            
            # Select numerical features
            numerical_cols = baseline.select_dtypes(include=[np.number]).columns
            baseline_num = baseline[numerical_cols]
            current_num = current[numerical_cols]
            
            if baseline_num.empty or current_num.empty:
                return alerts
            
            # Scale and transform
            baseline_scaled = scaler.transform(baseline_num.fillna(0))
            current_scaled = scaler.transform(current_num.fillna(0))
            
            baseline_pca = pca.transform(baseline_scaled)
            current_pca = pca.transform(current_scaled)
            
            # Compare PCA distributions for each component
            for i in range(min(3, pca.n_components_)):  # Check first 3 components
                ks_stat, p_value = stats.ks_2samp(baseline_pca[:, i], current_pca[:, i])
                
                if p_value < self.drift_threshold:
                    alert = DriftAlert(
                        alert_id=f"pca_drift_{model_name}_pc{i+1}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
                        model_name=model_name,
                        drift_type=DriftType.DATA_DRIFT,
                        severity=self._get_severity(p_value, self.drift_threshold),
                        detected_at=datetime.utcnow(),
                        metric_name=f"pca_component_{i+1}",
                        current_value=ks_stat,
                        baseline_value=0.0,
                        threshold=self.drift_threshold,
                        confidence=1.0 - p_value,
                        description=f"Multivariate drift detected in PCA component {i+1} (KS: {ks_stat:.4f})",
                        recommended_actions=[
                            "Investigate multivariate feature relationships",
                            "Check for correlated feature changes",
                            "Review feature engineering pipeline",
                            "Consider dimensionality reduction updates"
                        ]
                    )
                    alerts.append(alert)
        
        except Exception as e:
            self.log_error(f"Failed to detect PCA drift for model {model_name}", e)
        
        return alerts
    
    def _calculate_psi(self, baseline: pd.Series, current: pd.Series, bins: int = 10) -> float:
        """Calculate Population Stability Index (PSI)."""
        try:
            # Create bins based on baseline quantiles
            _, bin_edges = pd.cut(baseline, bins=bins, retbins=True, duplicates='drop')
            
            # Calculate distributions
            baseline_dist = pd.cut(baseline, bins=bin_edges, include_lowest=True).value_counts(normalize=True)
            current_dist = pd.cut(current, bins=bin_edges, include_lowest=True).value_counts(normalize=True)
            
            # Align distributions
            baseline_dist = baseline_dist.reindex(baseline_dist.index.union(current_dist.index), fill_value=0.001)
            current_dist = current_dist.reindex(baseline_dist.index, fill_value=0.001)
            
            # Calculate PSI
            psi = np.sum((current_dist - baseline_dist) * np.log(current_dist / baseline_dist))
            
            return psi
            
        except Exception:
            return 0.0
    
    def _calculate_js_divergence(self, baseline: np.ndarray, current: np.ndarray, bins: int = 50) -> float:
        """Calculate Jensen-Shannon divergence between two distributions."""
        try:
            # Create histograms
            min_val = min(baseline.min(), current.min())
            max_val = max(baseline.max(), current.max())
            bin_edges = np.linspace(min_val, max_val, bins + 1)
            
            baseline_hist, _ = np.histogram(baseline, bins=bin_edges, density=True)
            current_hist, _ = np.histogram(current, bins=bin_edges, density=True)
            
            # Normalize to probabilities
            baseline_prob = baseline_hist / np.sum(baseline_hist)
            current_prob = current_hist / np.sum(current_hist)
            
            # Add small epsilon to avoid log(0)
            epsilon = 1e-10
            baseline_prob = baseline_prob + epsilon
            current_prob = current_prob + epsilon
            
            # Calculate JS divergence
            js_div = jensenshannon(baseline_prob, current_prob)
            
            return js_div
            
        except Exception:
            return 0.0
    
    def _get_severity(self, value: float, threshold: float) -> AlertSeverity:
        """Determine alert severity based on value and threshold."""
        ratio = value / threshold if threshold > 0 else float('inf')
        
        if ratio >= 10:
            return AlertSeverity.CRITICAL
        elif ratio >= 5:
            return AlertSeverity.HIGH
        elif ratio >= 2:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
    
    async def _trigger_alert(self, alert: DriftAlert) -> None:
        """Trigger alert callbacks and save alert."""
        try:
            # Call registered callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.log_error(f"Alert callback failed: {e}")
            
            # Save alert to disk
            alert_file = self.alerts_path / f"alert_{alert.alert_id}.json"
            async with aiofiles.open(alert_file, 'w') as f:
                await f.write(json.dumps(alert.to_dict(), indent=2))
            
            self.alerts_sent += 1
            
        except Exception as e:
            self.log_error(f"Failed to trigger alert {alert.alert_id}", e)
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                # Periodic cleanup of old alerts
                await self._cleanup_old_alerts()
                
                # Sleep for monitoring interval
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.log_error("Error in monitoring loop", e)
                await asyncio.sleep(60)  # Short sleep on error
    
    async def _cleanup_old_alerts(self) -> None:
        """Cleanup old alerts based on retention policy."""
        try:
            retention_days = 30  # Keep alerts for 30 days
            cutoff_time = datetime.utcnow() - timedelta(days=retention_days)
            
            # Remove old alerts from memory
            self.alerts = [alert for alert in self.alerts if alert.detected_at >= cutoff_time]
            
            # Remove old alert files
            for alert_file in self.alerts_path.glob("alert_*.json"):
                if alert_file.stat().st_mtime < cutoff_time.timestamp():
                    alert_file.unlink()
            
        except Exception as e:
            self.log_error("Failed to cleanup old alerts", e)
    
    async def _load_baselines(self) -> None:
        """Load baseline data from disk."""
        baseline_file = self.metrics_path / 'baselines.json'
        
        if not baseline_file.exists():
            return
        
        try:
            if AIOFILES_AVAILABLE:
                async with aiofiles.open(baseline_file, 'r') as f:
                    content = await f.read()
            else:
                with open(baseline_file, 'r') as f:
                    content = f.read()
            
            data = json.loads(content)
            
            # Load baseline DataFrames
            for model_name, baseline_data in data.get('baselines', {}).items():
                self.baseline_data[model_name] = pd.DataFrame(baseline_data)
            
            self.log_info(f"Loaded baselines for {len(self.baseline_data)} models")
            
        except Exception as e:
            self.log_error("Failed to load baselines", e)
    
    async def _save_baselines(self) -> None:
        """Save baseline data to disk."""
        baseline_file = self.metrics_path / 'baselines.json'
        
        try:
            # Convert DataFrames to serializable format
            baselines_data = {}
            for model_name, df in self.baseline_data.items():
                baselines_data[model_name] = df.to_dict('records')
            
            data = {
                'baselines': baselines_data,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            if AIOFILES_AVAILABLE:
                async with aiofiles.open(baseline_file, 'w') as f:
                    await f.write(json.dumps(data, indent=2))
            else:
                with open(baseline_file, 'w') as f:
                    f.write(json.dumps(data, indent=2))
            
        except Exception as e:
            self.log_error("Failed to save baselines", e)
    
    async def _load_alerts(self) -> None:
        """Load recent alerts from disk."""
        try:
            for alert_file in self.alerts_path.glob("alert_*.json"):
                try:
                    async with aiofiles.open(alert_file, 'r') as f:
                        content = await f.read()
                        alert_data = json.loads(content)
                    
                    alert = DriftAlert(
                        alert_id=alert_data['alert_id'],
                        model_name=alert_data['model_name'],
                        drift_type=DriftType(alert_data['drift_type']),
                        severity=AlertSeverity(alert_data['severity']),
                        detected_at=datetime.fromisoformat(alert_data['detected_at']),
                        metric_name=alert_data['metric_name'],
                        current_value=alert_data['current_value'],
                        baseline_value=alert_data['baseline_value'],
                        threshold=alert_data['threshold'],
                        confidence=alert_data['confidence'],
                        description=alert_data['description'],
                        recommended_actions=alert_data['recommended_actions']
                    )
                    
                    self.alerts.append(alert)
                    
                except Exception as e:
                    self.log_warning(f"Failed to load alert from {alert_file}: {e}")
            
            self.log_info(f"Loaded {len(self.alerts)} alerts")
            
        except Exception as e:
            self.log_error("Failed to load alerts", e)
    
    async def _save_alerts(self) -> None:
        """Save recent alerts to disk."""
        # Alerts are saved individually when triggered
        pass


class PerformanceTracker(BaseInterface):
    """
    Model performance tracking and monitoring system.
    
    Tracks model performance metrics over time and triggers alerts
    when performance degrades below acceptable thresholds.
    """
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        """
        Initialize the performance tracker.
        
        Args:
            config: Performance tracker configuration
            logger: Optional logger instance
        """
        super().__init__(config, logger)
        
        # Configuration
        self.tracking_window_hours = config.get('tracking_window_hours', 24)
        self.performance_threshold = config.get('performance_threshold', 0.1)  # 10% degradation
        self.min_samples_for_tracking = config.get('min_samples_for_tracking', 50)
        
        # Storage
        self.metrics_path = Path(config.get('metrics_path', 'monitoring/performance'))
        
        # Internal state
        self.performance_history: Dict[str, List[PerformanceMetrics]] = defaultdict(list)
        self.baseline_performance: Dict[str, PerformanceMetrics] = {}
        self.performance_callbacks: List[Callable[[str, PerformanceMetrics], None]] = []
        
        # Statistics
        self.metrics_recorded = 0
        self.performance_alerts = 0
        
        # Create directories
        self.metrics_path.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize the performance tracker."""
        try:
            # Load existing performance history
            await self._load_performance_history()
            
            self._initialized = True
            self.log_info("Performance tracker initialized successfully")
            
        except Exception as e:
            self.log_error("Failed to initialize performance tracker", e)
            raise MLOpsError(f"Performance tracker initialization failed: {e}")
    
    async def start(self) -> None:
        """Start the performance tracking service."""
        if not self._initialized:
            await self.initialize()
        
        self._running = True
        self.log_info("Performance tracker started")
    
    async def stop(self) -> None:
        """Stop the performance tracker."""
        self._running = False
        
        # Save performance history
        await self._save_performance_history()
        
        self.log_info("Performance tracker stopped")
    
    async def record_performance(self, model_name: str, metrics: PerformanceMetrics) -> None:
        """
        Record performance metrics for a model.
        
        Args:
            model_name: Name of the model
            metrics: Performance metrics to record
        """
        if not self._running:
            return
        
        try:
            # Add to history
            self.performance_history[model_name].append(metrics)
            
            # Keep only recent metrics
            cutoff_time = datetime.utcnow() - timedelta(hours=self.tracking_window_hours * 7)  # Keep 7 windows
            self.performance_history[model_name] = [
                m for m in self.performance_history[model_name] 
                if m.timestamp >= cutoff_time
            ]
            
            # Check for performance degradation
            await self._check_performance_degradation(model_name, metrics)
            
            # Save metrics
            await self._save_performance_metrics(model_name, metrics)
            
            self.metrics_recorded += 1
            
        except Exception as e:
            self.log_error(f"Failed to record performance for model {model_name}", e)
    
    async def set_baseline_performance(self, model_name: str, metrics: PerformanceMetrics) -> None:
        """
        Set baseline performance metrics for a model.
        
        Args:
            model_name: Name of the model
            metrics: Baseline performance metrics
        """
        self.baseline_performance[model_name] = metrics
        await self._save_performance_history()
        
        self.log_info(f"Set baseline performance for model {model_name}")
    
    def add_performance_callback(self, callback: Callable[[str, PerformanceMetrics], None]) -> None:
        """
        Add callback function for performance updates.
        
        Args:
            callback: Function to call when performance is recorded
        """
        self.performance_callbacks.append(callback)
    
    def get_recent_performance(self, model_name: str, hours: int = 24) -> List[PerformanceMetrics]:
        """
        Get recent performance metrics for a model.
        
        Args:
            model_name: Name of the model
            hours: Number of hours to look back
            
        Returns:
            List of recent performance metrics
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            m for m in self.performance_history.get(model_name, [])
            if m.timestamp >= cutoff_time
        ]
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the performance tracker.
        
        Returns:
            Dictionary containing performance tracker health status
        """
        return {
            'initialized': self._initialized,
            'running': self._running,
            'tracked_models': len(self.performance_history),
            'baseline_models': len(self.baseline_performance),
            'metrics_recorded': self.metrics_recorded,
            'performance_alerts': self.performance_alerts,
            'performance_callbacks': len(self.performance_callbacks),
            'tracking_window_hours': self.tracking_window_hours
        }
    
    async def _check_performance_degradation(self, model_name: str, current_metrics: PerformanceMetrics) -> None:
        """Check for performance degradation and trigger alerts."""
        if model_name not in self.baseline_performance:
            return
        
        baseline = self.baseline_performance[model_name]
        
        # Check key performance metrics
        degradation_detected = False
        
        # Check accuracy degradation
        if baseline.accuracy is not None and current_metrics.accuracy is not None:
            degradation = (baseline.accuracy - current_metrics.accuracy) / baseline.accuracy
            if degradation > self.performance_threshold:
                degradation_detected = True
                self.log_warning(f"Accuracy degradation detected for {model_name}: {degradation:.2%}")
        
        # Check F1 score degradation
        if baseline.f1_score is not None and current_metrics.f1_score is not None:
            degradation = (baseline.f1_score - current_metrics.f1_score) / baseline.f1_score
            if degradation > self.performance_threshold:
                degradation_detected = True
                self.log_warning(f"F1 score degradation detected for {model_name}: {degradation:.2%}")
        
        # Check threat detection rate degradation
        if baseline.threat_detection_rate is not None and current_metrics.threat_detection_rate is not None:
            degradation = (baseline.threat_detection_rate - current_metrics.threat_detection_rate) / baseline.threat_detection_rate
            if degradation > self.performance_threshold:
                degradation_detected = True
                self.log_warning(f"Threat detection rate degradation detected for {model_name}: {degradation:.2%}")
        
        if degradation_detected:
            self.performance_alerts += 1
            
            # Trigger callbacks
            for callback in self.performance_callbacks:
                try:
                    callback(model_name, current_metrics)
                except Exception as e:
                    self.log_error(f"Performance callback failed: {e}")
    
    async def _save_performance_metrics(self, model_name: str, metrics: PerformanceMetrics) -> None:
        """Save individual performance metrics to disk."""
        try:
            metrics_file = self.metrics_path / f"{model_name}_metrics.jsonl"
            
            # Append metrics to JSONL file
            async with aiofiles.open(metrics_file, 'a') as f:
                await f.write(json.dumps(metrics.to_dict()) + '\n')
            
        except Exception as e:
            self.log_error(f"Failed to save performance metrics for {model_name}", e)
    
    async def _load_performance_history(self) -> None:
        """Load performance history from disk."""
        try:
            for metrics_file in self.metrics_path.glob("*_metrics.jsonl"):
                model_name = metrics_file.stem.replace('_metrics', '')
                
                async with aiofiles.open(metrics_file, 'r') as f:
                    async for line in f:
                        try:
                            metrics_data = json.loads(line.strip())
                            metrics = PerformanceMetrics(
                                model_name=metrics_data['model_name'],
                                timestamp=datetime.fromisoformat(metrics_data['timestamp']),
                                accuracy=metrics_data.get('accuracy'),
                                precision=metrics_data.get('precision'),
                                recall=metrics_data.get('recall'),
                                f1_score=metrics_data.get('f1_score'),
                                mse=metrics_data.get('mse'),
                                mae=metrics_data.get('mae'),
                                r2_score=metrics_data.get('r2_score'),
                                threat_detection_rate=metrics_data.get('threat_detection_rate'),
                                false_positive_rate=metrics_data.get('false_positive_rate'),
                                response_time_ms=metrics_data.get('response_time_ms'),
                                data_drift_score=metrics_data.get('data_drift_score'),
                                concept_drift_score=metrics_data.get('concept_drift_score'),
                                prediction_drift_score=metrics_data.get('prediction_drift_score')
                            )
                            
                            self.performance_history[model_name].append(metrics)
                            
                        except Exception as e:
                            self.log_warning(f"Failed to parse metrics line: {e}")
            
            # Load baselines
            baseline_file = self.metrics_path / 'baselines.json'
            if baseline_file.exists():
                async with aiofiles.open(baseline_file, 'r') as f:
                    content = await f.read()
                    data = json.loads(content)
                
                for model_name, baseline_data in data.get('baselines', {}).items():
                    self.baseline_performance[model_name] = PerformanceMetrics(
                        model_name=baseline_data['model_name'],
                        timestamp=datetime.fromisoformat(baseline_data['timestamp']),
                        accuracy=baseline_data.get('accuracy'),
                        precision=baseline_data.get('precision'),
                        recall=baseline_data.get('recall'),
                        f1_score=baseline_data.get('f1_score'),
                        mse=baseline_data.get('mse'),
                        mae=baseline_data.get('mae'),
                        r2_score=baseline_data.get('r2_score'),
                        threat_detection_rate=baseline_data.get('threat_detection_rate'),
                        false_positive_rate=baseline_data.get('false_positive_rate'),
                        response_time_ms=baseline_data.get('response_time_ms'),
                        data_drift_score=baseline_data.get('data_drift_score'),
                        concept_drift_score=baseline_data.get('concept_drift_score'),
                        prediction_drift_score=baseline_data.get('prediction_drift_score')
                    )
            
            total_metrics = sum(len(history) for history in self.performance_history.values())
            self.log_info(f"Loaded {total_metrics} performance metrics for {len(self.performance_history)} models")
            
        except Exception as e:
            self.log_error("Failed to load performance history", e)
    
    async def _save_performance_history(self) -> None:
        """Save performance baselines to disk."""
        try:
            baseline_file = self.metrics_path / 'baselines.json'
            
            baselines_data = {}
            for model_name, baseline in self.baseline_performance.items():
                baselines_data[model_name] = baseline.to_dict()
            
            data = {
                'baselines': baselines_data,
                'last_updated': datetime.utcnow().isoformat()
            }
            
            async with aiofiles.open(baseline_file, 'w') as f:
                await f.write(json.dumps(data, indent=2))
            
        except Exception as e:
            self.log_error("Failed to save performance history", e)