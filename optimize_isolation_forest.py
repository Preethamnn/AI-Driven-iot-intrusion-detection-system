#!/usr/bin/env python3
"""
Isolation Forest Model Optimization Script

This script optimizes the Isolation Forest model for maximum accuracy
by implementing advanced feature engineering, hyperparameter tuning,
and ensemble methods.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from sklearn.decomposition import PCA
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings('ignore')

def load_and_engineer_features():
    """Load data and perform advanced feature engineering."""
    print("Loading and engineering features...")
    
    # Load the CSV data
    df = pd.read_csv('train_test_network.csv')
    print(f"Original dataset shape: {df.shape}")
    
    # Basic numeric features
    numeric_cols = ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes', 
                   'missed_bytes', 'src_pkts', 'dst_pkts', 'src_ip_bytes', 'dst_ip_bytes',
                   'dns_qclass', 'dns_qtype', 'dns_rcode', 'http_trans_depth',
                   'http_request_body_len', 'http_response_body_len', 'http_status_code']
    
    # Convert columns to numeric, replacing non-numeric values with 0
    X_basic = df[numeric_cols].copy()
    for col in numeric_cols:
        X_basic[col] = pd.to_numeric(X_basic[col], errors='coerce').fillna(0)
    
    # Advanced feature engineering
    features = X_basic.copy()
    
    # 1. Ratio features
    features['bytes_ratio'] = np.where(features['dst_bytes'] > 0, 
                                     features['src_bytes'] / features['dst_bytes'], 0)
    features['packets_ratio'] = np.where(features['dst_pkts'] > 0,
                                       features['src_pkts'] / features['dst_pkts'], 0)
    features['bytes_per_packet_src'] = np.where(features['src_pkts'] > 0,
                                              features['src_bytes'] / features['src_pkts'], 0)
    features['bytes_per_packet_dst'] = np.where(features['dst_pkts'] > 0,
                                              features['dst_bytes'] / features['dst_pkts'], 0)
    
    # 2. Traffic intensity features
    features['total_bytes'] = features['src_bytes'] + features['dst_bytes']
    features['total_packets'] = features['src_pkts'] + features['dst_pkts']
    features['avg_packet_size'] = np.where(features['total_packets'] > 0,
                                         features['total_bytes'] / features['total_packets'], 0)
    
    # 3. Duration-based features
    features['bytes_per_second'] = np.where(features['duration'] > 0,
                                          features['total_bytes'] / features['duration'], 0)
    features['packets_per_second'] = np.where(features['duration'] > 0,
                                            features['total_packets'] / features['duration'], 0)
    
    # 4. Port-based features
    features['is_well_known_src_port'] = (features['src_port'] <= 1024).astype(int)
    features['is_well_known_dst_port'] = (features['dst_port'] <= 1024).astype(int)
    features['port_difference'] = np.abs(features['src_port'] - features['dst_port'])
    
    # 5. Statistical features
    features['log_duration'] = np.log1p(features['duration'])
    features['log_total_bytes'] = np.log1p(features['total_bytes'])
    features['sqrt_total_packets'] = np.sqrt(features['total_packets'])
    
    # 6. Binary indicators
    features['has_missed_bytes'] = (features['missed_bytes'] > 0).astype(int)
    features['has_dns'] = ((features['dns_qclass'] > 0) | (features['dns_qtype'] > 0)).astype(int)
    features['has_http'] = (features['http_status_code'] > 0).astype(int)
    
    # Remove infinite and NaN values
    features = features.replace([np.inf, -np.inf], 0)
    features = features.fillna(0)
    
    print(f"Engineered features shape: {features.shape}")
    print(f"New features added: {features.shape[1] - len(numeric_cols)}")
    
    return features, df['label'].values

def optimize_isolation_forest_hyperparameters(X_train, y_train, X_val, y_val):
    """Optimize Isolation Forest hyperparameters using grid search."""
    print("\nOptimizing Isolation Forest hyperparameters...")
    
    # Define parameter grid
    param_grid = {
        'contamination': [0.05, 0.1, 0.15, 0.2, 0.25],
        'n_estimators': [50, 100, 200, 300],
        'max_samples': ['auto', 0.5, 0.7, 0.9],
        'max_features': [0.5, 0.7, 0.9, 1.0]
    }
    
    best_score = 0
    best_params = None
    best_model = None
    
    print("Testing parameter combinations...")
    total_combinations = len(param_grid['contamination']) * len(param_grid['n_estimators']) * \
                        len(param_grid['max_samples']) * len(param_grid['max_features'])
    
    current_combination = 0
    
    for contamination in param_grid['contamination']:
        for n_estimators in param_grid['n_estimators']:
            for max_samples in param_grid['max_samples']:
                for max_features in param_grid['max_features']:
                    current_combination += 1
                    
                    if current_combination % 10 == 0:
                        print(f"Progress: {current_combination}/{total_combinations}")
                    
                    try:
                        # Train model with current parameters
                        model = IsolationForest(
                            contamination=contamination,
                            n_estimators=n_estimators,
                            max_samples=max_samples,
                            max_features=max_features,
                            random_state=42,
                            n_jobs=-1
                        )
                        
                        # Fit on normal data only
                        model.fit(X_train[y_train == 0])
                        
                        # Predict on validation set
                        y_pred = (model.predict(X_val) == -1).astype(int)
                        
                        # Calculate F1 score (better for imbalanced data)
                        f1 = f1_score(y_val, y_pred, zero_division=0)
                        
                        if f1 > best_score:
                            best_score = f1
                            best_params = {
                                'contamination': contamination,
                                'n_estimators': n_estimators,
                                'max_samples': max_samples,
                                'max_features': max_features
                            }
                            best_model = model
                            
                    except Exception as e:
                        continue
    
    print(f"\nBest parameters found:")
    for param, value in best_params.items():
        print(f"  {param}: {value}")
    print(f"Best F1 score: {best_score:.4f}")
    
    return best_model, best_params

def create_ensemble_isolation_forest(X_train, y_train, n_models=5):
    """Create an ensemble of Isolation Forest models with different configurations."""
    print(f"\nCreating ensemble of {n_models} Isolation Forest models...")
    
    models = []
    configs = [
        {'contamination': 0.1, 'n_estimators': 200, 'max_samples': 0.7, 'max_features': 0.8},
        {'contamination': 0.15, 'n_estimators': 150, 'max_samples': 0.8, 'max_features': 0.9},
        {'contamination': 0.08, 'n_estimators': 250, 'max_samples': 0.6, 'max_features': 0.7},
        {'contamination': 0.12, 'n_estimators': 180, 'max_samples': 0.9, 'max_features': 1.0},
        {'contamination': 0.2, 'n_estimators': 100, 'max_samples': 0.5, 'max_features': 0.6}
    ]
    
    for i, config in enumerate(configs[:n_models]):
        print(f"Training model {i+1}/{n_models}...")
        model = IsolationForest(
            random_state=42 + i,
            n_jobs=-1,
            **config
        )
        model.fit(X_train[y_train == 0])
        models.append(model)
    
    return models

def ensemble_predict(models, X):
    """Make ensemble predictions using majority voting."""
    predictions = []
    
    for model in models:
        pred = (model.predict(X) == -1).astype(int)
        predictions.append(pred)
    
    # Majority voting
    predictions = np.array(predictions)
    ensemble_pred = (np.mean(predictions, axis=0) >= 0.5).astype(int)
    
    return ensemble_pred

def evaluate_model(y_true, y_pred, model_name):
    """Evaluate model performance."""
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    print(f"\n{model_name} Results:")
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1
    }

def main():
    """Main optimization function."""
    print("🚀 ISOLATION FOREST OPTIMIZATION")
    print("=" * 50)
    
    # Load and engineer features
    X, y = load_and_engineer_features()
    
    print(f"Dataset info:")
    print(f"  Total samples: {len(X)}")
    print(f"  Normal samples: {sum(y == 0)}")
    print(f"  Threat samples: {sum(y == 1)}")
    print(f"  Features: {X.shape[1]}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    X_train_split, X_val, y_train_split, y_val = train_test_split(
        X_train, y_train, test_size=0.3, random_state=42, stratify=y_train
    )
    
    # Feature scaling (try different scalers)
    scalers = {
        'StandardScaler': StandardScaler(),
        'RobustScaler': RobustScaler(),
        'MinMaxScaler': MinMaxScaler()
    }
    
    best_scaler_name = None
    best_scaler_score = 0
    best_scaler = None
    
    print("\n🔍 Testing different feature scalers...")
    for scaler_name, scaler in scalers.items():
        print(f"\nTesting {scaler_name}...")
        
        # Scale features
        X_train_scaled = scaler.fit_transform(X_train_split)
        X_val_scaled = scaler.transform(X_val)
        
        # Quick test with basic Isolation Forest
        model = IsolationForest(contamination=0.1, n_estimators=100, random_state=42)
        model.fit(X_train_scaled[y_train_split == 0])
        y_pred = (model.predict(X_val_scaled) == -1).astype(int)
        f1 = f1_score(y_val, y_pred, zero_division=0)
        
        print(f"  F1 Score: {f1:.4f}")
        
        if f1 > best_scaler_score:
            best_scaler_score = f1
            best_scaler_name = scaler_name
            best_scaler = scaler
    
    print(f"\n✅ Best scaler: {best_scaler_name} (F1: {best_scaler_score:.4f})")
    
    # Scale all data with best scaler
    X_train_scaled = best_scaler.fit_transform(X_train)
    X_test_scaled = best_scaler.transform(X_test)
    X_train_split_scaled = best_scaler.fit_transform(X_train_split)
    X_val_scaled = best_scaler.transform(X_val)
    
    # Feature selection
    print("\n🎯 Performing feature selection...")
    selector = SelectKBest(score_func=mutual_info_classif, k=min(20, X.shape[1]))
    X_train_selected = selector.fit_transform(X_train_scaled, y_train)
    X_test_selected = selector.transform(X_test_scaled)
    X_train_split_selected = selector.fit_transform(X_train_split_scaled, y_train_split)
    X_val_selected = selector.transform(X_val_scaled)
    
    selected_features = selector.get_support()
    print(f"Selected {sum(selected_features)} out of {len(selected_features)} features")
    
    # Hyperparameter optimization
    print("\n⚙️ Optimizing hyperparameters...")
    best_model, best_params = optimize_isolation_forest_hyperparameters(
        X_train_split_selected, y_train_split, X_val_selected, y_val
    )
    
    # Train final optimized model
    print("\n🏋️ Training final optimized model...")
    final_model = IsolationForest(
        random_state=42,
        n_jobs=-1,
        **best_params
    )
    final_model.fit(X_train_selected[y_train == 0])
    
    # Create ensemble
    print("\n🎭 Creating ensemble model...")
    ensemble_models = create_ensemble_isolation_forest(X_train_selected, y_train)
    
    # Evaluate all models
    print("\n" + "=" * 70)
    print("📊 FINAL EVALUATION RESULTS")
    print("=" * 70)
    
    # Baseline model
    baseline_model = IsolationForest(contamination=0.1, n_estimators=100, random_state=42)
    baseline_model.fit(X_test_scaled[y_test == 0][:1000])  # Use subset for baseline
    y_pred_baseline = (baseline_model.predict(X_test_scaled) == -1).astype(int)
    baseline_results = evaluate_model(y_test, y_pred_baseline, "🔹 BASELINE ISOLATION FOREST")
    
    # Optimized single model
    y_pred_optimized = (final_model.predict(X_test_selected) == -1).astype(int)
    optimized_results = evaluate_model(y_test, y_pred_optimized, "⭐ OPTIMIZED ISOLATION FOREST")
    
    # Ensemble model
    y_pred_ensemble = ensemble_predict(ensemble_models, X_test_selected)
    ensemble_results = evaluate_model(y_test, y_pred_ensemble, "🏆 ENSEMBLE ISOLATION FOREST")
    
    # Summary
    print("\n" + "=" * 70)
    print("📈 IMPROVEMENT SUMMARY")
    print("=" * 70)
    
    baseline_acc = baseline_results['accuracy']
    optimized_acc = optimized_results['accuracy']
    ensemble_acc = ensemble_results['accuracy']
    
    print(f"Baseline Accuracy:    {baseline_acc*100:.2f}%")
    print(f"Optimized Accuracy:   {optimized_acc*100:.2f}% (+{(optimized_acc-baseline_acc)*100:.2f}%)")
    print(f"Ensemble Accuracy:    {ensemble_acc*100:.2f}% (+{(ensemble_acc-baseline_acc)*100:.2f}%)")
    
    best_accuracy = max(baseline_acc, optimized_acc, ensemble_acc)
    if best_accuracy == ensemble_acc:
        best_model_name = "Ensemble"
    elif best_accuracy == optimized_acc:
        best_model_name = "Optimized"
    else:
        best_model_name = "Baseline"
    
    print(f"\n🎯 Best Model: {best_model_name} with {best_accuracy*100:.2f}% accuracy")
    
    # Save best configuration
    print(f"\n💾 Best configuration:")
    print(f"  Scaler: {best_scaler_name}")
    print(f"  Features selected: {sum(selected_features)}")
    print(f"  Best parameters: {best_params}")
    
    return {
        'best_accuracy': best_accuracy,
        'best_model_name': best_model_name,
        'improvement': (best_accuracy - baseline_acc) * 100
    }

if __name__ == "__main__":
    results = main()
    print(f"\n🎉 Optimization complete! Achieved {results['best_accuracy']*100:.2f}% accuracy")
    print(f"   Improvement: +{results['improvement']:.2f}% over baseline")