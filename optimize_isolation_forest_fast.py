#!/usr/bin/env python3
"""
Fast Isolation Forest Model Optimization Script

This script optimizes the Isolation Forest model for maximum accuracy
using efficient feature engineering and hyperparameter tuning.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_selection import SelectKBest, mutual_info_classif
import warnings
warnings.filterwarnings('ignore')

def load_and_engineer_features():
    """Load data and perform feature engineering."""
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
    
    # 2. Traffic intensity features
    features['total_bytes'] = features['src_bytes'] + features['dst_bytes']
    features['total_packets'] = features['src_pkts'] + features['dst_pkts']
    features['avg_packet_size'] = np.where(features['total_packets'] > 0,
                                         features['total_bytes'] / features['total_packets'], 0)
    
    # 3. Duration-based features
    features['bytes_per_second'] = np.where(features['duration'] > 0,
                                          features['total_bytes'] / features['duration'], 0)
    
    # 4. Port-based features
    features['is_well_known_src_port'] = (features['src_port'] <= 1024).astype(int)
    features['is_well_known_dst_port'] = (features['dst_port'] <= 1024).astype(int)
    
    # 5. Log transformations
    features['log_duration'] = np.log1p(features['duration'])
    features['log_total_bytes'] = np.log1p(features['total_bytes'])
    
    # Remove infinite and NaN values
    features = features.replace([np.inf, -np.inf], 0)
    features = features.fillna(0)
    
    print(f"Engineered features shape: {features.shape}")
    
    return features, df['label'].values

def optimize_isolation_forest(X_train, y_train, X_val, y_val):
    """Optimize Isolation Forest hyperparameters."""
    print("Optimizing Isolation Forest hyperparameters...")
    
    # Define parameter grid (reduced for speed)
    param_combinations = [
        {'contamination': 0.05, 'n_estimators': 100, 'max_samples': 0.7, 'max_features': 0.8},
        {'contamination': 0.1, 'n_estimators': 150, 'max_samples': 0.8, 'max_features': 0.9},
        {'contamination': 0.15, 'n_estimators': 200, 'max_samples': 0.6, 'max_features': 0.7},
        {'contamination': 0.2, 'n_estimators': 100, 'max_samples': 0.9, 'max_features': 1.0},
        {'contamination': 0.25, 'n_estimators': 120, 'max_samples': 0.5, 'max_features': 0.6}
    ]
    
    best_score = 0
    best_params = None
    best_model = None
    
    for i, params in enumerate(param_combinations):
        print(f"Testing combination {i+1}/{len(param_combinations)}: {params}")
        
        try:
            # Train model with current parameters
            model = IsolationForest(
                random_state=42,
                n_jobs=-1,
                **params
            )
            
            # Fit on normal data only
            model.fit(X_train[y_train == 0])
            
            # Predict on validation set
            y_pred = (model.predict(X_val) == -1).astype(int)
            
            # Calculate accuracy
            accuracy = accuracy_score(y_val, y_pred)
            
            print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
            
            if accuracy > best_score:
                best_score = accuracy
                best_params = params
                best_model = model
                
        except Exception as e:
            print(f"  Error: {e}")
            continue
    
    print(f"\nBest parameters: {best_params}")
    print(f"Best accuracy: {best_score:.4f} ({best_score*100:.2f}%)")
    
    return best_model, best_params, best_score

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
    
    return accuracy

def main():
    """Main optimization function."""
    print("🚀 FAST ISOLATION FOREST OPTIMIZATION")
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
    
    # Test different scalers quickly
    print("\n🔍 Testing feature scalers...")
    scalers = {
        'StandardScaler': StandardScaler(),
        'RobustScaler': RobustScaler(),
        'MinMaxScaler': MinMaxScaler()
    }
    
    best_scaler_name = None
    best_scaler_score = 0
    best_scaler = None
    
    for scaler_name, scaler in scalers.items():
        print(f"Testing {scaler_name}...")
        
        # Scale features
        X_train_scaled = scaler.fit_transform(X_train_split)
        X_val_scaled = scaler.transform(X_val)
        
        # Quick test with basic Isolation Forest
        model = IsolationForest(contamination=0.1, n_estimators=50, random_state=42)
        model.fit(X_train_scaled[y_train_split == 0])
        y_pred = (model.predict(X_val_scaled) == -1).astype(int)
        accuracy = accuracy_score(y_val, y_pred)
        
        print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        
        if accuracy > best_scaler_score:
            best_scaler_score = accuracy
            best_scaler_name = scaler_name
            best_scaler = scaler
    
    print(f"\n✅ Best scaler: {best_scaler_name}")
    
    # Scale all data with best scaler
    X_train_scaled = best_scaler.fit_transform(X_train)
    X_test_scaled = best_scaler.transform(X_test)
    X_train_split_scaled = best_scaler.fit_transform(X_train_split)
    X_val_scaled = best_scaler.transform(X_val)
    
    # Feature selection
    print("\n🎯 Performing feature selection...")
    selector = SelectKBest(score_func=mutual_info_classif, k=min(15, X.shape[1]))
    X_train_selected = selector.fit_transform(X_train_scaled, y_train)
    X_test_selected = selector.transform(X_test_scaled)
    X_train_split_selected = selector.fit_transform(X_train_split_scaled, y_train_split)
    X_val_selected = selector.transform(X_val_scaled)
    
    selected_features = selector.get_support()
    print(f"Selected {sum(selected_features)} out of {len(selected_features)} features")
    
    # Hyperparameter optimization
    print("\n⚙️ Optimizing hyperparameters...")
    best_model, best_params, best_score = optimize_isolation_forest(
        X_train_split_selected, y_train_split, X_val_selected, y_val
    )
    
    # Train final optimized model on full training set
    print("\n🏋️ Training final optimized model...")
    final_model = IsolationForest(
        random_state=42,
        n_jobs=-1,
        **best_params
    )
    final_model.fit(X_train_selected[y_train == 0])
    
    # Evaluate models
    print("\n" + "=" * 70)
    print("📊 FINAL EVALUATION RESULTS")
    print("=" * 70)
    
    # Baseline model (original parameters)
    baseline_model = IsolationForest(contamination=0.1, n_estimators=100, random_state=42)
    baseline_model.fit(X_test_scaled[y_test == 0][:5000])  # Use subset for speed
    y_pred_baseline = (baseline_model.predict(X_test_scaled) == -1).astype(int)
    baseline_acc = evaluate_model(y_test, y_pred_baseline, "🔹 BASELINE ISOLATION FOREST")
    
    # Optimized model
    y_pred_optimized = (final_model.predict(X_test_selected) == -1).astype(int)
    optimized_acc = evaluate_model(y_test, y_pred_optimized, "⭐ OPTIMIZED ISOLATION FOREST")
    
    # Summary
    print("\n" + "=" * 70)
    print("📈 IMPROVEMENT SUMMARY")
    print("=" * 70)
    
    improvement = (optimized_acc - baseline_acc) * 100
    
    print(f"Baseline Accuracy:    {baseline_acc*100:.2f}%")
    print(f"Optimized Accuracy:   {optimized_acc*100:.2f}%")
    print(f"Improvement:          +{improvement:.2f} percentage points")
    
    if optimized_acc > baseline_acc:
        print(f"\n🎯 SUCCESS! Achieved {optimized_acc*100:.2f}% accuracy")
        print(f"   Improvement: +{improvement:.2f}% over baseline")
    else:
        print(f"\n⚠️  No improvement achieved. Best accuracy: {max(baseline_acc, optimized_acc)*100:.2f}%")
    
    # Save best configuration
    print(f"\n💾 Best configuration:")
    print(f"  Scaler: {best_scaler_name}")
    print(f"  Features selected: {sum(selected_features)}")
    print(f"  Best parameters: {best_params}")
    
    return {
        'best_accuracy': optimized_acc,
        'baseline_accuracy': baseline_acc,
        'improvement': improvement,
        'best_params': best_params,
        'best_scaler': best_scaler_name
    }

if __name__ == "__main__":
    results = main()
    print(f"\n🎉 Optimization complete!")
    print(f"   Final accuracy: {results['best_accuracy']*100:.2f}%")
    print(f"   Improvement: +{results['improvement']:.2f}% over baseline")