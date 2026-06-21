#!/usr/bin/env python3
"""
Validate Optimized Isolation Forest Model

Final validation of the optimized Isolation Forest model performance.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import warnings
warnings.filterwarnings('ignore')

def prepare_enhanced_features(df):
    """Prepare enhanced features for better model performance."""
    
    # Basic numeric features
    numeric_cols = ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes', 
                   'missed_bytes', 'src_pkts', 'dst_pkts', 'src_ip_bytes', 'dst_ip_bytes']
    
    # Convert to numeric and handle missing values
    features = df[numeric_cols].copy()
    for col in numeric_cols:
        features[col] = pd.to_numeric(features[col], errors='coerce').fillna(0)
    
    # Enhanced feature engineering (based on optimization results)
    # 1. Traffic ratios
    features['bytes_ratio'] = np.where(features['dst_bytes'] > 0, 
                                     features['src_bytes'] / features['dst_bytes'], 0)
    features['packets_ratio'] = np.where(features['dst_pkts'] > 0,
                                       features['src_pkts'] / features['dst_pkts'], 0)
    
    # 2. Traffic volume and intensity
    features['total_bytes'] = features['src_bytes'] + features['dst_bytes']
    features['total_packets'] = features['src_pkts'] + features['dst_pkts']
    features['bytes_per_second'] = np.where(features['duration'] > 0,
                                          features['total_bytes'] / features['duration'], 0)
    features['packets_per_second'] = np.where(features['duration'] > 0,
                                            features['total_packets'] / features['duration'], 0)
    
    # 3. Packet analysis
    features['avg_packet_size'] = np.where(features['total_packets'] > 0,
                                         features['total_bytes'] / features['total_packets'], 0)
    
    # 4. Port analysis
    features['is_high_src_port'] = (features['src_port'] > 1024).astype(int)
    features['is_high_dst_port'] = (features['dst_port'] > 1024).astype(int)
    
    # 5. Log transformations for skewed distributions
    features['log_duration'] = np.log1p(features['duration'])
    features['log_total_bytes'] = np.log1p(features['total_bytes'])
    
    # Clean up infinite and NaN values
    features = features.replace([np.inf, -np.inf], 0)
    features = features.fillna(0)
    
    return features

def main():
    """Main validation function."""
    print("🔍 VALIDATING OPTIMIZED ISOLATION FOREST MODEL")
    print("=" * 60)
    
    # Load data
    print("Loading dataset...")
    df = pd.read_csv('train_test_network.csv')
    
    # Prepare enhanced features
    print("Preparing enhanced features...")
    X = prepare_enhanced_features(df)
    y = df['label'].values
    
    print(f"Dataset info:")
    print(f"  Total samples: {len(X):,}")
    print(f"  Normal samples: {sum(y == 0):,}")
    print(f"  Threat samples: {sum(y == 1):,}")
    print(f"  Features: {X.shape[1]}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    # Scale features
    print("\nScaling features...")
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("\n" + "=" * 60)
    print("🔬 MODEL COMPARISON")
    print("=" * 60)
    
    # 1. Original Baseline Model
    print("\n1️⃣ ORIGINAL BASELINE MODEL")
    baseline_model = IsolationForest(
        contamination=0.1,
        n_estimators=100,
        max_samples='auto',
        random_state=42,
        n_jobs=-1
    )
    baseline_model.fit(X_train_scaled[y_train == 0])
    y_pred_baseline = (baseline_model.predict(X_test_scaled) == -1).astype(int)
    
    baseline_acc = accuracy_score(y_test, y_pred_baseline)
    baseline_prec = precision_score(y_test, y_pred_baseline, zero_division=0)
    baseline_rec = recall_score(y_test, y_pred_baseline, zero_division=0)
    baseline_f1 = f1_score(y_test, y_pred_baseline, zero_division=0)
    
    print(f"   Accuracy:  {baseline_acc*100:6.2f}%")
    print(f"   Precision: {baseline_prec*100:6.2f}%")
    print(f"   Recall:    {baseline_rec*100:6.2f}%")
    print(f"   F1-Score:  {baseline_f1*100:6.2f}%")
    
    # 2. Optimized Model
    print("\n2️⃣ OPTIMIZED MODEL (Best Configuration)")
    optimized_model = IsolationForest(
        contamination=0.25,      # Optimized parameter
        n_estimators=100,        # Optimized parameter
        max_samples=0.9,         # Optimized parameter
        random_state=42,
        n_jobs=-1
    )
    optimized_model.fit(X_train_scaled[y_train == 0])
    y_pred_optimized = (optimized_model.predict(X_test_scaled) == -1).astype(int)
    
    optimized_acc = accuracy_score(y_test, y_pred_optimized)
    optimized_prec = precision_score(y_test, y_pred_optimized, zero_division=0)
    optimized_rec = recall_score(y_test, y_pred_optimized, zero_division=0)
    optimized_f1 = f1_score(y_test, y_pred_optimized, zero_division=0)
    
    print(f"   Accuracy:  {optimized_acc*100:6.2f}%")
    print(f"   Precision: {optimized_prec*100:6.2f}%")
    print(f"   Recall:    {optimized_rec*100:6.2f}%")
    print(f"   F1-Score:  {optimized_f1*100:6.2f}%")
    
    # Calculate improvements
    acc_improvement = (optimized_acc - baseline_acc) * 100
    prec_improvement = (optimized_prec - baseline_prec) * 100
    rec_improvement = (optimized_rec - baseline_rec) * 100
    f1_improvement = (optimized_f1 - baseline_f1) * 100
    
    print("\n" + "=" * 60)
    print("📊 IMPROVEMENT ANALYSIS")
    print("=" * 60)
    
    print(f"Accuracy Improvement:  {acc_improvement:+6.2f} percentage points")
    print(f"Precision Improvement: {prec_improvement:+6.2f} percentage points")
    print(f"Recall Improvement:    {rec_improvement:+6.2f} percentage points")
    print(f"F1-Score Improvement:  {f1_improvement:+6.2f} percentage points")
    
    # Overall assessment
    print(f"\n🎯 OPTIMIZATION SUMMARY:")
    print(f"   Baseline Accuracy:  {baseline_acc*100:.2f}%")
    print(f"   Optimized Accuracy: {optimized_acc*100:.2f}%")
    
    if acc_improvement > 0:
        print(f"\n✅ SUCCESS! Achieved {acc_improvement:.2f}% improvement in accuracy")
        print(f"   The optimized model performs significantly better!")
    else:
        print(f"\n⚠️  No improvement in accuracy achieved")
    
    # Detailed classification report for optimized model
    print(f"\n📋 DETAILED CLASSIFICATION REPORT (Optimized Model):")
    print("=" * 60)
    print(classification_report(y_test, y_pred_optimized, 
                              target_names=['Normal', 'Threat'], 
                              digits=4))
    
    # Configuration summary
    print(f"\n⚙️  OPTIMIZED CONFIGURATION:")
    print(f"   Contamination: 0.25")
    print(f"   N Estimators:  100")
    print(f"   Max Samples:   0.9")
    print(f"   Features:      {X.shape[1]} (enhanced)")
    print(f"   Scaler:        RobustScaler")
    
    return {
        'baseline_accuracy': baseline_acc,
        'optimized_accuracy': optimized_acc,
        'improvement': acc_improvement
    }

if __name__ == "__main__":
    results = main()
    
    print(f"\n🎉 VALIDATION COMPLETE!")
    print(f"   Final optimized accuracy: {results['optimized_accuracy']*100:.2f}%")
    print(f"   Total improvement: {results['improvement']:+.2f}% over baseline")
    
    if results['improvement'] > 0:
        print(f"   🏆 Optimization was successful!")
    else:
        print(f"   📝 Further optimization may be needed")