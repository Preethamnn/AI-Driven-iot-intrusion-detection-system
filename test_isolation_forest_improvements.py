#!/usr/bin/env python3
"""
Test Isolation Forest Improvements

Quick test to evaluate improved Isolation Forest configurations.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import accuracy_score
import warnings
warnings.filterwarnings('ignore')

print("🚀 Testing Isolation Forest Improvements")
print("=" * 50)

# Load data
print("Loading data...")
df = pd.read_csv('train_test_network.csv')

# Prepare features
numeric_cols = ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes', 
               'missed_bytes', 'src_pkts', 'dst_pkts']

X = df[numeric_cols].copy()
for col in numeric_cols:
    X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

# Enhanced features
X['bytes_ratio'] = np.where(X['dst_bytes'] > 0, X['src_bytes'] / X['dst_bytes'], 0)
X['total_bytes'] = X['src_bytes'] + X['dst_bytes']
X['bytes_per_second'] = np.where(X['duration'] > 0, X['total_bytes'] / X['duration'], 0)
X['log_duration'] = np.log1p(X['duration'])

# Clean data
X = X.replace([np.inf, -np.inf], 0).fillna(0)
y = df['label'].values

print(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
print(f"Normal: {sum(y==0)}, Threats: {sum(y==1)}")

# Split and scale
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
scaler = RobustScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Test configurations
configs = [
    {'name': 'Original', 'contamination': 0.1, 'n_estimators': 100},
    {'name': 'Optimized-1', 'contamination': 0.05, 'n_estimators': 200},
    {'name': 'Optimized-2', 'contamination': 0.15, 'n_estimators': 150},
    {'name': 'Optimized-3', 'contamination': 0.2, 'n_estimators': 250}
]

print("\n🔧 Testing configurations...")
results = []

for config in configs:
    print(f"\nTesting {config['name']}...")
    
    # Create model
    model = IsolationForest(
        contamination=config['contamination'],
        n_estimators=config['n_estimators'],
        random_state=42,
        n_jobs=1  # Single thread for speed
    )
    
    # Train on normal data
    model.fit(X_train_scaled[y_train == 0])
    
    # Predict
    y_pred = (model.predict(X_test_scaled) == -1).astype(int)
    accuracy = accuracy_score(y_test, y_pred)
    
    results.append({'name': config['name'], 'accuracy': accuracy})
    print(f"  Accuracy: {accuracy*100:.2f}%")

# Show results
print("\n" + "=" * 50)
print("📊 RESULTS SUMMARY")
print("=" * 50)

best_result = max(results, key=lambda x: x['accuracy'])
baseline = next(r for r in results if r['name'] == 'Original')

for result in results:
    status = "🏆" if result == best_result else "  "
    print(f"{status} {result['name']:<12}: {result['accuracy']*100:6.2f}%")

improvement = (best_result['accuracy'] - baseline['accuracy']) * 100
print(f"\n📈 Best: {best_result['name']} with {best_result['accuracy']*100:.2f}% accuracy")
print(f"   Improvement: +{improvement:.2f} percentage points over baseline")

if improvement > 0:
    print(f"\n✅ SUCCESS! Improved by {improvement:.2f}%")
else:
    print(f"\n⚠️  No improvement achieved")