#!/usr/bin/env python3
"""
AI Model Accuracy Evaluation Script

This script evaluates the current AI models in the IoT IDS system
and provides accuracy metrics for each model type.
"""

import asyncio
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Import our model implementations
from ai_iot_ids.inference.models.isolation_forest_model import IsolationForestModel
from ai_iot_ids.inference.models.xgboost_model import XGBoostModel
from ai_iot_ids.inference.models.catboost_model import CatBoostModel


def load_and_prepare_data():
    """Load and prepare the training dataset."""
    print("Loading training dataset...")
    
    # Load the CSV data
    df = pd.read_csv('train_test_network.csv')
    print(f"Dataset shape: {df.shape}")
    
    # Basic data info
    print(f"Columns: {list(df.columns)}")
    print(f"Label distribution:")
    print(df['label'].value_counts())
    
    # Prepare features (exclude non-numeric and target columns)
    exclude_cols = ['src_ip', 'dst_ip', 'service', 'conn_state', 'dns_query', 
                   'ssl_subject', 'ssl_issuer', 'http_method', 'http_uri', 
                   'http_version', 'http_user_agent', 'http_orig_mime_types',
                   'http_resp_mime_types', 'weird_name', 'weird_addl', 
                   'weird_notice', 'label', 'type']
    
    feature_cols = [col for col in df.columns if col not in exclude_cols]
    
    # Handle missing values and convert to numeric
    X = df[feature_cols].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')
    
    # Fill missing values with median
    X = X.fillna(X.median())
    
    # Convert labels to binary (0=normal, 1=threat)
    y = (df['label'] == 1).astype(int)
    
    print(f"Features shape: {X.shape}")
    print(f"Selected features: {feature_cols[:10]}...")  # Show first 10
    
    return X, y, feature_cols


async def evaluate_isolation_forest(X, y):
    """Evaluate Isolation Forest model."""
    print("\n" + "="*50)
    print("ISOLATION FOREST MODEL EVALUATION")
    print("="*50)
    
    # Configuration for Isolation Forest
    config = {
        'contamination': 0.1,  # Assume 10% anomalies
        'n_estimators': 100,
        'random_state': 42
    }
    
    # Create and train model
    model = IsolationForestModel(config)
    await model.load_model()
    
    # For unsupervised learning, we train on "normal" data only
    # Use samples labeled as 0 (normal) for training
    normal_indices = y == 0
    X_normal = X[normal_indices]
    
    print(f"Training on {len(X_normal)} normal samples...")
    await model.fit(X_normal)
    
    # Evaluate on full dataset
    anomaly_scores = await model.predict_anomaly_score(X)
    
    # Convert anomaly scores to binary predictions (threshold at 0.5)
    y_pred = (anomaly_scores > 0.5).astype(int)
    
    # Calculate metrics
    accuracy = accuracy_score(y, y_pred)
    precision = precision_score(y, y_pred, zero_division=0)
    recall = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    
    try:
        auc = roc_auc_score(y, anomaly_scores)
    except ValueError:
        auc = 0.0  # In case of issues with AUC calculation
    
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f} ({precision*100:.2f}%)")
    print(f"Recall:    {recall:.4f} ({recall*100:.2f}%)")
    print(f"F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
    print(f"ROC-AUC:   {auc:.4f} ({auc*100:.2f}%)")
    
    return {
        'model': 'Isolation Forest',
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'roc_auc': auc
    }


async def evaluate_xgboost(X, y):
    """Evaluate XGBoost model."""
    print("\n" + "="*50)
    print("XGBOOST MODEL EVALUATION")
    print("="*50)
    
    try:
        # Configuration for XGBoost
        config = {
            'max_depth': 6,
            'learning_rate': 0.1,
            'n_estimators': 100,
            'random_state': 42
        }
        
        # Split data for supervised learning
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"Training samples: {len(X_train)}")
        print(f"Test samples: {len(X_test)}")
        
        # Create and train model
        model = XGBoostModel(config)
        await model.load_model()
        await model.fit(X_train, y_train)
        
        # Evaluate on test set
        metrics = await model.evaluate(X_test, y_test)
        
        print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"F1-Score:  {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        print(f"ROC-AUC:   {metrics['roc_auc']:.4f} ({metrics['roc_auc']*100:.2f}%)")
        
        return {
            'model': 'XGBoost',
            **metrics
        }
        
    except ImportError:
        print("XGBoost not available - skipping evaluation")
        return {
            'model': 'XGBoost',
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'roc_auc': 0.0,
            'note': 'XGBoost not installed'
        }


async def evaluate_catboost(X, y):
    """Evaluate CatBoost model."""
    print("\n" + "="*50)
    print("CATBOOST MODEL EVALUATION")
    print("="*50)
    
    try:
        # Configuration for CatBoost
        config = {
            'iterations': 100,
            'learning_rate': 0.1,
            'depth': 6,
            'random_seed': 42,
            'verbose': False
        }
        
        # Split data for supervised learning
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        print(f"Training samples: {len(X_train)}")
        print(f"Test samples: {len(X_test)}")
        
        # Create and train model
        model = CatBoostModel(config)
        await model.load_model()
        await model.fit(X_train, y_train)
        
        # Evaluate on test set
        metrics = await model.evaluate(X_test, y_test)
        
        print(f"Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"F1-Score:  {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        print(f"ROC-AUC:   {metrics['roc_auc']:.4f} ({metrics['roc_auc']*100:.2f}%)")
        
        return {
            'model': 'CatBoost',
            **metrics
        }
        
    except ImportError:
        print("CatBoost not available - skipping evaluation")
        return {
            'model': 'CatBoost',
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0,
            'roc_auc': 0.0,
            'note': 'CatBoost not installed'
        }


def print_summary(results):
    """Print summary of all model results."""
    print("\n" + "="*70)
    print("AI MODEL ACCURACY SUMMARY")
    print("="*70)
    
    print(f"{'Model':<15} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'ROC-AUC':<10}")
    print("-" * 70)
    
    for result in results:
        model_name = result['model']
        accuracy = result['accuracy']
        precision = result['precision']
        recall = result['recall']
        f1_score = result['f1_score']
        roc_auc = result['roc_auc']
        
        print(f"{model_name:<15} {accuracy:<10.4f} {precision:<10.4f} {recall:<10.4f} {f1_score:<10.4f} {roc_auc:<10.4f}")
    
    print("-" * 70)
    
    # Find best performing model
    best_model = max(results, key=lambda x: x['accuracy'])
    print(f"\nBest performing model: {best_model['model']} with {best_model['accuracy']*100:.2f}% accuracy")
    
    print("\nNOTE: These are preliminary results on a sample dataset.")
    print("Production models should be trained on larger, more diverse datasets.")


async def main():
    """Main evaluation function."""
    print("AI-Driven IoT IDS - Model Accuracy Evaluation")
    print("=" * 50)
    
    try:
        # Load and prepare data
        X, y, feature_cols = load_and_prepare_data()
        
        # Evaluate all models
        results = []
        
        # Isolation Forest (Unsupervised)
        if_result = await evaluate_isolation_forest(X, y)
        results.append(if_result)
        
        # XGBoost (Supervised)
        xgb_result = await evaluate_xgboost(X, y)
        results.append(xgb_result)
        
        # CatBoost (Supervised)
        cb_result = await evaluate_catboost(X, y)
        results.append(cb_result)
        
        # Print summary
        print_summary(results)
        
    except Exception as e:
        print(f"Error during evaluation: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())