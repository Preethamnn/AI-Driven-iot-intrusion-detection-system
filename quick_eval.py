import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import xgboost as xgb

print('AI-Driven IoT IDS - Model Accuracy Evaluation')
print('=' * 50)

# Load data
df = pd.read_csv('train_test_network.csv')
print(f'Dataset shape: {df.shape}')
print(f'Label distribution: Normal={sum(df.label==0)}, Threats={sum(df.label==1)}')

# Prepare features
numeric_cols = ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes', 'missed_bytes', 'src_pkts', 'dst_pkts']
X = df[numeric_cols].fillna(0)
y = df['label'].values

# 1. Isolation Forest
print('\nISOLATION FOREST RESULTS:')
model_if = IsolationForest(contamination=0.1, random_state=42)
model_if.fit(X[y==0])
y_pred_if = (model_if.predict(X) == -1).astype(int)
print(f'Accuracy: {accuracy_score(y, y_pred_if)*100:.2f}%')

# 2. XGBoost
print('\nXGBOOST RESULTS:')
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
model_xgb = xgb.XGBClassifier(max_depth=6, learning_rate=0.1, n_estimators=100, random_state=42)
model_xgb.fit(X_train, y_train)
y_pred_xgb = model_xgb.predict(X_test)
y_pred_proba_xgb = model_xgb.predict_proba(X_test)

acc = accuracy_score(y_test, y_pred_xgb)
prec = precision_score(y_test, y_pred_xgb)
rec = recall_score(y_test, y_pred_xgb)
f1 = f1_score(y_test, y_pred_xgb)
auc = roc_auc_score(y_test, y_pred_proba_xgb[:, 1])

print(f'Accuracy:  {acc*100:.2f}%')
print(f'Precision: {prec*100:.2f}%')
print(f'Recall:    {rec*100:.2f}%')
print(f'F1-Score:  {f1*100:.2f}%')
print(f'ROC-AUC:   {auc*100:.2f}%')

print(f'\nBest Model: XGBoost with {acc*100:.2f}% accuracy')