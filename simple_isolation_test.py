import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Load data
df = pd.read_csv('train_test_network.csv')
cols = ['src_port', 'dst_port', 'duration', 'src_bytes', 'dst_bytes']
X = df[cols].fillna(0)
y = df['label'].values

# Add simple engineered features
X['total_bytes'] = X['src_bytes'] + X['dst_bytes']
X['bytes_ratio'] = np.where(X['dst_bytes'] > 0, X['src_bytes'] / X['dst_bytes'], 0)
X = X.replace([np.inf, -np.inf], 0)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

print("Testing Isolation Forest configurations...")

# Test 1: Original
model1 = IsolationForest(contamination=0.1, n_estimators=50, random_state=42)
model1.fit(X_train[y_train == 0])
pred1 = (model1.predict(X_test) == -1).astype(int)
acc1 = accuracy_score(y_test, pred1)
print(f"Original:    {acc1*100:.2f}%")

# Test 2: Lower contamination
model2 = IsolationForest(contamination=0.05, n_estimators=50, random_state=42)
model2.fit(X_train[y_train == 0])
pred2 = (model2.predict(X_test) == -1).astype(int)
acc2 = accuracy_score(y_test, pred2)
print(f"Lower cont:  {acc2*100:.2f}%")

# Test 3: Higher contamination
model3 = IsolationForest(contamination=0.2, n_estimators=50, random_state=42)
model3.fit(X_train[y_train == 0])
pred3 = (model3.predict(X_test) == -1).astype(int)
acc3 = accuracy_score(y_test, pred3)
print(f"Higher cont: {acc3*100:.2f}%")

best_acc = max(acc1, acc2, acc3)
improvement = (best_acc - acc1) * 100
print(f"\nBest accuracy: {best_acc*100:.2f}%")
print(f"Improvement: +{improvement:.2f}%")