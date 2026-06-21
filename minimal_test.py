import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score

# Load small sample
df = pd.read_csv('train_test_network.csv').head(1000)
X = df[['src_port', 'dst_port', 'duration']].fillna(0)
y = df['label'].values

# Quick test
model = IsolationForest(contamination=0.1, n_estimators=10)
model.fit(X[y == 0])
pred = (model.predict(X) == -1).astype(int)
acc = accuracy_score(y, pred)

print(f"Quick test accuracy: {acc*100:.2f}%")
print("Test completed successfully!")