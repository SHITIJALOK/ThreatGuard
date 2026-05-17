import pandas as pd
import numpy as np
import pickle
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


print("Loading datasets...")

BASE_DIR = Path(__file__).resolve().parent

# Load CSVs
benign = pd.read_csv(BASE_DIR / "New Benign.csv")
portscan = pd.read_csv(BASE_DIR / "New Portscan.csv")
dos = pd.read_csv(BASE_DIR / "New Dos.csv")
bruteforce = pd.read_csv(BASE_DIR / "bruteforce.csv")

# Downsample larger datasets
portscan = portscan.sample(n=min(3000, len(portscan)), random_state=42)
dos = dos.sample(n=min(3000, len(dos)), random_state=42)

# Add labels
benign["label"] = 0
portscan["label"] = 1
dos["label"] = 1
bruteforce["label"] = 1

# Combine
df = pd.concat([
    benign,
    portscan,
    dos,
    bruteforce
], ignore_index=True)

print("Dataset shape:", df.shape)

# Clean bad values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Split X and y
X = df.drop("label", axis=1)
y = df["label"]

feature_names = X.columns.tolist()

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Scale
print("Scaling features...")
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train model
print("Training model...")

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train_scaled, y_train)

# Predict
y_pred = model.predict(X_test_scaled)

print("\nAccuracy:")
print(accuracy_score(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model
print("Saving model...")

with open(BASE_DIR / "binary_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open(BASE_DIR / "scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open(BASE_DIR / "feature_names.pkl", "wb") as f:
    pickle.dump(feature_names, f)

print("Done!")
