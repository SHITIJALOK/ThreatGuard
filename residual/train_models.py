

import os
import time
import warnings
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    f1_score, precision_score, recall_score,
)

warnings.filterwarnings("ignore")

                                                                
                
                                                                

DATASET_PATH = os.environ.get(
    "THREATGUARD_CICIDS_DATASET",
    r"D:\Dataset - codex\Monday-WorkingHours.pcap_ISCX.csv",
)
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "threatguard", "models final")
RANDOM_STATE = 42
TEST_SIZE = 0.2

                                       
DROP_COLUMNS = [
    "Unnamed: 0.1", "Unnamed: 0",
    "uid",                                               
    "originh",                                             
    "responh",                                                  
    "traffic_category",                                            
    "Label",                                 
]

                                                            
RF_PARAMS_STAGE1 = {
    "n_estimators": 200,
    "max_depth": 25,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "class_weight": "balanced",                                                 
    "n_jobs": -1,
    "random_state": RANDOM_STATE,
    "verbose": 0,
}

RF_PARAMS_STAGE2 = {
    "n_estimators": 200,
    "max_depth": 30,
    "min_samples_split": 4,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
    "class_weight": "balanced",                                 
    "n_jobs": -1,
    "random_state": RANDOM_STATE,
    "verbose": 0,
}

def load_and_preprocess(path: str) -> pd.DataFrame:
    
    print(f"📂 Loading dataset from: {path}")
    t0 = time.time()
    df = pd.read_csv(path)
    print(f"   ✅ Loaded {len(df):,} rows × {len(df.columns)} columns in {time.time()-t0:.1f}s")

                                                       
    initial_len = len(df)
    df = df.dropna()
    dropped = initial_len - len(df)
    if dropped > 0:
        print(f"   ⚠️  Dropped {dropped:,} rows with missing values")

                                           
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)

    print(f"   📊 Final dataset: {len(df):,} rows")
    return df

def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    
    feature_cols = [c for c in df.columns if c not in DROP_COLUMNS]

                               
    X = df[feature_cols].select_dtypes(include=[np.number])
    feature_names = list(X.columns)

    print(f"   🔢 {len(feature_names)} numeric features selected")
    return X, feature_names

def train_stage1(df: pd.DataFrame, feature_names: list[str]) -> dict:
    
    print("\n" + "=" * 70)
    print("  STAGE 1: Binary Classifier (Normal vs Attack)")
    print("=" * 70)

    X = df[feature_names].values
    y = df["Label"].values

    print(f"\n   Class distribution:")
    print(f"     Normal (0): {(y == 0).sum():,}")
    print(f"     Attack (1): {(y == 1).sum():,}")
    print(f"     Attack ratio: {(y == 1).mean():.1%}")

                      
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n   Train: {len(X_train):,} | Test: {len(X_test):,}")

                         
    print(f"\n   🌲 Training Random Forest ({RF_PARAMS_STAGE1['n_estimators']} trees)...")
    t0 = time.time()
    clf = RandomForestClassifier(**RF_PARAMS_STAGE1)
    clf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"   ✅ Training complete in {train_time:.1f}s")

              
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")
    precision = precision_score(y_test, y_pred, average="weighted")
    recall = recall_score(y_test, y_pred, average="weighted")

    print(f"\n   📈 Results on test set:")
    print(f"     Accuracy:  {accuracy:.4f} ({accuracy:.2%})")
    print(f"     F1 Score:  {f1:.4f}")
    print(f"     Precision: {precision:.4f}")
    print(f"     Recall:    {recall:.4f}")
    print(f"\n   📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Normal", "Attack"]))

    print(f"   📋 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"                 Predicted Normal  Predicted Attack")
    print(f"     Actual Normal    {cm[0][0]:>8,}        {cm[0][1]:>8,}")
    print(f"     Actual Attack    {cm[1][0]:>8,}        {cm[1][1]:>8,}")

                                 
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1][:15]
    print(f"\n   🏆 Top 15 Features:")
    for rank, idx in enumerate(indices, 1):
        print(f"     {rank:2d}. {feature_names[idx]:<35s} {importances[idx]:.4f}")

    return {
        "model": clf,
        "accuracy": accuracy,
        "f1": f1,
        "precision": precision,
        "recall": recall,
        "feature_names": feature_names,
        "train_time": train_time,
    }

def train_stage2(df: pd.DataFrame, feature_names: list[str]) -> dict:
    
    print("\n" + "=" * 70)
    print("  STAGE 2: Attack Type Classifier")
    print("=" * 70)

                                   
    attack_df = df[df["Label"] == 1].copy()
    print(f"\n   Attack samples: {len(attack_df):,}")

    X = attack_df[feature_names].values
    y_raw = attack_df["traffic_category"].values

                               
    le = LabelEncoder()
    y = le.fit_transform(y_raw)
    class_names = list(le.classes_)

    print(f"\n   Attack type distribution:")
    for cls_name in class_names:
        count = (y_raw == cls_name).sum()
        print(f"     {cls_name}: {count:,}")

                      
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n   Train: {len(X_train):,} | Test: {len(X_test):,}")

                         
    print(f"\n   🌲 Training Random Forest ({RF_PARAMS_STAGE2['n_estimators']} trees)...")
    t0 = time.time()
    clf = RandomForestClassifier(**RF_PARAMS_STAGE2)
    clf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"   ✅ Training complete in {train_time:.1f}s")

              
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")
    precision = precision_score(y_test, y_pred, average="weighted")
    recall = recall_score(y_test, y_pred, average="weighted")

    print(f"\n   📈 Results on test set:")
    print(f"     Accuracy:  {accuracy:.4f} ({accuracy:.2%})")
    print(f"     F1 Score:  {f1:.4f}")
    print(f"     Precision: {precision:.4f}")
    print(f"     Recall:    {recall:.4f}")
    print(f"\n   📋 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=class_names))

    print(f"   📋 Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
                  
    header = "                  " + "  ".join(f"{n[:10]:>10s}" for n in class_names)
    print(header)
    for i, cls_name in enumerate(class_names):
        row = f"     {cls_name:<14s}" + "  ".join(f"{cm[i][j]:>10,}" for j in range(len(class_names)))
        print(row)

                                 
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1][:15]
    print(f"\n   🏆 Top 15 Features:")
    for rank, idx in enumerate(indices, 1):
        print(f"     {rank:2d}. {feature_names[idx]:<35s} {importances[idx]:.4f}")

    return {
        "model": clf,
        "label_encoder": le,
        "class_names": class_names,
        "accuracy": accuracy,
        "f1": f1,
        "precision": precision,
        "recall": recall,
        "feature_names": feature_names,
        "train_time": train_time,
    }

def save_models(stage1_result: dict, stage2_result: dict, output_dir: str):
    
    os.makedirs(output_dir, exist_ok=True)

                  
    stage1_path = os.path.join(output_dir, "stage1_nids_model.pkl")
    with open(stage1_path, "wb") as f:
        pickle.dump({
            "model": stage1_result["model"],
            "feature_names": stage1_result["feature_names"],
            "accuracy": stage1_result["accuracy"],
            "f1": stage1_result["f1"],
            "type": "binary_classifier",
            "algorithm": "RandomForest",
            "dataset": "CICIDS2017",
        }, f)
    size1 = os.path.getsize(stage1_path) / (1024 * 1024)
    print(f"\n   💾 Stage 1 saved: {stage1_path} ({size1:.1f} MB)")

                  
    stage2_path = os.path.join(output_dir, "stage2_nids_model.pkl")
    with open(stage2_path, "wb") as f:
        pickle.dump({
            "model": stage2_result["model"],
            "label_encoder": stage2_result["label_encoder"],
            "class_names": stage2_result["class_names"],
            "feature_names": stage2_result["feature_names"],
            "accuracy": stage2_result["accuracy"],
            "f1": stage2_result["f1"],
            "type": "attack_type_classifier",
            "algorithm": "RandomForest",
            "dataset": "CICIDS2017",
        }, f)
    size2 = os.path.getsize(stage2_path) / (1024 * 1024)
    print(f"   💾 Stage 2 saved: {stage2_path} ({size2:.1f} MB)")

                                      
    features_path = os.path.join(output_dir, "feature_names.txt")
    with open(features_path, "w") as f:
        for name in stage1_result["feature_names"]:
            f.write(name + "\n")
    print(f"   📄 Feature names saved: {features_path}")

    return stage1_path, stage2_path

def main():
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   ThreatGuard — ML Model Training Pipeline                  ║")
    print("║   Algorithm: Random Forest    Dataset: CICIDS2017           ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    total_start = time.time()

               
    df = load_and_preprocess(DATASET_PATH)

                      
    X_df, feature_names = prepare_features(df)

                                                 
    df_features = df.copy()

                                    
    stage1 = train_stage1(df_features, feature_names)

                                         
    stage2 = train_stage2(df_features, feature_names)

                 
    print("\n" + "=" * 70)
    print("  SAVING MODELS")
    print("=" * 70)
    s1_path, s2_path = save_models(stage1, stage2, OUTPUT_DIR)

    total_time = time.time() - total_start

             
    print("\n" + "=" * 70)
    print("  TRAINING SUMMARY")
    print("=" * 70)
    print(f"""
   Dataset:       CICIDS2017 ({len(df):,} samples)
   Algorithm:     Random Forest

   Stage 1 (Binary):
     Accuracy:    {stage1['accuracy']:.4f} ({stage1['accuracy']:.2%})
     F1 Score:    {stage1['f1']:.4f}
     Train Time:  {stage1['train_time']:.1f}s
     Model:       {s1_path}

   Stage 2 (Attack Type):
     Accuracy:    {stage2['accuracy']:.4f} ({stage2['accuracy']:.2%})
     F1 Score:    {stage2['f1']:.4f}
     Classes:     {', '.join(stage2['class_names'])}
     Train Time:  {stage2['train_time']:.1f}s
     Model:       {s2_path}

   Total Time:    {total_time:.1f}s
    """)
    print("   ✅ Models are ready for integration into ThreatGuard Dashboard!")
    print("=" * 70)

if __name__ == "__main__":
    main()
