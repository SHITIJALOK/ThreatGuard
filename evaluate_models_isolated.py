import os
import pickle
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(r"d:\trae")
MODELS_DIR = PROJECT_ROOT / "threatguard" / "models final"
DATASET_DIR = Path(r"D:\Dataset - codex")
CSV_FILES = [
    DATASET_DIR / "Monday-WorkingHours.pcap_ISCX.csv",
    DATASET_DIR / "Tuesday-WorkingHours.pcap_ISCX.csv",
    DATASET_DIR / "Wednesday-workingHours.pcap_ISCX.csv",
]
CHUNK_SIZE = 50_000


def _load_pickle(path: Path):
    with open(path, "rb") as f:
        return pickle.load(f)


def _extract_model(blob):
    if isinstance(blob, dict) and "model" in blob:
        return blob["model"]
    return blob


def _normalize_stage1_pred(values):
    out = []
    for v in values:
        if isinstance(v, (int, np.integer, float, np.floating)):
            out.append(1 if int(v) == 1 else 0)
        else:
            s = str(v).strip().lower()
            out.append(1 if s in {"1", "attack", "attacker", "anomaly", "malicious", "intrusion"} else 0)
    return np.asarray(out, dtype=np.int64)


def _safe_div(a, b):
    return float(a) / float(b) if b else 0.0


def _binary_metrics(tp, tn, fp, fn):
    total = tp + tn + fp + fn
    acc = _safe_div(tp + tn, total)
    prec = _safe_div(tp, tp + fp)
    rec = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * prec * rec, (prec + rec))
    return {
        "total": total,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
    }


def _multiclass_weighted_metrics(cm: np.ndarray):
    support = cm.sum(axis=1).astype(np.float64)
    tp = np.diag(cm).astype(np.float64)
    fp = cm.sum(axis=0).astype(np.float64) - tp
    fn = support - tp
    total = float(support.sum())

    precision_i = np.divide(tp, tp + fp, out=np.zeros_like(tp), where=(tp + fp) != 0)
    recall_i = np.divide(tp, tp + fn, out=np.zeros_like(tp), where=(tp + fn) != 0)
    f1_i = np.divide(
        2 * precision_i * recall_i,
        precision_i + recall_i,
        out=np.zeros_like(tp),
        where=(precision_i + recall_i) != 0,
    )

    w = np.divide(support, total, out=np.zeros_like(support), where=total != 0)
    weighted_precision = float(np.sum(w * precision_i))
    weighted_recall = float(np.sum(w * recall_i))
    weighted_f1 = float(np.sum(w * f1_i))
    accuracy = _safe_div(float(tp.sum()), total)

    return {
        "total": int(total),
        "accuracy": accuracy,
        "precision_weighted": weighted_precision,
        "recall_weighted": weighted_recall,
        "f1_weighted": weighted_f1,
    }


def main():
    stage1_model = _extract_model(_load_pickle(MODELS_DIR / "stage1_nids_model.pkl"))
    stage2_model = _extract_model(_load_pickle(MODELS_DIR / "stage2_nids_model.pkl"))
    scaler = _load_pickle(MODELS_DIR / "scaler.pkl")
    label_encoder = _load_pickle(MODELS_DIR / "label_encoder.pkl")
    feature_names = list(_load_pickle(MODELS_DIR / "feature_names.pkl"))
    metadata = _load_pickle(MODELS_DIR / "metadata.pkl")

    missing = [str(p) for p in CSV_FILES if not p.exists()]
    if missing:
        raise FileNotFoundError(f"Missing dataset files: {missing}")

    n_classes = len(label_encoder.classes_)
    cm2 = np.zeros((n_classes, n_classes), dtype=np.int64)
    tp = tn = fp = fn = 0

    required_cols = set(feature_names + ["Label"])

    for csv_path in CSV_FILES:
        print(f"Processing: {csv_path}")
        for chunk in pd.read_csv(csv_path, chunksize=CHUNK_SIZE, low_memory=False):
            chunk.columns = [c.strip() for c in chunk.columns]
            if not required_cols.issubset(set(chunk.columns)):
                missing_cols = sorted(required_cols - set(chunk.columns))
                raise ValueError(f"Missing columns in {csv_path.name}: {missing_cols[:5]}")

            labels = chunk["Label"].astype(str).str.strip()
            X = chunk[feature_names].replace([np.inf, -np.inf], np.nan).fillna(0.0)
            Xs = scaler.transform(X)

            y_true_1 = (labels != "BENIGN").astype(np.int64).to_numpy()
            y_pred_1 = _normalize_stage1_pred(stage1_model.predict(Xs))

            tp += int(np.sum((y_true_1 == 1) & (y_pred_1 == 1)))
            tn += int(np.sum((y_true_1 == 0) & (y_pred_1 == 0)))
            fp += int(np.sum((y_true_1 == 0) & (y_pred_1 == 1)))
            fn += int(np.sum((y_true_1 == 1) & (y_pred_1 == 0)))

            atk_mask = y_true_1 == 1
            if not np.any(atk_mask):
                continue

            atk_labels = labels.to_numpy()[atk_mask]
            known_mask = np.isin(atk_labels, label_encoder.classes_)
            if not np.any(known_mask):
                continue

            X2 = Xs[atk_mask][known_mask]
            y2_true = label_encoder.transform(atk_labels[known_mask])
            y2_pred = stage2_model.predict(X2)
            y2_pred = np.asarray(y2_pred, dtype=np.int64)

            np.add.at(cm2, (y2_true, y2_pred), 1)

    m1 = _binary_metrics(tp, tn, fp, fn)
    m2 = _multiclass_weighted_metrics(cm2)

    print("\n===== ISOLATED MODEL EVALUATION =====")
    print(f"Dataset files: {len(CSV_FILES)} | Chunk size: {CHUNK_SIZE}")

    print("\nStage 1 (Binary) Metrics:")
    print(f"  Accuracy : {m1['accuracy']:.6f} ({m1['accuracy']:.2%})")
    print(f"  Precision: {m1['precision']:.6f} ({m1['precision']:.2%})")
    print(f"  Recall   : {m1['recall']:.6f} ({m1['recall']:.2%})")
    print(f"  F1 Score : {m1['f1']:.6f} ({m1['f1']:.2%})")
    print(f"  Samples  : {m1['total']:,}")
    print(f"  Confusion (TP/TN/FP/FN): {tp:,} / {tn:,} / {fp:,} / {fn:,}")

    print("\nStage 2 (Multiclass, attack-only) Metrics:")
    print(f"  Accuracy : {m2['accuracy']:.6f} ({m2['accuracy']:.2%})")
    print(f"  Precision: {m2['precision_weighted']:.6f} ({m2['precision_weighted']:.2%}) [weighted]")
    print(f"  Recall   : {m2['recall_weighted']:.6f} ({m2['recall_weighted']:.2%}) [weighted]")
    print(f"  F1 Score : {m2['f1_weighted']:.6f} ({m2['f1_weighted']:.2%}) [weighted]")
    print(f"  Samples  : {m2['total']:,}")

    print("\nStored metadata reference:")
    print(f"  stage1_accuracy : {metadata.get('stage1_accuracy')}")
    print(f"  stage1_precision: {metadata.get('stage1_precision')}")
    print(f"  stage1_recall   : {metadata.get('stage1_recall')}")
    print(f"  stage1_f1       : {metadata.get('stage1_f1')}")
    print(f"  stage2_accuracy : {metadata.get('stage2_accuracy')}")


if __name__ == "__main__":
    main()
