

from __future__ import annotations

import os
import pickle
import threading
from datetime import datetime

import numpy as np
from PySide6.QtCore import QObject, Signal

CICIDS_MODELS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "models final"
)
SAMPLES_PATH = os.path.join(CICIDS_MODELS_DIR, "online_samples.pkl")

class OnlineLearner(QObject):
    

    retrain_complete = Signal(str)                                          
    status_update = Signal(str)                             

                                              
    MIN_SAMPLES_RETRAIN = 500

    def __init__(self, parent=None):
        super().__init__(parent)
        self._samples_X: list[np.ndarray] = []
        self._samples_y_binary: list[int] = []
        self._samples_y_attack: list[str] = []
        self._lock = threading.Lock()
        self._retrain_count = 0

                                           
        self._load_saved_samples()

    @property
    def sample_count(self) -> int:
        return len(self._samples_y_binary)

    def add_sample(self, features: np.ndarray, is_attack: bool, attack_label: str = ""):
        
        with self._lock:
            self._samples_X.append(features.copy())
            self._samples_y_binary.append(1 if is_attack else 0)
            self._samples_y_attack.append(attack_label if is_attack else "Benign")

                                     
        if len(self._samples_y_binary) % 100 == 0:
            self._save_samples()
            self.status_update.emit(
                f"Online learning: {len(self._samples_y_binary)} samples collected"
            )

    def can_retrain(self) -> bool:
        
        return len(self._samples_y_binary) >= self.MIN_SAMPLES_RETRAIN

    def retrain(self):
        
        if not self.can_retrain():
            self.status_update.emit(
                f"Need {self.MIN_SAMPLES_RETRAIN - len(self._samples_y_binary)} "
                f"more samples before retraining"
            )
            return

        self.status_update.emit("Retraining started...")

        with self._lock:
            X = np.array(self._samples_X)
            y_binary = np.array(self._samples_y_binary)
            y_attack = np.array(self._samples_y_attack)

        metadata_path = os.path.join(CICIDS_MODELS_DIR, "online_retrain_metadata.pkl")
        try:
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "sample_count": int(len(y_binary)),
                "status": "queued",
                "dataset": "CICIDS2017",
                "note": "Online retraining is disabled in-app; retrain offline with CICIDS pipeline.",
            }
            with open(metadata_path, "wb") as f:
                pickle.dump(metadata, f)
            self._retrain_count += 1
            self.retrain_complete.emit(
                f"Queued CICIDS retrain metadata with {len(y_binary)} samples."
            )
        except Exception as e:
            self.status_update.emit(f"Retrain queue failed: {str(e)}")

    def _save_samples(self):
        
        try:
            os.makedirs(CICIDS_MODELS_DIR, exist_ok=True)
            with open(SAMPLES_PATH, "wb") as f:
                pickle.dump({
                    "X": self._samples_X,
                    "y_binary": self._samples_y_binary,
                    "y_attack": self._samples_y_attack,
                }, f)
        except Exception:
            pass

    def _load_saved_samples(self):
        
        if os.path.isfile(SAMPLES_PATH):
            try:
                with open(SAMPLES_PATH, "rb") as f:
                    data = pickle.load(f)
                self._samples_X = data.get("X", [])
                self._samples_y_binary = data.get("y_binary", [])
                self._samples_y_attack = data.get("y_attack", [])
            except Exception:
                pass

    def clear_samples(self):
        
        with self._lock:
            self._samples_X.clear()
            self._samples_y_binary.clear()
            self._samples_y_attack.clear()
        if os.path.isfile(SAMPLES_PATH):
            os.remove(SAMPLES_PATH)
