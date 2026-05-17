                      
"""
ThreatGuard Detection Test Script
Tests ML models directly to verify attack detection pipeline.
"""

import os
import sys
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

                         
sys.path.insert(0, str(Path(__file__).parent))

from threatguard.core.packet import ThreatType

def load_models(models_dir="threatguard/models final"):
    
    print(f"[*] Loading models from: {models_dir}")
    
    models = {}
    
                                     
    stage1_path = os.path.join(models_dir, "stage1_nids_model.pkl")
    if os.path.exists(stage1_path):
        with open(stage1_path, "rb") as f:
            models["stage1"] = pickle.load(f)
        print(f"[OK] Stage 1 (Binary) loaded: {stage1_path}")
    else:
        print(f"[FAIL] Stage 1 model NOT found: {stage1_path}")
        return None
    
                                          
    stage2_path = os.path.join(models_dir, "stage2_nids_model.pkl")
    if os.path.exists(stage2_path):
        with open(stage2_path, "rb") as f:
            models["stage2"] = pickle.load(f)
        print(f"[OK] Stage 2 (Attack) loaded: {stage2_path}")
    else:
        print(f"[FAIL] Stage 2 model NOT found: {stage2_path}")
        return None
    
                 
    scaler_path = os.path.join(models_dir, "scaler.pkl")
    if os.path.exists(scaler_path):
        with open(scaler_path, "rb") as f:
            models["scaler"] = pickle.load(f)
        print(f"[OK] Feature Scaler loaded")
    
                        
    encoder_path = os.path.join(models_dir, "label_encoder.pkl")
    if os.path.exists(encoder_path):
        with open(encoder_path, "rb") as f:
            models["label_encoder"] = pickle.load(f)
        print(f"[OK] Label Encoder loaded")
    
                        
    features_path = os.path.join(models_dir, "feature_names.pkl")
    if os.path.exists(features_path):
        with open(features_path, "rb") as f:
            models["feature_names"] = pickle.load(f)
        print(f"[OK] Feature Names loaded: {len(models['feature_names'])} features")
    else:
        print(f"[FAIL] Feature names NOT found: {features_path}")
        return None
    
    return models

def test_detection(models):
    
    print("\n" + "="*60)
    print("DETECTION PIPELINE TEST")
    print("="*60)
    
                                                            
    n_features = len(models["feature_names"])
    normal_flow = np.zeros((1, n_features))
    
                                                               
    attack_flow = np.zeros((1, n_features))
    
                         
    feature_idx = {name: i for i, name in enumerate(models["feature_names"])}
    
                                                   
    if "Total Fwd Packets" in feature_idx:
        attack_flow[0, feature_idx["Total Fwd Packets"]] = 500
    if "Total Backward Packets" in feature_idx:
        attack_flow[0, feature_idx["Total Backward Packets"]] = 50
    if "Flow Bytes/s" in feature_idx:
        attack_flow[0, feature_idx["Flow Bytes/s"]] = 50000
    if "Flow Packets/s" in feature_idx:
        attack_flow[0, feature_idx["Flow Packets/s"]] = 600
    if "SYN Flag Count" in feature_idx:
        attack_flow[0, feature_idx["SYN Flag Count"]] = 200                       
    
    print("\n[*] Testing NORMAL flow (all features ~ 0)")
    _test_sample("NORMAL", normal_flow, models)
    
    print("\n[*] Testing ATTACK flow (high traffic + SYN flags)")
    _test_sample("ATTACK", attack_flow, models)
    
    print("\n[*] Testing PORT SCAN flow (many SYN, few ACK)")
    scan_flow = np.zeros((1, n_features))
    if "SYN Flag Count" in feature_idx:
        scan_flow[0, feature_idx["SYN Flag Count"]] = 50
    if "ACK Flag Count" in feature_idx:
        scan_flow[0, feature_idx["ACK Flag Count"]] = 2
    if "Total Fwd Packets" in feature_idx:
        scan_flow[0, feature_idx["Total Fwd Packets"]] = 60
    _test_sample("PORT_SCAN", scan_flow, models)

def _test_sample(name, features, models):
    
    try:
                        
        if models.get("scaler"):
            scaler = models["scaler"]
            if hasattr(scaler, "feature_names_in_") and models.get("feature_names"):
                frame = pd.DataFrame(features, columns=models["feature_names"])
                features = scaler.transform(frame)
            else:
                features = scaler.transform(features)
        
                                        
        stage1_pred = models["stage1"].predict(features)[0]
        stage1_proba = models["stage1"].predict_proba(features)[0]
        stage1_conf = float(max(stage1_proba))
        
        is_attack = int(stage1_pred) == 1
        
        print(f"  Stage 1 (Binary):")
        print(f"    Prediction: {'ATTACK' if is_attack else 'NORMAL'} (confidence: {stage1_conf:.2%})")
        
                                                  
        if is_attack and models.get("stage2"):
            stage2_pred = models["stage2"].predict(features)[0]
            stage2_proba = models["stage2"].predict_proba(features)[0]
            stage2_conf = float(max(stage2_proba))
            
            if models.get("label_encoder"):
                attack_label = models["label_encoder"].classes_[int(stage2_pred)]
            else:
                attack_label = str(stage2_pred)
            
            print(f"  Stage 2 (Attack Type):")
            print(f"    Prediction: {attack_label} (confidence: {stage2_conf:.2%})")
            print("  [WARN] DETECTION THRESHOLD CHECK:")
            print(f"    Stage 1 >= 0.75? {stage1_conf >= 0.75} (actual: {stage1_conf:.4f})")
            print(f"    Stage 2 >= 0.60? {stage2_conf >= 0.60} (actual: {stage2_conf:.4f})")
        
    except Exception as e:
        print(f"  [!] Error: {e}")

def check_requirements():
    
    print("[*] Checking requirements...")
    requirements = [
        ("numpy", "NumPy"),
        ("sklearn", "Scikit-Learn"),
        ("xgboost", "XGBoost"),
    ]
    
    all_ok = True
    for module, name in requirements:
        try:
            __import__(module)
            print(f"  [OK] {name}")
        except ImportError:
            print(f"  [FAIL] {name} NOT installed - install with: pip install {name.lower()}")
            all_ok = False
    
    return all_ok

def main():
    print("="*60)
    print("ThreatGuard ML Detection Pipeline Test")
    print("="*60)
    
                        
    if not check_requirements():
        print("\n[!] Please install missing packages")
        return 1
    
                 
    models = load_models()
    if not models:
        print("\n[!] Failed to load models. Exiting.")
        return 1
    
               
    test_detection(models)
    
    print("\n" + "="*60)
    print("[OK] Detection pipeline test complete!")
    print("="*60)
    print("\n[i] Next steps:")
    print("  1. Run the GUI: python main.py")
    print("  2. Make sure capture mode is set to 'Live (Scapy)'")
    print("  3. Click 'Start IDPS' (requires Administrator)")
    print("  4. From another machine/VM, run: hping3 -S -p 80 --flood <target-ip>")
    print("  5. Watch for attack detection in the dashboard")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
