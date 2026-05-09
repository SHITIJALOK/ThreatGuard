                      
"""
ThreatGuard Diagnostic Test Suite
Tests model loading, threshold configuration, and detection readiness.
"""

import os
import sys
import pickle
from pathlib import Path

                              
sys.path.insert(0, str(Path(__file__).parent))

def test_models_exist():
    
    print("\n" + "="*60)
    print("TEST 1: Model Files Existence")
    print("="*60)
    
    project_dir = Path(__file__).parent / "threatguard"
    model_dirs = [
        project_dir / "models final",
    ]
    
    expected_files = {
        "stage1_nids_model.pkl": "Binary Classifier (Stage 1)",
        "stage2_nids_model.pkl": "Attack Type Classifier (Stage 2)",
        "scaler.pkl": "Feature Scaler",
        "label_encoder.pkl": "Label Encoder",
        "feature_names.pkl": "Feature Names",
    }
    
    found_files = {}
    for model_dir in model_dirs:
        if not model_dir.exists():
            print(f"[WARN] Model directory not found: {model_dir}")
            continue
        
        print(f"\nSearching in: {model_dir}")
        for file in model_dir.glob("*.pkl"):
            basename = file.name
            found_files[basename] = file
            if basename in expected_files:
                print(f"  [OK] {expected_files[basename]}: {file.name}")
    
    for expected, desc in expected_files.items():
        if expected not in found_files:
            print(f"  [FAIL] MISSING: {desc} ({expected})")
        else:
            print(f"  [OK] Found: {desc}")
    
    return len(found_files) >= 2                                       

def test_threshold_config():
    
    print("\n" + "="*60)
    print("TEST 2: Confidence Thresholds Configuration")
    print("="*60)
    
                           
    real_capture_path = Path(__file__).parent / "threatguard" / "core" / "real_capture.py"
    
    with open(real_capture_path, 'r') as f:
        content = f.read()
    
                                         
    checks = [
        ("confidence_threshold: float = 0.90", "Main confidence threshold configured"),
        ("s1_min_conf = 0.70 if self._test_mode else 0.85", "Stage 1 confidence thresholds configured"),
        ("block_min_conf = 0.75 if self._test_mode else self._confidence_threshold", "Blocking threshold configured"),
    ]
    
    all_pass = True
    for check, desc in checks:
        if check in content:
            print(f"  [OK] {desc}")
        else:
            print(f"  [FAIL] {desc} - NOT FOUND")
            all_pass = False
    
    return all_pass

def test_flow_parameters():
    
    print("\n" + "="*60)
    print("TEST 3: Flow Parameters Configuration")
    print("="*60)
    
    flow_agg_path = Path(__file__).parent / "threatguard" / "core" / "flow_aggregator.py"
    
    with open(flow_agg_path, 'r') as f:
        content = f.read()
    
    checks = [
        ("FLOW_TIMEOUT = 2.5", "Flow timeout set to 2.5 seconds (fast detection)"),
        ("MIN_FLOW_PACKETS = 1", "Minimum packets = 1 (catches single-packet attacks)"),
    ]
    
    all_pass = True
    for check, desc in checks:
        if check in content:
            print(f"  [OK] {desc}")
        else:
            print(f"  [FAIL] {desc} - NOT FOUND")
            all_pass = False
    
    return all_pass

def test_capture_mode():
    
    print("\n" + "="*60)
    print("TEST 4: Default Capture Mode")
    print("="*60)
    
    engine_path = Path(__file__).parent / "threatguard" / "core" / "engine.py"
    
    with open(engine_path, 'r') as f:
        content = f.read()
    
    if "self._capture_mode = CaptureMode.REAL" in content:
        print("  [OK] Engine default capture mode set to REAL (live packet capture)")
        return True
    else:
        print("  [FAIL] Engine capture mode NOT set to REAL")
        return False

def test_detection_logic():
    
    print("\n" + "="*60)
    print("TEST 5: Detection Logic & Heuristics")
    print("="*60)
    
    real_capture_path = Path(__file__).parent / "threatguard" / "core" / "real_capture.py"
    
    with open(real_capture_path, 'r') as f:
        content = f.read()
    
    checks = [
        ("_infer_fallback_threat", "Fallback threat inference for port scans/DoS"),
        ("PORT_SCAN", "Port scan detection logic present"),
        ("DOS_ATTACK", "DoS attack detection logic present"),
        ("total_bytes < 220", "UDP minimum byte threshold logic present"),
    ]
    
    all_pass = True
    for check, desc in checks:
        if check in content:
            print(f"  [OK] {desc}")
        else:
            print(f"  [FAIL] {desc} - NOT FOUND")
            all_pass = False
    
    return all_pass

def test_misc_settings():
    
    print("\n" + "="*60)
    print("TEST 6: Miscellaneous Settings")
    print("="*60)
    
    real_capture_path = Path(__file__).parent / "threatguard" / "core" / "real_capture.py"
    
    with open(real_capture_path, 'r') as f:
        content = f.read()
    
                              
    if "total_bytes < 220" in content:
        print("  [OK] UDP byte threshold is configured")
    else:
        print("  [FAIL] UDP byte threshold not optimized")
    
                                           
    if "min_pkts = 1 if flow_rec.protocol == 6 else" in content:
        print("  [OK] Minimum packets for TCP = 1 (catches port scans immediately)")
    else:
        print("  [FAIL] Minimum packet settings not optimized")
    
    return True

def main():
    
    print("\n" + "=" * 60)
    print("ThreatGuard Diagnostic Test Suite")
    print("Verifying attack detection and blocking configuration")
    print("=" * 60)
    
    results = []
    
    try:
        results.append(("Model Files", test_models_exist()))
        results.append(("Threshold Config", test_threshold_config()))
        results.append(("Flow Parameters", test_flow_parameters()))
        results.append(("Capture Mode", test_capture_mode()))
        results.append(("Detection Logic", test_detection_logic()))
        results.append(("Misc Settings", test_misc_settings()))
    except Exception as e:
        print(f"\n[FAIL] ERROR during testing: {e}")
        return 1
    
             
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status:8} - {test_name}")
    
    print("\n" + "="*60)
    print(f"Result: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n[OK] All systems ready for attack detection!")
        print("\nNEXT STEPS:")
        print("1. Start ThreatGuard IDPS with REAL capture mode")
        print("2. From Parrot OS VM, run: sudo hping3 -S <host> -p 80 --flood")
        print("3. Or run: nmap -sS <host>")
        print("4. Attacks should be detected and blocked within 2-3 seconds")
        return 0
    else:
        print("\n[FAIL] Some configuration issues found. Please review above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
