# Network Intrusion Detection System (NIDS) - Complete Deployment Guide

## Deployment Addendum (Latest Runtime Behavior)

Use this addendum with the guide below for the current codebase behavior:

- **Privilege model**:
  - On Windows, startup enforces elevation via UAC relaunch.
  - Real capture and host firewall block actions require admin privileges.

- **Detection modes**:
  - Primary production detection is ML cascade (Stage 1 + Stage 2).
  - Signature-only path is intended for test/lab-style operation and is constrained in normal mode.
  - Behavioral scan assist is enabled to catch rapid SYN-scan bursts (for practical `nmap -sS` traffic patterns).

- **False-positive control improvements**:
  - Stricter confidence gating in normal mode.
  - Reduced fallback aggressiveness outside test mode.

- **Feature/scaler robustness**:
  - Runtime supports feature-name compatibility across model artifacts in this repository.
  - Scaler input uses named columns when required by scikit-learn.

- **Blocked table signal quality**:
  - Blocked entries are deduplicated by `(source_ip + threat_type)` with a 15-second window.
  - Prevents thousands of repeated entries from one scan burst while preserving distinct attack-type events.

## Overview

This guide provides instructions for deploying the trained CICIDS2017-based Network Intrusion Detection System in production environments.

### System Architecture

The NIDS uses a **two-stage classification pipeline**:

1. **Stage 1 (Binary Classifier)**: Distinguishes normal traffic from any attack
   - Input: Network flow features
   - Output: Normal (0) or Attack (1)
   - Accuracy: 99.89%
   - ROC-AUC: 1.0000

2. **Stage 2 (Multi-class Classifier)**: Identifies specific attack type
   - Input: Network flow features (only if Stage 1 detected attack)
   - Output: Attack type (14 categories)
   - Accuracy: 99.82%
   - Special focus: **PortScan detection (99.99% precision, 99.94% recall)**

---

## Trained Models Summary

### Stage 1: Binary Classification
```
Label Distribution (Test Set):
  Normal:  749,452 samples
  Attack:  7,151 samples
  
Metrics:
  Accuracy:  0.9989 (99.89%)
  Precision: 0.9965 (99.65%)
  Recall:    0.9972 (99.72%)
  F1 Score:  0.9969 (99.69%)
  ROC-AUC:   1.0000 (Perfect)
```

### Stage 2: Attack Type Classification
```
Recognized Attack Types (14 total):
  1. Bot
  2. DDoS
  3. DoS GoldenEye
  4. DoS Hulk
  5. DoS Slowhttptest
  6. DoS slowloris
  7. FTP-Patator
  8. Heartbleed
  9. Infiltration
  10. PortScan ⭐ (PRIORITY - 99.99% precision)
  11. SSH-Patator
  12. Web Attack – Brute Force
  13. Web Attack – Sql Injection
  14. Web Attack – XSS

Overall Accuracy: 99.82% (99.82%)

PortScan Specific Metrics:
  Precision: 0.9999 (99.99%)
  Recall:    0.9994 (99.94%)
  Correct:   27,231 / 27,246
```

---

## Saved Artifacts

All trained models and supporting files are saved in the `models/` directory:

| File | Purpose |
|------|---------|
| `stage1_nids_model.pkl` | Binary classification XGBoost model |
| `stage2_nids_model.pkl` | Multi-class attack classification XGBoost model |
| `scaler.pkl` | StandardScaler for feature normalization |
| `label_encoder.pkl` | Encoder for attack type labels |
| `feature_names.pkl` | List of 78 numerical features in correct order |
| `metadata.pkl` | Training metadata and statistics |

---

## Quick Start: Python API

### 1. Basic Usage

```python
from nids_predictor import NIIDSPredictor

# Initialize the predictor
predictor = NIIDSPredictor(models_dir='models')

# Single prediction
result = predictor.predict_flow({
    'Protocol': 6,
    'Src Port': 54321,
    'Dst Port': 443,
    'Flow Duration': 1000,
    # ... all 78 required features
})

# Handle results
if result['error']:
    print(f"Error: {result['error']}")
elif result['is_attack']:
    print(f"⚠️  ATTACK: {result['attack_type']}")
    print(f"  Confidence: {result['confidence']:.2%}")
else:
    print(f"✓ Normal traffic (confidence: {result['confidence']:.2%})")
```

### 2. Batch Predictions

```python
# Predict multiple flows
flows = [
    {'Protocol': 6, 'Src Port': 54321, ...},
    {'Protocol': 17, 'Src Port': 53, ...},
    # ... more flows
]

results = predictor.batch_predict(flows)

for result in results:
    if result['is_attack']:
        print(f"Attack: {result['attack_type']}")
```

### 3. Get Available Features and Attack Types

```python
# List all required features
features = predictor.get_feature_names()
print(f"Required features: {features}")

# List all attack types
attacks = predictor.get_attack_types()
print(f"Recognized attacks: {attacks}")
```

---

## Scapy Integration (Real-time Detection)

### Important: Feature Extraction

The NIDS requires **78 numerical features** from network flows. These must be extracted from Scapy packets and match the training features exactly.

**Common CICIDS2017 features include:**
- Protocol, Source Port, Destination Port
- Flow Duration, Total Flow Bytes
- Forward/Backward Packet Count and Bytes
- Inter-arrival times, Flag counts
- Header lengths, and statistical features

### Example: Real-time Packet Monitoring

```python
from scapy.all import sniff, IP, TCP, UDP
from nids_predictor import NIIDSPredictor
from collections import defaultdict

# Initialize predictor
predictor = NIIDSPredictor(models_dir='models')

# Store flow state
flows = defaultdict

def extract_flow_features(packet, flow_id):
    """
    CUSTOMIZATION REQUIRED: Extract features matching CICIDS2017 dataset
    
    Your implementation must:
    1. Calculate all 78 features
    2. Match feature names in feature_names.pkl
    3. Return dictionary with feature names as keys
    """
    features = {}
    
    if packet.haslayer(IP):
        ip = packet[IP]
        
        # Example features - CUSTOMIZE BASED ON YOUR DATASET
        features['Protocol'] = ip.proto
        features['Flow Duration'] = 0  # Calculate from flow state
        # ... add all 78 required features
    
    return features

def packet_callback(packet):
    """Process each packet"""
    flow_id = (packet[IP].src, packet[IP].dst, packet[IP].sport, packet[IP].dport)
    
    try:
        features = extract_flow_features(packet, flow_id)
        
        if not features:
            return
        
        result = predictor.predict_flow(features)
        
        if result['error']:
            print(f"[ERROR] {result['error']}")
        elif result['is_attack']:
            print(f"🚨 [{flow_id}] {result['attack_type']} detected")
            print(f"   Confidence: {result['confidence']:.2%}")
            # Log alert, send notification, block traffic, etc.
        else:
            print(f"✓ Normal traffic from {flow_id}")
    
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start monitoring
print("Starting real-time network monitoring...")
print("Press Ctrl+C to stop")

sniff(prn=packet_callback, filter='ip', store=False)
```

---

## Production Deployment

### Requirements

```
Python ≥ 3.8
pandas
numpy
scikit-learn
xgboost
matplotlib (optional, for visualization)
seaborn (optional, for visualization)
scapy (for packet capture)
```

### Installation

```bash
# Install dependencies
pip install pandas numpy scikit-learn xgboost scapy

# Optional: for visualization
pip install matplotlib seaborn
```

### Deployment Checklist

- [ ] Verify all model files in `models/` directory
- [ ] Test predictor initialization with sample data
- [ ] Implement feature extraction matching your network
- [ ] Test on known attack/normal traffic samples
- [ ] Set up alerting and logging
- [ ] Monitor model performance over time
- [ ] Plan for model retraining if performance degrades
- [ ] Document custom feature extraction process
- [ ] Security: Protect model files and credentials
- [ ] Performance: Monitor latency and resource usage

---

## Important: Known Limitations & Best Practices

### Data Leakage Prevention ✓
- ❌ IP addresses are NOT used as features
- ❌ Timestamps are NOT used as features
- ✓ Only numerical flow-based features
- ✓ Proper train/test split with stratification

### Production Considerations

1. **Feature Extraction**: The critical step is extracting the correct 78 features from your network traffic. Mismatch will cause poor predictions.

2. **Feature Scaling**: Features are automatically scaled using StandardScaler. The scaler is already fitted during training.

3. **Real-time Performance**: 
   - Batch prediction is more efficient than single predictions
   - Use multiprocessing for high-volume traffic
   - Consider GPU acceleration if latency is critical

4. **Model Monitoring**:
   - Track prediction confidence scores
   - Log anomalies and false alarms
   - Compare with manual analysis periodically
   - Retrain if attack patterns change

5. **Security Implications**:
   - PortScan detection has 99.99% precision (very few false positives)
   - General attack detection at 99.89% accuracy
   - Test on your specific network before full deployment
   - Monitor for adversarial examples

---

## Troubleshooting

### Missing Features Error
```
Error: Missing features: ['Feature1', 'Feature2']
```
**Solution**: Ensure your feature extraction provides all 78 features from `feature_names.pkl`

### Poor Accuracy on Your Data
- **Cause**: Feature extraction not matching CICIDS2017
- **Solution**: Compare packet-to-feature calculation with dataset documentation
- **Fallback**: Use tcpdump with known CICIDS2017 traffic for testing

### Performance Issues
- **Use batch_predict()** instead of single predictions
- **Implement caching** for common patterns
- **Consider GPU** with XGBoost gpu_id parameter

---

## Model Files Summary

```
File: stage1_nids_model.pkl
- Type: XGBoost Binary Classifier
- Classes: 2 (Normal=0, Attack=1)
- Features: 78 numerical
- Size: ~5-10 MB

File: stage2_nids_model.pkl
- Type: XGBoost Multi-class Classifier
- Classes: 14 attack types
- Features: 78 numerical
- Size: ~5-10 MB

File: scaler.pkl
- Type: StandardScaler
- Fitted on: 78 features from training data
- Operation: (X - mean) / std_dev

File: label_encoder.pkl
- Type: LabelEncoder
- Classes: 14 attack types
- Maps indices to attack type names

File: feature_names.pkl
- Type: List of strings
- Length: 78 features
- Critical for correct feature ordering
```

---

## Advanced: Custom Retraining

To retrain models with new data:

```bash
# Place new CSV files in dataset directory
cd "d:\Dataset - codex"

# Run training script
python train_nids_models.py

# Models will be saved to models/ directory
```

---

## Support & Documentation

### Feature Reference
Run to see all required features and attack types:
```python
from nids_predictor import NIIDSPredictor
predictor = NIIDSPredictor()
print(predictor.get_feature_names())
print(predictor.get_attack_types())
```

### Performance Tuning
- Adjust batch size for throughput vs latency tradeoff
- Use multiprocessing for parallel processing
- Cache predictions for duplicate flows

### Logging & Monitoring
```python
result = predictor.predict_flow(features)

# Log detailed results
if result['is_attack']:
    log_alert(flow_id, result['attack_type'], result['confidence'])
else:
    log_normal_traffic(flow_id, result['confidence'])
```

---

## Next Steps

1. ✓ Models are trained and saved
2. ⚬ Implement feature extraction for your network
3. ⚬ Test on production traffic (in detection mode first)
4. ⚬ Set up alerting and logging infrastructure
5. ⚬ Monitor and tune as needed

**Ready for deployment!** 🚀
## Runtime IP Manager Update

Current deployment includes a simplified IP Manager. Operators can pick from captured/scanned IPs, IDPS-blocked IPs, and existing ThreatGuard firewall rules. Block or Allow changes are staged locally, then applied to Windows Firewall with Apply Changes. Right-click actions on traffic rows can toggle a single source or destination IP between blocked and allowed. Reset All clears saved allowed/blocked state and removes ThreatGuard-managed firewall block rules.

Detectable attack families include Port Scan/probing, DoS, DDoS, brute force, Bot/Malware/C2-like communication, data exfiltration or infiltration, DNS tunneling, ARP spoofing, SQL injection, and XSS-style web attack labels when supported by the loaded model artifacts.
