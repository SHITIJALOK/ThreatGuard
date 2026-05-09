# ThreatGuard Master Project Overview

Last consolidated: 2026-04-19

## Project Summary

ThreatGuard is a Windows-focused desktop Intrusion Detection and Prevention System (IDPS). It captures live network traffic, aggregates packets into flows, extracts flow-level features, applies a staged machine learning pipeline, and can block malicious source IPs using the Windows firewall. The project also includes a PySide6 dashboard for monitoring traffic, blocked alerts, event details, and statistics.

This document consolidates the current repository state from the Markdown files and verifies key runtime behavior against the Python code.

## What The Project Does

- Live packet capture from host interfaces
- Flow aggregation and feature extraction
- Two-stage malicious traffic detection and attack classification
- Confidence-aware prevention
- Windows Firewall blocking for confirmed malicious sources
- Separate all-traffic and blocked-traffic views
- Detailed event inspection with threat type, confidence, model trace, and reason
- Blocked-alert de-duplication to reduce UI flooding
- Export support
- Mock/simulation mode for testing

## Verified Current Runtime Behavior

### Startup and privilege model

- Real capture and prevention require administrator privileges
- On Windows, the app auto-prompts for UAC elevation if it is not already running as admin
- If elevation is denied, the app exits with a clear message

### Model discovery and load order

The engine prefers model files in this order:

1. `threatguard\models final`

Supported filenames:

- Stage 1: `stage1_nids_model.pkl`
- Stage 2: `stage2_nids_model.pkl`

This means the runtime currently prefers the newer `models final` bundle when it is present.

### Prevention and blocking

- Blocking is implemented for Windows only
- ThreatGuard adds inbound firewall rules using `netsh advfirewall firewall add rule`
- Unsafe or non-routable IPs are not blocked
- Previously blocked IPs are tracked to avoid duplicate firewall rule creation

### Detection thresholds and behavior

- Default confidence threshold is `0.90`
- Blocking happens only when prevention is enabled and confidence passes the threshold
- Signature-only logic is constrained outside test mode to reduce false positives
- Behavioral scan assistance exists for rapid SYN-scan burst detection

### Blocked-alert de-duplication

- Blocked alerts are de-duplicated by `(source_ip + threat_type)`
- Current cooldown window is `15 seconds`
- This prevents blocked-table flooding during repeated scan bursts

## Repository Structure

Important top-level files:

- `main.py` - app entry point and admin/UAC handling
- `requirements.txt` - Python dependencies
- `residual\train_models.py` - archived legacy training helper
- `residual\test_models.py` - archived legacy evaluation launcher

Important Markdown sources consolidated into this file:

- `MCA_DISSERTATION_REPORT_THREATGUARD.md`
- `PROJECT_HISTORY_COMPLETE.md`
- `ThreatGuard README.md`
- `DEPLOYMENT_GUIDE.md`
- `IDPS_MODEL_INTEGRATION.md`

Main package structure:

- `threatguard\app.py`
- `threatguard\main_window.py`
- `threatguard\core\engine.py`
- `threatguard\core\real_capture.py`
- `threatguard\core\mock_capture.py`
- `threatguard\core\flow_aggregator.py`
- `threatguard\core\packet.py`
- `threatguard\widgets\*`
- `threatguard\utils\exporter.py`

## Architecture Overview

ThreatGuard follows a layered design:

- Presentation layer: PySide6 desktop dashboard
- Control layer: engine orchestration and state management
- Capture layer: Scapy-based live capture
- Feature layer: flow aggregation and feature generation
- ML inference layer: Stage 1 plus Stage 2 prediction pipeline
- Prevention layer: host firewall blocking
- Export/logging layer: event export and reporting

## Machine Learning Design

### Preferred current deployment bundle

The current documentation for `threatguard\models final` describes:

- a two-stage classification pipeline
- a `78`-feature input vector
- a CICIDS2017-based NIDS bundle
- `14` attack categories
- supporting files such as `scaler.pkl`, `label_encoder.pkl`, `feature_names.pkl`, and `metadata.pkl`

Documented Stage 2 attack categories:

- Bot
- DDoS
- DoS GoldenEye
- DoS Hulk
- DoS Slowhttptest
- DoS slowloris
- FTP-Patator
- Heartbleed
- Infiltration
- PortScan
- SSH-Patator
- Web Attack - Brute Force
- Web Attack - Sql Injection
- Web Attack - XSS

### Training and evaluation scripts

The repository includes archived helper scripts moved out of active runtime:

- `residual\train_models.py` is an archived training entry script
- `residual\test_models.py` is an archived evaluation launcher
- the runtime model bundle is `models final`

## Evaluation Metrics

This section answers: "Evaluation metrics you calculated?"

### Metrics documented for the preferred deployed NIDS bundle

Stage 1 binary classifier:

- Accuracy: `99.89%`
- Precision: `99.65%`
- Recall: `99.72%`
- F1 Score: `99.69%`
- ROC-AUC: `1.0000`

Stage 2 multi-class classifier:

- Overall Accuracy: `99.82%`

PortScan-specific metrics:

- Precision: `99.99%`
- Recall: `99.94%`

### Metrics computed by repository code

The local Python evaluation/training scripts compute:

- Accuracy
- Weighted F1 score
- Weighted precision
- Weighted recall
- Classification report
- Confusion matrix
- Detection rate
- False positive rate
- Feature importance
- Training time

### Important accuracy note

The high `99.89%` and `99.82%` values are documented in the Markdown files for the deployed NIDS bundle. Local scripts should be described as CICIDS-oriented utilities.

### What is not available in the Markdown docs

- Exact confusion matrix values for the preferred deployed bundle are not written in the Markdown files
- ROC-AUC is documented for the preferred deployed bundle, while local scripts may report a different subset of metrics

## Technology Stack

- Python
- PySide6
- Scapy
- scikit-learn
- XGBoost ecosystem components in the newer NIDS docs
- NumPy
- Pandas
- Windows Firewall / `netsh advfirewall`
- Npcap or WinPcap for live packet capture

## Deployment Notes

- Windows is the main supported target for prevention behavior
- Administrator rights are required for real capture and blocking
- Npcap or WinPcap should be installed for live capture support
- Validation should be done with controlled traffic from another host or VM

Examples mentioned in the docs:

- `nmap -sS`
- flood-style tests
- brute-force or service-probing tests

## Strengths

- End-to-end desktop IDPS workflow
- Real-time visibility and operator dashboard
- Confidence-aware prevention
- De-duplicated blocked-alert visibility
- Support for both newer and legacy model bundles
- Clear threat details with reason traces

## Limitations

- Host-centric deployment
- Windows-only firewall blocking implementation
- Requires admin privileges for important runtime features
- Detection quality depends on correct feature extraction and model compatibility
- The repository contains mixed historical references between newer and legacy model tracks
- The dissertation draft still includes placeholders and institution-specific fields

## Dissertation Status

`MCA_DISSERTATION_REPORT_THREATGUARD.md` is a structured draft and not a final submission-ready document. It already covers:

- problem definition
- objectives
- requirements
- design
- implementation
- testing
- limitations
- future scope

It still needs manual completion for:

- certificate page
- acknowledgement
- figures and diagrams
- screenshots
- cost table
- appendices
- personal and institute details

## Final Summary

ThreatGuard is a functional desktop IDPS that combines live traffic capture, staged ML-based detection, operator-facing visualization, and optional Windows firewall prevention. The strongest current value of the project is that it unifies monitoring, analysis, prevention, and visibility in a single local application. The main documentation risk is that the repository includes both a newer preferred deployment bundle and older legacy training/testing assets, so evaluation claims should always be labeled against the correct model track.

## Latest IP Manager Update

ThreatGuard now includes a simplified IP Manager that behaves like a local firewall manager. It lists captured/scanned IPs, current ThreatGuard firewall state, and pending changes. Operators can stage Block or Allow decisions and then apply them to Windows Firewall with one Apply Changes action.

Right-click actions are also available from the traffic and blocked tables. On a selected packet row, ThreatGuard offers the opposite action for each IP: blocked IPs can be allowed, and unblocked IPs can be blocked. The Reset All action clears saved allowed/blocked state and removes ThreatGuard-managed firewall block rules.

Detected attack categories include Port Scan, DoS, DDoS, Brute Force, Malware/Bot/C2-like communication, Data Exfiltration/Infiltration, DNS Tunneling, ARP Spoofing, and SQL/XSS-style web attacks when supported by the loaded model labels.
