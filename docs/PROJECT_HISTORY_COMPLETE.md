# ThreatGuard Project History (Start -> Current)

## 1. Project Vision

ThreatGuard was built as a desktop, real-time Intrusion Detection and Prevention System (IDPS) with:

- Live packet capture from host interfaces.
- Two-stage ML detection pipeline.
- Attack type classification and confidence scoring.
- Automatic prevention (host firewall block).
- Operator-friendly dashboard for monitoring and investigation.

---

## 2. Base Architecture Introduced

### UI Layer

- `main.py`: app entrypoint.
- `threatguard/app.py`: Qt application and theme setup.
- `threatguard/main_window.py`: dashboard orchestration.
- `threatguard/widgets/*`: toolbar, traffic table, blocked table, detail panel, status bar, export dialog.

### Detection/Engine Layer

- `threatguard/core/engine.py`: engine state management, thread control, UI signal fanout.
- `threatguard/core/real_capture.py`: live capture, feature extraction flow, inference, block actions.
- `threatguard/core/mock_capture.py`: simulation/testing source.
- `threatguard/core/flow_aggregator.py`: packet-to-flow aggregation and feature generation.
- `threatguard/core/packet.py`: packet/threat data model.

### Model Assets

- `threatguard/models final/`: primary model bundle (`stage1`, `stage2`, `scaler`, `label_encoder`, `feature_names`, metadata).
- `threatguard/models final/`: primary CICIDS model bundle.

---

## 3. Core Functional Intent

The intended runtime flow:

1. Capture traffic.
2. Aggregate packets into flows.
3. Compute feature vector.
4. Stage 1 ML model detects normal vs attack.
5. Stage 2 ML model classifies attack type.
6. If malicious and confidence high, block source via host firewall.
7. Show all traffic in left table and blocked events in right table.

---

## 4. Major Issues Found During Iteration

### Issue A: ML appeared to be non-functional

- Detection looked unreliable.
- Model-feature mismatch existed between available bundles.

### Issue B: False positives / random blocking

- Aggressive fallback/signature paths could classify benign bursts as attacks.

### Issue C: Missed practical scans

- Real `nmap -sS` behavior (many tiny SYN probes) could evade pure per-flow confidence gates.

### Issue D: Alert flooding

- Single scan bursts generated thousands of blocked entries.

### Issue E: Startup privilege friction

- Live capture/prevention required admin privileges, but startup path was not fully streamlined for users.

---

## 5. Key Engineering Updates Applied

### 5.1 Startup and privilege handling

- Added admin check at startup.
- Added automatic UAC elevation relaunch on Windows.
- If elevation denied/fails, app exits with clear user message.

### 5.2 Feature compatibility hardening

- Extended flow feature mapping to support both naming styles used in project model artifacts.
- Reduced model mismatch risk when switching available bundles.

### 5.3 Scaler input normalization fix

- Updated scaler inference path to pass named feature columns when required.
- Eliminated scikit-learn warning:
  - `X does not have valid feature names, but StandardScaler was fitted with feature names`.

### 5.4 Detection policy tuning

- Tightened confidence gates in normal mode to reduce false positives.
- Restricted noisy signature-only logic to test-focused contexts.
- Preserved practical detectability for real scan traffic.

### 5.5 Behavioral scan assist

- Added targeted SYN-scan burst behavior detection for practical `nmap -sS` coverage.
- Used as ML-assisted detection aid in real traffic where short probe flows underrepresent confidence.
- Added clear `model_used` trace values (`+ BehavioralScan`, `+ ScanEvidence`) for transparency.

### 5.6 Blocked-window deduplication

- Implemented dedup by `(source_ip + threat_type)` with 15-second cooldown.
- Behavior now:
  - Same source + same threat within cooldown -> single entry.
  - Same source + different threat -> separate entry.
  - Same source + same threat after cooldown -> new entry.

---

## 6. Current Detection Behavior (As Of Now)

### In normal operation

- Primary path: Stage 1 + Stage 2 ML.
- Signature-only path is constrained to avoid false-positive noise.
- Behavioral scan assist may trigger for clear SYN-scan bursts.

### In UI visibility

- Left table: all traffic and malicious alerts.
- Right table: deduplicated blocked events.
- Detail panel includes:
  - threat type,
  - confidence,
  - model path used,
  - prevention reason.

---

## 7. Operational Notes

- Windows admin rights are required for real capture and firewall block actions.
- Ensure target traffic reaches the monitored NIC.
- Validate with controlled attacks from a separate host/VM:
  - `nmap -sS`,
  - flood tests,
  - service-specific probes.

---

## 8. Current State Summary

The project has evolved from baseline ML integration to a hardened production-style runtime with:

- Admin-safe startup flow,
- model/feature compatibility improvements,
- reduced false positives,
- practical scan detection support,
- and actionable, non-flooding blocked-event visibility.

This document reflects the journey from original architecture through iterative fixes to the current working state.

---

## 9. Latest IP Manager Refinement

The IP Manager was refined into a local firewall workflow:

- Captured/scanned IPs are listed in the manager.
- IDPS-blocked IPs can be selected and allowed.
- Block/Allow choices are staged first and applied to Windows Firewall only when the operator clicks Apply Changes.
- Right-click actions were added to the All Traffic and Blocked Traffic tables for quick single-IP block/allow toggling.
- Reset All returns IP Manager to its default state by clearing saved allowed/blocked IPs and removing ThreatGuard-managed firewall block rules.

Current detectable attack families include Port Scan, DoS/DDoS, brute force, malware/bot/C2-like traffic, exfiltration/infiltration, DNS tunneling, ARP spoofing, and SQL/XSS-style web attacks where the model label maps to those classes.
