# MCA Dissertation Draft
## Project Title
**ThreatGuard: Machine Learning Based Intrusion Detection and Prevention System (IDPS) for Real-Time Network Traffic Monitoring**

---

## Front Matter

### Certificate Page (To be added as per institute format)
`[Insert institute certificate page here]`

### Declaration
I hereby declare that this dissertation titled **"ThreatGuard: Machine Learning Based Intrusion Detection and Prevention System (IDPS) for Real-Time Network Traffic Monitoring"** is my original work carried out under the guidance of my supervisor.  
The work has not been submitted previously for any degree or diploma.

### Acknowledgement
`[Add your acknowledgement text here for guide, department, institute, family]`

### Abstract
This dissertation presents the design and development of **ThreatGuard**, a desktop-based Intrusion Detection and Prevention System (IDPS) that uses machine learning for real-time threat monitoring and response. The system captures live network traffic, aggregates packets into flows, extracts feature vectors, and applies a two-stage machine learning pipeline for malicious traffic detection and attack-type classification. When confidence thresholds are satisfied, the system applies host-level prevention actions and logs events in a dedicated blocked-traffic panel.  
The solution is implemented in Python using PySide6, Scapy, scikit-learn, and XGBoost ecosystem components. The dissertation documents requirement analysis, architecture, system design, implementation, testing, validation, and deployment considerations.

### Keywords
Intrusion Detection, Intrusion Prevention, Machine Learning, Network Security, Real-Time Monitoring, PySide6, Scapy, XGBoost.

---

## Table of Contents
1. Chapter 1: Introduction / Problem Definition  
2. Chapter 2: System Requirement Analysis  
3. Chapter 3: System Design  
4. Chapter 4: System Development  
5. Chapter 5: System Implementation  
6. Bibliography  
7. Appendices  

---

# Chapter 1: Introduction / Problem Definition

## 1.1 Background
With increasing cyber threats, organizations and individuals require continuous monitoring of network traffic and immediate response capability. Traditional monitoring approaches are often reactive and require manual correlation across multiple tools. A unified platform that can detect suspicious behavior in real time and trigger preventive actions can significantly improve security posture.

## 1.2 Existing System and Gap
In many environments, traffic monitoring is either:
- manual (packet capture logs reviewed later),
- fragmented (separate tools for sniffing, analysis, and blocking), or
- signature-only (limited adaptability).

Such setups suffer from delayed response, operator overload, and inconsistency in threat handling.

## 1.3 Problem Definition
The problem addressed in this dissertation is the absence of an integrated, real-time, machine-learning-enabled desktop system that can:
- monitor traffic continuously,
- detect malicious behavior,
- classify attack category,
- and apply immediate prevention action with clear visual feedback.

## 1.4 Need for the New System
The proposed system is needed to improve:
- **Efficiency**: automatic pipeline from capture to action,
- **Effectiveness**: ML-based detection and classification,
- **Control**: centralized UI with status and event streams,
- **Security**: automatic host-level blocking with reason trace.

## 1.5 Objectives
1. Build a real-time network monitoring dashboard.  
2. Implement ML-based malicious traffic detection using staged inference.  
3. Classify attack type using a second-stage model.  
4. Trigger host-level blocking for confirmed malicious sources.  
5. Display all traffic and blocked traffic in separate windows.  
6. Provide detailed event-level explanation with confidence and action reason.  
7. Reduce duplicate alert flooding for operator usability.

## 1.6 Scope
### In Scope
- Desktop-based IDPS for live traffic capture and analysis.
- Two-stage ML pipeline integration.
- Event logging, visualization, and export.
- Host firewall-based prevention (Windows target).

### Out of Scope
- Distributed multi-node SOC deployment.
- Cloud-native autoscaling architecture.
- SIEM integrations (future extension).

## 1.7 Methodology
The development follows a practical SDLC with iterative refinement:
- requirement analysis,
- architecture and module design,
- incremental implementation,
- controlled testing,
- threshold tuning and usability hardening.

## 1.8 Data and Data Collection Method
- **Runtime data**: live packets captured via network interface using Scapy.
- **Derived data**: flow-level statistical features extracted from captured packet streams.
- **Model artifacts**: pre-trained Stage 1 and Stage 2 model files with scaler, label encoder, and feature metadata.
- **Validation data**: controlled test traffic generated from secondary machine in same network.

---

### Figure Placeholder (Chapter 1)
**Figure 1.1: Problem Context Diagram**  
`[Insert figure here: Existing fragmented monitoring vs proposed unified ThreatGuard pipeline]`

**What to show in this diagram**
- Left side: Existing system (sniffer -> manual analysis -> delayed action).  
- Right side: Proposed system (capture -> ML detect/classify -> block -> dashboard).

---

# Chapter 2: System Requirement Analysis

## 2.1 Stakeholders and Users
- Security operator / system admin.
- Developer / maintainer.
- End-user requiring local host protection.

## 2.2 Functional Requirements
1. Start/stop live packet capture.  
2. Select capture interface.  
3. Aggregate packets into flows for ML inference.  
4. Perform Stage 1 malicious detection.  
5. Perform Stage 2 attack-type classification for malicious traffic.  
6. Trigger blocking when prevention criteria are met.  
7. Show all traffic in Window 1 and blocked alerts in Window 2.  
8. Show deep details in detail panel.  
9. Export logs/events.

## 2.3 Non-Functional Requirements
- Real-time responsiveness.
- Reliable inference pipeline.
- Clear visual traceability of alerts.
- Low false-positive behavior in normal operation.
- Maintainability via modular codebase.

## 2.4 Process Identification
Primary processes:
- P1: Packet Capture
- P2: Flow Aggregation
- P3: Feature Preparation
- P4: Stage 1 Classification
- P5: Stage 2 Classification
- P6: Prevention Action
- P7: UI/Event Logging

## 2.5 Inputs and Outputs
### Input
- Raw IP packets from NIC.
- User controls (start/stop, mode toggles, model selections).
- Model artifacts from disk.

### Output
- Traffic table entries.
- Malicious alerts with threat type/confidence.
- Blocked table entries.
- Host firewall block rule actions.
- Exported logs.

## 2.6 Data Elements (sample)
- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `length`, `flags`, `timestamp`
- `is_malicious`, `threat_type`, `confidence`, `model_used`, `is_blocked`, `block_reason`

## 2.7 Rules, Controls, and Security
- Confidence threshold gates for action.
- Prevention toggle control.
- Admin privilege enforcement for live blocking.
- Input validations for model file presence and compatibility.
- Deduplication of blocked alerts by source+threat within cooldown window.

## 2.8 Deficiencies Observed During Development
- Feature-model mismatch risks across available model bundles.
- Potential false positives under aggressive fallback.
- Event flood in blocked table during burst scans.
- Privilege-related failures in capture/block actions.

## 2.9 Requirement Refinement Outcomes
- Hardened feature compatibility handling.
- Confidence and fallback policy tuning.
- blocked-event deduplication logic.
- improved startup privilege flow with UAC elevation support.

---

### Figure Placeholders (Chapter 2)
**Figure 2.1: Use Case Diagram**  
`[Insert UML use case diagram here]`

**What to show**
- Actor: Security Operator  
- Use cases: Start Monitoring, Stop Monitoring, View Traffic, View Blocked Alerts, Inspect Packet Details, Export Logs, Configure Model Paths.

**Figure 2.2: Requirement Traceability Matrix (Table/Diagram)**  
`[Insert matrix screenshot/table here]`

**What to include**
- Requirement ID, description, module, test case ID, status.

---

# Chapter 3: System Design

## 3.1 High-Level Architecture
ThreatGuard follows a layered architecture:
- Presentation Layer (PySide6 UI)
- Control Layer (Engine/Signal orchestration)
- Capture & Feature Layer (Real capture + flow aggregator)
- ML Inference Layer (Stage 1 + Stage 2)
- Prevention Layer (Host firewall actions)
- Persistence/Export Layer (log export utilities)

## 3.2 Module Design
### 3.2.1 UI Modules
- Main window layout, toolbar, sidebar, tables, detail panel.

### 3.2.2 Core Modules
- Engine state machine and thread management.
- Live capture thread for packet acquisition and inference dispatch.
- Packet data model and threat metadata model.

### 3.2.3 Analytics Modules
- Flow aggregation and feature extraction.
- Two-stage model inferencing.

### 3.2.4 Utility Modules
- Export handling and formatting.

## 3.3 Process Flow Logic
1. Capture packet from selected NIC.  
2. Emit raw packet to all-traffic table.  
3. Aggregate into flow state.  
4. Compute feature vector on flow expiry/trigger.  
5. Apply scaler and Stage 1 model.  
6. If malicious, apply Stage 2 classifier.  
7. Determine action and prevention reason.  
8. Emit blocked alert (deduplicated) and update stats.

## 3.4 Interface Design
### 3.4.1 Output Design
- **Window 1 (All Traffic)**: rolling traffic visibility.
- **Window 2 (Blocked Traffic)**: blocked-only event list.
- **Detail Panel**: selected event deep inspection.

### 3.4.2 Input Design
- Toolbar controls: Start/Stop, mode selection, model browsing, prevention toggle.
- Menu actions: export, clear, help/about.

## 3.5 Data/File Design
### 3.5.1 Model Artifact Files
- Stage 1 model file
- Stage 2 model file
- scaler, label encoder, feature names, metadata

### 3.5.2 Runtime Data Structures
- flow records, packet objects, stats object, dedup cache

## 3.6 Data Dictionary (sample extract)

| S.No | Field Name | Type/Size | Description | Module |
|---|---|---|---|---|
| 1 | src_ip | String/45 | Source IP address | packet model |
| 2 | dst_ip | String/45 | Destination IP address | packet model |
| 3 | threat_type | Enum | Classified threat class | inference |
| 4 | confidence | Float | Model confidence | inference |
| 5 | is_blocked | Bool | Prevention action status | engine |
| 6 | block_reason | String | Action explanation | engine/UI |

---

### Figure Placeholders (Chapter 3)
**Figure 3.1: System Architecture Diagram**  
`[Insert layered architecture diagram here]`

**What to show**
- UI -> Engine -> Capture/Flow -> ML -> Prevention -> UI Feedback loop.

**Figure 3.2: Data Flow Diagram (DFD Level-0)**  
`[Insert DFD Level-0 here]`

**What to show**
- External entity: Network Traffic Source  
- Processes: Capture, Analyze, Classify, Block, Display  
- Data stores: Model Files, Event Log.

**Figure 3.3: Flowchart of Detection Pipeline**  
`[Insert flowchart here]`

**What to show**
- Decision nodes: Stage 1 malicious? Stage 2 classified? block threshold reached?

---

# Chapter 4: System Development

## 4.1 Development Environment
- Python virtual environment
- PySide6 for GUI
- Scapy for live packet capture
- scikit-learn / XGBoost ecosystem for model inference
- Versioned local project workspace

## 4.2 Implementation Details
### 4.2.1 Application Bootstrap and Privilege Control
- Startup checks and Windows UAC elevation flow.

### 4.2.2 Capture and Feature Pipeline
- Live packet capture thread.
- Flow aggregation and feature vector generation.
- Feature/scaler compatibility handling for stable inference input.

### 4.2.3 ML Inference and Threat Lifecycle
- Stage 1 detection then Stage 2 classification.
- Confidence handling and prevention gating.
- Alert payload enrichment (confidence, model path, reason text).

### 4.2.4 Prevention and Event Emission
- Host firewall rule creation for malicious sources.
- Blocked alert deduplication for UI readability.

## 4.3 Testing and Debugging
### 4.3.1 Module Testing
- UI module checks.
- Engine state transition checks.
- model loading checks.
- flow feature generation checks.

### 4.3.2 System Testing
- End-to-end capture -> classify -> block -> display.
- Validation of blocked window behavior and dedup logic.

### 4.3.3 Error Handling Improvements
- model artifact validation before runtime.
- explicit runtime messages for missing dependencies/permissions.
- scaling warnings eliminated by named feature transforms.

## 4.4 Validation with Live Data
- Controlled traffic generation from separate host.
- Verification of detection output, confidence trace, block action, and UI updates.

## 4.5 Sample Runtime Output (To be inserted)
`[Insert screenshot set: dashboard running, alert details, blocked entries]`

---

### Figure Placeholders (Chapter 4)
**Figure 4.1: Activity Diagram (Runtime Sequence)**  
`[Insert activity diagram here]`

**What to show**
- Start monitoring -> packet capture -> flow build -> infer -> decision -> block/log.

**Figure 4.2: Sequence Diagram**  
`[Insert sequence diagram here]`

**Actors/objects**
- User, MainWindow, Engine, CaptureThread, FlowAggregator, MLModels, Firewall, UI Tables.

**Figure 4.3: Testing Evidence Screenshots**  
`[Insert screenshots with captions for module/system tests]`

---

# Chapter 5: System Implementation

## 5.1 Resource Requirements
### Hardware (Suggested)
- CPU: modern multi-core processor
- RAM: 8 GB minimum (16 GB recommended)
- Storage: SSD with free space for logs/model assets
- NIC: active network interface supporting packet capture

### Software
- Windows OS (admin rights)
- Python + required dependencies
- Npcap/WinPcap (for packet capture support)

### Human Resources
- 1 developer
- 1 project guide/supervisor
- 1 tester/operator (optional but recommended)

## 5.2 Cost Considerations
`[Add your actual cost table: hardware, software licenses (if any), deployment/training effort]`

## 5.3 Conversion Strategy
- Recommended: phased adoption
  - Start in monitor-only baseline observation.
  - Enable prevention after confidence review.
  - Expand to routine use with periodic threshold review.

## 5.4 Training Needs
- Operator training on:
  - start/stop and interface selection,
  - interpreting confidence and threat labels,
  - reviewing block reasons and exports,
  - troubleshooting permissions and capture issues.

## 5.5 Documentation
### 5.5.1 Operation Manual
- startup steps
- elevated launch behavior
- monitoring controls
- stop/shutdown procedure

### 5.5.2 User Manual
- table interpretation
- blocked alert meaning
- detail panel reading
- export and report usage

## 5.6 Outcomes
- Real-time visibility achieved.
- ML-based classification integrated.
- Automated prevention available.
- Operator dashboard made practical through dedup and reasoning traces.

## 5.7 Limitations
- Host-centric deployment.
- Platform-specific prevention behavior.
- Requires periodic model governance/tuning for evolving traffic profiles.

## 5.8 Future Enhancements
- policy profiles (strict/balanced/custom),
- SOC integration,
- richer analytics dashboard,
- retraining/feedback loop integration.

## 5.9 Conclusion
ThreatGuard demonstrates a complete end-to-end implementation of a practical machine-learning-driven IDPS. The system integrates live traffic capture, staged model inference, prevention actions, and operator-focused visualization into one workflow. The project validates that an academic ML security concept can be transformed into an operational desktop defense platform with measurable usability and response improvements.

---

# Bibliography (Sample - Replace/Expand)

1. Stallings, W., *Network Security Essentials*.  
2. Han, J., Kamber, M., *Data Mining: Concepts and Techniques*.  
3. Scikit-learn Documentation.  
4. XGBoost Documentation.  
5. PySide6/Qt Documentation.  
6. Scapy Documentation.  

---

# Appendices

## Appendix A: Questionnaire / Data Collection Instrument
`[Insert if required by your methodology]`

## Appendix B: Sample Feature List and Mapping
`[Insert snapshot/table from feature_names artifacts]`

## Appendix C: Test Cases and Results
`[Insert test case table and outputs]`

## Appendix D: Source Code Excerpts
`[Insert selected modules or attach complete source separately]`

---

## Information Needed From You To Finalize (Important)

Please share these so I can convert this draft to final submission-ready version:

1. Your name, roll number, institute, guide name.
2. Whether this is treated as **project** or **dissertation** in your final format.
3. Organization name (if any external organization is involved), else I will mark as academic/lab deployment.
4. Exact tools versions you want listed (Python, libraries).
5. Cost table values (or I can provide estimated values).
6. Whether you want IEEE or APA bibliography style.
7. Any required page-count limit from your department.

---

## Latest Implementation Addendum: IP Manager

ThreatGuard now includes a simplified IP Manager module. The module presents captured/scanned IP addresses, current ThreatGuard firewall state, and staged operator decisions. The operator can stage a selected IP as blocked or allowed, and the system updates Windows Firewall only after the Apply Changes action is submitted.

The application also supports right-click single-IP actions from both traffic tables. This allows quick allow/block control without opening Windows Firewall. The Reset All option clears saved allowed and blocked IP state and removes ThreatGuard-managed firewall block rules.

The current detection scope includes Port Scan/probing, DoS, DDoS, brute-force attacks, malware/bot/C2-like traffic, infiltration or data exfiltration, DNS tunneling, ARP spoofing, SQL injection, and XSS-style web attack labels when supported by the model artifacts.
