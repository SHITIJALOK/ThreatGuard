# ThreatGuard — ML-Powered IDPS Dashboard

ThreatGuard is a sophisticated, premium-grade Intrusion Detection and Prevention System (IDPS) built with Python and PySide6. It utilizes a two-stage Machine Learning (ML) pipeline to detect and block network threats in real-time.

## Current Runtime Notes (Latest)

- **Admin/UAC launch behavior**:
  - On Windows, if the app is started without admin rights, it now automatically requests elevation via a UAC prompt and relaunches itself.
  - If elevation is denied, the app exits with a clear message.

- **Detection path (production mode)**:
  - Primary path is still **Stage 1 + Stage 2 ML** on flow features.
  - Signature-only detection is restricted to **Test Mode** to avoid noisy false positives.
  - A targeted **BehavioralScan assist** is enabled for rapid SYN scan bursts (for real `nmap -sS` style behavior).

- **Blocked table de-duplication**:
  - Blocked entries are grouped by `(source_ip + threat_type)` with a **15-second cooldown**.
  - Same source + same threat within cooldown does not flood the Blocked window.
  - Same source + different threat appears as a separate entry.

- **Model compatibility improvements**:
  - Runtime now supports feature mapping compatibility for both model naming styles present in this project.
  - Scaler transform now passes named features to avoid `StandardScaler` feature-name warnings.

- **How to interpret `Model Used` in UI**:
  - `XGBoost` (or selected model name): ML path.
  - `... + ScanEvidence` / `... + BehavioralScan`: ML-assisted scan evidence path.
  - `... + Signature`: signature path (test-focused mode).

---

## 🚀 Key Features

*   **Real-Time Traffic Monitoring**: Deep packet inspection using the Scapy engine.
*   **Two-Stage ML Defense**:
    *   **Stage 1 (Binary)**: Ultra-fast XGBoost classifier determines if traffic is `Normal` or an `Attack`.
    *   **Stage 2 (Multi-Class)**: Classifies flagged traffic into 14 distinct attack categories.
*   **Intelligent Flow Aggregation**: Groups raw packets into network flows (5-tuple) and computes 78 CIC-IDS2017 features (IAT, throughput, flag counts, window sizes, etc.) for high-precision inference.
*   **Automatic Prevention**: Instantly drops malicious flows to protect the host machine.
*   **IPv6 Support**: Fully compatible with modern network stacks.
*   **Premium Dashboard UI**:
    *   **Live Statistics**: Real-time counter of total, malicious, blocked, and clean traffic.
    *   **Global Logging**: Centralized debug window for engine status and critical alerts.
    *   **Detailed Analysis**: Inspect deep packet headers and ML confidence scores on demand.
*   **Simulation Mode**: High-fidelity mock capture for testing and demonstrations without requiring root privileges.

---

## 🛠️ Technology Stack

*   **Core Logic**: Python 3.10+
*   **GUI Framework**: PySide6 (Qt for Python)
*   **Network Intelligence**: Scapy
*   **Machine Learning**: XGBoost, Scikit-Learn
*   **Data Processing**: NumPy, Pandas
*   **Styling**: Vanilla CSS (QSS) with a premium GitHub-inspired Dark Theme.

---

## 🧠 Machine Learning Details

The system is trained on the **CIC-IDS2017** dataset, using a refined 78-feature set.

### Stage 2 Categories (14 Classes)
The IDPS can specifically identify:
- `Bot`
- `DDoS`
- `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `DoS Slowloris`
- `FTP-Patator`, `SSH-Patator`
- `Heartbleed`
- `Infiltration`
- `PortScan`
- `Web Attack – Brute Force`, `Web Attack – Sql Injection`, `Web Attack – XSS`

### Feature Pipeline
1.  **Packet Sniffing**: Capture raw IPv4/IPv6 traffic.
2.  **Flow Aggregation**: Group by `(src_ip, dst_ip, src_port, dst_port, protocol)`.
3.  **Feature Extraction**: Calculate 78 statistical features (e.g., `Flow Duration`, `Flow IAT Mean`, `Init_Win_bytes_forward`).
4.  **Scaling**: Normalize data using a pre-trained `scaler.pkl`.
5.  **Inference**: Run through the XGBoost cascade.

---

## 📂 Project Structure

```text
ThreatGuard/
├── main.py                    # Entry point
├── requirements.txt           # Dependencies
├── threatguard/
│   ├── app.py                 # Application initialization
│   ├── main_window.py         # Main UI logic and layout
│   ├── core/
│   │   ├── engine.py          # IDPS Engine orchestration
│   │   ├── real_capture.py    # Live Scapy sniffing and ML classification
│   │   ├── mock_capture.py    # Simulated traffic generator
│   │   ├── flow_aggregator.py # 78-feature flow computation logic
│   │   └── packet.py          # Data models for network packets
│   ├── models final/          # Production ML models
│   │   ├── stage1_nids_model.pkl
│   │   ├── stage2_nids_model.pkl
│   │   ├── scaler.pkl
│   │   └── feature_names.pkl
│   ├── styles/                # CSS/QSS themes and assets
│   ├── utils/                 # Exporters and loggers
│   └── widgets/               # Modular UI components (Tables, Sidebar, Toolbar)
```

---

## 🚦 Getting Started

### Prerequisites
- WinPcap or Npcap (on Windows) must be installed for Scapy to capture live traffic.
- **Administrator Privileges**: Required to sniff on most interfaces.

### Installation
1.  **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the application**:
    ```bash
    python main.py
    ```

---

## 🧪 Testing & Demonstration

To demonstrate detection, you can run attacks from a different machine (or a VM in Bridged mode) targeting the host running ThreatGuard.

### 1. Port Scanning (Nmap)
The model detects the behavioral patterns of port scanning (many short SYN/RST flows).
```bash
sudo nmap -sS -p 1-1000 -T4 <target-ip>
```
*Wait ~5-7 seconds after the scan starts for the flow to time out and trigger an alert.*

### 2. DoS/DDoS (hping3)
Triggers flood detection and high-volume attack classification.
```bash
sudo hping3 -S --flood -p 80 <target-ip>
```

### 3. Brute Force (Hydra)
Targets SSH or FTP services to trigger "Patator" multi-class detection.
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
```

---

## ⚠️ Important Configuration

- **Flow Thresholds**: Located in `threatguard/core/flow_aggregator.py`. Default timeout of 5s and min packet count of 2 to ensure rapid detection of even stealthy nmap scans.
- **Confidence Threshold**: Default is set to **90%** to minimize false positives. This can be adjusted in `threatguard/core/real_capture.py`.
- **Interface Selection**: Use the dropdown in the UI to select your active Network Interface Card (NIC).

---

## IP Manager

ThreatGuard includes an **IP Manager** under `Tools -> IP Manager...`.

- Captured/scanned IPs are shown automatically.
- IPs blocked by the IDPS are selectable.
- Choose **Block Selected** or **Allow Selected** to stage a local decision.
- Click **Apply Changes** to update Windows Firewall.
- Use **Reset All** to clear saved allowed/blocked state and remove ThreatGuard-managed firewall block rules.
- Right-click a row in the All Traffic or Blocked Traffic table to quickly block or allow the source/destination IP.

## Attack Types

ThreatGuard can surface these attack families depending on the loaded model and runtime evidence:

- Port Scan / probing
- DoS and DDoS
- SSH/FTP brute force
- Bot or malware-like communication
- C2-style communication
- Data exfiltration / infiltration
- DNS tunneling
- ARP spoofing
- SQL injection and XSS-style web attacks
