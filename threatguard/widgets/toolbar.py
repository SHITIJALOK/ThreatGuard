

from __future__ import annotations

import socket

from PySide6.QtCore import Signal, QThread
from PySide6.QtWidgets import (
    QToolBar, QWidget, QPushButton, QComboBox, QLabel,
    QHBoxLayout, QVBoxLayout, QSizePolicy, QFileDialog,
)
from PySide6.QtGui import QFont

from threatguard.core.engine import AVAILABLE_MODELS, EngineState, CaptureMode

class _NicProbeThread(QThread):
    

    probe_finished = Signal(dict, str)                 

    def __init__(self, interfaces: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        self._interfaces = interfaces

    def run(self):
        counts: dict[str, int] = {}
        errors: list[str] = []

        try:
            from scapy.all import sniff
        except Exception as e:
            self.probe_finished.emit({}, f"Scapy unavailable: {e}")
            return

                                              
        for _, iface in self._interfaces[:10]:
            hit = [0]

            def _inc(_):
                hit[0] += 1

            try:
                sniff(
                    iface=iface,
                    prn=_inc,
                    store=False,
                    timeout=0.6,
                    count=150,
                )
                counts[iface] = hit[0]
            except Exception as e:
                errors.append(f"{iface}: {e}")
                counts[iface] = 0

        err = "; ".join(errors[:3])
        self.probe_finished.emit(counts, err)

class ControlToolbar(QToolBar):
    

    start_clicked = Signal()
    stop_clicked = Signal()
    disable_toggled = Signal(bool)
    model_changed = Signal(str)
    capture_mode_changed = Signal(CaptureMode)
    interface_changed = Signal(str)
    test_mode_toggled = Signal(bool)
    sensitivity_changed = Signal(str)
    binary_model_browse = Signal(str)
    attack_model_browse = Signal(str)

    def __init__(self, parent=None):
        super().__init__("IDPS Controls", parent)
        self.setMovable(False)
        self.setFloatable(False)
        self._setup_ui()

    def _setup_ui(self):
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(10, 6, 10, 6)
        outer.setSpacing(6)

                                                                         
        row1 = QHBoxLayout()
        row1.setSpacing(10)

        brand = QLabel("⛨  THREATGUARD IDPS")
        brand.setObjectName("titleLabel")
        brand.setFont(QFont("Segoe UI", 14, QFont.ExtraBold))
        brand.setMinimumWidth(200)
        row1.addWidget(brand)

        self._sep(row1)

               
        self.start_btn = QPushButton("▶  Start IDPS")
        self.start_btn.setObjectName("startButton")
        self.start_btn.setToolTip("Start the IDPS engine")
        self.start_btn.setMinimumWidth(110)
        self.start_btn.clicked.connect(self.start_clicked.emit)
        row1.addWidget(self.start_btn)

              
        self.stop_btn = QPushButton("■  Stop IDPS")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setToolTip("Stop the IDPS engine")
        self.stop_btn.setMinimumWidth(110)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_clicked.emit)
        row1.addWidget(self.stop_btn)

                            
        self.disable_btn = QPushButton("⚠  Disable Prevention")
        self.disable_btn.setObjectName("disableButton")
        self.disable_btn.setCheckable(True)
        self.disable_btn.setToolTip("Disable blocking — detection-only mode")
        self.disable_btn.setMinimumWidth(170)
        self.disable_btn.setEnabled(False)
        self.disable_btn.toggled.connect(self._on_disable_toggled)
        row1.addWidget(self.disable_btn)

                   
        self.test_mode_btn = QPushButton("Test Mode: OFF")
        self.test_mode_btn.setCheckable(True)
        self.test_mode_btn.setToolTip("Lower ML thresholds for validation/testing")
        self.test_mode_btn.setMinimumWidth(130)
        self.test_mode_btn.toggled.connect(self._on_test_mode_toggled)
        row1.addWidget(self.test_mode_btn)

        profile_label = QLabel("PROFILE:")
        profile_label.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        row1.addWidget(profile_label)

        self.sensitivity_combo = QComboBox()
        self.sensitivity_combo.addItems(["Balanced", "Strict", "Aggressive"])
        self.sensitivity_combo.setToolTip("Detection sensitivity profile")
        self.sensitivity_combo.setMinimumWidth(120)
        self.sensitivity_combo.currentTextChanged.connect(self.sensitivity_changed.emit)
        row1.addWidget(self.sensitivity_combo)

        row1.addStretch()

                                       
        self.status_indicator = QLabel("●  STOPPED")
        self.status_indicator.setObjectName("statusStopped")
        self.status_indicator.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self.status_indicator.setMinimumWidth(140)
        row1.addWidget(self.status_indicator)

        outer.addLayout(row1)

                                                                         
        row2 = QHBoxLayout()
        row2.setSpacing(10)

                      
        capture_label = QLabel("CAPTURE:")
        capture_label.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        row2.addWidget(capture_label)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Simulated", "Live (Scapy)"])
        self.mode_combo.setCurrentIndex(1)                                                   
        self.mode_combo.setToolTip("Select capture backend (Live requires admin)")
        self.mode_combo.setMinimumWidth(130)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        row2.addWidget(self.mode_combo)

        interface_label = QLabel("NIC:")
        interface_label.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        row2.addWidget(interface_label)

        self.interface_combo = QComboBox()
        self.interface_combo.setToolTip("Select network interface for live capture")
        self.interface_combo.setMinimumWidth(220)
        self.interface_combo.currentIndexChanged.connect(self._on_interface_changed)
        row2.addWidget(self.interface_combo)

        self.refresh_nic_btn = QPushButton("Refresh NICs")
        self.refresh_nic_btn.setToolTip("Reload available interfaces")
        self.refresh_nic_btn.clicked.connect(self._refresh_interfaces)
        row2.addWidget(self.refresh_nic_btn)
        
        self.probe_nic_btn = QPushButton("Probe NICs")
        self.probe_nic_btn.setToolTip("Find interface with highest live packet activity")
        self.probe_nic_btn.clicked.connect(self._probe_interfaces)
        row2.addWidget(self.probe_nic_btn)

        self._sep(row2)

                              
        browse_label = QLabel("LOAD MODELS:")
        browse_label.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold;")
        row2.addWidget(browse_label)

        self.browse_binary_btn = QPushButton("📂  Stage 1 (Binary)")
        self.browse_binary_btn.setToolTip("Browse for binary classifier model (.pkl, .joblib, .h5)")
        self.browse_binary_btn.setMinimumWidth(140)
        self.browse_binary_btn.clicked.connect(self._browse_binary_model)
        row2.addWidget(self.browse_binary_btn)

        self.browse_attack_btn = QPushButton("📂  Stage 2 (Attack)")
        self.browse_attack_btn.setToolTip("Browse for attack type classifier model (.pkl, .joblib, .h5)")
        self.browse_attack_btn.setMinimumWidth(140)
        self.browse_attack_btn.clicked.connect(self._browse_attack_model)
        row2.addWidget(self.browse_attack_btn)

        row2.addStretch()

        outer.addLayout(row2)
        self.addWidget(container)
        self._refresh_interfaces()

    def _sep(self, layout: QHBoxLayout):
        sep = QLabel("│")
        sep.setStyleSheet("color: #30363d; font-size: 18px; padding: 0 2px;")
        sep.setFixedWidth(14)
        layout.addWidget(sep)

    def _on_disable_toggled(self, checked: bool):
        if checked:
            self.disable_btn.setText("⚠  Prevention OFF")
        else:
            self.disable_btn.setText("⚠  Disable Prevention")
        self.disable_toggled.emit(not checked)

    def _on_mode_changed(self, index: int):
        mode = CaptureMode.MOCK if index == 0 else CaptureMode.REAL
        self.capture_mode_changed.emit(mode)
        self._update_interface_controls(mode)

    def _on_test_mode_toggled(self, checked: bool):
        self.test_mode_btn.setText("Test Mode: ON" if checked else "Test Mode: OFF")
        self.test_mode_toggled.emit(checked)

    def _on_interface_changed(self, index: int):
        interface = self.interface_combo.currentData()
        self.interface_changed.emit(interface or "")

    def _refresh_interfaces(self):
        current = self.interface_combo.currentData()
        interfaces = self._list_interfaces()

        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        self.interface_combo.addItem("Auto (Scapy default)", "")
        for display, value in interfaces:
            self.interface_combo.addItem(display, value)

        if current:
            idx = self.interface_combo.findData(current)
            if idx >= 0:
                self.interface_combo.setCurrentIndex(idx)
        self.interface_combo.blockSignals(False)
        self._on_interface_changed(self.interface_combo.currentIndex())
        self._update_interface_controls(
            CaptureMode.MOCK if self.mode_combo.currentIndex() == 0 else CaptureMode.REAL
        )

    def _list_interfaces(self) -> list[tuple[str, str]]:
        entries: list[tuple[str, str]] = []
        try:
            from scapy.arch.windows import get_windows_if_list

            seen = set()
            for iface in get_windows_if_list():
                value = (
                    iface.get("network_name")
                    or iface.get("name")
                    or iface.get("guid")
                    or ""
                )
                if not value or value in seen:
                    continue

                desc = iface.get("description") or iface.get("name") or value
                ips = iface.get("ips") or []
                ip_hint = ips[0] if ips else "no-ip"
                display = f"{desc} ({ip_hint})"
                entries.append((display, value))
                seen.add(value)

            if entries:
                return sorted(entries, key=lambda item: item[0].lower())
        except Exception:
            pass

        try:
            from scapy.all import get_if_list
            return [(name, name) for name in sorted(set(get_if_list()))]
        except Exception:
            pass

        try:
            return [(name, name) for name in sorted({name for _, name in socket.if_nameindex()})]
        except Exception:
            return []

    def _update_interface_controls(self, mode: CaptureMode):
        is_live = mode == CaptureMode.REAL
        self.interface_combo.setEnabled(is_live and self.start_btn.isEnabled())
        self.refresh_nic_btn.setEnabled(is_live and self.start_btn.isEnabled())
        self.probe_nic_btn.setEnabled(is_live and self.start_btn.isEnabled())

    def _probe_interfaces(self):
        interfaces = self._list_interfaces()
        if not interfaces:
            return

        self.probe_nic_btn.setEnabled(False)
        self.probe_nic_btn.setText("Probing...")
        self._probe_thread = _NicProbeThread(interfaces, self)
        self._probe_thread.probe_finished.connect(self._on_probe_finished)
        self._probe_thread.start()

    def _on_probe_finished(self, counts: dict, error: str):
        self.probe_nic_btn.setText("Probe NICs")
        self.probe_nic_btn.setEnabled(True)

        if not counts:
            self.probe_nic_btn.setToolTip(error or "Probe failed")
            return

                                               
        best_iface, best_count = max(counts.items(), key=lambda kv: kv[1])
        idx = self.interface_combo.findData(best_iface)
        if idx >= 0 and best_count > 0:
            self.interface_combo.setCurrentIndex(idx)
            self.interface_combo.setToolTip(
                f"Auto-selected busiest NIC: {best_iface} ({best_count} pkts during probe)"
            )
        else:
            self.interface_combo.setToolTip(
                "Probe found no active NIC. Generate traffic and probe again."
            )

    def _browse_binary_model(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Stage 1 — Binary Classifier Model",
            "",
            "ML Models (*.pkl *.joblib *.h5 *.pt *.onnx);;All Files (*)",
        )
        if path:
            self.browse_binary_btn.setText("✅  Stage 1 (Binary)")
            self.browse_binary_btn.setToolTip(f"Loaded: {path}")
            self.binary_model_browse.emit(path)

    def _browse_attack_model(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Stage 2 — Attack Type Classifier Model",
            "",
            "ML Models (*.pkl *.joblib *.h5 *.pt *.onnx);;All Files (*)",
        )
        if path:
            self.browse_attack_btn.setText("✅  Stage 2 (Attack)")
            self.browse_attack_btn.setToolTip(f"Loaded: {path}")
            self.attack_model_browse.emit(path)

    def update_state(self, state: EngineState):
        
        is_running = state in (EngineState.RUNNING, EngineState.DISABLED)

        self.start_btn.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)
        self.disable_btn.setEnabled(is_running)
        self.mode_combo.setEnabled(not is_running)
        self.test_mode_btn.setEnabled(not is_running)
        self.sensitivity_combo.setEnabled(not is_running)
        current_mode = CaptureMode.MOCK if self.mode_combo.currentIndex() == 0 else CaptureMode.REAL
        self._update_interface_controls(current_mode)

        if state == EngineState.RUNNING:
            self.status_indicator.setText("●  RUNNING")
            self.status_indicator.setObjectName("statusRunning")
        elif state == EngineState.DISABLED:
            self.status_indicator.setText("●  DETECTION ONLY")
            self.status_indicator.setObjectName("statusDisabled")
        else:
            self.status_indicator.setText("●  STOPPED")
            self.status_indicator.setObjectName("statusStopped")

        self.status_indicator.style().unpolish(self.status_indicator)
        self.status_indicator.style().polish(self.status_indicator)
