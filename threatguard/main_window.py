

from __future__ import annotations

import os

from PySide6.QtCore import Qt, QSize, QEvent, QModelIndex
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QSplitter, QMessageBox, QMenuBar, QMenu,
)
from PySide6.QtGui import QAction, QFont, QIcon

from threatguard.core.engine import IDPSEngine, EngineState, CaptureMode
from threatguard.core.packet import Packet
from threatguard.widgets.toolbar import ControlToolbar
from threatguard.widgets.sidebar import Sidebar
from threatguard.widgets.traffic_table import TrafficTableWidget
from threatguard.widgets.blocked_table import BlockedTableWidget
from threatguard.widgets.detail_panel import DetailPanel
from threatguard.widgets.status_bar import IDPSStatusBar
from threatguard.widgets.export_dialog import ExportDialog
from threatguard.widgets.ip_manager_dialog import IPManagerDialog
from threatguard.utils.ip_manager import add_allowed_ip, block_ip, list_blocked_ips, normalize_ip_text

class MainWindow(QMainWindow):
    

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ThreatGuard — ML-Powered IDPS Dashboard")
        self.setMinimumSize(1280, 800)
        self.resize(1500, 900)

                      
        self.engine = IDPSEngine(self)

                        
        self._setup_menubar()
        self._setup_toolbar()
        self._setup_central()
        self._setup_statusbar()
        self._connect_signals()
        self._setup_ip_context_menus()
        self._update_model_status()
        app = QApplication.instance()
        if app:
            app.installEventFilter(self)

                                                                
               
                                                                

    def _setup_menubar(self):
        menubar = self.menuBar()

                    
        file_menu = menubar.addMenu("File")

        export_action = QAction("Export Logs...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self._show_export_dialog)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

                    
        view_menu = menubar.addMenu("View")

        toggle_sidebar = QAction("Toggle Sidebar", self)
        toggle_sidebar.setShortcut("Ctrl+B")
        toggle_sidebar.triggered.connect(self._toggle_sidebar)
        view_menu.addAction(toggle_sidebar)

                     
        tools_menu = menubar.addMenu("Tools")

        start_action = QAction("Start IDPS", self)
        start_action.setShortcut("F5")
        start_action.triggered.connect(self._start_engine)
        tools_menu.addAction(start_action)

        stop_action = QAction("Stop IDPS", self)
        stop_action.setShortcut("F6")
        stop_action.triggered.connect(self._stop_engine)
        tools_menu.addAction(stop_action)

        tools_menu.addSeparator()

        model_health_action = QAction("Model Health...", self)
        model_health_action.triggered.connect(self._show_model_health)
        tools_menu.addAction(model_health_action)

        clear_action = QAction("Clear Traffic Data", self)
        clear_action.setShortcut("Ctrl+L")
        clear_action.triggered.connect(self._clear_data)
        tools_menu.addAction(clear_action)

        ip_manager_action = QAction("IP Manager...", self)
        ip_manager_action.setShortcut("Ctrl+I")
        ip_manager_action.triggered.connect(self._show_ip_manager)
        tools_menu.addAction(ip_manager_action)

                    
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About ThreatGuard", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_toolbar(self):
        self.toolbar = ControlToolbar(self)
        self.addToolBar(self.toolbar)

    def _setup_central(self):
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

                       
        self.sidebar = Sidebar()
        main_layout.addWidget(self.sidebar)

                                 
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(8, 8, 8, 8)
        content_layout.setSpacing(8)

                                                                         
        self.main_splitter = QSplitter(Qt.Vertical)
        self.main_splitter.setHandleWidth(5)

                                                                       
        self.top_splitter = QSplitter(Qt.Horizontal)
        self.top_splitter.setHandleWidth(5)

        self.traffic_table = TrafficTableWidget()
        self.blocked_table = BlockedTableWidget()

        self.top_splitter.addWidget(self.traffic_table)
        self.top_splitter.addWidget(self.blocked_table)
        self.top_splitter.setSizes([600, 400])

        self.main_splitter.addWidget(self.top_splitter)

                                                    
        self.detail_panel = DetailPanel()
        self.main_splitter.addWidget(self.detail_panel)

                                                      
        self.main_splitter.setSizes([500, 300])

        content_layout.addWidget(self.main_splitter)
        main_layout.addWidget(content_widget, 1)

    def _setup_statusbar(self):
        self.idps_status_bar = IDPSStatusBar(self)
        self.setStatusBar(self.idps_status_bar)

                                                                
                         
                                                                

    def _connect_signals(self):
                          
        self.toolbar.start_clicked.connect(self._start_engine)
        self.toolbar.stop_clicked.connect(self._stop_engine)
        self.toolbar.disable_toggled.connect(self.engine.toggle_prevention)
        self.toolbar.model_changed.connect(self.engine.set_model)
        self.toolbar.capture_mode_changed.connect(self._set_capture_mode)
        self.toolbar.interface_changed.connect(self._set_interface)
        self.toolbar.test_mode_toggled.connect(self._set_test_mode)
        self.toolbar.sensitivity_changed.connect(self._set_sensitivity_profile)
        self.toolbar.binary_model_browse.connect(self.engine.set_binary_model_path)
        self.toolbar.attack_model_browse.connect(self.engine.set_attack_model_path)

                     
        self.engine.state_changed.connect(self._on_state_changed)
        self.engine.packet_received.connect(self._on_packet_received)
        self.engine.packet_blocked.connect(self._on_packet_blocked)
        self.engine.stats_updated.connect(self._on_stats_updated)
        self.engine.capture_error.connect(self._on_capture_error)

                                       
        self.traffic_table.packet_selected.connect(self.detail_panel.show_packet)
        self.blocked_table.packet_selected.connect(self.detail_panel.show_packet)

                 
        self.sidebar.export_clicked.connect(self._show_export_dialog)

                                                                
               
                                                                

    def _setup_ip_context_menus(self):
        for table in (self.traffic_table, self.blocked_table):
            table.table_view.setContextMenuPolicy(Qt.CustomContextMenu)
            table.table_view.customContextMenuRequested.connect(
                lambda pos, source_table=table: self._show_ip_context_menu(source_table, pos)
            )

    def _show_ip_context_menu(self, table, pos):
        index = table.table_view.indexAt(pos)
        if not index.isValid():
            return

        packet = table.model.get_packet(index.row())
        if not packet:
            return

        menu = QMenu(self)
        for label, ip_addr in (("Source", packet.src_ip), ("Destination", packet.dst_ip)):
            ip_addr = normalize_ip_text(ip_addr)
            if not ip_addr:
                continue
            action_label = self._ip_toggle_label(label, ip_addr)
            action = menu.addAction(action_label)
            action.triggered.connect(
                lambda _checked=False, selected_ip=ip_addr: self._toggle_ip_rule(selected_ip)
            )

        if menu.actions():
            menu.exec(table.table_view.viewport().mapToGlobal(pos))

    def _ip_toggle_label(self, label: str, ip_addr: str) -> str:
        blocked_ips, _ = list_blocked_ips()
        if ip_addr in {normalize_ip_text(ip) for ip in blocked_ips}:
            return f"Allow {label} IP ({ip_addr})"
        return f"Block {label} IP ({ip_addr})"

    def _toggle_ip_rule(self, ip_addr: str):
        blocked_ips, _ = list_blocked_ips()
        blocked_set = {normalize_ip_text(ip) for ip in blocked_ips}
        if ip_addr in blocked_set:
            ok, msg = add_allowed_ip(ip_addr)
            level = "OK"
        else:
            ok, msg = block_ip(ip_addr)
            level = "WARN"

        self.sidebar.log(msg, level if ok else "ERROR")
        if not ok:
            QMessageBox.warning(self, "IP Rule", msg)

    def _update_model_status(self):
        
        if self.engine._binary_model_path:
            self.toolbar.browse_binary_btn.setText("✅  Stage 1 (Binary)")
            self.toolbar.browse_binary_btn.setToolTip(
                f"Auto-loaded: {self.engine._binary_model_path}"
            )
            self.sidebar.log("Stage 1 NIDS model loaded", "ML")
        else:
            self.sidebar.log("Stage 1 NIDS model NOT found", "ERROR")

        if self.engine._attack_model_path:
            self.toolbar.browse_attack_btn.setText("✅  Stage 2 (Attack)")
            self.toolbar.browse_attack_btn.setToolTip(
                f"Auto-loaded: {self.engine._attack_model_path}"
            )
            self.sidebar.log("Stage 2 NIDS model loaded", "ML")
        else:
            self.sidebar.log("Stage 2 NIDS model NOT found", "ERROR")

    def _start_engine(self):
        self.engine.start()
        self.traffic_table.set_live(True)

    def _stop_engine(self):
        self.engine.stop()
        self.traffic_table.set_live(False)

    def _set_capture_mode(self, mode: CaptureMode):
        self.engine.set_capture_mode(mode)
        label = "Live (Scapy)" if mode == CaptureMode.REAL else "Simulated"
        self.sidebar.log(f"Capture mode: {label}", "INFO")

    def _set_interface(self, interface: str):
        self.engine.set_interface(interface)
        if interface:
            self.sidebar.log(f"Capture interface: {interface}", "INFO")
        else:
            self.sidebar.log("Capture interface: Auto (Scapy default)", "INFO")

    def _set_test_mode(self, enabled: bool):
        self.engine.set_test_mode(enabled)
        if enabled:
            self.sidebar.log("Test mode enabled (lower detection thresholds)", "WARN")
        else:
            self.sidebar.log("Test mode disabled (strict thresholds)", "INFO")

    def _set_sensitivity_profile(self, profile: str):
        self.engine.set_sensitivity_profile(profile)
        self.sidebar.log(f"Detection profile: {profile}", "INFO")

    def _on_state_changed(self, state: EngineState):
        self.toolbar.update_state(state)
        self.sidebar.update_state(state)
        self.idps_status_bar.update_state(state)
        self.traffic_table.set_live(state in (EngineState.RUNNING, EngineState.DISABLED))

    def _on_packet_received(self, packet: Packet):
        self.traffic_table.add_packet(packet)

    def _on_packet_blocked(self, packet: Packet):
        self.blocked_table.add_packet(packet)
        self.sidebar.log(
            f"Blocked {packet.src_ip} as {packet.threat_type.display_name} ({packet.confidence:.0%})",
            "WARN",
        )

    def _on_stats_updated(self, stats: dict):
        self.sidebar.update_stats(stats)
        self.idps_status_bar.update_stats(stats)

    def _on_capture_error(self, error_msg: str):
        self.sidebar.log(f"CAPTURE ERROR: {error_msg}", "ERROR")
        QMessageBox.warning(
            self,
            "Capture Error",
            error_msg,
        )

    def _clear_data(self):
        self.traffic_table.clear()
        self.blocked_table.clear()
        self.detail_panel.clear_packet()

    def _toggle_sidebar(self):
        self.sidebar.setVisible(not self.sidebar.isVisible())

    def _show_export_dialog(self):
        all_packets = self.traffic_table.model.packets
        blocked_packets = self.blocked_table.model.packets

        if not all_packets:
            QMessageBox.information(
                self,
                "No Data",
                "No traffic data to export. Start the IDPS and capture some traffic first.",
            )
            return

        dialog = ExportDialog(all_packets, blocked_packets, self)
        dialog.exec()

    def _show_about(self):
        QMessageBox.about(
            self,
            "About ThreatGuard",
            "<h2>⛨ ThreatGuard IDPS</h2>"
            "<p><b>Version 1.0.0</b></p>"
            "<p>ML-Powered Intrusion Detection and Prevention System</p>"
            "<hr>"
            "<p><b>Two-Stage ML Pipeline:</b></p>"
            "<p>Stage 1 — Binary Classifier (Normal vs Attack)<br>"
            "Stage 2 — Attack Type Classifier (Bruteforce, Probing, etc.)</p>"
            "<hr>"
            "<p>Trained on CICIDS2017 dataset</p>"
            "<p>Built with PySide6 + Scapy</p>",
        )

    def _show_ip_manager(self):
        scanned_ips = set()
        for packet in self.traffic_table.model.packets:
            if packet.src_ip:
                scanned_ips.add(packet.src_ip)
            if packet.dst_ip:
                scanned_ips.add(packet.dst_ip)

        idps_blocked_ips = {
            packet.src_ip for packet in self.blocked_table.model.packets if packet.src_ip
        }

        dialog = IPManagerDialog(
            scanned_ips=scanned_ips,
            idps_blocked_ips=idps_blocked_ips,
            parent=self,
        )
        dialog.exec()
        self.sidebar.log("IP Manager opened", "INFO")

    def _show_model_health(self):
        QMessageBox.information(
            self,
            "Model Health",
            "<h3>ThreatGuard Model Health</h3>"
            f"<p><b>Stage 1 Binary:</b> {'found' if self.engine._binary_model_path else 'missing'}"
            f"<br>{self.engine._binary_model_path or 'N/A'}</p>"
            f"<p><b>Stage 2 Attack:</b> {'found' if self.engine._attack_model_path else 'missing'}"
            f"<br>{self.engine._attack_model_path or 'N/A'}</p>"
            f"<p><b>Scaler:</b> {'found' if self.engine._scaler_path else 'missing'}"
            f"<br>{self.engine._scaler_path or 'N/A'}</p>"
            f"<p><b>Label Encoder:</b> {'found' if self.engine._label_encoder_path else 'missing'}"
            f"<br>{self.engine._label_encoder_path or 'N/A'}</p>"
            f"<p><b>Feature Names:</b> {'found' if self.engine._feature_names_path else 'missing'}"
            f"<br>{self.engine._feature_names_path or 'N/A'}</p>",
        )

                                                                
                    
                                                                

    def closeEvent(self, event):
        
        app = QApplication.instance()
        if app:
            app.removeEventFilter(self)

        if self.engine.is_running:
            reply = QMessageBox.question(
                self,
                "Confirm Exit",
                "IDPS is currently running. Stop and exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            self.engine.stop()

        event.accept()

    def _clear_packet_selection(self):
        
        self.traffic_table.table_view.clearSelection()
        self.blocked_table.table_view.clearSelection()
        self.traffic_table.table_view.setCurrentIndex(QModelIndex())
        self.blocked_table.table_view.setCurrentIndex(QModelIndex())
        self.detail_panel.clear_packet()

    def eventFilter(self, watched, event):
        if event.type() == QEvent.MouseButtonPress:
            if hasattr(event, "button") and event.button() == Qt.LeftButton:
                widget = watched if isinstance(watched, QWidget) else None
                if widget is None:
                    return super().eventFilter(watched, event)

                traffic_view = self.traffic_table.table_view
                blocked_view = self.blocked_table.table_view

                in_traffic = widget == traffic_view or traffic_view.isAncestorOf(widget)
                in_blocked = widget == blocked_view or blocked_view.isAncestorOf(widget)
                if not in_traffic and not in_blocked:
                    self._clear_packet_selection()

        return super().eventFilter(watched, event)
