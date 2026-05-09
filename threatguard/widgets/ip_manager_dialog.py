from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QSplitter,
    QWidget,
    QFileDialog,
)

from threatguard.utils.ip_manager import (
    allow_ip,
    block_ip,
    list_blocked_ips,
    load_saved_rules,
    normalize_ip_text,
    reset_all_ip_rules,
    save_rules,
)


class IPManagerDialog(QDialog):
    def __init__(
        self,
        scanned_ips: set[str] | None = None,
        idps_blocked_ips: set[str] | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._scanned_ips = {normalize_ip_text(ip) for ip in (scanned_ips or set()) if ip}
        self._idps_blocked_ips = {
            normalize_ip_text(ip) for ip in (idps_blocked_ips or set()) if ip
        }
        self._pending: dict[str, str] = {}
        self.setWindowTitle("IP Manager")
        self.setMinimumSize(960, 540)
        self._setup_ui()
        self._refresh_all()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("IP Manager")
        title.setStyleSheet("color: #58a6ff; font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel("Pick an IP, choose Block or Allow, then Apply Changes.")
        subtitle.setStyleSheet("color: #8b949e; font-size: 12px;")
        layout.addWidget(subtitle)

        input_row = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP or CIDR (e.g. 192.168.1.14 or 203.0.113.0/24)")
        input_row.addWidget(self.ip_input, 1)

        self.stage_block_btn = QPushButton("Block Selected")
        self.stage_block_btn.clicked.connect(lambda: self._stage_selected("block"))
        input_row.addWidget(self.stage_block_btn)

        self.stage_allow_btn = QPushButton("Allow Selected")
        self.stage_allow_btn.clicked.connect(lambda: self._stage_selected("allow"))
        input_row.addWidget(self.stage_allow_btn)

        self.clear_stage_btn = QPushButton("Clear Pending")
        self.clear_stage_btn.clicked.connect(self._clear_pending)
        input_row.addWidget(self.clear_stage_btn)
        layout.addLayout(input_row)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_list_panel("1. Pick IP", "candidates"))
        splitter.addWidget(self._build_list_panel("2. Current Rules", "current"))
        splitter.addWidget(self._build_list_panel("3. Pending Changes", "pending"))
        splitter.setSizes([320, 320, 280])
        layout.addWidget(splitter, 1)

        bottom_row = QHBoxLayout()
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        bottom_row.addWidget(self.status_label, 1)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self._refresh_all)
        bottom_row.addWidget(self.refresh_btn)

        self.export_btn = QPushButton("Export Rules")
        self.export_btn.clicked.connect(self._on_export_clicked)
        bottom_row.addWidget(self.export_btn)

        self.remove_all_btn = QPushButton("Reset All")
        self.remove_all_btn.clicked.connect(self._on_remove_all_clicked)
        bottom_row.addWidget(self.remove_all_btn)

        self.submit_btn = QPushButton("Apply Changes")
        self.submit_btn.setObjectName("startButton")
        self.submit_btn.clicked.connect(self._submit_pending)
        bottom_row.addWidget(self.submit_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        bottom_row.addWidget(close_btn)

        layout.addLayout(bottom_row)

    def _build_list_panel(self, title: str, kind: str) -> QWidget:
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(6)

        label = QLabel(title)
        label.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: 600;")
        panel_layout.addWidget(label)

        list_widget = QListWidget()
        list_widget.itemSelectionChanged.connect(self._on_selection_changed)
        panel_layout.addWidget(list_widget)

        if kind == "candidates":
            self.candidate_list = list_widget
        elif kind == "current":
            self.current_list = list_widget
        else:
            self.pending_list = list_widget
        return panel

    def _set_status(self, text: str, is_error: bool = False):
        color = "#f85149" if is_error else "#8b949e"
        self.status_label.setStyleSheet(f"color: {color}; font-size: 11px;")
        self.status_label.setText(text)

    def _add_item(self, list_widget: QListWidget, text: str, ip_addr: str):
        item = QListWidgetItem(text)
        item.setData(Qt.UserRole, ip_addr)
        list_widget.addItem(item)

    def _refresh_all(self):
        firewall_blocked, err = list_blocked_ips()
        rules = load_saved_rules()
        blocked = {normalize_ip_text(ip) for ip in firewall_blocked + rules["blocked"]}
        allowed = {normalize_ip_text(ip) for ip in rules["allowed"]}
        candidates = sorted((self._scanned_ips | self._idps_blocked_ips | blocked | allowed))

        self.candidate_list.clear()
        for ip in candidates:
            badges = []
            if ip in self._idps_blocked_ips:
                badges.append("IDPS blocked")
            if ip in blocked:
                badges.append("blocked")
            if ip in allowed:
                badges.append("allowed")
            suffix = f" ({', '.join(badges)})" if badges else ""
            self._add_item(self.candidate_list, f"{ip}{suffix}", ip)

        self.current_list.clear()
        for ip in sorted(blocked):
            self._add_item(self.current_list, f"BLOCKED  {ip}", ip)
        for ip in sorted(allowed):
            self._add_item(self.current_list, f"ALLOWED  {ip}", ip)

        self._refresh_pending()
        if err:
            self._set_status(err, is_error=True)
            return
        self._set_status(
            f"{len(candidates)} selectable IP(s), {len(blocked)} blocked, {len(allowed)} allowed"
        )

    def _refresh_pending(self):
        self.pending_list.clear()
        for ip, action in sorted(self._pending.items()):
            self._add_item(self.pending_list, f"{action.upper()}  {ip}", ip)

    def _current_ip(self) -> str:
        for list_widget in (self.candidate_list, self.current_list, self.pending_list):
            item = list_widget.currentItem()
            if item:
                return item.data(Qt.UserRole) or item.text().split()[-1]
        return normalize_ip_text(self.ip_input.text())

    def _on_selection_changed(self):
        sender = self.sender()
        item = sender.currentItem() if sender else None
        ip_addr = item.data(Qt.UserRole) if item else self._current_ip()
        if ip_addr:
            self.ip_input.setText(ip_addr)

    def _stage_selected(self, action: str):
        ip_addr = normalize_ip_text(self.ip_input.text() or self._current_ip())
        if not ip_addr:
            self._set_status("Select or enter an IP first.", is_error=True)
            return
        self._pending[ip_addr] = action
        self._refresh_pending()
        self._set_status(f"Pending {action} for {ip_addr}. Apply Changes to update firewall.")

    def _clear_pending(self):
        self._pending.clear()
        self._refresh_pending()
        self._set_status("Cleared staged changes.")

    def _submit_pending(self):
        if not self._pending:
            self._set_status("No pending changes to apply.", is_error=True)
            return

        failures: list[str] = []
        applied = 0
        for ip_addr, action in sorted(self._pending.items()):
            if action == "block":
                ok, msg = block_ip(ip_addr)
            else:
                ok, msg = allow_ip(ip_addr)
                if ok:
                    rules = load_saved_rules()
                    if ip_addr not in rules["allowed"]:
                        rules["allowed"].append(ip_addr)
                    if ip_addr in rules["blocked"]:
                        rules["blocked"].remove(ip_addr)
                    save_rules(rules)
            if ok:
                applied += 1
            else:
                failures.append(msg)

        if failures:
            self._set_status(f"Applied {applied}; failed {len(failures)}.", is_error=True)
            QMessageBox.warning(self, "IP Manager", "\n".join(failures[:5]))
        else:
            self._set_status(f"Applied {applied} change(s).")
            self._pending.clear()
        self._refresh_all()

    def _on_export_clicked(self):
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export IP Rules",
            "threatguard_ip_rules.json",
            "JSON Files (*.json)",
        )
        if not filepath:
            return

        rules = load_saved_rules()
        blocked, _ = list_blocked_ips()
        export_data = {
            "blocked": blocked,
            "allowed": rules["allowed"],
            "pending": self._pending,
        }
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
        except Exception as exc:
            msg = f"Failed to export rules: {exc}"
            self._set_status(msg, is_error=True)
            QMessageBox.warning(self, "IP Manager", msg)
            return

        self._set_status(f"Exported IP rules to {filepath}")

    def _on_remove_all_clicked(self):
        reply = QMessageBox.question(
            self,
            "IP Manager",
            "Reset all IP Manager rules and remove all ThreatGuard firewall blocks?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return

        ok, msg = reset_all_ip_rules()
        if ok:
            self._pending.clear()
            self._set_status(msg)
            self._refresh_all()
            return
        self._set_status(msg, is_error=True)
        QMessageBox.warning(self, "IP Manager", msg)
