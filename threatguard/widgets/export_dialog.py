

from __future__ import annotations

from typing import Sequence

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QFileDialog, QRadioButton, QButtonGroup,
    QGroupBox, QMessageBox, QFrame, QProgressBar,
)
from PySide6.QtGui import QFont

from threatguard.core.packet import Packet
from threatguard.utils.exporter import export_to_json, export_to_csv, export_to_txt

FORMAT_EXTENSIONS = {
    "JSON (.json)": ".json",
    "CSV (.csv)": ".csv",
    "Text (.txt)": ".txt",
}

FORMAT_FILTERS = {
    "JSON (.json)": "JSON Files (*.json)",
    "CSV (.csv)": "CSV Files (*.csv)",
    "Text (.txt)": "Text Files (*.txt)",
}

EXPORTERS = {
    "JSON (.json)": export_to_json,
    "CSV (.csv)": export_to_csv,
    "Text (.txt)": export_to_txt,
}

class ExportDialog(QDialog):
    

    def __init__(
        self,
        all_packets: Sequence[Packet],
        blocked_packets: Sequence[Packet],
        parent=None,
    ):
        super().__init__(parent)
        self._all_packets = all_packets
        self._blocked_packets = blocked_packets
        self._malicious_packets = [p for p in all_packets if p.is_malicious]
        self.setWindowTitle("Export Logs — ThreatGuard")
        self.setMinimumWidth(500)
        self.setMinimumHeight(420)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

                     
        title = QLabel("📁  Export Traffic Logs")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet("color: #58a6ff;")
        layout.addWidget(title)

        desc = QLabel("Export captured traffic data for analysis and reporting.")
        desc.setStyleSheet("color: #8b949e; font-size: 12px; margin-bottom: 8px;")
        layout.addWidget(desc)

                                
        format_group = QGroupBox("Export Format")
        format_layout = QVBoxLayout(format_group)

        format_row = QHBoxLayout()
        format_label = QLabel("File Type:")
        format_label.setStyleSheet("color: #c9d1d9; font-weight: bold;")
        format_row.addWidget(format_label)

        self.format_combo = QComboBox()
        self.format_combo.addItems(FORMAT_EXTENSIONS.keys())
        self.format_combo.setMinimumWidth(200)
        format_row.addWidget(self.format_combo)
        format_row.addStretch()

        format_layout.addLayout(format_row)
        layout.addWidget(format_group)

                          
        scope_group = QGroupBox("Data Scope")
        scope_layout = QVBoxLayout(scope_group)

        self.scope_button_group = QButtonGroup(self)

        self.radio_all = QRadioButton(
            f"All Traffic  ({len(self._all_packets):,} packets)"
        )
        self.radio_all.setChecked(True)
        self.scope_button_group.addButton(self.radio_all, 0)
        scope_layout.addWidget(self.radio_all)

        self.radio_malicious = QRadioButton(
            f"Malicious Only  ({len(self._malicious_packets):,} packets)"
        )
        self.scope_button_group.addButton(self.radio_malicious, 1)
        scope_layout.addWidget(self.radio_malicious)

        self.radio_blocked = QRadioButton(
            f"Blocked Only  ({len(self._blocked_packets):,} packets)"
        )
        self.scope_button_group.addButton(self.radio_blocked, 2)
        scope_layout.addWidget(self.radio_blocked)

        layout.addWidget(scope_group)

                       
        preview_group = QGroupBox("Summary")
        preview_layout = QVBoxLayout(preview_group)

        self.preview_label = QLabel()
        self.preview_label.setWordWrap(True)
        self.preview_label.setStyleSheet("color: #8b949e; font-size: 11px; padding: 4px;")
        self._update_preview()
        preview_layout.addWidget(self.preview_label)

        layout.addWidget(preview_group)

                                            
        self.format_combo.currentTextChanged.connect(lambda: self._update_preview())
        self.scope_button_group.buttonClicked.connect(lambda: self._update_preview())

                        
        self.progress = QProgressBar()
        self.progress.setMaximum(100)
        self.progress.setValue(0)
        self.progress.hide()
        layout.addWidget(self.progress)

                       
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        self.export_btn = QPushButton("📁  Export")
        self.export_btn.setObjectName("exportButton")
        self.export_btn.setMinimumWidth(120)
        self.export_btn.clicked.connect(self._do_export)
        btn_layout.addWidget(self.export_btn)

        layout.addLayout(btn_layout)

    def _update_preview(self):
        packets = self._get_selected_packets()
        fmt = self.format_combo.currentText()
        count = len(packets)
        malicious = sum(1 for p in packets if p.is_malicious)
        blocked = sum(1 for p in packets if p.is_blocked)

        self.preview_label.setText(
            f"Format: {fmt}\n"
            f"Records to export: {count:,}\n"
            f"  • Malicious: {malicious:,}\n"
            f"  • Blocked: {blocked:,}\n"
            f"  • Clean: {count - malicious:,}"
        )

    def _get_selected_packets(self) -> list[Packet]:
        checked_id = self.scope_button_group.checkedId()
        if checked_id == 1:
            return self._malicious_packets
        elif checked_id == 2:
            return list(self._blocked_packets)
        return list(self._all_packets)

    def _do_export(self):
        fmt = self.format_combo.currentText()
        ext = FORMAT_EXTENSIONS[fmt]
        file_filter = FORMAT_FILTERS[fmt]

        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log File",
            f"threatguard_export{ext}",
            file_filter,
        )

        if not filepath:
            return

        packets = self._get_selected_packets()
        if not packets:
            QMessageBox.warning(
                self, "No Data",
                "No packets match the selected scope. Nothing to export."
            )
            return

        self.progress.show()
        self.progress.setValue(30)
        self.export_btn.setEnabled(False)

        try:
            exporter = EXPORTERS[fmt]
            count = exporter(packets, filepath)

            self.progress.setValue(100)

            QMessageBox.information(
                self, "Export Complete",
                f"Successfully exported {count:,} packets to:\n{filepath}"
            )
            self.accept()

        except Exception as e:
            self.progress.hide()
            self.export_btn.setEnabled(True)
            QMessageBox.critical(
                self, "Export Error",
                f"Failed to export logs:\n{str(e)}"
            )
