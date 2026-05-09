

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QWidget, QSizePolicy, QSpacerItem, QTextEdit,
)
from PySide6.QtGui import QFont, QTextCursor

from threatguard.core.engine import EngineState

class _CardFrame(QFrame):
    

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebarCard")

class Sidebar(QFrame):
    

    export_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebarFrame")
        self.setFixedWidth(230)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 12, 10, 12)
        layout.setSpacing(4)

                              
        status_header = QLabel("SYSTEM STATUS")
        status_header.setStyleSheet(
            "color: #8b949e; font-size: 9px; font-weight: bold; "
            "letter-spacing: 1px; border-bottom: 1px solid #21262d; "
            "padding-bottom: 4px; margin-bottom: 4px; background: transparent;"
        )
        layout.addWidget(status_header)

                     
        status_card = _CardFrame()
        status_card.setStyleSheet("""
            #sidebarCard {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        status_layout = QVBoxLayout(status_card)
        status_layout.setSpacing(6)
        status_layout.setContentsMargins(12, 12, 12, 12)

        self.status_dot = QLabel("●  STOPPED")
        self.status_dot.setStyleSheet("color: #f85149; font-size: 12px; font-weight: bold; background: transparent;")
        self.status_dot.setFont(QFont("Segoe UI", 11, QFont.Bold))
        status_layout.addWidget(self.status_dot)

        self.uptime_label = QLabel("Uptime: --")
        self.uptime_label.setStyleSheet("color: #8b949e; font-size: 11px; background: transparent;")
        status_layout.addWidget(self.uptime_label)

        layout.addWidget(status_card)
        layout.addSpacing(8)

                             
        stats_header = QLabel("LIVE STATISTICS")
        stats_header.setStyleSheet(
            "color: #8b949e; font-size: 9px; font-weight: bold; "
            "letter-spacing: 1px; border-bottom: 1px solid #21262d; "
            "padding-bottom: 4px; margin-bottom: 4px; background: transparent;"
        )
        layout.addWidget(stats_header)

        stats_card = _CardFrame()
        stats_card.setStyleSheet("""
            #sidebarCard {
                background-color: #161b22;
                border: 1px solid #21262d;
                border-radius: 8px;
            }
        """)
        stats_grid = QHBoxLayout(stats_card)
        stats_grid.setSpacing(4)
        stats_grid.setContentsMargins(8, 10, 8, 10)

        self.total_label = self._stat_block(stats_grid, "Total", "0", "#58a6ff")
        self.malicious_label = self._stat_block(stats_grid, "Threats", "0", "#f85149")
        self.blocked_label = self._stat_block(stats_grid, "Blocked", "0", "#f0883e")
        self.clean_label = self._stat_block(stats_grid, "Clean", "0", "#3fb950")

        layout.addWidget(stats_card)
        layout.addSpacing(8)

                                 
        debug_header = QLabel("DEBUG LOG")
        debug_header.setStyleSheet(
            "color: #8b949e; font-size: 9px; font-weight: bold; "
            "letter-spacing: 1px; border-bottom: 1px solid #21262d; "
            "padding-bottom: 4px; margin-bottom: 4px; background: transparent;"
        )
        layout.addWidget(debug_header)

        self.debug_log = QTextEdit()
        self.debug_log.setReadOnly(True)
        self.debug_log.setMaximumHeight(180)
        self.debug_log.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                color: #8b949e;
                border: 1px solid #21262d;
                border-radius: 6px;
                padding: 6px;
                font-family: "Consolas", "Cascadia Code", monospace;
                font-size: 10px;
            }
        """)
        layout.addWidget(self.debug_log)

                              
        self._log("System initialized", "INFO")
        self._log("Engine: STOPPED", "INFO")

        layout.addSpacing(8)

                       
        actions_header = QLabel("ACTIONS")
        actions_header.setStyleSheet(
            "color: #8b949e; font-size: 9px; font-weight: bold; "
            "letter-spacing: 1px; border-bottom: 1px solid #21262d; "
            "padding-bottom: 4px; margin-bottom: 4px; background: transparent;"
        )
        layout.addWidget(actions_header)

        export_btn = QPushButton("📁  Export Logs")
        export_btn.setObjectName("exportButton")
        export_btn.clicked.connect(self.export_clicked.emit)
        layout.addWidget(export_btn)

                      
        layout.addItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Expanding))

                      
        footer = QLabel("ThreatGuard v1.0.0")
        footer.setStyleSheet("color: #484f58; font-size: 10px; background: transparent;")
        footer.setAlignment(Qt.AlignCenter)
        layout.addWidget(footer)

    def _stat_block(self, parent_layout: QHBoxLayout, label_text: str, value: str, color: str) -> QLabel:
        
        block = QVBoxLayout()
        block.setSpacing(2)
        block.setContentsMargins(0, 0, 0, 0)

        value_label = QLabel(value)
        value_label.setStyleSheet(
            f"color: {color}; font-size: 16px; font-weight: bold; background: transparent;"
        )
        value_label.setAlignment(Qt.AlignCenter)
        value_label.setMinimumWidth(40)
        block.addWidget(value_label)

        label = QLabel(label_text)
        label.setStyleSheet(
            "color: #8b949e; font-size: 9px; background: transparent;"
        )
        label.setAlignment(Qt.AlignCenter)
        block.addWidget(label)

        parent_layout.addLayout(block)
        return value_label

                                                               

    def log(self, message: str, level: str = "INFO"):
        
        self._log(message, level)

    def _log(self, message: str, level: str = "INFO"):
        
        now = datetime.now().strftime("%H:%M:%S")
        color_map = {
            "INFO": "#8b949e",
            "OK": "#3fb950",
            "WARN": "#d29922",
            "ERROR": "#f85149",
            "ML": "#bc8cff",
        }
        color = color_map.get(level, "#8b949e")
        html = (
            f'<span style="color:#484f58">{now}</span> '
            f'<span style="color:{color};font-weight:bold">[{level}]</span> '
            f'<span style="color:#c9d1d9">{message}</span>'
        )
        self.debug_log.append(html)
                     
        cursor = self.debug_log.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.debug_log.setTextCursor(cursor)

    def update_stats(self, stats: dict):
        
        total = stats.get("total_packets", 0)
        malicious = stats.get("malicious_packets", 0)
        blocked = stats.get("blocked_packets", 0)
        clean = total - malicious

        self.total_label.setText(f"{total:,}")
        self.malicious_label.setText(f"{malicious:,}")
        self.blocked_label.setText(f"{blocked:,}")
        self.clean_label.setText(f"{clean:,}")

        uptime = stats.get("uptime", 0)
        mins, secs = divmod(int(uptime), 60)
        hours, mins = divmod(mins, 60)
        self.uptime_label.setText(f"Uptime: {hours:02d}:{mins:02d}:{secs:02d}")

    def update_state(self, state: EngineState):
        
        if state == EngineState.RUNNING:
            self.status_dot.setText("●  RUNNING")
            self.status_dot.setStyleSheet(
                "color: #3fb950; font-size: 12px; font-weight: bold; background: transparent;"
            )
            self._log("Engine started — monitoring traffic", "OK")
        elif state == EngineState.DISABLED:
            self.status_dot.setText("●  DETECTION ONLY")
            self.status_dot.setStyleSheet(
                "color: #d29922; font-size: 12px; font-weight: bold; background: transparent;"
            )
            self._log("Prevention DISABLED — detection-only mode", "WARN")
        else:
            self.status_dot.setText("●  STOPPED")
            self.status_dot.setStyleSheet(
                "color: #f85149; font-size: 12px; font-weight: bold; background: transparent;"
            )
            self._log("Engine stopped", "INFO")
