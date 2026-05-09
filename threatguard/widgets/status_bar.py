

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QStatusBar, QLabel, QHBoxLayout, QWidget, QFrame,
)
from PySide6.QtGui import QFont

from threatguard.core.engine import EngineState

class IDPSStatusBar(QStatusBar):
    

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        self.setStyleSheet("""
            QStatusBar {
                background-color: #010409;
                border-top: 1px solid #21262d;
                min-height: 28px;
            }
        """)

                                   
        self.status_label = QLabel("●  IDPS: STOPPED")
        self.status_label.setStyleSheet(
            "color: #f85149; font-weight: bold; font-size: 11px; padding: 0 8px;"
        )
        self.addWidget(self.status_label)

        self._add_separator()

                                        
        self.pps_label = QLabel("📊 0 pkt/s")
        self.pps_label.setStyleSheet("color: #8b949e; font-size: 11px; padding: 0 8px;")
        self.addWidget(self.pps_label)

        self._add_separator()

                                                 
        self.total_label = QLabel("Total: 0")
        self.total_label.setStyleSheet("color: #58a6ff; font-size: 11px; padding: 0 8px;")
        self.addWidget(self.total_label)

        self.threats_label = QLabel("Threats: 0")
        self.threats_label.setStyleSheet("color: #f85149; font-size: 11px; padding: 0 8px;")
        self.addWidget(self.threats_label)

        self.blocked_stat_label = QLabel("Blocked: 0")
        self.blocked_stat_label.setStyleSheet("color: #f0883e; font-size: 11px; padding: 0 8px;")
        self.addWidget(self.blocked_stat_label)

                             

        self.uptime_label = QLabel("⏱ 00:00:00")
        self.uptime_label.setStyleSheet("color: #8b949e; font-size: 11px; padding: 0 8px;")
        self.addPermanentWidget(self.uptime_label)

                              
        self._last_total = 0
        self._rate_timer = QTimer(self)
        self._rate_timer.timeout.connect(self._update_rate)
        self._rate_timer.start(1000)
        self._current_total = 0

    def _add_separator(self, permanent=False):
        sep = QLabel("│")
        sep.setStyleSheet("color: #21262d; font-size: 14px; padding: 0 2px;")
        if permanent:
            self.addPermanentWidget(sep)
        else:
            self.addWidget(sep)

    def _update_rate(self):
        rate = self._current_total - self._last_total
        self._last_total = self._current_total
        self.pps_label.setText(f"📊 {rate} pkt/s")

    def update_stats(self, stats: dict):
        
        total = stats.get("total_packets", 0)
        self._current_total = total

        self.total_label.setText(f"Total: {total:,}")
        self.threats_label.setText(f"Threats: {stats.get('malicious_packets', 0):,}")
        self.blocked_stat_label.setText(f"Blocked: {stats.get('blocked_packets', 0):,}")

        uptime = stats.get("uptime", 0)
        mins, secs = divmod(int(uptime), 60)
        hours, mins = divmod(mins, 60)
        self.uptime_label.setText(f"⏱ {hours:02d}:{mins:02d}:{secs:02d}")

    def update_state(self, state: EngineState):
        
        if state == EngineState.RUNNING:
            self.status_label.setText("●  IDPS: RUNNING")
            self.status_label.setStyleSheet(
                "color: #3fb950; font-weight: bold; font-size: 11px; padding: 0 8px;"
            )
        elif state == EngineState.DISABLED:
            self.status_label.setText("●  IDPS: DETECTION ONLY")
            self.status_label.setStyleSheet(
                "color: #d29922; font-weight: bold; font-size: 11px; padding: 0 8px;"
            )
        else:
            self.status_label.setText("●  IDPS: STOPPED")
            self.status_label.setStyleSheet(
                "color: #f85149; font-weight: bold; font-size: 11px; padding: 0 8px;"
            )
