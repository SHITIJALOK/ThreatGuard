

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QTextBrowser,
    QScrollArea, QWidget, QGridLayout,
)
from PySide6.QtGui import QFont

from threatguard.core.packet import Packet, ThreatType

                       
SEVERITY_STYLES = {
    "CRITICAL": ("background-color: #f85149; color: #ffffff;", "🔴"),
    "HIGH":     ("background-color: #f0883e; color: #ffffff;", "🟠"),
    "MEDIUM":   ("background-color: #d29922; color: #0d1117;", "🟡"),
    "LOW":      ("background-color: #58a6ff; color: #ffffff;", "🔵"),
    "NONE":     ("background-color: #21262d; color: #8b949e;", "⚪"),
}

class DetailPanel(QFrame):
    

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("detailPanel")
        self._current_packet: Packet | None = None
        self._setup_ui()
        self._show_empty()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

                      
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border-bottom: 1px solid #21262d;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 8, 14, 8)

        title = QLabel("🔍  PACKET DETAILS")
        title.setObjectName("panelTitle")
        title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        header_layout.addWidget(title)

        header_layout.addStretch()

        self.severity_badge = QLabel("")
        self.severity_badge.setStyleSheet("""
            padding: 3px 12px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        self.severity_badge.hide()
        header_layout.addWidget(self.severity_badge)

        layout.addWidget(header)

                            
        self.content = QTextBrowser()
        self.content.setOpenExternalLinks(False)
        self.content.setStyleSheet("""
            QTextBrowser {
                background-color: #0d1117;
                color: #c9d1d9;
                border: none;
                padding: 16px;
                font-family: "Consolas", "Cascadia Code", monospace;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.content)

    def _show_empty(self):
        
        self.content.setHtml("""
            <div style="text-align: center; padding: 40px; color: #484f58;">
                <p style="font-size: 28px;">🔍</p>
                <p style="font-size: 14px; font-weight: bold; color: #8b949e;">
                    No packet selected
                </p>
                <p style="font-size: 12px;">
                    Click on a packet in the traffic or blocked table to view its details
                </p>
            </div>
        """)
        self.severity_badge.hide()

    def show_packet(self, packet: Packet):
        
        self._current_packet = packet

                               
        severity = packet.threat_type.severity
        style, icon = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["NONE"])
        self.severity_badge.setText(f"{icon} {severity}")
        self.severity_badge.setStyleSheet(f"""
            {style}
            padding: 3px 12px;
            border-radius: 10px;
            font-size: 10px;
            font-weight: bold;
        """)
        self.severity_badge.setVisible(packet.is_malicious)

        html = self._build_detail_html(packet)
        self.content.setHtml(html)

    def clear_packet(self):
        
        self._current_packet = None
        self._show_empty()

    def _build_detail_html(self, p: Packet) -> str:
        
                      
        if p.is_blocked:
            status_color = "#f0883e"
            status_text = "⛔ BLOCKED"
            status_bg = "#3b2a00"
        elif p.is_malicious:
            status_color = "#f85149"
            status_text = "⚠️ MALICIOUS"
            status_bg = "#3d1f1f"
        else:
            status_color = "#3fb950"
            status_text = "✅ CLEAN"
            status_bg = "#1a3024"

        html = f"""
        <style>
            body {{ font-family: 'Consolas', monospace; color: #c9d1d9; }}
            .section {{ margin-bottom: 16px; }}
            .section-title {{
                color: #58a6ff; font-size: 13px; font-weight: bold;
                border-bottom: 1px solid #21262d; padding-bottom: 4px;
                margin-bottom: 8px; letter-spacing: 1px;
            }}
            .row {{ display: flex; margin: 3px 0; }}
            .label {{ color: #8b949e; min-width: 140px; display: inline-block; }}
            .value {{ color: #c9d1d9; font-weight: bold; }}
            .status-badge {{
                background-color: {status_bg}; color: {status_color};
                padding: 4px 14px; border-radius: 6px;
                font-weight: bold; font-size: 12px;
                border: 1px solid {status_color};
                display: inline-block; margin-top: 4px;
            }}
            .threat-badge {{
                background-color: #3d1f1f; color: #f85149;
                padding: 3px 10px; border-radius: 4px;
                font-weight: bold; font-size: 11px;
                display: inline-block;
            }}
            .payload-box {{
                background-color: #161b22; border: 1px solid #21262d;
                border-radius: 6px; padding: 10px; margin-top: 6px;
                font-family: 'Consolas', monospace; font-size: 11px;
                color: #e6edf3; white-space: pre-wrap; word-wrap: break-word;
            }}
            .confidence-bar {{
                background-color: #21262d; border-radius: 4px;
                height: 8px; margin-top: 4px; width: 200px;
                display: inline-block;
            }}
        </style>

        <!-- STATUS -->
        <div class="section">
            <span class="status-badge">{status_text}</span>
            <span style="color: #484f58; margin-left: 12px;">Packet ID: {p.id}</span>
        </div>

        <!-- SUMMARY -->
        <div class="section">
            <div class="section-title">📋 SUMMARY</div>
            <div><span class="label">Timestamp:</span>
                <span class="value">{p.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}</span></div>
            <div><span class="label">Protocol:</span>
                <span class="value">{p.protocol.value}</span></div>
            <div><span class="label">Length:</span>
                <span class="value">{p.length:,} bytes</span></div>
            <div><span class="label">TTL:</span>
                <span class="value">{p.ttl}</span></div>
            <div><span class="label">Flags:</span>
                <span class="value">{p.flags or 'N/A'}</span></div>
        </div>

        <!-- SOURCE / DESTINATION -->
        <div class="section">
            <div class="section-title">🌐 NETWORK</div>
            <div><span class="label">Source:</span>
                <span class="value" style="color: #79c0ff;">{p.src_ip}:{p.src_port}</span></div>
            <div><span class="label">Destination:</span>
                <span class="value" style="color: #79c0ff;">{p.dst_ip}:{p.dst_port}</span></div>
        </div>
        """

                                                  
        if p.is_malicious:
            conf_pct = int(p.confidence * 100)
            conf_color = "#f85149" if p.confidence > 0.9 else "#f0883e" if p.confidence > 0.8 else "#d29922"
            severity = p.threat_type.severity

            html += f"""
        <div class="section">
            <div class="section-title">🧠 ML ANALYSIS</div>
            <div><span class="label">Threat Type:</span>
                <span class="threat-badge">{p.threat_type.display_name}</span></div>
            <div><span class="label">Severity:</span>
                <span class="value" style="color: {conf_color};">{severity}</span></div>
            <div><span class="label">Confidence:</span>
                <span class="value" style="color: {conf_color};">{p.confidence:.1%}</span></div>
            <div style="margin-top: 4px;">
                <span class="label">&nbsp;</span>
                <div style="background-color: #21262d; border-radius: 4px; height: 8px;
                     width: 200px; display: inline-block; vertical-align: middle;">
                    <div style="background-color: {conf_color}; border-radius: 4px;
                         height: 8px; width: {conf_pct * 2}px;"></div>
                </div>
            </div>
            <div><span class="label">Model Used:</span>
                <span class="value" style="color: #a5d6ff;">{p.model_used}</span></div>
        </div>
            """

                                         
        if p.is_blocked:
            html += f"""
        <div class="section">
            <div class="section-title">🛡️ PREVENTION ACTION</div>
            <div style="background-color: #3b2a00; border: 1px solid #6e4000; border-radius: 6px;
                 padding: 10px; color: #f0883e; font-size: 12px; margin-top: 4px;">
                {p.block_reason}
            </div>
        </div>
            """

                 
        if p.payload_preview:
            html += f"""
        <div class="section">
            <div class="section-title">📦 PAYLOAD PREVIEW</div>
            <div class="payload-box">{p.payload_preview}</div>
        </div>
            """

        return html
