

from __future__ import annotations

import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from PySide6.QtGui import QFont, QPalette, QColor

STYLES_DIR = os.path.join(os.path.dirname(__file__), "styles")

def create_application(argv: list[str] | None = None) -> QApplication:
    
    if argv is None:
        argv = sys.argv

                      
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(argv)

                                                         
    app.setStyle("Fusion")

                              
    app.setApplicationName("ThreatGuard IDPS")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("ThreatGuard")

                      
    font = QFont("Segoe UI", 10)
    font.setHintingPreference(QFont.PreferFullHinting)
    app.setFont(font)

                         
    _apply_dark_theme(app)

                                  
    _apply_dark_palette(app)

    return app

def _apply_dark_theme(app: QApplication):
    
    qss_path = os.path.join(STYLES_DIR, "dark_theme.qss")

    if os.path.exists(qss_path):
        with open(qss_path, "r", encoding="utf-8") as f:
            stylesheet = f.read()
        app.setStyleSheet(stylesheet)
    else:
        print(f"Warning: Theme file not found at {qss_path}")

def _apply_dark_palette(app: QApplication):
    
    palette = QPalette()

                 
    palette.setColor(QPalette.Window, QColor("#0d1117"))
    palette.setColor(QPalette.WindowText, QColor("#c9d1d9"))
    palette.setColor(QPalette.Base, QColor("#0d1117"))
    palette.setColor(QPalette.AlternateBase, QColor("#161b22"))
    palette.setColor(QPalette.ToolTipBase, QColor("#1c2333"))
    palette.setColor(QPalette.ToolTipText, QColor("#c9d1d9"))
    palette.setColor(QPalette.Text, QColor("#c9d1d9"))
    palette.setColor(QPalette.Button, QColor("#21262d"))
    palette.setColor(QPalette.ButtonText, QColor("#c9d1d9"))
    palette.setColor(QPalette.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.Link, QColor("#58a6ff"))
    palette.setColor(QPalette.Highlight, QColor("#1f6feb"))
    palette.setColor(QPalette.HighlightedText, QColor("#ffffff"))

                     
    palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor("#484f58"))
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor("#484f58"))
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor("#484f58"))

    app.setPalette(palette)
