

from __future__ import annotations

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QTableView, QLabel,
    QHeaderView, QAbstractItemView, QLineEdit, QWidget,
)
from PySide6.QtGui import QFont

from threatguard.models.traffic_model import TrafficTableModel
from threatguard.core.packet import Packet

class TrafficTableWidget(QFrame):
    

    packet_selected = Signal(object)                

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("trafficPanel")
        self._model = TrafficTableModel()
        self._setup_ui()

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

        title = QLabel("📡  ALL TRAFFIC")
        title.setObjectName("panelTitle")
        title.setFont(QFont("Segoe UI", 11, QFont.Bold))
        header_layout.addWidget(title)

        header_layout.addStretch()

        self.count_label = QLabel("0 packets")
        self.count_label.setStyleSheet("color: #8b949e; font-size: 11px;")
        header_layout.addWidget(self.count_label)

                        
        self.live_dot = QLabel("●")
        self.live_dot.setStyleSheet("color: #3fb950; font-size: 14px; padding-left: 8px;")
        self.live_dot.setToolTip("Live capture active")
        self.live_dot.hide()
        header_layout.addWidget(self.live_dot)

        layout.addWidget(header)

                          
        self.table_view = QTableView()
        self.table_view.setModel(self._model)
        self.table_view.setAlternatingRowColors(False)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.setShowGrid(False)
        self.table_view.verticalHeader().setVisible(False)
        self.table_view.setWordWrap(False)

                       
        header_view = self.table_view.horizontalHeader()
        header_view.setStretchLastSection(True)
        header_view.setSectionResizeMode(0, QHeaderView.Fixed)                
        self.table_view.setColumnWidth(0, 60)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeToContents)        
        header_view.setSectionResizeMode(2, QHeaderView.Interactive)               
        header_view.setSectionResizeMode(3, QHeaderView.Interactive)                    
        header_view.setSectionResizeMode(4, QHeaderView.ResizeToContents)            
        header_view.setSectionResizeMode(5, QHeaderView.ResizeToContents)          
        header_view.setSectionResizeMode(6, QHeaderView.Stretch)                 
        header_view.setSectionResizeMode(7, QHeaderView.ResizeToContents)          

                    
        self.table_view.verticalHeader().setDefaultSectionSize(28)

                            
        self.table_view.selectionModel().selectionChanged.connect(
            self._on_selection_changed
        )

        layout.addWidget(self.table_view)

    def _on_selection_changed(self, selected, deselected):
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            packet = self._model.get_packet(row)
            if packet:
                self.packet_selected.emit(packet)

    def add_packet(self, packet: Packet):
        
        self._model.add_packet(packet)
        count = self._model.rowCount()
        self.count_label.setText(f"{count:,} packets")

                                                            
        sb = self.table_view.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 3
        if at_bottom:
            self.table_view.scrollToBottom()

    def clear(self):
        self._model.clear()
        self.count_label.setText("0 packets")

    def set_live(self, active: bool):
        self.live_dot.setVisible(active)

    @property
    def model(self) -> TrafficTableModel:
        return self._model
