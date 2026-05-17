

from __future__ import annotations

import collections
from typing import Any

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtGui import QColor, QFont, QIcon

from threatguard.core.packet import Packet, ThreatType

                                                                 

COLOR_NORMAL_BG = QColor("#0d1117")
COLOR_NORMAL_FG = QColor("#c9d1d9")
COLOR_MALICIOUS_BG = QColor("#3d1f1f")
COLOR_MALICIOUS_FG = QColor("#ff7b72")
COLOR_BLOCKED_BG = QColor("#3b2a00")
COLOR_BLOCKED_FG = QColor("#f0883e")
COLOR_HEADER_BG = QColor("#161b22")
COLOR_HEADER_FG = QColor("#8b949e")
COLOR_SELECTED_BG = QColor("#1f3a5f")

                 
SEVERITY_COLORS = {
    "CRITICAL": QColor("#f85149"),
    "HIGH": QColor("#f0883e"),
    "MEDIUM": QColor("#d29922"),
    "LOW": QColor("#58a6ff"),
    "NONE": QColor("#8b949e"),
}

class TrafficTableModel(QAbstractTableModel):
    

    COLUMNS = ["#", "Time", "Source", "Destination", "Protocol", "Length", "Status"]

    def __init__(self, max_rows: int = 10000, parent=None):
        super().__init__(parent)
        self._packets: collections.deque[Packet] = collections.deque(maxlen=max_rows)
        self._counter = 0

    @property
    def packets(self) -> list[Packet]:
        return list(self._packets)

    def add_packet(self, packet: Packet):
        
        self._counter += 1
        row = len(self._packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self._packets.append(packet)
        self.endInsertRows()

                                                                  
                                         
        if len(self._packets) == self._packets.maxlen:
            self.beginRemoveRows(QModelIndex(), 0, 0)
                                      
            self.endRemoveRows()

    def clear(self):
        
        self.beginResetModel()
        self._packets.clear()
        self._counter = 0
        self.endResetModel()

    def get_packet(self, row: int) -> Packet | None:
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None

                                                                 

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._packets)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal:
            if role == Qt.DisplayRole:
                return self.COLUMNS[section]
            if role == Qt.ForegroundRole:
                return COLOR_HEADER_FG
            if role == Qt.FontRole:
                font = QFont("Segoe UI", 9)
                font.setBold(True)
                return font
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row >= len(self._packets):
            return None

        packet = self._packets[row]

        if role == Qt.DisplayRole:
            return self._display_data(packet, col, row)

        if role == Qt.BackgroundRole:
            if packet.is_blocked:
                return COLOR_BLOCKED_BG
            if packet.is_malicious:
                return COLOR_MALICIOUS_BG
            return COLOR_NORMAL_BG

        if role == Qt.ForegroundRole:
            if packet.is_blocked:
                return COLOR_BLOCKED_FG
            if packet.is_malicious:
                return COLOR_MALICIOUS_FG
            return COLOR_NORMAL_FG

        if role == Qt.FontRole:
            font = QFont("Consolas", 9)
            if packet.is_malicious:
                font.setBold(True)
            return font

        if role == Qt.TextAlignmentRole:
            if col in (0, 4, 5):                       
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        if role == Qt.UserRole:
            return packet

        return None

    def _display_data(self, packet: Packet, col: int, row: int) -> str:
        if col == 0:
            return str(self._counter - len(self._packets) + row + 1)
        if col == 1:
            return packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
        if col == 2:
            return packet.source
        if col == 3:
            return packet.destination
        if col == 4:
            return packet.protocol.value
        if col == 5:
            return str(packet.length)
        if col == 6:
            return packet.status_text
        return ""

class BlockedTrafficModel(QAbstractTableModel):
    

    COLUMNS = ["#", "Time", "Source", "Destination", "Protocol", "Threat", "Confidence", "Block Reason"]

    def __init__(self, max_rows: int = 5000, parent=None):
        super().__init__(parent)
        self._packets: collections.deque[Packet] = collections.deque(maxlen=max_rows)
        self._counter = 0

    @property
    def packets(self) -> list[Packet]:
        return list(self._packets)

    def add_packet(self, packet: Packet):
        
        if not packet.is_blocked:
            return
        self._counter += 1
        row = len(self._packets)
        self.beginInsertRows(QModelIndex(), row, row)
        self._packets.append(packet)
        self.endInsertRows()

        if len(self._packets) == self._packets.maxlen:
            self.beginRemoveRows(QModelIndex(), 0, 0)
            self.endRemoveRows()

    def clear(self):
        self.beginResetModel()
        self._packets.clear()
        self._counter = 0
        self.endResetModel()

    def get_packet(self, row: int) -> Packet | None:
        if 0 <= row < len(self._packets):
            return self._packets[row]
        return None

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._packets)

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal:
            if role == Qt.DisplayRole:
                return self.COLUMNS[section]
            if role == Qt.ForegroundRole:
                return COLOR_HEADER_FG
            if role == Qt.FontRole:
                font = QFont("Segoe UI", 9)
                font.setBold(True)
                return font
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row >= len(self._packets):
            return None

        packet = self._packets[row]

        if role == Qt.DisplayRole:
            return self._display_data(packet, col, row)

        if role == Qt.BackgroundRole:
            severity = packet.threat_type.severity
            base = SEVERITY_COLORS.get(severity, COLOR_BLOCKED_BG)
                                   
            return QColor(base.red() // 4, base.green() // 4, base.blue() // 4)

        if role == Qt.ForegroundRole:
            severity = packet.threat_type.severity
            return SEVERITY_COLORS.get(severity, COLOR_BLOCKED_FG)

        if role == Qt.FontRole:
            font = QFont("Consolas", 9)
            font.setBold(True)
            return font

        if role == Qt.TextAlignmentRole:
            if col in (0, 4, 6):
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        if role == Qt.UserRole:
            return packet

        return None

    def _display_data(self, packet: Packet, col: int, row: int) -> str:
        if col == 0:
            return str(self._counter - len(self._packets) + row + 1)
        if col == 1:
            return packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
        if col == 2:
            return packet.source
        if col == 3:
            return packet.destination
        if col == 4:
            return packet.protocol.value
        if col == 5:
            return packet.threat_type.display_name
        if col == 6:
            return f"{packet.confidence:.0%}"
        if col == 7:
            return packet.block_reason
        return ""
