

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional

class ThreatType(Enum):
    
    NORMAL = auto()
    PORT_SCAN = auto()
    DOS_ATTACK = auto()
    DDOS_ATTACK = auto()
    SQL_INJECTION = auto()
    BRUTE_FORCE = auto()
    MALWARE_COMM = auto()
    C2_COMMUNICATION = auto()
    DATA_EXFILTRATION = auto()
    DNS_TUNNELING = auto()
    ARP_SPOOFING = auto()

    @property
    def display_name(self) -> str:
        return self.name.replace("_", " ").title()

    @property
    def severity(self) -> str:
        
        critical = {
            ThreatType.C2_COMMUNICATION,
            ThreatType.DATA_EXFILTRATION,
            ThreatType.MALWARE_COMM,
        }
        high = {
            ThreatType.DOS_ATTACK,
            ThreatType.DDOS_ATTACK,
            ThreatType.SQL_INJECTION,
        }
        medium = {
            ThreatType.BRUTE_FORCE,
            ThreatType.DNS_TUNNELING,
            ThreatType.ARP_SPOOFING,
        }
        if self in critical:
            return "CRITICAL"
        if self in high:
            return "HIGH"
        if self in medium:
            return "MEDIUM"
        if self == ThreatType.PORT_SCAN:
            return "LOW"
        return "NONE"

class Protocol(Enum):
    
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"
    ARP = "ARP"

@dataclass
class Packet:
    

              
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = field(default_factory=datetime.now)

                  
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: Protocol = Protocol.TCP
    length: int = 0
    ttl: int = 64
    flags: str = ""

             
    payload_preview: str = ""

                       
    is_malicious: bool = False
    threat_type: ThreatType = ThreatType.NORMAL
    confidence: float = 0.0
    model_used: str = "N/A"

                
    is_blocked: bool = False
    block_reason: str = ""

    @property
    def source(self) -> str:
        
        return f"{self.src_ip}:{self.src_port}"

    @property
    def destination(self) -> str:
        
        return f"{self.dst_ip}:{self.dst_port}"

    @property
    def status_text(self) -> str:
        if self.is_blocked:
            return "BLOCKED"
        if self.is_malicious:
            return "MALICIOUS"
        return "CLEAN"

    @property
    def info_text(self) -> str:
        
        if self.is_malicious:
            return f"{self.threat_type.display_name} (conf: {self.confidence:.0%})"
        return f"{self.protocol.value} {self.src_port} → {self.dst_port}"

    def to_dict(self) -> dict:
        
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol.value,
            "length": self.length,
            "ttl": self.ttl,
            "flags": self.flags,
            "payload_preview": self.payload_preview,
            "is_malicious": self.is_malicious,
            "threat_type": self.threat_type.name,
            "confidence": self.confidence,
            "model_used": self.model_used,
            "is_blocked": self.is_blocked,
            "block_reason": self.block_reason,
        }
