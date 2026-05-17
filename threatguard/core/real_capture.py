

from __future__ import annotations

import os
import pickle
import ipaddress
import platform
import re
import subprocess
import time
import traceback
import threading
import warnings
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QThread, Signal

from threatguard.core.packet import Packet, Protocol, ThreatType
from threatguard.core.flow_aggregator import FlowAggregator, FlowRecord
from threatguard.utils.ip_manager import is_ip_allowed, queue_block_ip

warnings.filterwarnings(
    "ignore",
    message=r"`sklearn\.utils\.parallel\.delayed` should be used with `sklearn\.utils\.parallel\.Parallel`.*",
    category=UserWarning,
)

                                                   
PORT_PROTOCOL_MAP = {
    80: Protocol.HTTP,
    443: Protocol.HTTPS,
    22: Protocol.SSH,
    21: Protocol.FTP,
    25: Protocol.SMTP,
    53: Protocol.DNS,
}

                                                     
_ATTACK_LABEL_MAP_RAW = {
                                        
    "bot": ThreatType.MALWARE_COMM,
    "ddos": ThreatType.DDOS_ATTACK,
    "dos goldeneye": ThreatType.DOS_ATTACK,
    "dos hulk": ThreatType.DOS_ATTACK,
    "dos slowhttptest": ThreatType.DOS_ATTACK,
    "dos slowloris": ThreatType.DOS_ATTACK,
    "ftp-patator": ThreatType.BRUTE_FORCE,
    "heartbleed": ThreatType.MALWARE_COMM,
    "infiltration": ThreatType.DATA_EXFILTRATION,
    "portscan": ThreatType.PORT_SCAN,
    "ssh-patator": ThreatType.BRUTE_FORCE,
    "web attack \u2013 brute force": ThreatType.BRUTE_FORCE,
    "web attack \u2013 sql injection": ThreatType.SQL_INJECTION,
    "web attack \u2013 xss": ThreatType.SQL_INJECTION,
                   
    "bruteforce": ThreatType.BRUTE_FORCE,
    "brute_force": ThreatType.BRUTE_FORCE,
    "probing": ThreatType.PORT_SCAN,
    "probe": ThreatType.PORT_SCAN,
    "port_scan": ThreatType.PORT_SCAN,
    "dos": ThreatType.DOS_ATTACK,
    "xmrigcc": ThreatType.MALWARE_COMM,
    "xmrig": ThreatType.MALWARE_COMM,
    "malware": ThreatType.MALWARE_COMM,
    "c2": ThreatType.C2_COMMUNICATION,
    "c&c": ThreatType.C2_COMMUNICATION,
    "command_and_control": ThreatType.C2_COMMUNICATION,
    "sql_injection": ThreatType.SQL_INJECTION,
    "sqli": ThreatType.SQL_INJECTION,
    "exfiltration": ThreatType.DATA_EXFILTRATION,
    "data_exfiltration": ThreatType.DATA_EXFILTRATION,
    "dns_tunneling": ThreatType.DNS_TUNNELING,
    "arp_spoofing": ThreatType.ARP_SPOOFING,
}

def _normalize_label(label: str) -> str:
    normalized = label.strip().lower().replace("\u2013", "-").replace("\u2014", "-")
    normalized = normalized.replace("-", "_").replace(" ", "_")
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized

ATTACK_LABEL_MAP = {
    _normalize_label(label): threat for label, threat in _ATTACK_LABEL_MAP_RAW.items()
}

def _map_attack_label(label: str) -> Optional[ThreatType]:
    
    normalized = _normalize_label(label)
    mapped = ATTACK_LABEL_MAP.get(normalized)
    if mapped is not None:
        return mapped

    # Fuzzy fallbacks for model-label variations across training runs.
    if "port" in normalized and "scan" in normalized:
        return ThreatType.PORT_SCAN
    if "ddos" in normalized:
        return ThreatType.DDOS_ATTACK
    if "dos" in normalized:
        return ThreatType.DOS_ATTACK
    if "patator" in normalized or "brute" in normalized:
        return ThreatType.BRUTE_FORCE
    if "sql" in normalized or "sqli" in normalized or "xss" in normalized:
        return ThreatType.SQL_INJECTION
    if "infiltration" in normalized or "exfiltration" in normalized:
        return ThreatType.DATA_EXFILTRATION
    if "dns" in normalized:
        return ThreatType.DNS_TUNNELING
    if "bot" in normalized or "malware" in normalized or "heartbleed" in normalized:
        return ThreatType.MALWARE_COMM
    return None

def _extract_model_from_blob(blob):
    
    if isinstance(blob, dict) and "model" in blob:
        return blob["model"]
    return blob

class RealCaptureThread(QThread):
    

    packet_captured = Signal(object)                        
    capture_error = Signal(str)                             

    def __init__(
        self,
        interface: Optional[str] = None,
        binary_model_path: Optional[str] = None,
        attack_model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        attack_scaler_path: Optional[str] = None,
        label_encoder_path: Optional[str] = None,
        feature_names_path: Optional[str] = None,
        attack_feature_names_path: Optional[str] = None,
        model_name: str = "Custom Model",
        prevention_enabled: bool = True,
        confidence_threshold: float = 0.40,
        sensitivity_profile: str = "Balanced",
        test_mode: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._interface = interface
        self._binary_model_path = binary_model_path
        self._attack_model_path = attack_model_path
        self._scaler_path = scaler_path
        self._attack_scaler_path = attack_scaler_path
        self._label_encoder_path = label_encoder_path
        self._feature_names_path = feature_names_path
        self._attack_feature_names_path = attack_feature_names_path
        self.model_name = model_name
        self._prevention_enabled = prevention_enabled
        self._confidence_threshold = confidence_threshold
        self._sensitivity_profile = sensitivity_profile
        self._test_mode = False
        self._running = False
        self._blocked_ips: set[str] = set()
        self._reported_block_failures: set[str] = set()
        self._error_report_timestamps: dict[str, float] = {}
        self._recent_alerts: dict[tuple[str, str], float] = {}
        self._alert_dedupe_sec = 8.0
        self._source_activity_lock = threading.Lock()
        self._source_activity = defaultdict(
            lambda: {
                "scan_times": deque(),
                "scan_ports": deque(),
                "packet_times": deque(),
                "udp_packet_times": deque(),
                "web_flow_times": deque(),
            }
        )

                                   
        self._binary_model = None
        self._attack_model = None
        self._scaler = None
        self._attack_scaler = None
        self._attack_label_encoder = None
        self._feature_names: list[str] = []
        self._attack_feature_names: list[str] = []

    def _report_runtime_issue(self, area: str, exc: Exception, min_interval_sec: float = 8.0):
        msg = f"{area}: {type(exc).__name__}: {exc}"
        now = time.time()
        last_seen = self._error_report_timestamps.get(msg, 0.0)
        if now - last_seen < min_interval_sec:
            return
        self._error_report_timestamps[msg] = now
        self.capture_error.emit(msg)
        print(f"[RealCapture] {msg}")

    @staticmethod
    def _prediction_is_attack(prediction) -> bool:
        
        if isinstance(prediction, (int, float)):
            return int(prediction) == 1
        label = str(prediction).strip().lower()
        return label in {"1", "attack", "attacker", "anomaly", "malicious", "intrusion"}

    def set_model(self, model_name: str):
        self.model_name = model_name

    def set_prevention(self, enabled: bool):
        self._prevention_enabled = enabled

    def set_sensitivity_profile(self, profile: str):
        self._sensitivity_profile = profile

    def _thresholds(self) -> dict[str, float]:
        if self._sensitivity_profile == "Aggressive":
            return {"stage1": 0.45, "stage2": 0.35, "block": 0.50}
        if self._sensitivity_profile == "Strict":
            return {"stage1": 0.85, "stage2": 0.80, "block": 0.90}
        return {"stage1": 0.65, "stage2": 0.70, "block": 0.85}

    def _stage2_min_conf_for_threat(self, threat_type: ThreatType, default_s2: float) -> float:
        if threat_type == ThreatType.PORT_SCAN:
            return 0.65
        if threat_type == ThreatType.DOS_ATTACK:
            return 0.80
        if threat_type == ThreatType.DDOS_ATTACK:
            return 0.85
        if threat_type == ThreatType.BRUTE_FORCE:
            return 0.75
        if threat_type == ThreatType.MALWARE_COMM:
            return 0.85
        return default_s2

    def _is_bruteforce_flow_plausible(self, flow_rec: FlowRecord, total_pkts: int, total_bytes: int) -> bool:
        auth_ports = {21, 22, 23, 25, 110, 143, 389, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 5900}
        web_ports = {80, 443, 8080, 8443}
        if flow_rec.dst_port in auth_ports:
            return total_pkts >= 6
        if flow_rec.dst_port in web_ports:
            return total_pkts >= 28 and total_bytes >= 3200
        return False
    
    def set_binary_model(self, path: str):
        self._binary_model_path = path
        self._binary_model = None                

    def set_attack_model(self, path: str):
        self._attack_model_path = path
        self._attack_model = None                

    def _should_emit_alert(self, src_ip: str, threat_type: ThreatType) -> bool:
        key = (src_ip, threat_type.name)
        now = time.time()
        last = self._recent_alerts.get(key, 0.0)
        if (now - last) < self._alert_dedupe_sec:
            return False
        self._recent_alerts[key] = now
        return True

    def _reset_runtime_detection_state(self):
        with self._source_activity_lock:
            self._source_activity.clear()
        self._recent_alerts.clear()

    def stop(self):
        self._running = False
        self._reset_runtime_detection_state()

    def _record_source_activity(
        self,
        flow_rec: FlowRecord,
        total_pkts: int,
        flow_duration: float,
    ) -> dict[str, int]:
        
        now = time.time()
        src = flow_rec.src_ip
        with self._source_activity_lock:
            bucket = self._source_activity[src]

            if (
                flow_rec.protocol == 6
                and total_pkts <= 3
                and flow_duration <= 3.0
                and flow_rec.syn_count >= 1
                and flow_rec.ack_count == 0
            ):
                bucket["scan_times"].append(now)
                bucket["scan_ports"].append((now, flow_rec.dst_port))

            for _ in range(total_pkts):
                bucket["packet_times"].append(now)
                if flow_rec.protocol == 17:
                    bucket["udp_packet_times"].append(now)
            if flow_rec.protocol == 6 and flow_rec.dst_port in {80, 443, 8000}:
                bucket["web_flow_times"].append(now)

            while bucket["scan_times"] and now - bucket["scan_times"][0] > 6.0:
                bucket["scan_times"].popleft()
            while bucket["scan_ports"] and now - bucket["scan_ports"][0][0] > 6.0:
                bucket["scan_ports"].popleft()
            while bucket["packet_times"] and now - bucket["packet_times"][0] > 3.0:
                bucket["packet_times"].popleft()
            while bucket["udp_packet_times"] and now - bucket["udp_packet_times"][0] > 3.0:
                bucket["udp_packet_times"].popleft()
            while bucket["web_flow_times"] and now - bucket["web_flow_times"][0] > 6.0:
                bucket["web_flow_times"].popleft()

            unique_ports = {port for _, port in bucket["scan_ports"]}
            return {
                "recent_scan_flows": len(bucket["scan_times"]),
                "recent_scan_ports": len(unique_ports),
                "recent_packets": len(bucket["packet_times"]),
                "recent_udp_packets": len(bucket["udp_packet_times"]),
                "recent_web_flows": len(bucket["web_flow_times"]),
            }

    def _detect_behavioral_dos(
        self,
        flow_rec: FlowRecord,
        total_pkts: int,
        total_bytes: int,
        flow_duration: float,
        activity: dict[str, int],
    ) -> Optional[ThreatType]:
        # Lab-targeted HTTP/HTTPS flood detector with safeguards against normal browsing.
        if flow_rec.protocol != 6:
            return None
        if flow_rec.dst_port not in {80, 443, 8000}:
            return None
        if total_pkts < 8:
            return None
        if flow_duration <= 0:
            return None

        pps = total_pkts / max(flow_duration, 1e-3)
        syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
        sustained_repetition = (
            activity.get("recent_web_flows", 0) >= 8
            and activity.get("recent_packets", 0) >= 260
        )

        # Catch AB-like floods that may appear as fewer but very heavy flows.
        extreme_single_flow = (
            total_pkts >= 120
            and pps >= 250
            and total_bytes >= 12000
            and syn_ratio >= 0.15
        )

        if not (sustained_repetition or extreme_single_flow):
            return None

        if pps < 90 and not extreme_single_flow:
            return None
        if not (syn_ratio >= 0.60 or total_pkts >= 20 or total_bytes >= 4000 or extreme_single_flow):
            return None
        return ThreatType.DOS_ATTACK

    def _infer_fallback_threat(
        self,
        flow_rec: FlowRecord,
        total_pkts: int,
        flow_duration: float,
    ) -> Optional[ThreatType]:
        
        pps = total_pkts / max(flow_duration, 1e-3)
        syn_ratio = flow_rec.syn_count / max(total_pkts, 1)

                                                        
        if flow_rec.protocol == 6:
            if pps >= 120 or total_pkts >= 80:
                return ThreatType.DOS_ATTACK
            if (
                flow_rec.syn_count >= 1
                and flow_rec.ack_count == 0
                and syn_ratio >= 0.50
                and total_pkts >= 2
                and flow_duration <= 3.0
            ):
                return ThreatType.PORT_SCAN

                                  
        if flow_rec.protocol == 17 and (pps >= 300 or total_pkts >= 200):
            return ThreatType.DOS_ATTACK

        return None

    def _detect_signature_threat(
        self,
        flow_rec: FlowRecord,
        total_pkts: int,
        total_bytes: int,
        flow_duration: float,
        activity: Optional[dict[str, int]] = None,
    ) -> Optional[ThreatType]:
        
        pps = total_pkts / max(flow_duration, 1e-3)
        syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
        if activity is None:
            activity = self._record_source_activity(flow_rec, total_pkts, flow_duration)

                                          
        if flow_rec.protocol == 6:
            sustained_burst = (
                activity["recent_packets"] >= 500
                and activity["recent_web_flows"] >= 5
            )

            strong_flow = (
                total_pkts >= 20
                and pps >= 30
                and total_bytes >= 2000
            )

            syn_pressure = syn_ratio >= 0.75

            if strong_flow and sustained_burst and syn_pressure:
                return ThreatType.DDOS_ATTACK

                                                                                   
        if (
            flow_rec.protocol == 6
            and (
                activity["recent_scan_ports"] >= 24
                or activity["recent_scan_flows"] >= 28
            )
        ):
            return ThreatType.PORT_SCAN

                              
        if (
            flow_rec.protocol == 17
            and (
                (total_pkts >= 160 and pps >= 600 and total_bytes >= 4000)
                or activity["recent_udp_packets"] >= 700
            )
        ):
            return ThreatType.DDOS_ATTACK

        return None

    def _rule_prefilter_suspicious(
        self,
        flow_rec: FlowRecord,
        total_pkts: int,
        total_bytes: int,
        flow_duration: float,
        activity: dict[str, int],
        signature_threat: Optional[ThreatType],
    ) -> bool:
        if signature_threat is not None:
            return True
        pps = total_pkts / max(flow_duration, 1e-3)
        auth_ports = {21, 22, 23, 25, 110, 143, 389, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 5900}
        if flow_rec.protocol == 6:
            if flow_rec.dst_port in auth_ports and activity["recent_scan_flows"] >= 6 and total_pkts >= 3:
                return True
            if total_pkts >= 24 and pps >= 80:
                return True
        if flow_rec.protocol == 17 and total_pkts >= 40 and pps >= 150 and total_bytes >= 2000:
            return True
        return False

    def _ensure_firewall_block(self, src_ip: str, threat_type: ThreatType) -> tuple[bool, str]:
        
        try:
            ip_obj = ipaddress.ip_address(src_ip)
        except ValueError:
            return False, f"Invalid IP '{src_ip}'"

        if (
            ip_obj.is_loopback
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_link_local
        ):
            return False, f"Unsafe non-routable IP"

        if is_ip_allowed(src_ip):
            return False, f"{src_ip} is allowlisted in IP Manager"

        if src_ip in self._blocked_ips:
            return True, f"Host firewall already blocking {src_ip}"

        if platform.system().lower() != "windows":
            return False, "Host blocking is implemented for Windows only"

        future = queue_block_ip(src_ip)
        self._blocked_ips.add(src_ip)

        def _report_result(done):
            try:
                ok, reason = done.result()
            except Exception as exc:
                ok, reason = False, f"Firewall command failed: {exc}"
            if not ok:
                self._blocked_ips.discard(src_ip)
                self._reported_block_failures.add(f"{src_ip}:{reason}")
                self.capture_error.emit(f"Prevention rule failed for {src_ip}: {reason}")

        future.add_done_callback(_report_result)
        return True, f"Queued host firewall rule for {src_ip}"

    def _resolve_interface(self) -> Optional[str]:
        
        if not self._interface:
            return None

        candidate = self._interface.strip()
        if not candidate:
            return None

        try:
            from scapy.all import get_if_list
            if candidate in set(get_if_list()):
                return candidate
        except Exception:
            pass

        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                keys = {
                    iface.get("network_name"),
                    iface.get("name"),
                    iface.get("description"),
                    iface.get("guid"),
                }
                if candidate in keys:
                    return iface.get("network_name") or iface.get("name") or candidate
        except Exception:
            pass

        return ""

    def _load_models(self):
        
        if self._binary_model_path and self._binary_model is None:
            try:
                with open(self._binary_model_path, "rb") as f:
                    binary_blob = pickle.load(f)
                if isinstance(binary_blob, dict):
                    self._binary_model = _extract_model_from_blob(binary_blob)
                    if not self._feature_names:
                        features = binary_blob.get("feature_names")
                        if isinstance(features, list):
                            self._feature_names = features
                else:
                    self._binary_model = binary_blob
            except Exception as e:
                self.capture_error.emit(f"Failed to load binary model: {e}")

        if self._attack_model_path and self._attack_model is None:
            try:
                with open(self._attack_model_path, "rb") as f:
                    attack_blob = pickle.load(f)
                if isinstance(attack_blob, dict):
                    self._attack_model = _extract_model_from_blob(attack_blob)
                    if self._attack_label_encoder is None:
                        self._attack_label_encoder = attack_blob.get("label_encoder")
                    if not self._feature_names:
                        features = attack_blob.get("feature_names")
                        if isinstance(features, list):
                            self._feature_names = features
                else:
                    self._attack_model = attack_blob
            except Exception as e:
                self.capture_error.emit(f"Failed to load attack model: {e}")

        if self._scaler_path and self._scaler is None:
            try:
                with open(self._scaler_path, "rb") as f:
                    self._scaler = pickle.load(f)
            except Exception as e:
                pass

        if self._label_encoder_path and self._attack_label_encoder is None:
            try:
                with open(self._label_encoder_path, "rb") as f:
                    self._attack_label_encoder = pickle.load(f)
            except Exception as e:
                pass

        if self._feature_names_path and not self._feature_names:
            try:
                with open(self._feature_names_path, "rb") as f:
                    self._feature_names = pickle.load(f)
            except Exception:
                                                                                  
                try:
                    with open(self._feature_names_path, "r", encoding="utf-8") as f:
                        self._feature_names = [
                            line.strip() for line in f if line.strip() and not line.startswith("#")
                        ]
                except Exception:
                    pass

        if self._attack_scaler_path and self._attack_scaler is None:
            try:
                with open(self._attack_scaler_path, "rb") as f:
                    self._attack_scaler = pickle.load(f)
            except Exception:
                self._attack_scaler = self._scaler

        if self._attack_feature_names_path and not self._attack_feature_names:
            try:
                with open(self._attack_feature_names_path, "rb") as f:
                    loaded = pickle.load(f)
                if isinstance(loaded, list):
                    self._attack_feature_names = loaded
            except Exception:
                pass
        if not self._attack_feature_names:
            self._attack_feature_names = list(self._feature_names)

    def _extract_features(self, scapy_packet) -> Optional[list]:
        
        try:
            from scapy.all import IP, TCP, UDP, ICMP

            if not scapy_packet.haslayer(IP):
                return None

            ip_layer = scapy_packet[IP]

            n_features = len(self._feature_names) if self._feature_names else 78
            features = [0.0] * n_features

            if not self._feature_names:
                return None

            idx_map = {name: i for i, name in enumerate(self._feature_names)}

                                         
                                                                                   
            sport = 0
            dport = 0
            plen = len(bytes(ip_layer.payload)) if ip_layer.payload else 0
            
            if scapy_packet.haslayer(TCP):
                tcp = scapy_packet[TCP]
                sport = tcp.sport
                dport = tcp.dport
            elif scapy_packet.haslayer(UDP):
                udp = scapy_packet[UDP]
                sport = udp.sport
                dport = udp.dport

            if "originp" in idx_map:
                features[idx_map["originp"]] = float(sport)
            if "responp" in idx_map:
                features[idx_map["responp"]] = float(dport)
            if "flow_duration" in idx_map:
                features[idx_map["flow_duration"]] = 0.5               
            if "fwd_pkts_tot" in idx_map:
                features[idx_map["fwd_pkts_tot"]] = 1.0

            return features

        except Exception:
            return None

    def _classify_packet(self, features: list) -> tuple[bool, ThreatType, float]:
        
        import numpy as np

        is_malicious = False
        threat_type = ThreatType.NORMAL
        confidence = 0.0

        feature_array = np.array(features).reshape(1, -1)
        if self._scaler is not None:
            scaler_input = feature_array
            scaler_feature_names = getattr(self._scaler, "feature_names_in_", None)
            if scaler_feature_names is not None and len(scaler_feature_names) == feature_array.shape[1]:
                import pandas as pd
                scaler_input = pd.DataFrame(feature_array, columns=list(scaler_feature_names))
            elif self._feature_names and len(self._feature_names) == feature_array.shape[1]:
                import pandas as pd
                scaler_input = pd.DataFrame(feature_array, columns=self._feature_names)
            feature_array = self._scaler.transform(scaler_input)

                                        
        if self._binary_model is not None:
            try:
                prediction = self._binary_model.predict(feature_array)[0]
                print("Prediction:", prediction)
                if hasattr(self._binary_model, "predict_proba"):
                    probas = self._binary_model.predict_proba(feature_array)[0]
                    confidence = float(max(probas))
                else:
                    confidence = 0.85                                  

                                                                         
                is_malicious = bool(prediction == 1) or (
                    isinstance(prediction, str) and prediction.lower() in ("attack", "malicious", "1")
                )
            except Exception:
                pass

                                                                                 
        if is_malicious and self._attack_model is not None:
            try:
                attack_pred = self._attack_model.predict(feature_array)[0]
                if hasattr(self._attack_model, "predict_proba"):
                    attack_probas = self._attack_model.predict_proba(feature_array)[0]
                    confidence = float(max(attack_probas))

                if self._attack_label_encoder and hasattr(self._attack_label_encoder, "classes_"):
                    if isinstance(attack_pred, (int, np.integer)):
                        label = self._attack_label_encoder.classes_[int(attack_pred)]
                    else:
                        label = str(attack_pred)
                elif hasattr(self._attack_model, "classes_"):
                    if isinstance(attack_pred, (int, np.integer)):
                        label = str(self._attack_model.classes_[int(attack_pred)])
                    else:
                        label = str(attack_pred)
                else:
                    label = str(attack_pred)

                threat_type = _map_attack_label(label)

            except Exception:
                threat_type = ThreatType.MALWARE_COMM            

        elif is_malicious:
                                                                 
            threat_type = ThreatType.MALWARE_COMM

        return is_malicious, threat_type, confidence

    def _scapy_packet_to_packet(self, scapy_pkt) -> Optional[Packet]:
        
        try:
            from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            src_port = 0
            dst_port = 0
            proto = Protocol.TCP
            flags = ""
            ttl = 0
            payload_preview = ""
            length = len(scapy_pkt)

            if scapy_pkt.haslayer(ARP):
                arp = scapy_pkt[ARP]
                src_ip = arp.psrc or "0.0.0.0"
                dst_ip = arp.pdst or "0.0.0.0"
                proto = Protocol.ARP
                payload_preview = f"ARP {arp.op}: {src_ip} → {dst_ip}"

            elif scapy_pkt.haslayer(IP) or scapy_pkt.haslayer(IPv6):
                if scapy_pkt.haslayer(IP):
                    ip = scapy_pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    ttl = ip.ttl
                else:
                    ip = scapy_pkt[IPv6]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    ttl = ip.hlim                                      

                if scapy_pkt.haslayer(TCP):
                    tcp = scapy_pkt[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    flags = str(tcp.flags)
                    proto = PORT_PROTOCOL_MAP.get(dst_port, Protocol.TCP)
                    payload_preview = (
                        f"TCP {src_port} → {dst_port} [{flags}] "
                        f"Seq={tcp.seq} Ack={tcp.ack}"
                    )

                elif scapy_pkt.haslayer(UDP):
                    udp = scapy_pkt[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    proto = Protocol.UDP

                    if scapy_pkt.haslayer(DNS):
                        proto = Protocol.DNS
                        dns = scapy_pkt[DNS]
                        if dns.qr == 0 and dns.qdcount > 0:
                            qname = dns.qd.qname.decode() if dns.qd else "?"
                            payload_preview = f"DNS Query: {qname}"
                        else:
                            payload_preview = f"DNS Response"
                    else:
                        payload_preview = f"UDP {src_port} → {dst_port} Len={len(bytes(udp.payload))}"

                elif scapy_pkt.haslayer(ICMP):
                    icmp = scapy_pkt[ICMP]
                    proto = Protocol.ICMP
                    payload_preview = f"ICMP Type={icmp.type} Code={icmp.code}"

                                     
                if not payload_preview and scapy_pkt.haslayer(Raw):
                    raw = bytes(scapy_pkt[Raw])[:80]
                    try:
                        payload_preview = raw.decode("utf-8", errors="replace")
                    except Exception:
                        payload_preview = raw.hex()[:80]
            else:
                               
                payload_preview = scapy_pkt.summary()

                                                                                        
            return Packet(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                length=length,
                ttl=ttl,
                flags=flags,
                payload_preview=payload_preview,
                is_malicious=False,
                threat_type=ThreatType.NORMAL,
                confidence=0.0,
                model_used=self.model_name,
                is_blocked=False,
                block_reason="",
            )

        except Exception as e:
            return None

    def run(self):
        
        self._running = True
        self._reset_runtime_detection_state()

        try:
            from scapy.all import sniff, conf

            resolved_iface = self._resolve_interface()
            if resolved_iface == "":
                self.capture_error.emit(
                    f"Selected interface is not valid: {self._interface}. "
                    "Choose NIC with your active VM/host traffic or use Auto."
                )
                return

            self._load_models()
            if self._binary_model is None:
                self.capture_error.emit(
                    "Stage 1 model could not be loaded. Check model path and dependencies (xgboost/sklearn)."
                )
                return
            if not self._feature_names:
                self.capture_error.emit(
                    "Feature names are missing. Ensure feature_names.pkl or feature_names.txt is present."
                )
                return

            self._flow_agg = FlowAggregator(feature_names=self._feature_names)
            conf.verb = 0

            def _check_expired():
                while self._running:
                    try:
                        for _, feature_vec, flow_rec in self._flow_agg.get_expired_flows():
                            self._classify_and_emit_flow(flow_rec, feature_vec)
                    except Exception as exc:
                        self._report_runtime_issue("expired-flow-check", exc)
                    time.sleep(0.8)

            import threading

            threading.Thread(target=_check_expired, daemon=True).start()
            packet_display_counter = [0]

            def _process_packet(scapy_pkt):
                if not self._running:
                    return

                try:
                                                         
                    packet = self._scapy_packet_to_packet(scapy_pkt)
                    if packet:
                        packet_display_counter[0] += 1
                        if packet.is_malicious or packet_display_counter[0] % 5 == 0:
                            self.packet_captured.emit(packet)

                                                                              
                    result = self._flow_agg.add_packet(scapy_pkt)
                    if result:
                        _, feature_vec, flow_rec = result
                        self._classify_and_emit_flow(flow_rec, feature_vec)
                except Exception as exc:
                    self._report_runtime_issue("packet-processing", exc)

            sniff(
                iface=resolved_iface,
                prn=_process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )

        except ImportError:
            self.capture_error.emit(
                "Scapy is not installed. Install with: pip install scapy\n"
                "Falling back to mock capture."
            )
        except PermissionError:
            self.capture_error.emit(
                "Permission denied. Run as Administrator for real packet capture."
            )
        except Exception as e:
            self.capture_error.emit(f"Capture error: {e}\n{traceback.format_exc()}")

    def _classify_and_emit_flow(self, flow_rec: FlowRecord, feature_vec):
        
        import numpy as np

        try:
            total_pkts = flow_rec.fwd_packets + flow_rec.bwd_packets
            total_bytes = sum(flow_rec.fwd_lengths) + sum(flow_rec.bwd_lengths)
            flow_duration = flow_rec.last_time - flow_rec.start_time
            thresholds = self._thresholds()
            if flow_rec.protocol not in (6, 17):
                return
            # User policy: ignore HTTPS flows entirely for detection/prevention.
            if flow_rec.protocol == 6 and (flow_rec.dst_port == 443 or flow_rec.src_port == 443):
                return

            # Require stronger evidence for live-mode ML classification to reduce false positives
            # on tiny normal HTTPS/TCP bursts; keep scan-style SYN-only flows detectable.
            if flow_rec.protocol == 6:
                if (
                    flow_rec.syn_count >= 1
                    and flow_rec.ack_count == 0
                    and flow_duration <= 3.0
                ):
                    min_pkts = 1
                    min_bytes = 0
                elif flow_rec.dst_port == 443:
                    min_pkts = 6
                    min_bytes = 280
                else:
                    min_pkts = 4
                    min_bytes = 220
            else:
                min_pkts = 8
                min_bytes = 320
            if total_pkts < min_pkts:
                return
            if total_bytes < min_bytes:
                return

                                                                                  
                                                                                                
            activity = self._record_source_activity(flow_rec, total_pkts, flow_duration)
            if flow_rec.protocol == 6:
                syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
                if (
                    flow_rec.syn_count >= 1
                    and flow_rec.ack_count == 0
                    and syn_ratio >= 0.80
                    and activity["recent_scan_ports"] >= 22
                    and activity["recent_scan_flows"] >= 25
                ):
                    threat_type = ThreatType.PORT_SCAN
                    confidence = 0.96
                    proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, Protocol.TCP)
                    should_block = False
                    block_reason = ""
                    block_min_conf = thresholds["block"]
                    if self._prevention_enabled and confidence >= block_min_conf:
                        blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
                        should_block = blocked
                        block_reason = (
                            f"Behavioral PortScan detection from {flow_rec.src_ip} "
                            f"[ports={activity['recent_scan_ports']}, flows={activity['recent_scan_flows']}, "
                            f"SYN ratio={syn_ratio:.0%}, Confidence: {confidence:.0%}] | {reason}"
                        )

                    alert_packet = Packet(
                        timestamp=datetime.now(),
                        src_ip=flow_rec.src_ip,
                        dst_ip=flow_rec.dst_ip,
                        src_port=flow_rec.src_port,
                        dst_port=flow_rec.dst_port,
                        protocol=proto,
                        length=total_bytes,
                        ttl=0,
                        flags="",
                        payload_preview=(
                            f"PORTSCAN ALERT: unique ports={activity['recent_scan_ports']}, "
                            f"flows={activity['recent_scan_flows']} | conf: {confidence:.0%}"
                        ),
                        is_malicious=True,
                        threat_type=threat_type,
                        confidence=confidence,
                        model_used=f"{self.model_name} + BehavioralScan",
                        is_blocked=should_block,
                        block_reason=block_reason,
                    )
                    self.packet_captured.emit(alert_packet)
                    return

                                                       
                                                                                             
            signature_threat = self._detect_signature_threat(
                flow_rec=flow_rec,
                total_pkts=total_pkts,
                total_bytes=total_bytes,
                flow_duration=flow_duration,
                activity=activity,
            )

            rule_prefilter_hit = self._rule_prefilter_suspicious(
                flow_rec=flow_rec,
                total_pkts=total_pkts,
                total_bytes=total_bytes,
                flow_duration=flow_duration,
                activity=activity,
                signature_threat=signature_threat,
            )

            if signature_threat is not None:
                threat_type = signature_threat
                confidence = 0.99
                if not self._should_emit_alert(flow_rec.src_ip, threat_type):
                    return
                proto = {6: Protocol.TCP, 17: Protocol.UDP}.get(flow_rec.protocol, Protocol.TCP)
                proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, proto)
                should_block = False
                block_reason = ""

                pps = total_pkts / max(flow_duration, 1e-3)
                syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
                block_min_conf = thresholds["block"]
                if self._prevention_enabled and confidence >= block_min_conf:
                    blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
                    should_block = blocked
                    block_reason = (
                        f"Signature detection: {threat_type.display_name} from {flow_rec.src_ip} "
                        f"[{total_pkts} pkts, {pps:.1f} pps, SYN ratio {syn_ratio:.0%}, "
                        f"Confidence: {confidence:.0%}] | {reason}"
                    )
                    if not blocked:
                        key = f"{flow_rec.src_ip}:{reason}"
                        if key not in self._reported_block_failures:
                            self._reported_block_failures.add(key)
                            self.capture_error.emit(
                                f"Prevention rule failed for {flow_rec.src_ip}: {reason}"
                            )

                alert_packet = Packet(
                    timestamp=datetime.now(),
                    src_ip=flow_rec.src_ip,
                    dst_ip=flow_rec.dst_ip,
                    src_port=flow_rec.src_port,
                    dst_port=flow_rec.dst_port,
                    protocol=proto,
                    length=total_bytes,
                    ttl=0,
                    flags="",
                    payload_preview=(
                        f"SIGNATURE ALERT: {threat_type.display_name} | "
                        f"{flow_rec.fwd_packets}↑ {flow_rec.bwd_packets}↓ pkts | "
                        f"rate {pps:.1f} pps | conf: {confidence:.0%}"
                    ),
                    is_malicious=True,
                    threat_type=threat_type,
                    confidence=confidence,
                    model_used=f"{self.model_name} + Signature",
                    is_blocked=should_block,
                    block_reason=block_reason,
                )
                self.packet_captured.emit(alert_packet)
                return

            # Behavioral DoS detection (additive; Port Scan path above stays unchanged)
            dos_threat = self._detect_behavioral_dos(
                flow_rec=flow_rec,
                total_pkts=total_pkts,
                total_bytes=total_bytes,
                flow_duration=flow_duration,
                activity=activity,
            )
            if dos_threat is not None:
                threat_type = dos_threat
                confidence = 0.95
                if not self._should_emit_alert(flow_rec.src_ip, threat_type):
                    return
                proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, Protocol.TCP)
                should_block = False
                block_reason = ""

                pps = total_pkts / max(flow_duration, 1e-3)
                syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
                block_min_conf = thresholds["block"]
                if self._prevention_enabled and confidence >= block_min_conf:
                    blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
                    should_block = blocked
                    block_reason = (
                        f"Behavioral DoS detection from {flow_rec.src_ip} "
                        f"[{total_pkts} pkts, {pps:.1f} pps, SYN ratio={syn_ratio:.0%}, "
                        f"web_flows={activity.get('recent_web_flows', 0)}, "
                        f"recent_pkts={activity.get('recent_packets', 0)}, "
                        f"Confidence: {confidence:.0%}] | {reason}"
                    )
                    if not blocked:
                        key = f"{flow_rec.src_ip}:{reason}"
                        if key not in self._reported_block_failures:
                            self._reported_block_failures.add(key)
                            self.capture_error.emit(
                                f"Prevention rule failed for {flow_rec.src_ip}: {reason}"
                            )

                alert_packet = Packet(
                    timestamp=datetime.now(),
                    src_ip=flow_rec.src_ip,
                    dst_ip=flow_rec.dst_ip,
                    src_port=flow_rec.src_port,
                    dst_port=flow_rec.dst_port,
                    protocol=proto,
                    length=total_bytes,
                    ttl=0,
                    flags="",
                    payload_preview=(
                        f"DOS ALERT: {total_pkts} pkts | {pps:.1f} pps | "
                        f"web_flows={activity.get('recent_web_flows', 0)} | conf: {confidence:.0%}"
                    ),
                    is_malicious=True,
                    threat_type=threat_type,
                    confidence=confidence,
                    model_used=f"{self.model_name} + BehavioralDoS",
                    is_blocked=should_block,
                    block_reason=block_reason,
                )
                self.packet_captured.emit(alert_packet)
                return

            # Conservative HTTPS browsing-noise filter (after behavioral detectors).
            # This skips ML on small low-rate 443 flows while keeping DoS/PortScan detection active.
            if flow_rec.protocol == 6 and flow_rec.dst_port == 443:
                pps_https = total_pkts / max(flow_duration, 1e-3)
                syn_ratio_https = flow_rec.syn_count / max(total_pkts, 1)
                if (
                    total_pkts <= 14
                    and total_bytes <= 3500
                    and pps_https <= 65
                    and syn_ratio_https <= 0.35
                    and activity.get("recent_web_flows", 0) <= 4
                ):
                    return

            X = feature_vec.reshape(1, -1)
            if self._scaler is not None:
                try:
                    scaler_input = X
                    scaler_feature_names = getattr(self._scaler, "feature_names_in_", None)
                    if scaler_feature_names is not None and len(scaler_feature_names) == X.shape[1]:
                        import pandas as pd
                        scaler_input = pd.DataFrame(X, columns=list(scaler_feature_names))
                    elif self._feature_names and len(self._feature_names) == X.shape[1]:
                        import pandas as pd
                        scaler_input = pd.DataFrame(X, columns=self._feature_names)
                    X = self._scaler.transform(scaler_input)
                except Exception:
                    pass

            if self._binary_model is None:
                return

            pred = self._binary_model.predict(X)[0]
            s1_confidence = 0.80
            if hasattr(self._binary_model, "predict_proba"):
                s1_confidence = float(max(self._binary_model.predict_proba(X)[0]))

            is_malicious = self._prediction_is_attack(pred)
            s1_min_conf = thresholds["stage1"]
            if not is_malicious or s1_confidence < s1_min_conf:
                return
            if not rule_prefilter_hit:
                return

            threat_type = None
            confidence = s1_confidence
            stage2_label = "Unknown"
            stage2_confidence = 0.0
            detection_source = "stage1_only"

            if self._attack_model is not None:
                try:
                    X_stage2 = feature_vec.reshape(1, -1)
                    if self._attack_scaler is not None:
                        try:
                            atk_scaler_input = X_stage2
                            atk_scaler_feature_names = getattr(self._attack_scaler, "feature_names_in_", None)
                            if atk_scaler_feature_names is not None and len(atk_scaler_feature_names) == X_stage2.shape[1]:
                                import pandas as pd
                                atk_scaler_input = pd.DataFrame(X_stage2, columns=list(atk_scaler_feature_names))
                            elif self._attack_feature_names and len(self._attack_feature_names) == X_stage2.shape[1]:
                                import pandas as pd
                                atk_scaler_input = pd.DataFrame(X_stage2, columns=self._attack_feature_names)
                            X_stage2 = self._attack_scaler.transform(atk_scaler_input)
                        except Exception:
                            pass

                    atk_pred = self._attack_model.predict(X_stage2)[0]
                    s2_confidence = 0.0
                    if hasattr(self._attack_model, "predict_proba"):
                        s2_confidence = float(max(self._attack_model.predict_proba(X_stage2)[0]))

                    label = str(atk_pred)
                    if self._attack_label_encoder and hasattr(self._attack_label_encoder, "classes_"):
                        if isinstance(atk_pred, (int, np.integer)):
                            label = self._attack_label_encoder.classes_[int(atk_pred)]
                    elif hasattr(self._attack_model, "classes_"):
                        if isinstance(atk_pred, (int, np.integer)):
                            label = str(self._attack_model.classes_[int(atk_pred)])

                    stage2_label = str(label)
                    stage2_confidence = s2_confidence
                    mapped = _map_attack_label(str(label))
                    if mapped is not None:
                        s2_min_conf = self._stage2_min_conf_for_threat(mapped, thresholds["stage2"])
                        if mapped == ThreatType.BRUTE_FORCE and not self._is_bruteforce_flow_plausible(
                            flow_rec, total_pkts, total_bytes
                        ):
                            mapped = None
                        ddos_relaxed = (
                            mapped in {ThreatType.DOS_ATTACK, ThreatType.DDOS_ATTACK}
                            and s1_confidence >= 0.90
                            and s2_confidence >= 0.35
                            and total_pkts >= 10
                        )
                        if mapped is not None and (s2_confidence >= s2_min_conf or ddos_relaxed):
                            threat_type = mapped
                            confidence = max(s2_confidence, s1_confidence if ddos_relaxed else s2_confidence)
                            detection_source = "stage2_mapped"
                except Exception:
                    pass

                                                                          
            if threat_type is None:
                                                                     
                                                                                            
                if (
                    is_malicious
                    and s1_confidence >= 0.75
                    and flow_rec.protocol == 6
                ):
                    scan_assist = self._detect_signature_threat(
                        flow_rec=flow_rec,
                        total_pkts=total_pkts,
                        total_bytes=total_bytes,
                        flow_duration=flow_duration,
                        activity=activity,
                    )
                    if scan_assist == ThreatType.PORT_SCAN:
                        threat_type = ThreatType.PORT_SCAN
                        confidence = max(confidence, 0.92)
                        detection_source = "signature_scan_assist"

                if threat_type is None:
                    # Live mode policy: drop weak/unconfirmed stage-1-only predictions.
                    # Keep a very strict fallback path for high-confidence sustained flows.
                    if (
                        is_malicious
                        and s1_confidence >= max(0.985, s1_min_conf + 0.20)
                        and total_pkts >= 16
                        and total_bytes >= 1500
                    ):
                        threat_type = ThreatType.MALWARE_COMM
                        confidence = max(confidence, s1_confidence)
                        detection_source = "stage1_high_conf_fallback"
                    else:
                        return
                if threat_type is None:
                    threat_type = self._infer_fallback_threat(flow_rec, total_pkts, flow_duration)
                    if threat_type is None:
                        return
                    confidence = max(confidence, 0.80)
                    detection_source = "heuristic_fallback"

            should_block = False
            block_reason = ""
            pps = total_pkts / max(flow_duration, 1e-3)
            syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
            block_min_conf = thresholds["block"]
            detection_reason = (
                f"Stage1={s1_confidence:.0%} (pred={pred}), "
                f"Stage2={stage2_label} ({stage2_confidence:.0%}), "
                f"Profile={self._sensitivity_profile}, "
                f"Source={detection_source}, "
                f"flow={total_pkts} pkts/{total_bytes} bytes/{pps:.1f} pps, "
                f"SYN ratio={syn_ratio:.0%}"
            )
            confirmed_for_block = detection_source in {
                "stage2_mapped",
                "signature_scan_assist",
                "heuristic_fallback",
            }
            if self._prevention_enabled and confidence >= block_min_conf and confirmed_for_block:
                blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
                should_block = blocked
                block_reason = (
                    f"ML Flow Analysis: {threat_type.display_name} from {flow_rec.src_ip} "
                    f"[{total_pkts} pkts, Confidence: {confidence:.0%}] | {detection_reason} | {reason}"
                )
                if not blocked:
                    key = f"{flow_rec.src_ip}:{reason}"
                    if key not in self._reported_block_failures:
                        self._reported_block_failures.add(key)
                        self.capture_error.emit(
                            f"Prevention rule failed for {flow_rec.src_ip}: {reason}"
                        )
            elif self._prevention_enabled:
                block_reason = (
                    f"Detection-only: {threat_type.display_name} from {flow_rec.src_ip} "
                    f"[{total_pkts} pkts, Confidence: {confidence:.0%}] | {detection_reason}"
                )

            proto = {6: Protocol.TCP, 17: Protocol.UDP}.get(flow_rec.protocol, Protocol.TCP)
            proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, proto)

            model_used_label = self.model_name
            if threat_type == ThreatType.PORT_SCAN and stage2_label == "Unknown":
                model_used_label = f"{self.model_name} + ScanEvidence"

            alert_packet = Packet(
                timestamp=datetime.now(),
                src_ip=flow_rec.src_ip,
                dst_ip=flow_rec.dst_ip,
                src_port=flow_rec.src_port,
                dst_port=flow_rec.dst_port,
                protocol=proto,
                length=total_bytes,
                ttl=0,
                flags="",
                payload_preview=(
                    f"FLOW ALERT: {threat_type.display_name} | "
                        f"{flow_rec.fwd_packets}↑ {flow_rec.bwd_packets}↓ pkts | "
                        f"S1 {s1_confidence:.0%} | S2 {stage2_label} {stage2_confidence:.0%} | "
                        f"conf: {confidence:.0%}"
                ),
                is_malicious=True,
                threat_type=threat_type,
                confidence=confidence,
                model_used=model_used_label,
                is_blocked=should_block,
                block_reason=block_reason,
            )
            self.packet_captured.emit(alert_packet)
        except Exception as exc:
            self._report_runtime_issue("flow-classification", exc)
