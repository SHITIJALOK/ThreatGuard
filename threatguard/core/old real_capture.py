

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
from collections import defaultdict, deque
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QThread, Signal

from threatguard.core.packet import Packet, Protocol, ThreatType
from threatguard.core.flow_aggregator import FlowAggregator, FlowRecord
from threatguard.utils.ip_manager import is_ip_allowed, queue_block_ip

                                                   
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
    "port_scan": ThreatType.PORT_SCAN,
    "ddos": ThreatType.DDOS_ATTACK,
    "brute_force": ThreatType.BRUTE_FORCE,
                   
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
        label_encoder_path: Optional[str] = None,
        feature_names_path: Optional[str] = None,
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
        self._label_encoder_path = label_encoder_path
        self._feature_names_path = feature_names_path
        self.model_name = model_name
        self._prevention_enabled = prevention_enabled
        self._confidence_threshold = confidence_threshold
        self._sensitivity_profile = sensitivity_profile
        self._test_mode = bool(test_mode)
        self._running = False
        self._blocked_ips: set[str] = set()
        self._reported_block_failures: set[str] = set()
        self._source_activity_lock = threading.Lock()
        self._source_activity = defaultdict(
            lambda: {
                "scan_times": deque(),
                "scan_ports": deque(),
                "packet_times": deque(),
                "udp_packet_times": deque(),
            }
        )

                                   
        self._binary_model = None
        self._attack_model = None
        self._scaler = None
        self._attack_label_encoder = None
        self._feature_names: list[str] = []

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
        return{
        "stage1": 0.78,
        "stage2": 0.68,
        "block": 0.88
    }
    
    def set_binary_model(self, path: str):
        self._binary_model_path = path
        self._binary_model = None                

    def set_attack_model(self, path: str):
        self._attack_model_path = path
        self._attack_model = None                

    def stop(self):
        self._running = False

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

            while bucket["scan_times"] and now - bucket["scan_times"][0] > 6.0:
                bucket["scan_times"].popleft()
            while bucket["scan_ports"] and now - bucket["scan_ports"][0][0] > 6.0:
                bucket["scan_ports"].popleft()
            while bucket["packet_times"] and now - bucket["packet_times"][0] > 3.0:
                bucket["packet_times"].popleft()
            while bucket["udp_packet_times"] and now - bucket["udp_packet_times"][0] > 3.0:
                bucket["udp_packet_times"].popleft()

            unique_ports = {port for _, port in bucket["scan_ports"]}
            return {
                "recent_scan_flows": len(bucket["scan_times"]),
                "recent_scan_ports": len(unique_ports),
                "recent_packets": len(bucket["packet_times"]),
                "recent_udp_packets": len(bucket["udp_packet_times"]),
            }

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
                flow_rec.syn_count >= 3
                and flow_rec.ack_count == 0
                and syn_ratio >= 0.80
                and total_pkts >= 6
                and flow_duration <= 2.0
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
    ) -> Optional[ThreatType]:
        
        pps = total_pkts / max(flow_duration, 1e-3)
        syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
        activity = self._record_source_activity(flow_rec, total_pkts, flow_duration)

                                          
        if (
            flow_rec.protocol == 6
            and (
                (total_pkts >= 80 and pps >= 180 and syn_ratio >= 0.80)
                or (activity["recent_packets"] >= 500 and syn_ratio >= 0.75)
            )
        ):
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
                    except Exception:
                        pass
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
                except Exception:
                    pass

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
        import pandas as pd
        import os

        try:
            total_pkts = flow_rec.fwd_packets + flow_rec.bwd_packets
            total_bytes = sum(flow_rec.fwd_lengths) + sum(flow_rec.bwd_lengths)
            flow_duration = max(flow_rec.last_time - flow_rec.start_time, 0.001)
            pps = total_pkts / flow_duration
            syn_ratio = flow_rec.syn_count / max(total_pkts, 1)

            thresholds = self._thresholds()

            # ------------------------------------------------
            # Ignore noisy tiny flows
            # ------------------------------------------------
            if flow_rec.protocol not in (6, 17):
                return

            if total_pkts < 4:
                return

            if flow_rec.dst_port in [53, 443] and total_pkts < 8:
                return

            proto = {6: Protocol.TCP, 17: Protocol.UDP}.get(
                flow_rec.protocol,
                Protocol.TCP
            )
            proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, proto)

            # ------------------------------------------------
            # PORTSCAN BEHAVIORAL DETECTION (stable)
            # ------------------------------------------------
            if flow_rec.protocol == 6:

                activity = self._record_source_activity(
                    flow_rec,
                    total_pkts,
                    flow_duration
                )

                if (
                    flow_rec.syn_count >= 1
                    and flow_rec.ack_count == 0
                    and syn_ratio >= 0.80
                    and activity["recent_scan_ports"] >= 22
                    and activity["recent_scan_flows"] >= 25
                ):

                    should_block = False
                    block_reason = ""

                    confidence = 0.96
                    threat_type = ThreatType.PORT_SCAN

                    if (
                        self._prevention_enabled
                        and confidence >= thresholds["block"]
                    ):
                        blocked, reason = self._ensure_firewall_block(
                            flow_rec.src_ip,
                            threat_type
                        )
                        should_block = blocked
                        block_reason = reason

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
                            f"PORTSCAN ALERT | "
                            f"ports={activity['recent_scan_ports']} | "
                            f"flows={activity['recent_scan_flows']} | "
                            f"conf={confidence:.0%}"
                        ),
                        is_malicious=True,
                        threat_type=threat_type,
                        confidence=confidence,
                        model_used=f"{self.model_name} + Behavioral",
                        is_blocked=should_block,
                        block_reason=block_reason,
                    )

                    self.packet_captured.emit(alert_packet)
                    return

            # ------------------------------------------------
            # SAVE FLOW CSV
            # ------------------------------------------------
            try:
                df = pd.DataFrame(
                    [feature_vec],
                    columns=self._feature_names
                )

                csv_file = "runtime_flows.csv"

                df.to_csv(
                    csv_file,
                    mode="a",
                    header=not os.path.exists(csv_file),
                    index=False
                )
            except Exception:
                pass

            # ------------------------------------------------
            # FEATURE PREP
            # ------------------------------------------------
            X = feature_vec.reshape(1, -1)

            if self._scaler is not None:
                try:
                    scaler_input = pd.DataFrame(
                        X,
                        columns=self._feature_names
                    )
                    X = self._scaler.transform(scaler_input)
                except Exception:
                    pass

            # ------------------------------------------------
            # STAGE 1
            # ------------------------------------------------
            if self._binary_model is None:
                return

            pred = self._binary_model.predict(X)[0]

            s1_confidence = 0.80
            if hasattr(self._binary_model, "predict_proba"):
                s1_confidence = float(
                    max(self._binary_model.predict_proba(X)[0])
                )

            is_malicious = self._prediction_is_attack(pred)

            if (
                not is_malicious
                or s1_confidence < thresholds["stage1"]
            ):
                return

            # ------------------------------------------------
            # STAGE 2
            # ------------------------------------------------
            threat_type = None
            confidence = s1_confidence
            stage2_label = "Unknown"
            stage2_confidence = 0.0

            if self._attack_model is not None:
                try:
                    atk_pred = self._attack_model.predict(X)[0]

                    if hasattr(self._attack_model, "predict_proba"):
                        stage2_confidence = float(
                            max(
                                self._attack_model.predict_proba(X)[0]
                            )
                        )

                    label = str(atk_pred)

                    if (
                        self._attack_label_encoder
                        and hasattr(
                            self._attack_label_encoder,
                            "classes_"
                        )
                    ):
                        if isinstance(
                            atk_pred,
                            (int, np.integer)
                        ):
                            label = (
                                self._attack_label_encoder
                                .classes_[int(atk_pred)]
                            )

                    stage2_label = str(label)

                    if (
                        stage2_confidence
                        >= thresholds["stage2"]
                    ):
                        mapped = _map_attack_label(label)

                        # sanity filters
                        if mapped == ThreatType.PORT_SCAN:
                            if flow_rec.dst_port in [53, 443]:
                                mapped = None
                            elif total_pkts < 8:
                                mapped = None

                        if mapped is not None:
                            threat_type = mapped
                            confidence = stage2_confidence

                except Exception:
                    pass

            # ------------------------------------------------
            # SAFE FALLBACK
            # ------------------------------------------------
            if threat_type is None:

                signature = self._detect_signature_threat(
                    flow_rec=flow_rec,
                    total_pkts=total_pkts,
                    total_bytes=total_bytes,
                    flow_duration=flow_duration,
                )

                if signature is not None:
                    threat_type = signature
                    confidence = max(confidence, 0.90)

            if threat_type is None:
                threat_type = self._infer_fallback_threat(
                    flow_rec,
                    total_pkts,
                    flow_duration
                )

                if threat_type is not None:
                    confidence = max(confidence, 0.80)

            if threat_type is None:
                return

            # ------------------------------------------------
            # PREVENTION
            # ------------------------------------------------
            should_block = False
            block_reason = ""

            if (
                self._prevention_enabled
                and confidence >= thresholds["block"]
            ):
                blocked, reason = self._ensure_firewall_block(
                    flow_rec.src_ip,
                    threat_type
                )

                should_block = blocked
                block_reason = reason

            # ------------------------------------------------
            # FINAL ALERT
            # ------------------------------------------------
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
                    f"{flow_rec.fwd_packets}↑ "
                    f"{flow_rec.bwd_packets}↓ | "
                    f"S1 {s1_confidence:.0%} | "
                    f"S2 {stage2_label} "
                    f"{stage2_confidence:.0%} | "
                    f"conf {confidence:.0%}"
                ),
                is_malicious=True,
                threat_type=threat_type,
                confidence=confidence,
                model_used=self.model_name,
                is_blocked=should_block,
                block_reason=block_reason,
            )

            self.packet_captured.emit(alert_packet)

        except Exception as e:
            print("FLOW ERROR:", e)
            traceback.print_exc()
    # def _classify_and_emit_flow(self, flow_rec: FlowRecord, feature_vec):
        
    #     import numpy as np

    #     try:
    #         total_pkts = flow_rec.fwd_packets + flow_rec.bwd_packets
    #         total_bytes = sum(flow_rec.fwd_lengths) + sum(flow_rec.bwd_lengths)
    #         flow_duration = flow_rec.last_time - flow_rec.start_time
    #         thresholds = self._thresholds()
    #         print("FLOW READY")
    #         print("Packets:", total_pkts)
    #         print("Bytes:", total_bytes)
    #         print("Duration:", flow_duration)
    #         if flow_rec.protocol not in (6, 17):
    #             return

                                               
    #         #min_pkts = 1
    #         # Ignore tiny flows (biggest false-positive fix)
    #         if total_pkts < 4:
    #             return

    #         # Ignore tiny HTTPS/DNS sessions
    #         if flow_rec.dst_port in [53, 443] and total_pkts < 8:
    #             return                                                  
                                                                                                
    #         if flow_rec.protocol == 6:
    #             activity = self._record_source_activity(flow_rec, total_pkts, flow_duration)
    #             syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
    #             if (
    #                 flow_rec.syn_count >= 1
    #                 and flow_rec.ack_count == 0
    #                 and syn_ratio >= 0.80
    #                 and activity["recent_scan_ports"] >= 22
    #                 and activity["recent_scan_flows"] >= 25
    #             ):
    #                 threat_type = ThreatType.PORT_SCAN
    #                 confidence = 0.96
    #             proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, Protocol.TCP)
    #             should_block = False
    #             block_reason = ""
    #             block_min_conf = thresholds["block"]
    #             if self._prevention_enabled and confidence >= block_min_conf:
    #                 blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
    #                 should_block = blocked
    #                 block_reason = (
    #                     f"Behavioral PortScan detection from {flow_rec.src_ip} "
    #                     f"[ports={activity['recent_scan_ports']}, flows={activity['recent_scan_flows']}, "
    #                     f"SYN ratio={syn_ratio:.0%}, Confidence: {confidence:.0%}] | {reason}"
    #                 )

    #                 alert_packet = Packet(
    #                     timestamp=datetime.now(),
    #                     src_ip=flow_rec.src_ip,
    #                     dst_ip=flow_rec.dst_ip,
    #                     src_port=flow_rec.src_port,
    #                     dst_port=flow_rec.dst_port,
    #                     protocol=proto,
    #                     length=total_bytes,
    #                     ttl=0,
    #                     flags="",
    #                     payload_preview=(
    #                         f"PORTSCAN ALERT: unique ports={activity['recent_scan_ports']}, "
    #                         f"flows={activity['recent_scan_flows']} | conf: {confidence:.0%}"
    #                     ),
    #                     is_malicious=True,
    #                     threat_type=threat_type,
    #                     confidence=confidence,
    #                     model_used=f"{self.model_name} + BehavioralScan",
    #                     is_blocked=should_block,
    #                     block_reason=block_reason,
    #                 )
    #                 self.packet_captured.emit(alert_packet)
    #                 return

                                                                                                 
    #         signature_threat = None
    #         if self._test_mode:
    #             signature_threat = self._detect_signature_threat(
    #                 flow_rec=flow_rec,
    #                 total_pkts=total_pkts,
    #                 total_bytes=total_bytes,
    #                 flow_duration=flow_duration,
    #             )

    #         if signature_threat is not None:
    #             threat_type = signature_threat
    #             confidence = 0.99
    #             proto = {6: Protocol.TCP, 17: Protocol.UDP}.get(flow_rec.protocol, Protocol.TCP)
    #             proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, proto)
    #             should_block = False
    #             block_reason = ""

    #             pps = total_pkts / max(flow_duration, 1e-3)
    #             syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
    #             block_min_conf = thresholds["block"]
    #             if self._prevention_enabled and confidence >= block_min_conf:
    #                 blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
    #                 should_block = blocked
    #                 block_reason = (
    #                     f"Signature detection: {threat_type.display_name} from {flow_rec.src_ip} "
    #                     f"[{total_pkts} pkts, {pps:.1f} pps, SYN ratio {syn_ratio:.0%}, "
    #                     f"Confidence: {confidence:.0%}] | {reason}"
    #                 )
    #                 if not blocked:
    #                     key = f"{flow_rec.src_ip}:{reason}"
    #                     if key not in self._reported_block_failures:
    #                         self._reported_block_failures.add(key)
    #                         self.capture_error.emit(
    #                             f"Prevention rule failed for {flow_rec.src_ip}: {reason}"
    #                         )

    #             alert_packet = Packet(
    #                 timestamp=datetime.now(),
    #                 src_ip=flow_rec.src_ip,
    #                 dst_ip=flow_rec.dst_ip,
    #                 src_port=flow_rec.src_port,
    #                 dst_port=flow_rec.dst_port,
    #                 protocol=proto,
    #                 length=total_bytes,
    #                 ttl=0,
    #                 flags="",
    #                 payload_preview=(
    #                     f"SIGNATURE ALERT: {threat_type.display_name} | "
    #                     f"{flow_rec.fwd_packets}↑ {flow_rec.bwd_packets}↓ pkts | "
    #                     f"rate {pps:.1f} pps | conf: {confidence:.0%}"
    #                 ),
    #                 is_malicious=True,
    #                 threat_type=threat_type,
    #                 confidence=confidence,
    #                 model_used=f"{self.model_name} + Signature",
    #                 is_blocked=should_block,
    #                 block_reason=block_reason,
    #             )
    #             self.packet_captured.emit(alert_packet)
    #             return

    #         X = feature_vec.reshape(1, -1)
            
    #         import pandas as pd
    #         import os

    #         df = pd.DataFrame([feature_vec], columns=self._feature_names)
    #         csv_file = "runtime_flows.csv"
    #         df.to_csv(
    #             csv_file,
    #             mode="a",
    #             header=not os.path.exists(csv_file),
    #             index=False
    #         )            
            
    #         if self._scaler is not None:
    #             try:
    #                 scaler_input = X
    #                 scaler_feature_names = getattr(self._scaler, "feature_names_in_", None)
    #                 if scaler_feature_names is not None and len(scaler_feature_names) == X.shape[1]:
    #                     import pandas as pd
    #                     scaler_input = pd.DataFrame(X, columns=list(scaler_feature_names))
    #                 elif self._feature_names and len(self._feature_names) == X.shape[1]:
    #                     import pandas as pd
    #                     scaler_input = pd.DataFrame(X, columns=self._feature_names)
    #                 X = self._scaler.transform(scaler_input)
    #             except Exception:
    #                 pass

    #         if self._binary_model is None:
    #             return
    #         print("STAGE 1 RUNNING")

    #         pred = self._binary_model.predict(X)[0]
    #         print("Prediction:", pred)
    #         s1_confidence = 0.80
    #         if hasattr(self._binary_model, "predict_proba"):
    #             s1_confidence = float(max(self._binary_model.predict_proba(X)[0]))

    #         is_malicious = self._prediction_is_attack(pred)
    #         s1_min_conf = thresholds["stage1"]
    #         if not is_malicious or s1_confidence < s1_min_conf:
    #             return

    #         threat_type = None
    #         confidence = s1_confidence
    #         stage2_label = "Unknown"
    #         stage2_confidence = 0.0

    #         if self._attack_model is not None:
    #             try:
    #                 atk_pred = self._attack_model.predict(X)[0]
    #                 s2_confidence = 0.0
    #                 if hasattr(self._attack_model, "predict_proba"):
    #                     s2_confidence = float(max(self._attack_model.predict_proba(X)[0]))

    #                 label = str(atk_pred)
    #                 if self._attack_label_encoder and hasattr(self._attack_label_encoder, "classes_"):
    #                     if isinstance(atk_pred, (int, np.integer)):
    #                         label = self._attack_label_encoder.classes_[int(atk_pred)]
    #                 elif hasattr(self._attack_model, "classes_"):
    #                     if isinstance(atk_pred, (int, np.integer)):
    #                         label = str(self._attack_model.classes_[int(atk_pred)])

    #                 stage2_label = str(label)
    #                 stage2_confidence = s2_confidence
    #                 s2_min_conf = thresholds["stage2"]
    #                 if s2_confidence >= s2_min_conf:
    #                     mapped = _map_attack_label(str(label))

    #                     # Sanity filter for false positives
    #                     if mapped == ThreatType.PORT_SCAN:
    #                         # DNS / HTTPS should not be port scans
    #                         if flow_rec.dst_port in [53, 443]:
    #                             mapped = None

    #                         # Real scans need more packets
    #                         elif total_pkts < 12:
    #                             mapped = None
                                            
    #                     if mapped is not None:
    #                         threat_type = mapped
    #                         confidence = s2_confidence
    #             except Exception:
    #                 pass

                                                                          
    #         if threat_type is None:                                                                                                           
    #             if (
    #                 not self._test_mode
    #                 and is_malicious
    #                 and s1_confidence >= 0.75
    #                 and flow_rec.protocol == 6
    #             ):
    #                 scan_assist = self._detect_signature_threat(
    #                     flow_rec=flow_rec,
    #                     total_pkts=total_pkts,
    #                     total_bytes=total_bytes,
    #                     flow_duration=flow_duration,
    #                 )
    #                 if scan_assist == ThreatType.PORT_SCAN:
    #                     threat_type = ThreatType.PORT_SCAN
    #                     confidence = max(confidence, 0.92)

                                                                                        
                                                                               
    #             if not self._test_mode and threat_type is None:
    #                 pass
    #                 # Keep ML detection alive even when stage-2 class names
    #                 # do not map exactly to local ThreatType labels.
    #                 # if is_malicious and s1_confidence >= max(0.80, s1_min_conf):
    #                 #     threat_type = ThreatType.MALWARE_COMM
    #                 #     confidence = max(confidence, s1_confidence)
    #                 # else:
    #                 #     return
    #             if threat_type is None:
    #                 threat_type = self._infer_fallback_threat(flow_rec, total_pkts, flow_duration)
    #                 if threat_type is None:
    #                     return
    #                 confidence = max(confidence, 0.80)

    #         should_block = False
    #         block_reason = ""
    #         pps = total_pkts / max(flow_duration, 1e-3)
    #         syn_ratio = flow_rec.syn_count / max(total_pkts, 1)
    #         block_min_conf = thresholds["block"]
    #         detection_reason = (
    #             f"Stage1={s1_confidence:.0%} (pred={pred}), "
    #             f"Stage2={stage2_label} ({stage2_confidence:.0%}), "
    #             f"Profile={self._sensitivity_profile}, "
    #             f"flow={total_pkts} pkts/{total_bytes} bytes/{pps:.1f} pps, "
    #             f"SYN ratio={syn_ratio:.0%}"
    #         )

    #         if self._prevention_enabled and confidence >= block_min_conf:
    #             blocked, reason = self._ensure_firewall_block(flow_rec.src_ip, threat_type)
    #             should_block = blocked
    #             block_reason = (
    #                 f"ML Flow Analysis: {threat_type.display_name} from {flow_rec.src_ip} "
    #                 f"[{total_pkts} pkts, Confidence: {confidence:.0%}] | {detection_reason} | {reason}"
    #             )
    #             if not blocked:
    #                 key = f"{flow_rec.src_ip}:{reason}"
    #                 if key not in self._reported_block_failures:
    #                     self._reported_block_failures.add(key)
    #                     self.capture_error.emit(
    #                         f"Prevention rule failed for {flow_rec.src_ip}: {reason}"
    #                     )
    #         elif self._prevention_enabled:
    #             block_reason = (
    #                 f"Detection-only: {threat_type.display_name} from {flow_rec.src_ip} "
    #                 f"[{total_pkts} pkts, Confidence: {confidence:.0%}] | {detection_reason}"
    #             )

    #         proto = {6: Protocol.TCP, 17: Protocol.UDP}.get(flow_rec.protocol, Protocol.TCP)
    #         proto = PORT_PROTOCOL_MAP.get(flow_rec.dst_port, proto)

    #         model_used_label = self.model_name
    #         if not self._test_mode and threat_type == ThreatType.PORT_SCAN and stage2_label == "Unknown":
    #             model_used_label = f"{self.model_name} + ScanEvidence"

    #         alert_packet = Packet(
    #             timestamp=datetime.now(),
    #             src_ip=flow_rec.src_ip,
    #             dst_ip=flow_rec.dst_ip,
    #             src_port=flow_rec.src_port,
    #             dst_port=flow_rec.dst_port,
    #             protocol=proto,
    #             length=total_bytes,
    #             ttl=0,
    #             flags="",
    #             payload_preview=(
    #                 f"FLOW ALERT: {threat_type.display_name} | "
    #                     f"{flow_rec.fwd_packets}↑ {flow_rec.bwd_packets}↓ pkts | "
    #                     f"S1 {s1_confidence:.0%} | S2 {stage2_label} {stage2_confidence:.0%} | "
    #                     f"conf: {confidence:.0%}"
    #             ),
    #             is_malicious=True,
    #             threat_type=threat_type,
    #             confidence=confidence,
    #             model_used=model_used_label,
    #             is_blocked=should_block,
    #             block_reason=block_reason,
    #         )
    #         self.packet_captured.emit(alert_packet)
    #     except Exception:
    #         pass
