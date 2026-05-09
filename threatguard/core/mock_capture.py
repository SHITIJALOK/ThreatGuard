

from __future__ import annotations

import os
import pickle
import random
import re
import time
from datetime import datetime
from typing import Optional

import numpy as np
from PySide6.QtCore import QThread, Signal

from threatguard.core.packet import Packet, Protocol, ThreatType

                                                              
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.100",
    "192.168.1.105", "192.168.1.200", "10.0.0.5", "10.0.0.15",
    "10.0.0.42", "10.0.1.8", "172.16.0.10", "172.16.0.50",
]

EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "104.16.132.229", "151.101.1.140",
    "13.107.42.14", "52.96.166.130", "172.217.14.206", "31.13.71.36",
    "199.232.69.194", "140.82.121.4", "93.184.216.34", "23.215.0.136",
]

COMMON_PORTS = [80, 443, 8080, 22, 21, 25, 53, 3306, 5432, 8443, 3389]

                                               
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
    "bruteforce-xml": ThreatType.BRUTE_FORCE,
    "probing": ThreatType.PORT_SCAN,
    "probe": ThreatType.PORT_SCAN,
    "xmrigcc cryptominer": ThreatType.MALWARE_COMM,
    "xmrigcc": ThreatType.MALWARE_COMM,
    "xmrig": ThreatType.MALWARE_COMM,
}

                            
MODEL_SEARCH_DIRS = [
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "models final"),
]

def _normalize_label(label: str) -> str:
    normalized = label.strip().lower().replace("\u2013", "-").replace("\u2014", "-")
    normalized = normalized.replace("-", "_").replace(" ", "_")
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized

ATTACK_LABEL_MAP = {
    _normalize_label(label): threat for label, threat in _ATTACK_LABEL_MAP_RAW.items()
}

def _map_attack_label(label: str) -> ThreatType:
    
    normalized = _normalize_label(label)
    return ATTACK_LABEL_MAP.get(normalized, ThreatType.MALWARE_COMM)

def _extract_model_from_blob(blob):
    
    if isinstance(blob, dict) and "model" in blob:
        return blob["model"]
    return blob

class MockCaptureThread(QThread):
    

    packet_captured = Signal(object)

    def __init__(
        self,
        min_delay: float = 0.06,
        max_delay: float = 0.25,
        model_name: str = "Random Forest",
        binary_model_path: str | None = None,
        attack_model_path: str | None = None,
        scaler_path: str | None = None,
        label_encoder_path: str | None = None,
        feature_names_path: str | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.model_name = model_name
        self._running = False
        self._prevention_enabled = True

                   
        self._binary_model = None
        self._attack_model = None
        self._scaler = None
        self._attack_label_encoder = None
        self._feature_names: list[str] = []

                     
        self._binary_model_path = binary_model_path
        self._attack_model_path = attack_model_path
        self._scaler_path = scaler_path
        self._label_encoder_path = label_encoder_path
        self._feature_names_path = feature_names_path
        self._load_models()

    def _load_models(self):
        
                                                                 
        bin_path = self._binary_model_path
        atk_path = self._attack_model_path

        if not bin_path:
            for model_dir in MODEL_SEARCH_DIRS:
                for name in ("stage1_nids_model.pkl",):
                    candidate = os.path.join(model_dir, name)
                    if os.path.isfile(candidate):
                        bin_path = candidate
                        break
                if bin_path:
                    break

        if not atk_path:
            for model_dir in MODEL_SEARCH_DIRS:
                for name in ("stage2_nids_model.pkl",):
                    candidate = os.path.join(model_dir, name)
                    if os.path.isfile(candidate):
                        atk_path = candidate
                        break
                if atk_path:
                    break

        scaler_path = self._scaler_path
        label_enc_path = self._label_encoder_path
        feat_path = self._feature_names_path

        for model_dir in MODEL_SEARCH_DIRS:
            if not scaler_path:
                candidate = os.path.join(model_dir, "scaler.pkl")
                if os.path.isfile(candidate):
                    scaler_path = candidate
            if not label_enc_path:
                candidate = os.path.join(model_dir, "label_encoder.pkl")
                if os.path.isfile(candidate):
                    label_enc_path = candidate
            if not feat_path:
                candidate = os.path.join(model_dir, "feature_names.pkl")
                if os.path.isfile(candidate):
                    feat_path = candidate

        if bin_path and os.path.isfile(bin_path):
            try:
                with open(bin_path, "rb") as f:
                    binary_blob = pickle.load(f)
                if isinstance(binary_blob, dict):
                    self._binary_model = _extract_model_from_blob(binary_blob)
                    if not self._feature_names:
                        features = binary_blob.get("feature_names")
                        if isinstance(features, list):
                            self._feature_names = features
                else:
                    self._binary_model = binary_blob
            except Exception:
                pass

        if atk_path and os.path.isfile(atk_path):
            try:
                with open(atk_path, "rb") as f:
                    attack_blob = pickle.load(f)
                if isinstance(attack_blob, dict):
                    self._attack_model = _extract_model_from_blob(attack_blob)
                    if self._attack_label_encoder is None:
                        self._attack_label_encoder = attack_blob.get("label_encoder")
                else:
                    self._attack_model = attack_blob
            except Exception:
                pass

        if scaler_path and os.path.isfile(scaler_path):
            try:
                with open(scaler_path, "rb") as f:
                    self._scaler = pickle.load(f)
            except Exception:
                pass

        if label_enc_path and os.path.isfile(label_enc_path):
            try:
                with open(label_enc_path, "rb") as f:
                    self._attack_label_encoder = pickle.load(f)
            except Exception:
                pass

        if feat_path and os.path.isfile(feat_path):
            try:
                with open(feat_path, "rb") as f:
                    self._feature_names = pickle.load(f)
            except Exception:
                pass

    def set_model(self, model_name: str):
        self.model_name = model_name

    def set_prevention(self, enabled: bool):
        self._prevention_enabled = enabled

    def stop(self):
        self._running = False

    def run(self):
        self._running = True
        while self._running:
            try:
                packet = self._generate_and_classify()
                self.packet_captured.emit(packet)
                delay = random.uniform(self.min_delay, self.max_delay)
                time.sleep(delay)
            except Exception:
                continue

    def _generate_feature_vector(self) -> np.ndarray:
        
        n_features = len(self._feature_names) if self._feature_names else 78

        features = np.zeros(n_features)

                                                
        dst_port = random.choice(COMMON_PORTS)
        flow_duration = random.uniform(1000, 30000000)                
        fwd_pkts = random.randint(1, 30)
        bwd_pkts = random.randint(1, 25)
        pkt_length = random.randint(40, 1500)
        total_fwd_len = fwd_pkts * pkt_length
        total_bwd_len = bwd_pkts * pkt_length

        feature_map = {
            "Destination Port": dst_port,
            "Flow Duration": flow_duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": total_fwd_len,
            "Total Length of Bwd Packets": total_bwd_len,
            "Fwd Packet Length Max": random.randint(200, 1460),
            "Fwd Packet Length Min": random.randint(0, 100),
            "Fwd Packet Length Mean": float(pkt_length),
            "Fwd Packet Length Std": random.uniform(0, 400),
            "Bwd Packet Length Max": random.randint(200, 1460),
            "Bwd Packet Length Min": random.randint(0, 100),
            "Bwd Packet Length Mean": float(pkt_length),
            "Bwd Packet Length Std": random.uniform(0, 500),
            "Flow Bytes/s": (total_fwd_len + total_bwd_len) / max(flow_duration / 1e6, 0.001),
            "Flow Packets/s": (fwd_pkts + bwd_pkts) / max(flow_duration / 1e6, 0.001),
            "Flow IAT Mean": flow_duration / max(fwd_pkts + bwd_pkts - 1, 1),
            "Flow IAT Std": random.uniform(0, flow_duration * 0.3),
            "Flow IAT Max": random.uniform(flow_duration * 0.1, flow_duration),
            "Flow IAT Min": random.uniform(0, flow_duration * 0.05),
            "Fwd IAT Total": flow_duration * 0.5,
            "Fwd IAT Mean": flow_duration * 0.5 / max(fwd_pkts - 1, 1),
            "Fwd IAT Std": random.uniform(0, flow_duration * 0.2),
            "Fwd IAT Max": random.uniform(0, flow_duration * 0.5),
            "Fwd IAT Min": random.uniform(0, flow_duration * 0.05),
            "Bwd IAT Total": flow_duration * 0.5,
            "Bwd IAT Mean": flow_duration * 0.5 / max(bwd_pkts - 1, 1),
            "Bwd IAT Std": random.uniform(0, flow_duration * 0.2),
            "Bwd IAT Max": random.uniform(0, flow_duration * 0.5),
            "Bwd IAT Min": random.uniform(0, flow_duration * 0.05),
            "Fwd PSH Flags": random.randint(0, fwd_pkts),
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "Fwd Header Length": fwd_pkts * random.randint(20, 44),
            "Bwd Header Length": bwd_pkts * random.randint(20, 44),
            "Fwd Packets/s": fwd_pkts / max(flow_duration / 1e6, 0.001),
            "Bwd Packets/s": bwd_pkts / max(flow_duration / 1e6, 0.001),
            "Min Packet Length": random.randint(0, 60),
            "Max Packet Length": random.randint(200, 1460),
            "Packet Length Mean": float(pkt_length),
            "Packet Length Std": random.uniform(0, 500),
            "Packet Length Variance": random.uniform(0, 250000),
            "FIN Flag Count": random.choice([0, 1, 2]),
            "SYN Flag Count": random.choice([0, 1, 2]),
            "RST Flag Count": 0,
            "PSH Flag Count": random.randint(0, fwd_pkts),
            "ACK Flag Count": max(0, fwd_pkts + bwd_pkts - 2),
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": bwd_pkts / max(fwd_pkts, 1),
            "Average Packet Size": float(pkt_length),
            "Avg Fwd Segment Size": float(pkt_length),
            "Avg Bwd Segment Size": float(pkt_length),
            "Fwd Header Length.1": fwd_pkts * random.randint(20, 44),
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": fwd_pkts,
            "Subflow Fwd Bytes": total_fwd_len,
            "Subflow Bwd Packets": bwd_pkts,
            "Subflow Bwd Bytes": total_bwd_len,
            "Init_Win_bytes_forward": random.choice([8192, 16384, 29200, 65535]),
            "Init_Win_bytes_backward": random.choice([8192, 16384, 29200, 65160, 65535]),
            "act_data_pkt_fwd": max(1, fwd_pkts - 2),
            "min_seg_size_forward": 20,
            "Active Mean": random.uniform(0, flow_duration * 0.5),
            "Active Std": random.uniform(0, flow_duration * 0.1),
            "Active Max": random.uniform(0, flow_duration * 0.5),
            "Active Min": random.uniform(0, flow_duration * 0.3),
            "Idle Mean": 0,
            "Idle Std": 0,
            "Idle Max": 0,
            "Idle Min": 0,
        }

                                             
        for i, name in enumerate(self._feature_names):
            if name in feature_map:
                features[i] = feature_map[name]

        return features

    def _classify(self, features: np.ndarray) -> tuple[bool, ThreatType, float]:
        
        if self._binary_model is None:
            return False, ThreatType.NORMAL, 0.0

        X = features.reshape(1, -1)
        if self._scaler is not None:
            X = self._scaler.transform(X)

                                        
        try:
            pred = self._binary_model.predict(X)[0]
            if hasattr(self._binary_model, "predict_proba"):
                probas = self._binary_model.predict_proba(X)[0]
                confidence = float(max(probas))
            else:
                confidence = 0.85

            is_malicious = int(pred) == 1
        except Exception:
            return False, ThreatType.NORMAL, 0.0

        if not is_malicious:
            return False, ThreatType.NORMAL, confidence

                              
        threat_type = ThreatType.MALWARE_COMM
        if self._attack_model is not None:
            try:
                atk_pred = self._attack_model.predict(X)[0]
                if hasattr(self._attack_model, "predict_proba"):
                    atk_probas = self._attack_model.predict_proba(X)[0]
                    confidence = float(max(atk_probas))

                if self._attack_label_encoder and hasattr(self._attack_label_encoder, "classes_"):
                    if isinstance(atk_pred, (int, np.integer)):
                        label = self._attack_label_encoder.classes_[int(atk_pred)]
                    else:
                        label = str(atk_pred)
                else:
                    label = str(atk_pred)

                threat_type = _map_attack_label(label)
            except Exception:
                pass

        return True, threat_type, confidence

    def _generate_and_classify(self) -> Packet:
        
        protocol = random.choice([
            Protocol.TCP, Protocol.UDP, Protocol.HTTP,
            Protocol.HTTPS, Protocol.DNS, Protocol.SSH,
        ])
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        if random.random() < 0.3:
            src_ip, dst_ip = dst_ip, src_ip

        src_port = random.randint(1024, 65535)
        dst_port = random.choice(COMMON_PORTS)
        length = random.randint(40, 1500)

        flags_map = {
            Protocol.TCP: random.choice(["SYN", "ACK", "SYN-ACK", "PSH-ACK", "FIN-ACK"]),
            Protocol.HTTP: "PSH-ACK",
            Protocol.HTTPS: "PSH-ACK",
        }
        payloads = {
            Protocol.HTTP: f"GET /page/{random.randint(1, 100)} HTTP/1.1",
            Protocol.HTTPS: f"TLS 1.3 Application Data [{length} bytes]",
            Protocol.DNS: f"DNS Standard query A www.example{random.randint(1, 50)}.com",
            Protocol.SSH: "SSH-2.0-OpenSSH_8.9 KEX_INIT",
            Protocol.TCP: f"TCP {src_port} > {dst_port} [ACK] Len={length}",
            Protocol.UDP: f"UDP {src_port} > {dst_port} Len={length}",
        }

                                 
        features = self._generate_feature_vector()
        is_malicious, threat_type, confidence = self._classify(features)

                    
        should_block = (
            is_malicious
            and self._prevention_enabled
            and confidence > 0.50
        )
        block_reason = ""
        if should_block:
            block_reason = (
                f"ML Model ({self.model_name}): {threat_type.display_name} "
                f"detected [Confidence: {confidence:.0%}]"
            )

        info_text = f"{protocol.value} {src_port} > {dst_port}"
        if is_malicious:
            info_text = f"{threat_type.display_name} (conf: {confidence:.0%})"

        return Packet(
            timestamp=datetime.now(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            ttl=random.choice([64, 128, 255]),
            flags=flags_map.get(protocol, ""),
            payload_preview=payloads.get(protocol, f"{protocol.value} data"),
            is_malicious=is_malicious,
            threat_type=threat_type,
            confidence=confidence,
            model_used=self.model_name,
            is_blocked=should_block,
            block_reason=block_reason,
        )
