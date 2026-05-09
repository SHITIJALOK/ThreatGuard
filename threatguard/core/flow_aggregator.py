

from __future__ import annotations

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

                                                               
FLOW_TIMEOUT = 10.0                                                                    
                                                   
MAX_FLOW_PACKETS = 200
                                                      
MIN_FLOW_PACKETS = 10                                                 

@dataclass
class FlowRecord:
    
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 6               

    start_time: float = 0.0
    last_time: float = 0.0

                                           
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_lengths: list = field(default_factory=list)
    bwd_lengths: list = field(default_factory=list)
    fwd_times: list = field(default_factory=list)
    bwd_times: list = field(default_factory=list)
    all_times: list = field(default_factory=list)

                  
    fwd_header_sizes: list = field(default_factory=list)
    bwd_header_sizes: list = field(default_factory=list)

           
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    fwd_psh_count: int = 0
    bwd_psh_count: int = 0
    fwd_urg_count: int = 0
    bwd_urg_count: int = 0

                  
    init_win_fwd: int = 0
    init_win_bwd: int = 0
    init_win_fwd_set: bool = False
    init_win_bwd_set: bool = False

                          
    active_times: list = field(default_factory=list)
    idle_times: list = field(default_factory=list)
    _last_active: float = 0.0
    _active_start: float = 0.0

                  
    act_data_pkt_fwd: int = 0
    min_seg_size_fwd: int = 20

def _safe_stats(arr: list) -> tuple:
    
    if not arr:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    a = np.array(arr, dtype=float)
    return float(np.mean(a)), float(np.std(a)), float(np.max(a)), float(np.min(a)), float(np.sum(a))

def compute_features(flow: FlowRecord, feature_names: list[str]) -> np.ndarray:
    
    n = len(feature_names)
    features = np.zeros(n)
    idx = {name: i for i, name in enumerate(feature_names)}

    duration_us = (flow.last_time - flow.start_time) * 1e6                
    duration_s = max(flow.last_time - flow.start_time, 1e-6)
    total_fwd_len = sum(flow.fwd_lengths) if flow.fwd_lengths else 0
    total_bwd_len = sum(flow.bwd_lengths) if flow.bwd_lengths else 0
    total_pkts = flow.fwd_packets + flow.bwd_packets

                         
    fwd_mean, fwd_std, fwd_max, fwd_min, _ = _safe_stats(flow.fwd_lengths)
    bwd_mean, bwd_std, bwd_max, bwd_min, _ = _safe_stats(flow.bwd_lengths)
    all_lengths = flow.fwd_lengths + flow.bwd_lengths
    all_mean, all_std, all_max, all_min, _ = _safe_stats(all_lengths)

                                                              
    def iat_from_times(times):
        if len(times) < 2:
            return []
        sorted_t = sorted(times)
        return [(sorted_t[i+1] - sorted_t[i]) * 1e6 for i in range(len(sorted_t)-1)]

    flow_iats = iat_from_times(flow.all_times)
    fwd_iats = iat_from_times(flow.fwd_times)
    bwd_iats = iat_from_times(flow.bwd_times)

    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min, flow_iat_total = _safe_stats(flow_iats)
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min, fwd_iat_total = _safe_stats(fwd_iats)
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, bwd_iat_total = _safe_stats(bwd_iats)

                       
    act_mean, act_std, act_max, act_min, _ = _safe_stats(flow.active_times)
    idle_mean, idle_std, idle_max, idle_min, _ = _safe_stats(flow.idle_times)

                                                                        
    fwd_h_mean, fwd_h_std, fwd_h_max, fwd_h_min, fwd_h_total = _safe_stats(flow.fwd_header_sizes)
    bwd_h_mean, bwd_h_std, bwd_h_max, bwd_h_min, bwd_h_total = _safe_stats(flow.bwd_header_sizes)
    fwd_l_mean, fwd_l_std, fwd_l_max, fwd_l_min, fwd_l_total = _safe_stats(flow.fwd_lengths)
    bwd_l_mean, bwd_l_std, bwd_l_max, bwd_l_min, bwd_l_total = _safe_stats(flow.bwd_lengths)

    active_total = float(np.sum(flow.active_times)) if flow.active_times else 0.0
    idle_total = float(np.sum(flow.idle_times)) if flow.idle_times else 0.0

                       
    fmap = {
                           
        "Destination Port": flow.dst_port,
        "Flow Duration": duration_us,
        "Total Fwd Packets": flow.fwd_packets,
        "Total Backward Packets": flow.bwd_packets,
        "Total Length of Fwd Packets": total_fwd_len,
        "Total Length of Bwd Packets": total_bwd_len,
        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": fwd_mean,
        "Fwd Packet Length Std": fwd_std,
        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": bwd_std,
        "Flow Bytes/s": (total_fwd_len + total_bwd_len) / duration_s,
        "Flow Packets/s": total_pkts / duration_s,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": flow.fwd_psh_count,
        "Bwd PSH Flags": flow.bwd_psh_count,
        "Fwd URG Flags": flow.fwd_urg_count,
        "Bwd URG Flags": flow.bwd_urg_count,
        "Fwd Header Length": sum(flow.fwd_header_sizes) if flow.fwd_header_sizes else 0,
        "Bwd Header Length": sum(flow.bwd_header_sizes) if flow.bwd_header_sizes else 0,
        "Fwd Packets/s": flow.fwd_packets / duration_s,
        "Bwd Packets/s": flow.bwd_packets / duration_s,
        "Min Packet Length": all_min if all_lengths else 0,
        "Max Packet Length": all_max if all_lengths else 0,
        "Packet Length Mean": all_mean,
        "Packet Length Std": all_std,
        "Packet Length Variance": all_std ** 2,
        "FIN Flag Count": flow.fin_count,
        "SYN Flag Count": flow.syn_count,
        "RST Flag Count": flow.rst_count,
        "PSH Flag Count": flow.psh_count,
        "ACK Flag Count": flow.ack_count,
        "URG Flag Count": flow.urg_count,
        "CWE Flag Count": flow.cwe_count,
        "ECE Flag Count": flow.ece_count,
        "Down/Up Ratio": flow.bwd_packets / max(flow.fwd_packets, 1),
        "Average Packet Size": (total_fwd_len + total_bwd_len) / max(total_pkts, 1),
        "Avg Fwd Segment Size": fwd_mean,
        "Avg Bwd Segment Size": bwd_mean,
        "Fwd Header Length.1": sum(flow.fwd_header_sizes) if flow.fwd_header_sizes else 0,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": flow.fwd_packets,
        "Subflow Fwd Bytes": total_fwd_len,
        "Subflow Bwd Packets": flow.bwd_packets,
        "Subflow Bwd Bytes": total_bwd_len,
        "Init_Win_bytes_forward": flow.init_win_fwd,
        "Init_Win_bytes_backward": flow.init_win_bwd,
        "act_data_pkt_fwd": flow.act_data_pkt_fwd,
        "min_seg_size_forward": flow.min_seg_size_fwd,
        "Active Mean": act_mean,
        "Active Std": act_std,
        "Active Max": act_max,
        "Active Min": act_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min,

                            
        "originp": flow.src_port,
        "responp": flow.dst_port,
        "flow_duration": duration_s,
        "fwd_pkts_tot": flow.fwd_packets,
        "bwd_pkts_tot": flow.bwd_packets,
        "fwd_data_pkts_tot": flow.act_data_pkt_fwd,
        "bwd_data_pkts_tot": flow.bwd_packets,
        "fwd_pkts_per_sec": flow.fwd_packets / duration_s,
        "bwd_pkts_per_sec": flow.bwd_packets / duration_s,
        "flow_pkts_per_sec": total_pkts / duration_s,
        "down_up_ratio": flow.bwd_packets / max(flow.fwd_packets, 1),
        "fwd_header_size_tot": fwd_h_total,
        "fwd_header_size_min": fwd_h_min,
        "fwd_header_size_max": fwd_h_max,
        "bwd_header_size_tot": bwd_h_total,
        "bwd_header_size_min": bwd_h_min,
        "bwd_header_size_max": bwd_h_max,
        "flow_FIN_flag_count": flow.fin_count,
        "flow_SYN_flag_count": flow.syn_count,
        "flow_RST_flag_count": flow.rst_count,
        "fwd_PSH_flag_count": flow.fwd_psh_count,
        "bwd_PSH_flag_count": flow.bwd_psh_count,
        "flow_ACK_flag_count": flow.ack_count,
        "fwd_URG_flag_count": flow.fwd_urg_count,
        "bwd_URG_flag_count": flow.bwd_urg_count,
        "flow_CWR_flag_count": flow.cwe_count,
        "flow_ECE_flag_count": flow.ece_count,
        "fwd_pkts_payload.min": fwd_l_min,
        "fwd_pkts_payload.max": fwd_l_max,
        "fwd_pkts_payload.tot": fwd_l_total,
        "fwd_pkts_payload.avg": fwd_l_mean,
        "fwd_pkts_payload.std": fwd_l_std,
        "bwd_pkts_payload.min": bwd_l_min,
        "bwd_pkts_payload.max": bwd_l_max,
        "bwd_pkts_payload.tot": bwd_l_total,
        "bwd_pkts_payload.avg": bwd_l_mean,
        "bwd_pkts_payload.std": bwd_l_std,
        "flow_pkts_payload.min": all_min if all_lengths else 0.0,
        "flow_pkts_payload.max": all_max if all_lengths else 0.0,
        "flow_pkts_payload.tot": total_fwd_len + total_bwd_len,
        "flow_pkts_payload.avg": all_mean,
        "flow_pkts_payload.std": all_std,
        "fwd_iat.min": fwd_iat_min,
        "fwd_iat.max": fwd_iat_max,
        "fwd_iat.tot": fwd_iat_total,
        "fwd_iat.avg": fwd_iat_mean,
        "fwd_iat.std": fwd_iat_std,
        "bwd_iat.min": bwd_iat_min,
        "bwd_iat.max": bwd_iat_max,
        "bwd_iat.tot": bwd_iat_total,
        "bwd_iat.avg": bwd_iat_mean,
        "bwd_iat.std": bwd_iat_std,
        "flow_iat.min": flow_iat_min,
        "flow_iat.max": flow_iat_max,
        "flow_iat.tot": flow_iat_total,
        "flow_iat.avg": flow_iat_mean,
        "flow_iat.std": flow_iat_std,
        "payload_bytes_per_second": (total_fwd_len + total_bwd_len) / duration_s,
        "fwd_subflow_pkts": flow.fwd_packets,
        "bwd_subflow_pkts": flow.bwd_packets,
        "fwd_subflow_bytes": total_fwd_len,
        "bwd_subflow_bytes": total_bwd_len,
        "fwd_bulk_bytes": 0.0,
        "bwd_bulk_bytes": 0.0,
        "fwd_bulk_packets": 0.0,
        "bwd_bulk_packets": 0.0,
        "fwd_bulk_rate": 0.0,
        "bwd_bulk_rate": 0.0,
        "active.min": act_min,
        "active.max": act_max,
        "active.tot": active_total,
        "active.avg": act_mean,
        "active.std": act_std,
        "idle.min": idle_min,
        "idle.max": idle_max,
        "idle.tot": idle_total,
        "idle.avg": idle_mean,
        "idle.std": idle_std,
        "fwd_init_window_size": flow.init_win_fwd,
        "bwd_init_window_size": flow.init_win_bwd,
        "fwd_last_window_size": flow.init_win_fwd,
    }

    for name, val in fmap.items():
        if name in idx:
            features[idx[name]] = float(val) if np.isfinite(val) else 0.0

                     
    features = np.nan_to_num(features, nan=0.0, posinf=0.0, neginf=0.0)
    return features

class FlowAggregator:
    

    def __init__(self, feature_names: list[str], timeout: float = FLOW_TIMEOUT):
        self._flows: dict[str, FlowRecord] = {}
        self._feature_names = feature_names
        self._timeout = timeout
        self._lock = threading.Lock()

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, proto) -> str:
        
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{proto}"

    def add_packet(self, scapy_pkt) -> Optional[tuple]:
        
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6

            now = time.time()

                                
            if scapy_pkt.haslayer(IP):
                ip = scapy_pkt[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                proto = ip.proto
            elif scapy_pkt.haslayer(IPv6):
                ip = scapy_pkt[IPv6]
                src_ip = ip.src
                dst_ip = ip.dst
                proto = ip.nh
            else:
                return None

            src_port = 0
            dst_port = 0
            tcp_flags = 0
            header_len = 20
            window_size = 0
            payload_len = 0

            if scapy_pkt.haslayer(TCP):
                tcp = scapy_pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = int(tcp.flags)
                header_len = tcp.dataofs * 4 if tcp.dataofs else 20
                window_size = tcp.window
                payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
            elif scapy_pkt.haslayer(UDP):
                udp = scapy_pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                header_len = 8
                payload_len = len(bytes(udp.payload)) if udp.payload else 0

            key = self._flow_key(src_ip, dst_ip, src_port, dst_port, proto)
            pkt_len = len(scapy_pkt)

            with self._lock:
                if key not in self._flows:
                    self._flows[key] = FlowRecord(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=src_port, dst_port=dst_port,
                        protocol=proto,
                        start_time=now, last_time=now,
                        _last_active=now, _active_start=now,
                    )

                flow = self._flows[key]
                flow.last_time = now

                                     
                is_forward = (src_ip == flow.src_ip and src_port == flow.src_port)

                if is_forward:
                    flow.fwd_packets += 1
                    flow.fwd_lengths.append(pkt_len)
                    flow.fwd_times.append(now)
                    flow.fwd_header_sizes.append(header_len)
                    if payload_len > 0:
                        flow.act_data_pkt_fwd += 1
                else:
                    flow.bwd_packets += 1
                    flow.bwd_lengths.append(pkt_len)
                    flow.bwd_times.append(now)
                    flow.bwd_header_sizes.append(header_len)

                flow.all_times.append(now)

                             
                if tcp_flags:
                    if tcp_flags & 0x01: flow.fin_count += 1
                    if tcp_flags & 0x02: flow.syn_count += 1
                    if tcp_flags & 0x04: flow.rst_count += 1
                    if tcp_flags & 0x08:
                        flow.psh_count += 1
                        if is_forward:
                            flow.fwd_psh_count += 1
                        else:
                            flow.bwd_psh_count += 1
                    if tcp_flags & 0x10: flow.ack_count += 1
                    if tcp_flags & 0x20:
                        flow.urg_count += 1
                        if is_forward:
                            flow.fwd_urg_count += 1
                        else:
                            flow.bwd_urg_count += 1
                    if tcp_flags & 0x40: flow.ece_count += 1
                    if tcp_flags & 0x80: flow.cwe_count += 1

                                     
                if is_forward and not flow.init_win_fwd_set:
                    flow.init_win_fwd = window_size
                    flow.init_win_fwd_set = True
                elif not is_forward and not flow.init_win_bwd_set:
                    flow.init_win_bwd = window_size
                    flow.init_win_bwd_set = True

                                      
                gap = now - flow._last_active
                if gap > 1.0:                  
                    flow.idle_times.append(gap * 1e6)
                    if flow._active_start < flow._last_active:
                        flow.active_times.append(
                            (flow._last_active - flow._active_start) * 1e6
                        )
                    flow._active_start = now
                flow._last_active = now

                                                    
                total = flow.fwd_packets + flow.bwd_packets
                if total >= MAX_FLOW_PACKETS:
                    fv = compute_features(flow, self._feature_names)
                    result = (key, fv, flow)
                    del self._flows[key]
                    return result

            return None

        except Exception:
            return None

    def get_expired_flows(self) -> list[tuple]:
        
        now = time.time()
        expired = []

        with self._lock:
            expired_keys = [
                k for k, f in self._flows.items()
                if (now - f.last_time) > self._timeout
                and (f.fwd_packets + f.bwd_packets) >= MIN_FLOW_PACKETS
            ]
            for key in expired_keys:
                flow = self._flows.pop(key)
                                      
                if flow._active_start < flow._last_active:
                    flow.active_times.append(
                        (flow._last_active - flow._active_start) * 1e6
                    )
                fv = compute_features(flow, self._feature_names)
                expired.append((key, fv, flow))

        return expired

    def clear(self):
        with self._lock:
            self._flows.clear()
