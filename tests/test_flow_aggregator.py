import numpy as np
from scapy.layers.inet import IP, TCP

from threatguard.core.flow_aggregator import FlowAggregator, FlowRecord, compute_features


def test_flow_key_is_direction_agnostic():
    agg = FlowAggregator(feature_names=["Flow Duration"])
    key1 = agg._flow_key("10.0.0.1", "10.0.0.2", 1111, 80, 6)
    key2 = agg._flow_key("10.0.0.2", "10.0.0.1", 80, 1111, 6)
    assert key1 == key2


def test_compute_features_returns_expected_shape():
    names = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "SYN Flag Count"]
    flow = FlowRecord(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol=6,
        start_time=1.0,
        last_time=2.0,
        fwd_packets=1,
        bwd_packets=1,
        fwd_lengths=[60],
        bwd_lengths=[52],
        all_times=[1.0, 2.0],
        syn_count=1,
    )
    features = compute_features(flow, names)
    assert isinstance(features, np.ndarray)
    assert features.shape == (len(names),)
    assert np.isfinite(features).all()


def test_add_packet_and_expire_flow():
    names = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]
    agg = FlowAggregator(feature_names=names, timeout=-1.0)
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
    result = agg.add_packet(pkt)
    assert result is None
    expired = agg.get_expired_flows()
    assert len(expired) == 1
    key, features, flow = expired[0]
    assert isinstance(key, str)
    assert features.shape == (len(names),)
    assert flow.src_ip == "10.0.0.1"
