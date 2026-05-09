from threatguard.core.packet import Packet, ThreatType, Protocol


def test_packet_status_text_priority():
    packet = Packet(is_malicious=True, is_blocked=True)
    assert packet.status_text == "BLOCKED"


def test_packet_info_text_for_clean_packet():
    packet = Packet(protocol=Protocol.TCP, src_port=1234, dst_port=80, is_malicious=False)
    assert "TCP" in packet.info_text
    assert "1234" in packet.info_text
    assert "80" in packet.info_text


def test_packet_info_text_for_threat_packet():
    packet = Packet(is_malicious=True, threat_type=ThreatType.PORT_SCAN, confidence=0.9)
    assert "Port Scan" in packet.info_text
    assert "90%" in packet.info_text


def test_packet_to_dict_contains_expected_fields():
    packet = Packet(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        is_malicious=True,
        threat_type=ThreatType.DDOS_ATTACK,
        confidence=0.87,
        is_blocked=True,
        block_reason="rule-added",
    )
    data = packet.to_dict()
    assert data["src_ip"] == "10.0.0.1"
    assert data["threat_type"] == "DDOS_ATTACK"
    assert data["is_blocked"] is True
    assert data["block_reason"] == "rule-added"
