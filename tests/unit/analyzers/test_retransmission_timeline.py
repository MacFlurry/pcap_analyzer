"""
Unit tests for packet timeline logic in RetransmissionAnalyzer.
Specifically targets bugs with SYN retransmissions and stream isolation.
"""

import pytest
import os
import re
from scapy.all import rdpcap
from src.analyzers.retransmission import RetransmissionAnalyzer

def test_syn_retrans_correct_packet_timeline():
    """
    Test that SYN retransmission timeline shows correct frames from correct TCP stream.

    Regression test for bug where frames from wrong TCP streams appeared in timeline.
    Uses real PCAP: tests/data/syn_retrans_bug.pcap
    Flow: 10.20.0.165:1831 → 2.19.147.191:80 (tcp.stream 131)
    """
    # Load test PCAP
    pcap_path = "tests/data/syn_retrans_bug.pcap"
    assert os.path.exists(pcap_path), f"Test PCAP not found: {pcap_path}"
    packets = rdpcap(pcap_path)

    # Analyze
    analyzer = RetransmissionAnalyzer()
    analyzer.analyze(packets)

    # Find flow - SYN,ACK retrans come from SERVER, so flow key is reversed
    # Client sends SYN: 10.20.0.165:1831 → 2.19.147.191:80
    # Server sends SYN,ACK (retrans): 2.19.147.191:80 → 10.20.0.165:1831
    flow_key_client = "10.20.0.165:1831->2.19.147.191:80"
    flow_key_server = "2.19.147.191:80->10.20.0.165:1831"

    # SYN,ACK retransmissions are in server→client direction
    if flow_key_server in analyzer.sampled_timelines:
        flow_key = flow_key_server
    elif flow_key_client in analyzer.sampled_timelines:
        flow_key = flow_key_client
    else:
        # Debug: print all available flows
        available_flows = list(analyzer.sampled_timelines.keys())
        pytest.fail(f"Flow not found. Looking for {flow_key_client} or {flow_key_server}.\nAvailable flows with retrans: {available_flows}")

    timeline = analyzer.sampled_timelines[flow_key]

    # Merge forward and reverse handshakes to get complete picture
    # (SYN might be in reverse_handshake if flow_key is server→client)
    all_handshake = list(timeline.handshake) + list(timeline.reverse_handshake)
    all_handshake.sort(key=lambda p: p.timestamp)

    # Verify handshake contains correct frames (tcp.stream 131 only)
    # expected frames (Wireshark 1-based): 7458 (SYN), 7462 (SYN,ACK), etc.
    # actual frames (Scapy 0-based): 7457, 7461, ...

    actual_frames = {pkt.frame for pkt in all_handshake}
    print(f"Handshake frames (forward): {[pkt.frame for pkt in timeline.handshake]}")
    print(f"Handshake frames (reverse): {[pkt.frame for pkt in timeline.reverse_handshake]}")
    print(f"All handshake frames: {sorted(actual_frames)}")

    # CRITICAL: Must include client SYN frame for this handshake.
    # Depending on parser/frame indexing behavior, this may appear as 7457 or 7458.
    expected_syn_frames = {7457, 7458}
    assert actual_frames.intersection(expected_syn_frames), \
        f"Missing SYN packet (expected one of {sorted(expected_syn_frames)}) in handshake! Found: {sorted(actual_frames)}"

    # CRITICAL: Must NOT include frames from other streams
    # Frames from tcp.stream 130 (port 1830), 129 (port 1829), etc.
    # 7422 -> 7421, 7452 -> 7451
    wrong_frames = {7421, 7451, 7565, 7573, 7946, 8051}
    actual_wrong = actual_frames.intersection(wrong_frames)
    assert len(actual_wrong) == 0, f"Handshake contains frames from wrong TCP streams: {actual_wrong}"

    # Verify all handshake packets belong to correct flow
    for pkt in all_handshake:
        # Check ports to ensure stream isolation
        ports = {pkt.src_port, pkt.dst_port}
        assert 1831 in ports, f"Frame {pkt.frame} does not belong to stream 131 (port 1831). Ports: {ports}"
        assert 80 in ports, f"Frame {pkt.frame} does not belong to stream 131 (port 80). Ports: {ports}"

def test_syn_retrans_diagnostic_client_unreachable():
    """
    Test that SYN,ACK retransmissions are correctly diagnosed as "client unreachable".

    Regression test for bug where tool showed "server unreachable" when actually
    server WAS reachable (sending SYN,ACK) but client didn't complete handshake.
    """
    pcap_path = "tests/data/syn_retrans_bug.pcap"
    packets = rdpcap(pcap_path)

    analyzer = RetransmissionAnalyzer()
    analyzer.analyze(packets)

    # Find SYN retransmissions for flow 10.20.0.165:1831 → 2.19.147.191:80
    # In the result, retransmissions are in analyzer.retransmissions
    syn_retrans = [r for r in analyzer.retransmissions if r.is_syn_retrans and r.dst_port == 1831]

    assert len(syn_retrans) > 0, "No SYN retransmissions found"

    # All should be SYN,ACK retransmissions (tcp_flags="SA" or contains both SYN and ACK)
    for retrans in syn_retrans:
        # Accept either "SA" (compact notation) or flags containing both "SYN" and "ACK"
        is_syn_ack = (
            retrans.tcp_flags == "SA" or
            ("SYN" in retrans.tcp_flags and "ACK" in retrans.tcp_flags)
        )
        assert is_syn_ack, \
            f"Expected SYN,ACK flags but got: {retrans.tcp_flags}"

        # Diagnostic should be "client_unreachable" not "server_unreachable"
        assert retrans.syn_retrans_direction == "client_unreachable", \
            f"Wrong diagnosis: {retrans.syn_retrans_direction} (expected client_unreachable)"
