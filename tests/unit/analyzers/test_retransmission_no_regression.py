"""
Non-regression tests for RetransmissionAnalyzer.
Ensures fixes for SYN retransmissions don't break normal flow analysis.
"""

import pytest
import os
from scapy.all import rdpcap
from src.analyzers.retransmission import RetransmissionAnalyzer

def test_no_regression_on_normal_flows():
    """Ensure fix doesn't break normal flow analysis."""
    # Use existing test PCAPs if available, or skip
    test_files = [
        "tests/test_data/test_small.pcap",
        "tests/test_data/test_bidirectional.pcap",
    ]

    for pcap_file in test_files:
        if not os.path.exists(pcap_file):
            print(f"Skipping missing test file: {pcap_file}")
            continue

        packets = rdpcap(pcap_file)
        analyzer = RetransmissionAnalyzer()
        analyzer.analyze(packets)

        # Verify all sampled timelines have valid data
        for flow_key, timeline in analyzer.sampled_timelines.items():
            # Handshake packets should all belong to same flow
            if timeline.handshake:
                flow_ips_ports = set()
                for pkt in timeline.handshake:
                    # Sort ips/ports to make it direction-agnostic for comparison
                    ips = tuple(sorted([pkt.src_ip, pkt.dst_ip]))
                    ports = tuple(sorted([pkt.src_port, pkt.dst_port]))
                    flow_ips_ports.add((ips, ports))

                # Should have at most 1 unique combination (because we sorted them)
                assert len(flow_ips_ports) <= 1, f"Flow {flow_key} has handshake packets from multiple flows: {flow_ips_ports}"
            
            # Same for reverse_handshake
            if timeline.reverse_handshake:
                flow_ips_ports = set()
                for pkt in timeline.reverse_handshake:
                    ips = tuple(sorted([pkt.src_ip, pkt.dst_ip]))
                    ports = tuple(sorted([pkt.src_port, pkt.dst_port]))
                    flow_ips_ports.add((ips, ports))
                assert len(flow_ips_ports) <= 1, f"Flow {flow_key} has reverse_handshake packets from multiple flows: {flow_ips_ports}"
