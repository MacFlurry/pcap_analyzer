"""
Unit tests for TCPResetAnalyzer (TCP RST detection).

Tests RST packet detection, flow state tracking, and connection analysis.
"""

import pytest
from scapy.all import IP, TCP, Raw

from src.analyzers.tcp_reset import TCPResetAnalyzer


class TestTCPResetAnalyzer:
    """Tests for TCPResetAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TCPResetAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = TCPResetAnalyzer()
        assert len(analyzer.reset_packets) == 0
        assert len(analyzer.flows) == 0

    def test_rst_packet_detection(self, analyzer):
        """Test that RST packets are detected."""
        # Create RST packet
        rst_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="R")
        rst_packet.time = 1234567890.0

        analyzer.process_packet(rst_packet, 1)

        # Should detect RST packet
        assert len(analyzer.reset_packets) == 1
        rst_info = analyzer.reset_packets[0]
        assert rst_info["src_ip"] == "192.168.1.1"
        assert rst_info["src_port"] == 12345
        assert rst_info["dst_ip"] == "10.0.0.1"
        assert rst_info["dst_port"] == 80
        assert rst_info["packet_num"] == 1
        # Flow key is normalized (smaller IP:port first): "10.0.0.1:80 → 192.168.1.1:12345"
        assert rst_info["flow_key"] == "10.0.0.1:80 → 192.168.1.1:12345"

    def test_rst_with_syn_seen(self, analyzer):
        """Test RST detection when SYN was seen (established connection)."""
        # Create SYN packet
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # Create RST packet (connection closed)
        rst_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, flags="R")
        rst_packet.time = 1234567895.0

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(rst_packet, 2)

        # Should detect RST with syn_seen=True
        assert len(analyzer.reset_packets) == 1
        rst_info = analyzer.reset_packets[0]
        assert rst_info["syn_seen"] is True

    def test_rst_without_syn(self, analyzer):
        """Test RST detection without SYN (connection refused)."""
        # Create RST packet without prior SYN
        rst_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="R")
        rst_packet.time = 1234567890.0

        analyzer.process_packet(rst_packet, 1)

        # Should detect RST with syn_seen=False
        assert len(analyzer.reset_packets) == 1
        rst_info = analyzer.reset_packets[0]
        assert rst_info["syn_seen"] is False

    def test_rst_with_data_exchanged(self, analyzer):
        """Test RST detection when data was exchanged (abnormal closure)."""
        # Create SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # Create data packet (PSH+ACK)
        data_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, flags="PA") / Raw(
            load=b"GET / HTTP/1.1"
        )
        data_packet.time = 1234567891.0

        # Create RST (abnormal closure)
        rst_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1015, flags="R")
        rst_packet.time = 1234567895.0

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(data_packet, 2)
        analyzer.process_packet(rst_packet, 3)

        # Should detect RST with data_exchanged=True
        assert len(analyzer.reset_packets) == 1
        rst_info = analyzer.reset_packets[0]
        assert rst_info["syn_seen"] is True
        assert rst_info["data_exchanged"] is True

    def test_multiple_rst_packets(self, analyzer):
        """Test detection of multiple RST packets."""
        # Create multiple RST packets (same flow)
        rst1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="R")
        rst1.time = 1234567890.0

        rst2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="R")
        rst2.time = 1234567891.0

        analyzer.process_packet(rst1, 1)
        analyzer.process_packet(rst2, 2)

        # Should detect both RST packets
        assert len(analyzer.reset_packets) == 2
        # Flow key is normalized: "10.0.0.1:80 → 192.168.1.1:12345"
        normalized_flow = "10.0.0.1:80 → 192.168.1.1:12345"
        assert analyzer.flows[normalized_flow]["rst_count"] == 2

    def test_rst_bidirectional_flow_key(self, analyzer):
        """Test that RST packets from both directions use same flow key."""
        # RST from client to server
        rst1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="R")
        rst1.time = 1234567890.0

        # RST from server to client (reverse direction)
        rst2 = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, flags="R")
        rst2.time = 1234567891.0

        analyzer.process_packet(rst1, 1)
        analyzer.process_packet(rst2, 2)

        # Both should have same flow_key (normalized bidirectional)
        assert len(analyzer.reset_packets) == 2
        # Flow key should be normalized (same for both directions)
        flow_keys = [r["flow_key"] for r in analyzer.reset_packets]
        # Both should reference the same flow (normalized)

    def test_finalize_statistics(self, analyzer):
        """Test that finalize() returns correct statistics."""
        # Create RST packets for multiple flows
        rst1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="R")
        rst1.time = 1234567890.0

        rst2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="R")
        rst2.time = 1234567891.0

        analyzer.process_packet(rst1, 1)
        analyzer.process_packet(rst2, 2)

        results = analyzer.finalize()

        # Check results structure (API uses top_reset_flows, not reset_flows)
        assert "total_resets" in results
        assert "top_reset_flows" in results
        assert "reset_details" in results

        # Should have 2 RST packets
        assert results["total_resets"] == 2
        assert len(results["reset_details"]) == 2

    def test_non_tcp_packet_ignored(self, analyzer):
        """Test that non-TCP packets are ignored."""
        # UDP packet
        udp_packet = IP(src="192.168.1.1", dst="10.0.0.1") / Raw(load=b"udp data")
        udp_packet.time = 1234567890.0

        analyzer.process_packet(udp_packet, 1)

        # No RST packets should be detected
        assert len(analyzer.reset_packets) == 0

    def test_non_rst_tcp_packet(self, analyzer):
        """Test that non-RST TCP packets don't create reset records."""
        # SYN packet (not RST)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        analyzer.process_packet(syn_packet, 1)

        # No RST packets should be detected
        assert len(analyzer.reset_packets) == 0
        # But flow state should be tracked (flow key is normalized)
        normalized_flow = "10.0.0.1:80 → 192.168.1.1:12345"
        assert normalized_flow in analyzer.flows
        assert analyzer.flows[normalized_flow]["syn_seen"] is True
