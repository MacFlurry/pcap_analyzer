"""
Unit tests for ThroughputAnalyzer.

Tests throughput calculation per flow, bandwidth usage, and flow tracking.
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw

from src.analyzers.throughput import ThroughputAnalyzer


class TestThroughputAnalyzer:
    """Tests for ThroughputAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ThroughputAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = ThroughputAnalyzer()
        assert len(analyzer.flows) == 0
        assert analyzer.total_bytes == 0
        assert analyzer.total_packets == 0
        assert analyzer.first_packet_time is None
        assert analyzer.last_packet_time is None

    def test_tcp_flow_throughput_calculation(self, analyzer):
        """Test throughput calculation for TCP flow."""
        # Create TCP packets for one flow
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1.time = 1234567890.0

        packet2 = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345) / Raw(load=b"response")
        packet2.time = 1234567890.5  # 0.5 seconds later

        packet3 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data2")
        packet3.time = 1234567891.0  # 1 second total

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.process_packet(packet3, 3)
        analyzer.finalize()

        # Should track flow and calculate throughput
        assert len(analyzer.flows) == 1
        flow_key = list(analyzer.flows.keys())[0]
        flow = analyzer.flows[flow_key]
        assert flow["bytes"] > 0
        assert flow["packets"] == 3
        assert flow["protocol"] == "TCP"
        assert flow["first_timestamp"] == pytest.approx(1234567890.0, abs=0.01)
        assert flow["last_timestamp"] == pytest.approx(1234567891.0, abs=0.01)

    def test_udp_flow_throughput_calculation(self, analyzer):
        """Test throughput calculation for UDP flow."""
        # Create UDP packets for one flow
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"dns query")
        packet1.time = 1234567890.0

        packet2 = IP(src="10.0.0.1", dst="192.168.1.1") / UDP(sport=53, dport=12345) / Raw(load=b"dns response")
        packet2.time = 1234567890.1  # 0.1 seconds later

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.finalize()

        # Should track UDP flow
        assert len(analyzer.flows) == 1
        flow_key = list(analyzer.flows.keys())[0]
        flow = analyzer.flows[flow_key]
        assert flow["protocol"] == "UDP"
        assert flow["packets"] == 2

    def test_multiple_flows_tracking(self, analyzer):
        """Test that multiple flows are tracked separately."""
        # Flow 1: Client 1 -> Server
        packet1_flow1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1_flow1.time = 1234567890.0

        # Flow 2: Client 2 -> Server
        packet1_flow2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80) / Raw(load=b"data1")
        packet1_flow2.time = 1234567891.0

        analyzer.process_packet(packet1_flow1, 1)
        analyzer.process_packet(packet1_flow2, 2)
        analyzer.finalize()

        # Should track both flows separately
        assert len(analyzer.flows) == 2

    def test_bidirectional_flow_key(self, analyzer):
        """Test that bidirectional flows use normalized flow keys."""
        # Client -> Server
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data")
        packet1.time = 1234567890.0

        # Server -> Client (reverse direction)
        packet2 = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345) / Raw(load=b"response")
        packet2.time = 1234567890.5

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.finalize()

        # Should use same flow key for both directions (bidirectional)
        assert len(analyzer.flows) == 1
        flow_key = list(analyzer.flows.keys())[0]
        # Flow key should be normalized (smaller IP:port first)
        assert "<->" in flow_key
        flow = analyzer.flows[flow_key]
        assert flow["packets"] == 2  # Both directions counted

    def test_throughput_units_calculation(self, analyzer):
        """Test that throughput is calculated in multiple units (bps, kbps, mbps)."""
        # Create flow with known throughput
        # 1000 bytes in 1 second = 1000 B/s = 8000 bps = 8 kbps = 0.008 mbps
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"x" * 1000)
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"y" * 1000)
        packet2.time = 1234567891.0  # 1 second later

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.finalize()

        # Get results and check throughput calculation
        results = analyzer.finalize()
        assert "top_flows" in results

        # Check that throughput is calculated (exact values depend on packet overhead)
        assert len(results["top_flows"]) >= 1
        flow_stat = results["top_flows"][0]
        assert flow_stat["bytes"] > 0
        assert "throughput_mbps" in flow_stat
        assert "throughput_kbps" in flow_stat

    def test_global_statistics(self, analyzer):
        """Test that global statistics are tracked correctly."""
        # Create multiple packets
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data2")
        packet2.time = 1234567891.0

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)

        # Should track global statistics
        assert analyzer.total_packets == 2
        assert analyzer.total_bytes > 0
        assert analyzer.first_packet_time == pytest.approx(1234567890.0, abs=0.01)
        assert analyzer.last_packet_time == pytest.approx(1234567891.0, abs=0.01)

    def test_single_packet_flow(self, analyzer):
        """Test handling of single packet flow (duration = 0)."""
        # Single packet
        packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data")
        packet.time = 1234567890.0

        analyzer.process_packet(packet, 1)
        analyzer.finalize()

        # Should handle single packet (duration = 0, uses minimum 0.001s for calculation)
        assert len(analyzer.flows) == 1
        flow_key = list(analyzer.flows.keys())[0]
        flow = analyzer.flows[flow_key]
        assert flow["packets"] == 1
        assert flow["first_timestamp"] == flow["last_timestamp"]

    def test_non_tcp_udp_packet(self, analyzer):
        """Test handling of non-TCP/UDP packets (ICMP, etc.)."""
        # ICMP packet (no ports)
        icmp_packet = IP(src="192.168.1.1", dst="10.0.0.1") / Raw(load=b"icmp data")
        icmp_packet.time = 1234567890.0

        analyzer.process_packet(icmp_packet, 1)
        analyzer.finalize()

        # Should track as IP-only flow (no ports)
        assert len(analyzer.flows) == 1
        flow_key = list(analyzer.flows.keys())[0]
        flow = analyzer.flows[flow_key]
        assert flow["src_port"] is None
        assert flow["dst_port"] is None
        assert flow["bytes"] > 0

    def test_finalize_results(self, analyzer):
        """Test that finalize() returns correct results structure."""
        # Create flow
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data2")
        packet2.time = 1234567891.0

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)

        results = analyzer.finalize()

        # Check results structure (API uses global_throughput, top_flows, total_flows)
        assert "global_throughput" in results
        assert "top_flows" in results
        assert "total_flows" in results

        # Should have flow statistics
        assert results["global_throughput"]["total_packets"] == 2
        assert results["global_throughput"]["total_bytes"] > 0
        assert results["total_flows"] == 1

    def test_flow_duration_calculation(self, analyzer):
        """Test that flow duration is calculated correctly."""
        # Flow spanning 5 seconds
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data2")
        packet2.time = 1234567895.0  # 5 seconds later

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.finalize()

        # Should calculate duration correctly
        flow_key = list(analyzer.flows.keys())[0]
        flow = analyzer.flows[flow_key]
        duration = flow["last_timestamp"] - flow["first_timestamp"]
        assert duration == pytest.approx(5.0, abs=0.01)

    def test_bytes_counting(self, analyzer):
        """Test that bytes are counted correctly per flow."""
        # Create packets with known sizes
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"x" * 100)
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"y" * 200)
        packet2.time = 1234567891.0

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.finalize()

        # Should count bytes correctly (includes IP/TCP headers, so > 300)
        flow_key = list(analyzer.flows.keys())[0]
        flow = analyzer.flows[flow_key]
        assert flow["bytes"] > 300  # At least payload + headers

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.finalize()

        # Should return empty results (API uses global_throughput structure)
        assert results["global_throughput"]["total_packets"] == 0
        assert results["global_throughput"]["total_bytes"] == 0
        assert results["total_flows"] == 0
        assert len(results["top_flows"]) == 0
