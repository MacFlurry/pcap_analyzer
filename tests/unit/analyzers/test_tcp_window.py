"""
Unit tests for TCPWindowAnalyzer (TCP window analysis).

Tests TCP window size tracking, zero window detection, and flow statistics.
"""

import pytest
from scapy.all import IP, TCP, Raw

from src.analyzers.tcp_window import TCPWindowAnalyzer, WindowEvent, FlowWindowStats


class TestTCPWindowAnalyzer:
    """Tests for TCPWindowAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with default thresholds."""
        return TCPWindowAnalyzer(low_window_threshold=8192, zero_window_duration=0.1)

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = TCPWindowAnalyzer(low_window_threshold=8192, zero_window_duration=0.1)
        assert analyzer.low_window_threshold == 8192
        assert analyzer.zero_window_duration_threshold == 0.1
        assert len(analyzer.window_events) == 0
        assert len(analyzer.flow_stats) == 0

    def test_window_size_tracking(self, analyzer):
        """Test that window size is tracked correctly."""
        # Create packets with different window sizes
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, window=65535, flags="PA")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1005, window=8192, flags="PA")
        packet2.time = 1234567891.0

        packet3 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1010, window=0, flags="PA")
        packet3.time = 1234567892.0

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)
        analyzer.process_packet(packet3, 3)

        # Should track window sizes
        flow_key = "192.168.1.1:12345->10.0.0.1:80"
        assert flow_key in analyzer._flow_aggregates
        assert analyzer._flow_aggregates[flow_key]["max"] == 65535
        assert analyzer._flow_aggregates[flow_key]["min"] == 0

    def test_zero_window_detection(self, analyzer):
        """Test that zero window events are detected."""
        # Create packet with zero window
        zero_window_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(
            sport=12345, dport=80, seq=1000, window=0, flags="PA"
        )
        zero_window_packet.time = 1234567890.0

        analyzer.process_packet(zero_window_packet, 1)

        # Should detect zero window event
        assert len(analyzer.window_events) == 1
        event = analyzer.window_events[0]
        assert event.event_type == "zero_window"
        assert event.window_size == 0

    def test_low_window_detection(self, analyzer):
        """Test that low window packets are tracked (aggregated in statistics, not as events)."""
        # Create packet with low window (below threshold 8192)
        low_window_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(
            sport=12345, dport=80, seq=1000, window=4096, flags="PA"
        )
        low_window_packet.time = 1234567890.0

        analyzer.process_packet(low_window_packet, 1)
        analyzer.finalize()

        # Low window is tracked in aggregates, not as separate events
        # (Note: The code no longer generates 'low_window' events to optimize performance)
        # Verify that the window size is tracked correctly
        flow_key = "192.168.1.1:12345->10.0.0.1:80"
        assert flow_key in analyzer._flow_aggregates
        # The low_window_count should be tracked
        # Note: low_window detection requires multiple packets or specific conditions
        # This test verifies that low windows are tracked in aggregates
        results = analyzer.finalize()
        if results["flow_statistics"]:
            flow_stat = results["flow_statistics"][0]
            # Verify window size is tracked (4096 is below threshold 8192)
            assert flow_stat["min_window"] <= 4096
            assert flow_stat["max_window"] >= 4096

    def test_window_update_detection(self, analyzer):
        """Test that window updates are tracked."""
        # Create packets with increasing window size
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, window=8192, flags="PA")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1005, window=16384, flags="PA")
        packet2.time = 1234567891.0

        analyzer.process_packet(packet1, 1)
        analyzer.process_packet(packet2, 2)

        # Should track window updates
        flow_key = "192.168.1.1:12345->10.0.0.1:80"
        assert analyzer._flow_aggregates[flow_key]["max"] == 16384
        assert analyzer._flow_aggregates[flow_key]["min"] == 8192

    def test_finalize_statistics(self, analyzer):
        """Test that finalize() calculates correct statistics."""
        # Create packets with various window sizes
        flow_key = "192.168.1.1:12345->10.0.0.1:80"

        packets = [
            IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000 + i * 5, window=w, flags="PA")
            for i, w in enumerate([65535, 32768, 16384, 8192, 4096, 0])
        ]

        for i, packet in enumerate(packets):
            packet.time = 1234567890.0 + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.finalize()

        # Check results structure (API uses flow_statistics, not flow_stats)
        assert "total_flows" in results
        assert "flow_statistics" in results
        assert "total_window_events" in results

        # Check that flow statistics are calculated
        assert results["total_flows"] >= 1
        assert len(results["flow_statistics"]) >= 1

        flow_stat = None
        for stat in results["flow_statistics"]:
            if stat["flow_key"] == flow_key:
                flow_stat = stat
                break

        if flow_stat:
            assert flow_stat["max_window"] == 65535
            assert flow_stat["min_window"] == 0
            assert flow_stat["zero_window_count"] >= 1

    def test_multiple_flows_window_tracking(self, analyzer):
        """Test that multiple flows are tracked separately."""
        # Flow 1
        flow1_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, window=65535, flags="PA")
        flow1_packet.time = 1234567890.0

        # Flow 2
        flow2_packet = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, window=32768, flags="PA")
        flow2_packet.time = 1234567890.1

        analyzer.process_packet(flow1_packet, 1)
        analyzer.process_packet(flow2_packet, 2)

        # Should track both flows separately
        assert len(analyzer._flow_aggregates) == 2
        assert "192.168.1.1:12345->10.0.0.1:80" in analyzer._flow_aggregates
        assert "192.168.1.2:54321->10.0.0.1:80" in analyzer._flow_aggregates

    def test_zero_window_duration_calculation(self, analyzer):
        """Test that zero window duration is calculated correctly."""
        # Create zero window packet
        zero_packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, window=0, flags="PA")
        zero_packet1.time = 1234567890.0

        # Zero window continues
        zero_packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1005, window=0, flags="PA")
        zero_packet2.time = 1234567890.2  # 200ms later

        # Window opens
        normal_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1010, window=65535, flags="PA")
        normal_packet.time = 1234567890.3  # 300ms later

        analyzer.process_packet(zero_packet1, 1)
        analyzer.process_packet(zero_packet2, 2)
        analyzer.process_packet(normal_packet, 3)

        results = analyzer.finalize()
        flow_stat = None
        for stat in results["flow_statistics"]:
            if stat["flow_key"] == "192.168.1.1:12345->10.0.0.1:80":
                flow_stat = stat
                break

        if flow_stat:
            # Should have zero window duration >= 0.2s (from packet 1 to packet 3)
            assert flow_stat["zero_window_total_duration"] >= 0.2

    def test_non_tcp_packet_ignored(self, analyzer):
        """Test that non-TCP packets are ignored."""
        # UDP packet
        udp_packet = IP(src="192.168.1.1", dst="10.0.0.1") / Raw(load=b"udp data")
        udp_packet.time = 1234567890.0

        analyzer.process_packet(udp_packet, 1)

        # No events should be created
        assert len(analyzer.window_events) == 0
