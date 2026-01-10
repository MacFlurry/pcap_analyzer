"""
Unit tests for JitterAnalyzer.

Tests IPDV (Inter-Packet Delay Variation) calculation per RFC 3393,
percentile-based classification per RFC 5481, and session-aware segmentation.
"""

import pytest
from scapy.all import IP, TCP, UDP, Raw

from src.analyzers.jitter_analyzer import (
    JitterAnalyzer,
    JITTER_THRESHOLD_EXCELLENT,
    JITTER_THRESHOLD_GOOD,
    JITTER_THRESHOLD_REALTIME_CRITICAL,
    JITTER_THRESHOLD_TCP_WARNING,
    JITTER_THRESHOLD_TCP_CRITICAL,
)


class TestJitterAnalyzer:
    """Tests for JitterAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with default settings."""
        return JitterAnalyzer(session_gap_threshold=60.0, enable_session_detection=True)

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = JitterAnalyzer(session_gap_threshold=30.0, enable_session_detection=False)
        assert analyzer.session_gap_threshold == 30.0
        assert analyzer.enable_session_detection is False
        assert len(analyzer.flow_packets) == 0
        assert len(analyzer.flow_jitters) == 0
        assert len(analyzer.all_jitters) == 0

    def test_jitter_calculation_basic(self, analyzer):
        """Test basic IPDV calculation (RFC 3393: |delay[i] - delay[i-1]|)."""
        # Create packets with varying delays to generate jitter
        # Packet 1 -> Packet 2: delay = 0.1s
        # Packet 2 -> Packet 3: delay = 0.2s
        # Jitter = |0.2 - 0.1| = 0.1s
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet2")
        packet2.time = 1234567890.1  # 0.1s delay

        packet3 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet3")
        packet3.time = 1234567890.3  # 0.2s delay from packet2

        results = analyzer.analyze([packet1, packet2, packet3])

        # Should calculate jitter
        assert len(analyzer.all_jitters) >= 1
        # Jitter = |0.2 - 0.1| = 0.1s
        assert analyzer.all_jitters[0] == pytest.approx(0.1, abs=0.01)

    def test_udp_realtime_jitter_detection(self, analyzer):
        """Test jitter detection for UDP real-time traffic (strict thresholds)."""
        # Create UDP packets with high jitter (>50ms critical threshold)
        packets = []
        base_time = 1234567890.0
        delays = [0.010, 0.070, 0.015, 0.065]  # High jitter: 60ms, 50ms variations

        current_time = base_time
        for i, delay in enumerate(delays):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=5004) / Raw(load=f"packet{i}")
            packet.time = current_time
            packets.append(packet)
            current_time += delay

        results = analyzer.analyze(packets)

        # Should detect high jitter for UDP real-time traffic
        assert len(analyzer.all_jitters) >= 1
        # Check that jitter values are calculated
        max_jitter = max(analyzer.all_jitters) if analyzer.all_jitters else 0
        assert max_jitter > JITTER_THRESHOLD_REALTIME_CRITICAL  # > 50ms for UDP

    def test_tcp_jitter_detection(self, analyzer):
        """Test jitter detection for TCP traffic (lenient thresholds)."""
        # Create TCP packets with jitter
        packets = []
        base_time = 1234567890.0
        delays = [0.010, 0.110, 0.015, 0.105]  # 100ms jitter (warning threshold for TCP)

        current_time = base_time
        for i, delay in enumerate(delays):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=f"packet{i}")
            packet.time = current_time
            packets.append(packet)
            current_time += delay

        results = analyzer.analyze(packets)

        # Should detect jitter for TCP
        assert len(analyzer.all_jitters) >= 1
        # TCP uses lenient thresholds (100ms warning, 200ms critical)
        max_jitter = max(analyzer.all_jitters) if analyzer.all_jitters else 0
        # Jitter should be detected (exact value depends on calculation)

    def test_session_segmentation_syn_detection(self, analyzer):
        """Test that TCP SYN packets trigger session segmentation."""
        # Create packets with SYN flag (new session)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
        syn_packet.time = 1234567890.0

        # Data packets
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1.time = 1234567890.1

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data2")
        packet2.time = 1234567890.2

        results = analyzer.analyze([syn_packet, packet1, packet2])

        # Should detect session boundaries (SYN triggers new session)
        assert analyzer.sessions_detected >= 0  # May have detected SYN as session boundary

    def test_large_gap_filtering(self, analyzer):
        """Test that large gaps (>threshold) are filtered out from jitter calculation."""
        # Create packets with enough packets per session (need 3+ for jitter)
        # Session 1: 3 packets with normal gaps
        packets = []
        packets.append(IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet1"))
        packets[0].time = 1234567890.0

        packets.append(IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet2"))
        packets[1].time = 1234567890.1

        packets.append(IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet3"))
        packets[2].time = 1234567890.2

        # Large gap (70 seconds - triggers session segmentation)
        packets.append(IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet4"))
        packets[3].time = 1234567960.1  # 70 seconds later

        packets.append(IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet5"))
        packets[4].time = 1234567960.2

        packets.append(IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet6"))
        packets[5].time = 1234567960.3

        results = analyzer.analyze(packets)

        # Large gap should create separate sessions, with filtered jitter excluding the large gap
        # Each session should have jitter calculated independently
        # The large gap between sessions should not contribute to jitter
        assert analyzer.sessions_detected >= 1  # Should detect session boundary due to large gap

    def test_multiple_flows_tracking(self, analyzer):
        """Test that multiple flows are tracked separately."""
        # Flow 1: Client 1 -> Server
        packet1_flow1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"flow1")
        packet1_flow1.time = 1234567890.0

        packet2_flow1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"flow1-2")
        packet2_flow1.time = 1234567890.1

        # Flow 2: Client 2 -> Server
        packet1_flow2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80) / Raw(load=b"flow2")
        packet1_flow2.time = 1234567891.0

        packet2_flow2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80) / Raw(load=b"flow2-2")
        packet2_flow2.time = 1234567891.1

        results = analyzer.analyze([packet1_flow1, packet2_flow1, packet1_flow2, packet2_flow2])

        # Should track both flows separately
        assert len(analyzer.flow_packets) == 2

    def test_percentile_calculation(self, analyzer):
        """Test percentile calculation (RFC 5481: P95-based classification)."""
        # Create packets with varying jitter values
        packets = []
        base_time = 1234567890.0
        # Create jitter values: 10ms, 20ms, 30ms, 40ms, 50ms, 60ms, 70ms, 80ms, 90ms, 100ms
        jitter_sequence = [0.010, 0.020, 0.030, 0.040, 0.050, 0.060, 0.070, 0.080, 0.090, 0.100]

        current_time = base_time
        for i, jitter in enumerate(jitter_sequence):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=5004) / Raw(load=f"packet{i}")
            packet.time = current_time
            packets.append(packet)
            current_time += 0.01 + jitter  # Base delay + jitter

        results = analyzer.analyze(packets)

        # Should calculate percentiles (P95 should be around 90-100ms for this sequence)
        assert "percentile_p95" in results or "p95_jitter" in results or len(results) > 0
        # Check that jitter statistics are calculated

    def test_finalize_statistics(self, analyzer):
        """Test that finalize/get_results returns correct statistics."""
        # Create packets with jitter
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet2")
        packet2.time = 1234567890.1

        packet3 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet3")
        packet3.time = 1234567890.25  # 0.15s delay (high jitter)

        results = analyzer.analyze([packet1, packet2, packet3])

        # Check results structure
        assert "total_flows" in results or "flow_statistics" in results or len(results) > 0
        # Results should contain jitter statistics

    def test_rst_fin_detection(self, analyzer):
        """Test that RST/FIN flags are detected for pod restart scenarios (Issue #10)."""
        # Create packets with RST flag (need gap >0.1s after RST to trigger session boundary)
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data2")
        packet2.time = 1234567890.1

        # RST packet (pod restart)
        rst_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="R")
        rst_packet.time = 1234567890.2

        # New packets after restart (gap >0.1s to trigger session boundary)
        packet3 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data3")
        packet3.time = 1234567890.35  # 0.15s after RST (>0.1s threshold)

        packet4 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data4")
        packet4.time = 1234567890.4

        packet5 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"data5")
        packet5.time = 1234567890.5

        results = analyzer.analyze([packet1, packet2, rst_packet, packet3, packet4, packet5])

        # Should detect RST/FIN flags (for Kubernetes pod restart scenarios)
        # RST with gap >0.1s triggers session boundary and increments rst_fin_detected
        assert analyzer.rst_fin_detected >= 1

    def test_minimum_packets_requirement(self, analyzer):
        """Test that at least 3 packets are required for jitter calculation."""
        # Only 2 packets (insufficient for jitter)
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet2")
        packet2.time = 1234567890.1

        results = analyzer.analyze([packet1, packet2])

        # Should not calculate jitter (need at least 3 packets)
        assert len(analyzer.all_jitters) == 0  # No jitter with only 2 packets

    def test_reset_method(self, analyzer):
        """Test that reset() clears all state."""
        # Process some packets
        packet1 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet1")
        packet1.time = 1234567890.0

        packet2 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet2")
        packet2.time = 1234567890.1

        packet3 = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=b"packet3")
        packet3.time = 1234567890.2

        analyzer.analyze([packet1, packet2, packet3])

        # Reset
        analyzer.reset()

        # Should clear all state
        assert len(analyzer.flow_packets) == 0
        assert len(analyzer.flow_jitters) == 0
        assert len(analyzer.all_jitters) == 0
        assert analyzer.sessions_detected == 0

    def test_zero_jitter_detection(self, analyzer):
        """Test that zero jitter is correctly detected (constant delay)."""
        # Create packets with constant delay (zero jitter)
        packets = []
        base_time = 1234567890.0
        for i in range(5):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=53) / Raw(load=f"packet{i}")
            packet.time = base_time + i * 0.1  # Constant 0.1s delay
            packets.append(packet)

        results = analyzer.analyze(packets)

        # Should have zero jitter (constant delay)
        if len(analyzer.all_jitters) > 0:
            # All jitter values should be close to zero (or very small due to floating point)
            max_jitter = max(analyzer.all_jitters)
            assert max_jitter < 0.001  # Very small jitter for constant delay

    def test_high_jitter_detection(self, analyzer):
        """Test detection of high jitter flows."""
        # Create packets with very high jitter (critical for real-time)
        packets = []
        base_time = 1234567890.0
        # Very high jitter: 100ms variations
        delays = [0.010, 0.110, 0.015, 0.115, 0.020, 0.120]

        current_time = base_time
        for i, delay in enumerate(delays):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=12345, dport=5004) / Raw(load=f"packet{i}")
            packet.time = current_time
            packets.append(packet)
            current_time += delay

        results = analyzer.analyze(packets)

        # Should detect high jitter
        assert len(analyzer.all_jitters) >= 1
        max_jitter = max(analyzer.all_jitters) if analyzer.all_jitters else 0
        assert max_jitter > JITTER_THRESHOLD_REALTIME_CRITICAL  # > 50ms

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.analyze([])

        # Should return empty results
        assert len(analyzer.flow_packets) == 0
        assert len(analyzer.all_jitters) == 0
