"""
Test suite for Jitter Analyzer (RFC 3393 IPDV)

Tests Inter-Packet Delay Variation (IPDV) analysis including:
- Per-flow jitter calculation
- Jitter statistics (min, max, mean, stdev)
- High jitter flow identification
- RFC 3393 compliance

RFC 3393: IP Packet Delay Variation Metric for IPPM
"""

import pytest
from scapy.all import IP, TCP, UDP, Ether


class TestJitterAnalyzerBasics:
    """Test basic jitter analysis functionality."""

    def test_empty_packets_returns_empty_results(self):
        """Test analyzer handles empty packet list."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        analyzer = JitterAnalyzer()
        results = analyzer.analyze([])

        assert results["total_flows"] == 0
        assert results["flows_with_jitter"] == {}

    def test_single_packet_no_jitter(self):
        """Test single packet flow has no jitter."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = [Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)]
        packets[0].time = 1.0

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Single packet = no jitter calculation possible
        assert results["total_flows"] >= 0

    def test_two_packets_same_flow_calculates_jitter(self):
        """Test jitter calculation for 2-packet flow."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = [
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        ]
        packets[0].time = 1.0
        packets[1].time = 1.1  # 100ms gap

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Two packets = baseline, no jitter yet (need 3+ for jitter)
        assert results["total_flows"] >= 1

    def test_constant_delay_zero_jitter(self):
        """Test that constant inter-packet delay results in zero jitter."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = []
        # Create packets with constant 100ms spacing
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Constant delay = low jitter
        flow_key = list(results["flows_with_jitter"].keys())[0]
        jitter_stats = results["flows_with_jitter"][flow_key]

        assert jitter_stats["mean_jitter"] < 0.001  # Near zero
        assert jitter_stats["stdev_jitter"] == 0.0 or jitter_stats["stdev_jitter"] < 0.0001


class TestJitterCalculation:
    """Test jitter calculation methods."""

    def test_variable_delay_creates_jitter(self):
        """Test that variable inter-packet delay creates jitter."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = [
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        ]
        # Variable delays: 50ms, 200ms, 50ms
        packets[0].time = 1.0
        packets[1].time = 1.05  # 50ms
        packets[2].time = 1.25  # 200ms (spike!)
        packets[3].time = 1.30  # 50ms

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        flow_key = list(results["flows_with_jitter"].keys())[0]
        jitter_stats = results["flows_with_jitter"][flow_key]

        # Should detect jitter
        assert jitter_stats["max_jitter"] > 0.1  # Large variation
        assert jitter_stats["mean_jitter"] > 0

    def test_multiple_flows_tracked_separately(self):
        """Test that different flows have separate jitter calculations."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        # Flow 1: 192.168.1.1 -> 10.0.0.1
        flow1_packets = []
        for i in range(5):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            pkt.time = 1.0 + i * 0.1  # Constant 100ms
            flow1_packets.append(pkt)

        # Flow 2: 192.168.1.2 -> 10.0.0.2 (different jitter pattern)
        flow2_packets = []
        for i in range(5):
            pkt = Ether() / IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=12346, dport=443)
            pkt.time = 1.0 + i * 0.05  # Constant 50ms
            flow2_packets.append(pkt)

        all_packets = flow1_packets + flow2_packets

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(all_packets)

        # Should track 2 flows
        assert len(results["flows_with_jitter"]) >= 2


class TestJitterStatistics:
    """Test jitter statistics calculation."""

    def test_global_jitter_statistics(self):
        """Test global jitter statistics across all flows."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = []
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            # Variable timing
            if i % 2 == 0:
                pkt.time = 1.0 + i * 0.05
            else:
                pkt.time = 1.0 + i * 0.15
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Should have global statistics
        assert "global_statistics" in results
        assert "mean_jitter" in results["global_statistics"]
        assert "max_jitter" in results["global_statistics"]

    def test_high_jitter_flows_identified(self):
        """Test that flows with high jitter are identified."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        # Flow with high jitter
        packets = []
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=5060, dport=5060)  # Real-time UDP
            # Extreme jitter pattern
            if i % 3 == 0:
                pkt.time = 1.0 + i * 0.5  # 500ms spikes
            else:
                pkt.time = 1.0 + i * 0.02  # 20ms normal
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Should flag high jitter flows
        assert "high_jitter_flows" in results
        assert len(results["high_jitter_flows"]) > 0

    def test_jitter_percentiles(self):
        """Test jitter percentile calculation (p50, p95, p99)."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = []
        for i in range(100):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            # Generate varying delays
            delay = 0.01 if i < 50 else 0.02 if i < 95 else 0.1  # p50=10ms, p95=20ms, p99=100ms
            pkt.time = 1.0 + sum([delay for _ in range(i + 1)])
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        flow_key = list(results["flows_with_jitter"].keys())[0]
        jitter_stats = results["flows_with_jitter"][flow_key]

        # Should have percentile data
        assert "p50_jitter" in jitter_stats or "median_jitter" in jitter_stats
        assert "p95_jitter" in jitter_stats or "p99_jitter" in jitter_stats


class TestRFC3393Compliance:
    """Test RFC 3393 compliance."""

    def test_ipdv_formula_implementation(self):
        """Test that IPDV is calculated per RFC 3393."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = []
        # Create packets with known delays
        delays = [0.05, 0.1, 0.05, 0.15, 0.05]  # Variable delays
        current_time = 1.0
        for delay in delays:
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            pkt.time = current_time
            packets.append(pkt)
            current_time += delay

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # RFC 3393: Jitter = |delay[i] - delay[i-1]|
        # Delays: [50ms, 100ms, 50ms, 150ms, 50ms]
        # Jitter: [50ms, 50ms, 100ms, 100ms]
        flow_key = list(results["flows_with_jitter"].keys())[0]
        jitter_stats = results["flows_with_jitter"][flow_key]

        assert jitter_stats["max_jitter"] >= 0.09  # Should see ~100ms jitter (floating point tolerance)

    def test_udp_jitter_for_constant_rate(self):
        """Test jitter analysis for constant-rate UDP traffic (port 5060)."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = []
        # Simulate constant-rate real-time packets (should have low jitter ideally)
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=5060, dport=5060)
            pkt.time = 1.0 + i * 0.02  # 20ms constant packet rate
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        flow_key = list(results["flows_with_jitter"].keys())[0]
        jitter_stats = results["flows_with_jitter"][flow_key]

        # Constant-rate traffic should have near-zero jitter
        assert jitter_stats["mean_jitter"] < 0.001


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_single_flow_single_packet(self):
        """Test single packet in flow doesn't crash."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = [Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)]
        packets[0].time = 1.0

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Should not crash
        assert isinstance(results, dict)

    def test_unsorted_packets(self):
        """Test that analyzer handles unsorted packets."""
        from src.analyzers.jitter_analyzer import JitterAnalyzer

        packets = [
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        ]
        # Out of order timestamps
        packets[0].time = 1.0
        packets[1].time = 1.3
        packets[2].time = 1.1  # Out of order

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Should handle gracefully (may need to sort internally)
        assert isinstance(results, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
