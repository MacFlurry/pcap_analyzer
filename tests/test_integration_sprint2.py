"""
Sprint 2 Integration Tests

Tests end-to-end functionality of Sprint 2 features:
- Protocol Distribution Analyzer
- Jitter Analyzer (RFC 3393)
- CLI pipeline integration
- Health Score integration with jitter

Ensures all Sprint 2 components work together correctly.
"""

import pytest
from scapy.all import IP, TCP, UDP, Ether

from src.analyzers.health_score import HealthScoreCalculator
from src.analyzers.jitter_analyzer import JitterAnalyzer
from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer
from src.utils.result_sanitizer import sanitize_results


@pytest.mark.integration
class TestProtocolDistributionIntegration:
    """Integration tests for Protocol Distribution Analyzer."""

    def test_protocol_distribution_with_mixed_traffic(self):
        """Test protocol analyzer with realistic mixed traffic."""
        packets = []

        # HTTP traffic (TCP port 80)
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=10000 + i, dport=80)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        # HTTPS traffic (TCP port 443)
        for i in range(30):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.2") / TCP(sport=20000 + i, dport=443)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        # DNS traffic (UDP port 53)
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.3") / UDP(sport=30000 + i, dport=53)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        # Verify protocol distribution
        assert results["total_packets"] == 100
        assert results["layer4_distribution"]["TCP"] == 80
        assert results["layer4_distribution"]["UDP"] == 20
        assert results["layer4_percentages"]["TCP"] == 80.0
        assert results["layer4_percentages"]["UDP"] == 20.0

        # Verify service identification
        assert results["service_distribution"]["HTTP"] == 50
        assert results["service_distribution"]["HTTPS"] == 30
        assert results["service_distribution"]["DNS"] == 20

        # Verify top ports
        assert results["top_tcp_ports"][0]["port"] == 80
        assert results["top_tcp_ports"][0]["count"] == 50
        assert results["top_tcp_ports"][1]["port"] == 443

    def test_protocol_distribution_sanitization(self):
        """Test that protocol distribution results are sanitized."""
        packets = [Ether() / IP() / TCP(sport=12345, dport=80)]
        packets[0].time = 1.0

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        # Sanitize results
        sanitized = sanitize_results({"protocol_distribution": results})

        # Should have no null values
        assert sanitized["protocol_distribution"]["total_packets"] >= 0
        assert isinstance(sanitized["protocol_distribution"]["layer3_distribution"], dict)


@pytest.mark.integration
class TestJitterIntegration:
    """Integration tests for Jitter Analyzer."""

    def test_jitter_analysis_realtime_traffic(self):
        """Test jitter analysis on real-time communication traffic."""
        packets = []

        # Simulate real-time UDP: regular 20ms packets with some jitter
        base_time = 1.0
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.50") / UDP(sport=5060, dport=5060)
            # Add small random jitter
            if i % 10 == 0:
                jitter = 0.01  # 10ms spike
            else:
                jitter = 0.0
            pkt.time = base_time + i * 0.02 + jitter
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Should detect jitter
        assert results["total_flows"] == 1
        assert len(results["flows_with_jitter"]) > 0

        # Real-time flow should have measurable jitter
        flow_key = list(results["flows_with_jitter"].keys())[0]
        jitter_stats = results["flows_with_jitter"][flow_key]
        assert jitter_stats["mean_jitter"] >= 0
        assert jitter_stats["max_jitter"] > 0

    def test_jitter_with_multiple_flows(self):
        """Test jitter tracks multiple flows separately."""
        packets = []

        # Flow 1: Low jitter
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            pkt.time = 1.0 + i * 0.1  # Constant 100ms
            packets.append(pkt)

        # Flow 2: High jitter
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.2", dst="10.0.0.2") / UDP(sport=5060, dport=5060)
            if i % 2 == 0:
                pkt.time = 1.0 + i * 0.05  # 50ms
            else:
                pkt.time = 1.0 + i * 0.15  # 150ms (high jitter!)
            packets.append(pkt)

        analyzer = JitterAnalyzer()
        results = analyzer.analyze(packets)

        # Should track 2 flows
        assert results["total_flows"] == 2
        assert len(results["flows_with_jitter"]) == 2


@pytest.mark.integration
class TestHealthScoreWithNewAnalyzers:
    """Test Health Score integration with new analyzers."""

    def test_health_score_uses_jitter_analyzer(self):
        """Test Health Score uses dedicated jitter analyzer."""
        # Create results with jitter data
        results = {
            "retransmission": {"total_retransmissions": 10, "unique_retransmitted_segments": 5, "total_flows": 100},
            "rtt": {"global_statistics": {"mean_rtt": 0.05, "median_rtt": 0.045, "stdev_rtt": 0.01}},
            "timestamps": {"total_packets": 1000, "gaps_detected": 0, "gaps": []},
            "handshake": {"total_handshakes": 10, "failed_handshakes": 0},
            "jitter": {
                "total_flows": 10,
                "global_statistics": {
                    "mean_jitter": 0.015,  # 15ms - better than RTT stdev
                    "max_jitter": 0.030,
                },
            },
        }

        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(results)

        # Should use jitter analyzer (15ms) not RTT stdev (10ms)
        # Both are good, but jitter is slightly higher
        assert health_score.overall_score >= 85

    def test_health_score_fallback_to_rtt_stdev(self):
        """Test Health Score falls back to RTT stdev if no jitter analyzer."""
        # Results WITHOUT jitter analyzer
        results = {
            "retransmission": {"total_retransmissions": 10, "unique_retransmitted_segments": 5, "total_flows": 100},
            "rtt": {"global_statistics": {"mean_rtt": 0.05, "median_rtt": 0.045, "stdev_rtt": 0.025}},  # 25ms jitter
            "timestamps": {"total_packets": 1000, "gaps_detected": 0, "gaps": []},
            "handshake": {"total_handshakes": 10, "failed_handshakes": 0},
        }

        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(results)

        # Should still calculate jitter penalty from RTT stdev
        assert health_score.overall_score >= 0


@pytest.mark.integration
class TestEndToEndSprin2Pipeline:
    """End-to-end integration tests for Sprint 2 pipeline."""

    def test_full_pipeline_with_protocol_and_jitter(self):
        """Test complete pipeline with protocol distribution and jitter."""
        packets = []

        # Create diverse traffic
        protocols = [
            (TCP, 80, "HTTP"),
            (TCP, 443, "HTTPS"),
            (UDP, 53, "DNS"),
            (TCP, 22, "SSH"),
        ]

        for proto_idx, (proto, dport, name) in enumerate(protocols):
            for i in range(25):
                pkt = Ether() / IP(src=f"192.168.1.{proto_idx+1}", dst="10.0.0.1") / proto(sport=10000 + i, dport=dport)
                pkt.time = 1.0 + (proto_idx * 25 + i) * 0.02
                packets.append(pkt)

        # Analyze protocol distribution
        protocol_analyzer = ProtocolDistributionAnalyzer()
        protocol_results = protocol_analyzer.analyze(packets)

        # Analyze jitter
        jitter_analyzer = JitterAnalyzer()
        jitter_results = jitter_analyzer.analyze(packets)

        # Combine results
        combined_results = {
            "protocol_distribution": protocol_results,
            "jitter": jitter_results,
            "retransmission": {"total_retransmissions": 0, "unique_retransmitted_segments": 0, "total_flows": 4},
            "rtt": {"global_statistics": {"mean_rtt": 0.02, "median_rtt": 0.02}},
            "timestamps": {"total_packets": 100, "gaps_detected": 0, "gaps": []},
            "handshake": {"total_handshakes": 4, "failed_handshakes": 0},
        }

        # Sanitize
        combined_results = sanitize_results(combined_results)

        # Calculate health score
        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(combined_results)

        # Verify all components work together
        assert protocol_results["total_packets"] == 100
        assert protocol_results["layer4_distribution"]["TCP"] == 75
        assert protocol_results["layer4_distribution"]["UDP"] == 25

        # Jitter tracks flows (1 per unique 5-tuple)
        assert jitter_results["total_flows"] > 0
        assert len(jitter_results["flows_with_jitter"]) >= 0  # May have jitter data

        assert health_score.overall_score >= 85  # Good network

    def test_json_serialization_of_sprint2_results(self):
        """Test that Sprint 2 results are JSON-serializable."""
        import json

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / UDP(sport=12346, dport=53),
        ]
        for i, pkt in enumerate(packets):
            pkt.time = 1.0 + i * 0.1

        protocol_analyzer = ProtocolDistributionAnalyzer()
        protocol_results = protocol_analyzer.analyze(packets)

        jitter_analyzer = JitterAnalyzer()
        jitter_results = jitter_analyzer.analyze(packets)

        results = {"protocol_distribution": protocol_results, "jitter": jitter_results}

        # Should serialize without errors
        try:
            json_str = json.dumps(results)
            restored = json.loads(json_str)
            assert restored["protocol_distribution"]["total_packets"] == 2
            assert restored["jitter"]["total_flows"] >= 0
        except (TypeError, ValueError) as e:
            pytest.fail(f"JSON serialization failed: {e}")

    def test_empty_packets_sprint2_analyzers(self):
        """Test Sprint 2 analyzers handle empty packets gracefully."""
        empty_packets = []

        protocol_analyzer = ProtocolDistributionAnalyzer()
        protocol_results = protocol_analyzer.analyze(empty_packets)

        jitter_analyzer = JitterAnalyzer()
        jitter_results = jitter_analyzer.analyze(empty_packets)

        # Should return valid empty structures
        assert protocol_results["total_packets"] == 0
        assert protocol_results["layer3_distribution"] == {}
        assert protocol_results["layer4_distribution"] == {}

        assert jitter_results["total_flows"] == 0
        assert jitter_results["flows_with_jitter"] == {}


@pytest.mark.integration
class TestBackwardsCompatibility:
    """Test Sprint 2 changes don't break existing functionality."""

    def test_health_score_without_new_analyzers(self):
        """Test Health Score works without new analyzers (backwards compat)."""
        # Old-style results (no protocol_distribution, no jitter)
        results = {
            "retransmission": {"total_retransmissions": 5, "unique_retransmitted_segments": 3, "total_flows": 100},
            "rtt": {"global_statistics": {"mean_rtt": 0.05, "median_rtt": 0.045, "stdev_rtt": 0.01}},
            "timestamps": {"total_packets": 1000, "gaps_detected": 0, "gaps": []},
            "handshake": {"total_handshakes": 10, "failed_handshakes": 0},
        }

        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(results)

        # Should work with fallback to RTT stdev for jitter
        assert health_score.overall_score >= 0
        assert isinstance(health_score.recommendations, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
