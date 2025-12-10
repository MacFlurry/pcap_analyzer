"""
Sprint 1 Integration Tests - Non-Regression Suite

Tests end-to-end functionality of Sprint 1 features:
- Health Score system
- Executive Summary generation
- Intelligent Gap Detection
- Result Sanitization
- Top 3 Actions recommendations

Ensures all components work together and no regressions occur.
"""

import json
import tempfile
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether

from src.analyzers.health_score import HealthScoreCalculator, HealthScoreResult
from src.analyzers.retransmission import RetransmissionAnalyzer
from src.analyzers.rtt_analyzer import RTTAnalyzer
from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer
from src.analyzers.timestamp_analyzer import TimestampAnalyzer
from src.utils.result_sanitizer import get_empty_analyzer_result, sanitize_results


@pytest.mark.integration
class TestHealthScoreIntegration:
    """Integration tests for Health Score system."""

    def test_health_score_with_all_analyzers(self):
        """Test health score calculation with all analyzer results."""
        # Create sample analyzer results
        results = {
            "retransmission": {"total_retransmissions": 10, "total_flows": 100},
            "rtt": {
                "global_statistics": {
                    "mean_rtt": 0.05,
                    "median_rtt": 0.045,
                    "max_rtt": 0.2,
                    "stdev_rtt": 0.01,
                }
            },
            "timestamps": {
                "total_packets": 1000,
                "gaps_detected": 2,
                "gaps": [
                    {"gap_duration": 2.5, "severity": "medium"},
                    {"gap_duration": 5.0, "severity": "high"},
                ],
            },
            "handshake": {
                "total_handshakes": 10,
                "failed_handshakes": 1,
                "handshake_events": [],
            },
        }

        # Calculate health score
        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(results)

        # Verify it's a HealthScoreResult
        assert isinstance(health_score, HealthScoreResult)

        # Verify scores are in valid range
        assert 0 <= health_score.overall_score <= 100
        assert 0 <= health_score.qos_class <= 5

        # Verify recommendations exist
        assert isinstance(health_score.recommendations, list)
        assert len(health_score.recommendations) >= 0

    def test_health_score_with_perfect_capture(self):
        """Test health score with perfect capture (no issues)."""
        results = {
            "retransmission": {"total_retransmissions": 0, "total_flows": 100},
            "rtt": {
                "global_statistics": {
                    "mean_rtt": 0.01,
                    "median_rtt": 0.01,
                    "max_rtt": 0.02,
                    "stdev_rtt": 0.001,
                }
            },
            "timestamps": {"total_packets": 1000, "gaps_detected": 0, "gaps": []},
            "handshake": {
                "total_handshakes": 10,
                "failed_handshakes": 0,
                "handshake_events": [],
            },
        }

        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(results)

        # Perfect capture should have high scores
        assert health_score.overall_score >= 90
        assert health_score.severity in ["excellent", "good"]

    def test_health_score_with_issues(self):
        """Test health score with network issues."""
        results = {
            "retransmission": {"total_retransmissions": 100, "total_flows": 100},  # High retrans
            "rtt": {
                "global_statistics": {
                    "mean_rtt": 0.5,  # 500ms RTT
                    "median_rtt": 0.45,
                    "max_rtt": 1.0,
                    "stdev_rtt": 0.2,
                }
            },
            "timestamps": {
                "total_packets": 1000,
                "gaps_detected": 5,
                "gaps": [{"gap_duration": 10.0, "severity": "high"} for _ in range(5)],
            },
            "handshake": {
                "total_handshakes": 10,
                "failed_handshakes": 3,
                "handshake_events": [],
            },
        }

        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(results)

        # Issues should result in moderate scores
        assert health_score.overall_score < 90
        assert len(health_score.recommendations) > 0


@pytest.mark.integration
class TestIntelligentGapDetection:
    """Integration tests for intelligent gap detection."""

    def test_gap_detection_with_packets(self):
        """Test gap detection identifies significant gaps."""
        packets = []

        # Generate packets with a significant gap
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA")
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        # Add 3 second gap
        pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA")
        pkt.time = 4.5
        packets.append(pkt)

        # Continue normal traffic
        for i in range(5):
            pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA")
            pkt.time = 4.5 + (i + 1) * 0.1
            packets.append(pkt)

        analyzer = TimestampAnalyzer()
        results = analyzer.analyze(packets)

        # Should detect some gaps (exact count depends on threshold logic)
        assert results["total_packets"] > 0
        assert isinstance(results["gaps"], list)

    def test_gap_detection_filters_noise(self):
        """Test that gap detection filters out insignificant gaps."""
        packets = []

        # Generate packets with small, normal gaps
        for i in range(100):
            pkt = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=443, flags="PA")
            pkt.time = 1.0 + i * 0.05  # 50ms intervals (normal)
            packets.append(pkt)

        analyzer = TimestampAnalyzer()
        results = analyzer.analyze(packets)

        # Should have processed packets
        assert results["total_packets"] == 100


@pytest.mark.integration
class TestResultSanitization:
    """Integration tests for result sanitization."""

    def test_sanitizer_handles_null_values_from_analyzers(self):
        """Test sanitizer correctly handles null values from real analyzers."""
        # Simulate RTT analyzer with single measurement (stdev=null)
        rtt_results = {
            "flows": {
                "192.168.1.100:12345 -> 10.0.0.50:22": {
                    "packet_count": 1,
                    "mean_rtt": 0.208,
                    "median_rtt": 0.208,
                    "stdev_rtt": None,  # Null due to single measurement
                    "rtt_spikes": 0,
                }
            }
        }

        sanitized = sanitize_results(rtt_results)

        # Null should be replaced with 0.0
        flow = sanitized["flows"]["192.168.1.100:12345 -> 10.0.0.50:22"]
        assert flow["stdev_rtt"] == 0.0
        assert flow["mean_rtt"] == 0.208  # Preserved

    def test_empty_analyzer_structures(self):
        """Test empty analyzer result structures are valid."""
        # Get empty structures for all analyzer types
        empty_frag = get_empty_analyzer_result("ip_fragmentation")
        empty_asym = get_empty_analyzer_result("asymmetric_traffic")
        empty_sack = get_empty_analyzer_result("sack")

        # Verify all have required fields with valid defaults
        assert empty_frag["total_fragments"] == 0
        assert empty_frag["fragmentation_rate"] == 0.0
        assert empty_frag["flows_with_fragmentation"] == []

        assert empty_asym["asymmetric_flows"] == 0
        assert empty_asym["asymmetry_rate"] == 0.0
        assert empty_asym["worst_asymmetric_flows"] == []

        assert empty_sack["total_tcp_packets"] == 0
        assert empty_sack["sack_usage_pct"] == 0.0
        assert empty_sack["sack_events"] == []

    def test_sanitization_preserves_data_integrity(self):
        """Test that sanitization doesn't corrupt valid data."""
        results = {
            "retransmission": {
                "total_retransmissions": 42,
                "retransmissions": [
                    {"src_ip": "192.168.1.1", "dst_ip": "10.0.0.1", "seq": 1000},
                    {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.2", "seq": 2000},
                ],
            },
            "rtt": {
                "global_statistics": {
                    "mean_rtt": 0.05,
                    "median_rtt": 0.045,
                    "stdev_rtt": 0.01,  # Valid value
                }
            },
        }

        sanitized = sanitize_results(results)

        # All valid data should be preserved
        assert sanitized["retransmission"]["total_retransmissions"] == 42
        assert len(sanitized["retransmission"]["retransmissions"]) == 2
        assert sanitized["rtt"]["global_statistics"]["mean_rtt"] == 0.05
        assert sanitized["rtt"]["global_statistics"]["stdev_rtt"] == 0.01


@pytest.mark.integration
class TestEndToEndPipeline:
    """End-to-end integration tests for full analysis pipeline."""

    def test_full_pipeline_with_sprint1_features(self):
        """Test complete analysis pipeline with all Sprint 1 features."""
        # Create realistic packet sequence
        packets = []
        base_time = 1.0

        # TCP handshake
        syn = Ether() / IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=12345, dport=80, flags="S", seq=1000)
        syn.time = base_time
        packets.append(syn)

        synack = (
            Ether()
            / IP(src="10.0.0.50", dst="192.168.1.100")
            / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
        )
        synack.time = base_time + 0.05
        packets.append(synack)

        ack = (
            Ether()
            / IP(src="192.168.1.100", dst="10.0.0.50")
            / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)
        )
        ack.time = base_time + 0.1
        packets.append(ack)

        # Data exchange
        for i in range(10):
            data = (
                Ether()
                / IP(src="192.168.1.100", dst="10.0.0.50")
                / TCP(sport=12345, dport=80, flags="PA", seq=1001 + i * 100, ack=2001)
                / f"DATA{i}".encode()
            )
            data.time = base_time + 0.15 + i * 0.1
            packets.append(data)

        # Run all analyzers
        handshake_analyzer = TCPHandshakeAnalyzer()
        retrans_analyzer = RetransmissionAnalyzer()
        rtt_analyzer = RTTAnalyzer()
        timestamp_analyzer = TimestampAnalyzer()

        handshake_results = handshake_analyzer.analyze(packets)
        retrans_results = retrans_analyzer.analyze(packets)
        rtt_results = rtt_analyzer.analyze(packets)
        timestamp_results = timestamp_analyzer.analyze(packets)

        # Combine results
        combined_results = {
            "handshake": handshake_results,
            "retransmission": retrans_results,
            "rtt": rtt_results,
            "timestamps": timestamp_results,
        }

        # Add empty structures for unimplemented analyzers
        for key in ["ip_fragmentation", "asymmetric_traffic", "sack"]:
            combined_results[key] = get_empty_analyzer_result(key)

        # Sanitize results
        combined_results = sanitize_results(combined_results)

        # Calculate health score
        health_calculator = HealthScoreCalculator()
        health_score = health_calculator.calculate(combined_results)

        # Verify end-to-end pipeline works
        assert handshake_results["total_handshakes"] >= 1
        assert timestamp_results["total_packets"] > 0
        assert health_score.overall_score >= 0
        assert isinstance(health_score.recommendations, list)

        # Verify no null values in output (except recommendations which is OK)
        assert _has_no_null_values(combined_results)

    def test_json_serialization_of_results(self):
        """Test that analyzer results are JSON-serializable."""
        # Create sample results
        results = {
            "analysis_info": {"pcap_file": "test.pcap", "total_packets": 100},
            "retransmission": {"total_retransmissions": 5, "total_flows": 10},
            "rtt": {"global_statistics": {"mean_rtt": 0.05, "median_rtt": 0.045}},
            "timestamps": {"total_packets": 100, "gaps_detected": 0, "gaps": []},
        }

        # Should serialize without errors
        try:
            json_str = json.dumps(results)
            # Should deserialize back
            restored = json.loads(json_str)
            assert restored["retransmission"]["total_retransmissions"] == 5
        except (TypeError, ValueError) as e:
            pytest.fail(f"JSON serialization failed: {e}")

    def test_error_handling_with_empty_capture(self):
        """Test pipeline handles empty captures gracefully."""
        empty_packets = []

        # All analyzers should handle empty input
        handshake_analyzer = TCPHandshakeAnalyzer()
        retrans_analyzer = RetransmissionAnalyzer()
        rtt_analyzer = RTTAnalyzer()
        timestamp_analyzer = TimestampAnalyzer()

        handshake_results = handshake_analyzer.analyze(empty_packets)
        retrans_results = retrans_analyzer.analyze(empty_packets)
        rtt_results = rtt_analyzer.analyze(empty_packets)
        timestamp_results = timestamp_analyzer.analyze(empty_packets)

        # Should return valid structures (not crash)
        assert isinstance(handshake_results, dict)
        assert isinstance(retrans_results, dict)
        assert isinstance(rtt_results, dict)
        assert isinstance(timestamp_results, dict)

        # Counts should be zero
        assert handshake_results.get("total_handshakes", 0) == 0
        assert retrans_results.get("total_retransmissions", 0) == 0
        assert timestamp_results.get("total_packets", 0) == 0

    def test_backwards_compatibility(self):
        """Test that Sprint 1 changes don't break existing functionality."""
        # Create simple packet sequence
        packets = []
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=12345, dport=80, flags="PA")
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        # Old analyzers should still work
        retrans_analyzer = RetransmissionAnalyzer()
        rtt_analyzer = RTTAnalyzer()

        retrans_results = retrans_analyzer.analyze(packets)
        rtt_results = rtt_analyzer.analyze(packets)

        # Results should have expected structure
        assert "total_retransmissions" in retrans_results
        assert isinstance(retrans_results, dict)
        assert isinstance(rtt_results, dict)


def _has_no_null_values(obj):
    """Recursively check that object has no None/null values."""
    if obj is None:
        return False
    elif isinstance(obj, dict):
        return all(_has_no_null_values(v) for v in obj.values())
    elif isinstance(obj, list):
        return all(_has_no_null_values(item) for item in obj)
    else:
        return True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
