"""
Test suite for Health Score Calculator

Tests RFC 2330 & ITU-T Y.1541 compliant health scoring system.
Follows TDD methodology - tests written before implementation.

References:
    RFC 2330: Framework for IP Performance Metrics (IPPM)
    RFC 2680: One-way Packet Loss Metric for IPPM
    RFC 3393: IP Packet Delay Variation (Jitter) Metric for IPPM
    RFC 6349: Framework for TCP Throughput Testing
    RFC 7680: TCP Loss Detection Algorithms
    ITU-T Y.1541: Network Performance Objectives for IP-based Services
    ITU-T G.114: One-way Transmission Time
"""

import pytest

from src.analyzers.health_score import HealthScoreCalculator, HealthScoreResult, MetricScore


class TestHealthScoreCalculator:
    """Test suite for RFC 2330 & ITU-T Y.1541 compliant health scoring"""

    def test_perfect_network_score_100(self):
        """
        Test Case 1: Perfect network should score 100 (QoS Class 0)

        Given: No retransmissions, low RTT, no DNS errors, low jitter
        When: Health score is calculated
        Then: Score = 100, QoS Class = 0, Severity = excellent
        """
        calculator = HealthScoreCalculator()

        # Perfect network: no issues
        analysis_results = {
            "timestamps": {"total_packets": 10000, "capture_duration_seconds": 60.0},
            "retransmission": {
                "total_retransmissions": 0,
                "unique_retransmitted_segments": 0,
                "anomaly_types": {"dup_ack": 0, "out_of_order": 0, "zero_window": 0},
            },
            "rtt": {"global_statistics": {"median_rtt": 0.020, "stdev_rtt": 0.002}},  # 20ms  # 2ms jitter
            "dns": {
                "total_transactions": 100,
                "timeout_transactions": 0,
                "error_transactions": 0,
                "slow_transactions": 0,
            },
        }

        result = calculator.calculate(analysis_results)

        assert result.overall_score == 100.0
        assert result.qos_class == 0
        assert result.severity == "excellent"
        assert result.severity_badge == "🟢"
        assert result.total_penalty == 0.0

    def test_good_network_score_90(self):
        """
        Test Case 2: Good network (0.5% retrans, 80ms RTT) should score ~90 (QoS Class 1)

        RFC 7680: <1% retransmissions is good
        ITU-T G.114: <150ms RTT is good
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 100000, "capture_duration_seconds": 300.0},
            "retransmission": {
                "total_retransmissions": 500,  # 0.5% retrans
                "unique_retransmitted_segments": 450,
                "anomaly_types": {"dup_ack": 1000, "out_of_order": 200, "zero_window": 2},
            },
            "rtt": {
                "global_statistics": {
                    "median_rtt": 0.080,  # 80ms - good per ITU-T G.114
                    "stdev_rtt": 0.015,  # 15ms jitter
                }
            },
            "dns": {
                "total_transactions": 500,
                "timeout_transactions": 2,
                "error_transactions": 1,
                "slow_transactions": 10,
            },
        }

        result = calculator.calculate(analysis_results)

        # Score should be in "good" range (85-94)
        assert 87 <= result.overall_score <= 93
        assert result.qos_class == 1
        assert result.severity == "good"
        assert result.severity_badge == "🟡"

    def test_acceptable_network_score_75(self):
        """
        Test Case 3: Acceptable network (2% retrans, 200ms RTT) should score ~75 (QoS Class 2)

        RFC 7680: 1-3% retransmissions is acceptable
        ITU-T G.114: 150-400ms RTT is acceptable
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 50000, "capture_duration_seconds": 180.0},
            "retransmission": {
                "total_retransmissions": 1000,  # 2% retrans
                "unique_retransmitted_segments": 900,
                "anomaly_types": {"dup_ack": 2000, "out_of_order": 500, "zero_window": 8},
            },
            "rtt": {
                "global_statistics": {
                    "median_rtt": 0.200,  # 200ms - acceptable per ITU-T G.114
                    "stdev_rtt": 0.040,  # 40ms jitter
                }
            },
            "dns": {
                "total_transactions": 200,
                "timeout_transactions": 10,
                "error_transactions": 5,
                "slow_transactions": 30,
            },
        }

        result = calculator.calculate(analysis_results)

        assert 70 <= result.overall_score <= 80  # Acceptable range
        assert result.qos_class == 2
        assert result.severity == "warning"
        assert result.severity_badge == "🟠"

    def test_poor_network_score_55(self):
        """
        Test Case 4: Poor network (4% retrans, 500ms RTT) should score ~55 (QoS Class 3)

        RFC 7680: 3-5% retransmissions is poor
        ITU-T G.114: >400ms RTT is poor
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 30000, "capture_duration_seconds": 120.0},
            "retransmission": {
                "total_retransmissions": 1200,  # 4% retrans
                "unique_retransmitted_segments": 1100,
                "anomaly_types": {"dup_ack": 3000, "out_of_order": 800, "zero_window": 15},
            },
            "rtt": {"global_statistics": {"median_rtt": 0.500, "stdev_rtt": 0.080}},  # 500ms - poor  # 80ms jitter
            "dns": {
                "total_transactions": 150,
                "timeout_transactions": 30,
                "error_transactions": 10,
                "slow_transactions": 50,
            },
        }

        result = calculator.calculate(analysis_results)

        assert 50 <= result.overall_score <= 65  # Poor range
        assert result.qos_class == 3
        assert result.severity == "poor"
        assert result.severity_badge == "🔴"

    def test_critical_network_score_30(self):
        """
        Test Case 5: Critical network (8% retrans, 1000ms RTT) should score ~30 (QoS Class 4)

        RFC 7680: >5% retransmissions is critical
        ITU-T G.114: >800ms RTT is critical
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 20000, "capture_duration_seconds": 90.0},
            "retransmission": {
                "total_retransmissions": 1600,  # 8% retrans
                "unique_retransmitted_segments": 1500,
                "anomaly_types": {"dup_ack": 5000, "out_of_order": 1500, "zero_window": 30},
            },
            "rtt": {
                "global_statistics": {"median_rtt": 1.000, "stdev_rtt": 0.150}  # 1000ms - critical  # 150ms jitter
            },
            "dns": {
                "total_transactions": 100,
                "timeout_transactions": 50,
                "error_transactions": 20,
                "slow_transactions": 60,
            },
        }

        result = calculator.calculate(analysis_results)

        assert 25 <= result.overall_score <= 45  # Critical range
        assert result.qos_class == 4
        assert result.severity == "critical"
        assert result.severity_badge == "⚫"

    def test_emergency_network_score_15(self):
        """
        Test Case 6: Emergency network (15% retrans, 2000ms RTT) should score ~15 (QoS Class 5)

        Network failure conditions
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 10000, "capture_duration_seconds": 60.0},
            "retransmission": {
                "total_retransmissions": 1500,  # 15% retrans
                "unique_retransmitted_segments": 1400,
                "anomaly_types": {"dup_ack": 8000, "out_of_order": 3000, "zero_window": 50},
            },
            "rtt": {
                "global_statistics": {"median_rtt": 2.000, "stdev_rtt": 0.300}  # 2000ms - emergency  # 300ms jitter
            },
            "dns": {
                "total_transactions": 50,
                "timeout_transactions": 45,
                "error_transactions": 30,
                "slow_transactions": 48,
            },
        }

        result = calculator.calculate(analysis_results)

        assert 0 <= result.overall_score <= 24  # Emergency range
        assert result.qos_class == 5
        assert result.severity == "emergency"
        assert result.severity_badge == "🆘"

    def test_rfc_7680_compliance_retransmissions(self):
        """
        Test Case 7: Verify RFC 7680 threshold compliance (<1% retrans target)

        At exactly 1% retrans (RFC 7680 target), should be in "good" range
        """
        calculator = HealthScoreCalculator()

        # Test at exactly 1% retrans
        analysis_results = {
            "timestamps": {"total_packets": 100000, "capture_duration_seconds": 300.0},
            "retransmission": {
                "total_retransmissions": 1000,  # Exactly 1%
                "unique_retransmitted_segments": 900,
                "anomaly_types": {"dup_ack": 0, "out_of_order": 0, "zero_window": 0},
            },
            "rtt": {"global_statistics": {"median_rtt": 0.020, "stdev_rtt": 0.002}},
            "dns": {
                "total_transactions": 100,
                "timeout_transactions": 0,
                "error_transactions": 0,
                "slow_transactions": 0,
            },
        }

        result = calculator.calculate(analysis_results)

        # At 1% retrans, should be in "good" range (penalty ~5-10 points)
        assert result.overall_score >= 85

        # Find TCP retransmission metric
        metric = next(m for m in result.metric_scores if m.metric_name == "TCP Retransmissions")
        assert metric.threshold_status == "good"
        assert metric.rfc_reference == "RFC 7680"

    def test_itu_t_g114_compliance_rtt(self):
        """
        Test Case 8: Verify ITU-T G.114 compliance (150ms good, 400ms acceptable)

        At exactly 150ms (ITU-T G.114 "good" threshold)
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 50000, "capture_duration_seconds": 120.0},
            "retransmission": {
                "total_retransmissions": 0,
                "unique_retransmitted_segments": 0,
                "anomaly_types": {"dup_ack": 0, "out_of_order": 0, "zero_window": 0},
            },
            "rtt": {"global_statistics": {"median_rtt": 0.150, "stdev_rtt": 0.010}},  # Exactly 150ms
            "dns": {
                "total_transactions": 100,
                "timeout_transactions": 0,
                "error_transactions": 0,
                "slow_transactions": 0,
            },
        }

        result = calculator.calculate(analysis_results)

        metric = next(m for m in result.metric_scores if m.metric_name == "RTT (Latency)")
        assert metric.threshold_status in ["good", "acceptable"]
        assert metric.rfc_reference == "ITU-T G.114"

    def test_zero_packets_edge_case(self):
        """
        Test Case 9: Handle edge case with zero packets gracefully

        Should not crash with division by zero
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 0, "capture_duration_seconds": 0.0},
            "retransmission": {"total_retransmissions": 0, "unique_retransmitted_segments": 0, "anomaly_types": {}},
            "rtt": {"global_statistics": {}},
            "dns": {"total_transactions": 0},
        }

        result = calculator.calculate(analysis_results)

        # Should handle gracefully without division by zero
        assert 0 <= result.overall_score <= 100
        assert isinstance(result.qos_class, int)
        assert 0 <= result.qos_class <= 5

    def test_recommendation_generation(self):
        """
        Test Case 10: Verify recommendations are generated for issues

        High retransmissions should trigger actionable recommendations
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 10000, "capture_duration_seconds": 60.0},
            "retransmission": {
                "total_retransmissions": 800,  # 8% - critical
                "unique_retransmitted_segments": 750,
                "anomaly_types": {"dup_ack": 500, "out_of_order": 100, "zero_window": 3},
            },
            "rtt": {"global_statistics": {"median_rtt": 0.050, "stdev_rtt": 0.005}},
            "dns": {
                "total_transactions": 100,
                "timeout_transactions": 0,
                "error_transactions": 0,
                "slow_transactions": 0,
            },
        }

        result = calculator.calculate(analysis_results)

        # Should have recommendations for high retransmissions
        assert len(result.recommendations) > 0
        assert any("retransmission" in rec.lower() for rec in result.recommendations)

    def test_metric_scores_structure(self):
        """
        Test Case 11: Verify metric_scores structure is complete

        Should return all 6 metrics with proper structure
        """
        calculator = HealthScoreCalculator()

        analysis_results = {
            "timestamps": {"total_packets": 1000, "capture_duration_seconds": 10.0},
            "retransmission": {"total_retransmissions": 0, "unique_retransmitted_segments": 0, "anomaly_types": {}},
            "rtt": {"global_statistics": {"median_rtt": 0.02, "stdev_rtt": 0.002}},
            "dns": {
                "total_transactions": 10,
                "timeout_transactions": 0,
                "error_transactions": 0,
                "slow_transactions": 0,
            },
        }

        result = calculator.calculate(analysis_results)

        # Should have 6 metrics
        assert len(result.metric_scores) == 6

        # Verify metric names
        metric_names = [m.metric_name for m in result.metric_scores]
        assert "TCP Retransmissions" in metric_names
        assert "Packet Loss Rate" in metric_names
        assert "RTT (Latency)" in metric_names
        assert "DNS Errors" in metric_names
        assert "Jitter (IPDV)" in metric_names
        assert "Protocol Anomalies" in metric_names

        # Verify each metric has required fields
        for metric in result.metric_scores:
            assert hasattr(metric, "metric_name")
            assert hasattr(metric, "raw_value")
            assert hasattr(metric, "penalty")
            assert hasattr(metric, "weight")
            assert hasattr(metric, "weighted_penalty")
            assert hasattr(metric, "threshold_status")
            assert hasattr(metric, "rfc_reference")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
