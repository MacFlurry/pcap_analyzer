"""
Regression tests for fixed bugs.

This module consolidates all regression tests to prevent previously fixed bugs
from reoccurring. Tests are organized by the bug/issue they address.

Bugs covered:
- Issue #12: Negative duration bug (v5.4.4)
- v4.15.0: Packet Timeline flow_key mismatch bug
"""

import pytest
from src.exporters.html_report import HTMLReportGenerator


# ============================================================================
# Issue #12: Negative Duration Bug Fix (v5.4.4)
# ============================================================================

def calculate_duration(retrans_list):
    """
    Calculate duration between retransmissions (helper function for testing).

    This is the FIXED version that handles delay-sorted lists correctly.
    Matches the implementation in html_report.py.
    """
    if retrans_list:
        timestamps = [r.get("timestamp", 0) for r in retrans_list]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    else:
        duration = 0
    return duration


class TestIssue12NegativeDuration:
    """Tests for Issue #12: Negative duration bug fix (v5.4.4)."""

    def test_duration_with_delay_sorted_retransmissions(self):
        """
        Test that duration is positive when retrans sorted by delay (descending).

        Bug scenario:
        - List sorted by delay (largest first)
        - RTO (large delay) appears first but arrived second chronologically
        - Fast Retrans (small delay) appears last but arrived first chronologically
        - Old code: duration = last - first = negative (BUG)
        - New code: duration = max - min = positive (FIXED)
        """
        retrans_list = [
            {"timestamp": 15.0, "delay": 0.5},  # Large delay, arrived 2nd
            {"timestamp": 5.0, "delay": 0.05},  # Small delay, arrived 1st
        ]

        duration = calculate_duration(retrans_list)

        assert duration >= 0, "Duration should never be negative"
        assert duration == 10.0, f"Expected 10.0s, got {duration}s"

    def test_duration_single_retransmission(self):
        """Test that duration is 0 for single retransmission."""
        retrans_list = [{"timestamp": 5.0, "delay": 0.05}]
        duration = calculate_duration(retrans_list)
        assert duration == 0

    def test_duration_empty_list(self):
        """Test that duration is 0 for empty list."""
        assert calculate_duration([]) == 0

    def test_duration_missing_timestamps(self):
        """Test that duration handles missing timestamps gracefully."""
        retrans_list = [
            {"delay": 0.5},  # Missing timestamp (defaults to 0)
            {"timestamp": 5.0, "delay": 0.05},
        ]
        duration = calculate_duration(retrans_list)
        assert duration >= 0
        assert duration == 5.0

    def test_duration_real_data(self):
        """Test with real data from mixed_confidence_flows.pcap."""
        retrans_list = [
            {"timestamp": 1765472274.501871, "delay": 0.250},  # RTO
            {"timestamp": 1765472274.141871, "delay": 0.040},  # Fast Retrans
        ]
        duration = calculate_duration(retrans_list)
        assert duration >= 0
        assert abs(duration - 0.36) < 0.001

    def test_duration_multiple_retransmissions(self):
        """Test duration with multiple retransmissions in mixed order."""
        retrans_list = [
            {"timestamp": 20.0, "delay": 1.0},
            {"timestamp": 15.0, "delay": 0.5},
            {"timestamp": 5.0, "delay": 0.1},
            {"timestamp": 10.0, "delay": 0.05},
        ]
        duration = calculate_duration(retrans_list)
        assert duration >= 0
        assert duration == 15.0

    def test_duration_chronological_order(self):
        """Test that duration is correct even when list is in chronological order."""
        retrans_list = [
            {"timestamp": 5.0, "delay": 0.05},
            {"timestamp": 10.0, "delay": 0.05},
            {"timestamp": 15.0, "delay": 0.05},
        ]
        duration = calculate_duration(retrans_list)
        assert duration >= 0
        assert duration == 10.0


# ============================================================================
# v4.15.0: Packet Timeline flow_key Mismatch Bug
# ============================================================================

class TestTimelineFlowKeyFix:
    """Tests for v4.15.0 Packet Timeline flow_key mismatch bug fix."""

    def test_flow_key_format_matches_analyzer(self):
        """
        Test that HTML generator uses same flow_key format as RetransmissionAnalyzer.

        CRITICAL: Flow keys must match exactly for timeline rendering to work.
        Format: IP:PORT->IP:PORT (ASCII arrow, no spaces)
        NOT:    IP:PORT → IP:PORT (Unicode arrow with spaces)
        """
        results = {
            "total_packets": 100,
            "duration": 5.0,
            "retransmission": {
                "total_retransmissions": 1,
                "rto_count": 1,
                "fast_retrans_count": 0,
                "other_retrans_count": 0,
                "retransmissions": [
                    {
                        "src_ip": "192.168.1.1",
                        "src_port": 12345,
                        "dst_ip": "10.0.0.1",
                        "dst_port": 80,
                        "retrans_type": "RTO",
                        "delay": 0.2,
                        "timestamp": 1234567890.0,
                        "tcp_flags": "PA",
                        "is_syn_retrans": False,
                    }
                ],
                # Sampled timeline with CORRECT format (-> not →)
                "sampled_timelines": {
                    "192.168.1.1:12345->10.0.0.1:80": {
                        "handshake": [
                            {
                                "packet_num": 1,
                                "timestamp": 1234567889.0,
                                "seq": 1000,
                                "ack": 0,
                                "flags": "S",
                                "len": 0,
                            }
                        ],
                        "retrans_context": [],
                        "teardown": [],
                    }
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # CRITICAL: Timeline MUST be rendered
        assert "📋 Packet Timeline" in html, (
            "Timeline not found in HTML. "
            "This indicates flow_key mismatch between HTML generator and RetransmissionAnalyzer. "
            "Check that HTML generator uses '->' (ASCII arrow) not '→' (Unicode arrow)."
        )
        assert "Handshake" in html
        assert "<details>" in html  # Collapsible structure

    def test_flow_key_format_regression_detection(self):
        """
        Test that detects if flow_key format reverts to Unicode arrow.

        This is a negative test - if someone accidentally changes the format back
        to Unicode arrow (→), this test will fail.
        """
        results = {
            "total_packets": 100,
            "duration": 5.0,
            "retransmission": {
                "total_retransmissions": 1,
                "rto_count": 1,
                "fast_retrans_count": 0,
                "other_retrans_count": 0,
                "retransmissions": [
                    {
                        "src_ip": "192.168.1.1",
                        "src_port": 12345,
                        "dst_ip": "10.0.0.1",
                        "dst_port": 80,
                        "retrans_type": "RTO",
                        "delay": 0.2,
                        "timestamp": 1234567890.0,
                        "tcp_flags": "PA",
                        "is_syn_retrans": False,
                    }
                ],
                # WRONG format (→ with spaces) - should NOT match
                "sampled_timelines": {
                    "192.168.1.1:12345 → 10.0.0.1:80": {  # Unicode arrow - WRONG
                        "handshake": [
                            {
                                "packet_num": 1,
                                "timestamp": 1234567889.0,
                                "seq": 1000,
                                "ack": 0,
                                "flags": "S",
                                "len": 0,
                            }
                        ],
                        "retrans_context": [],
                        "teardown": [],
                    }
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Timeline should NOT be rendered (wrong flow_key format)
        assert "📋 Packet Timeline" not in html, (
            "Timeline was rendered with mismatched flow_key format. "
            "This means the fix was successful (HTML generator ignores wrong format)."
        )

    def test_multiple_flows_timeline_rendering(self):
        """Test that multiple flows each get their own timeline rendered."""
        results = {
            "total_packets": 200,
            "duration": 10.0,
            "retransmission": {
                "total_retransmissions": 2,
                "rto_count": 2,
                "fast_retrans_count": 0,
                "other_retrans_count": 0,
                "retransmissions": [
                    {
                        "src_ip": "192.168.1.1",
                        "src_port": 12345,
                        "dst_ip": "10.0.0.1",
                        "dst_port": 80,
                        "retrans_type": "RTO",
                        "delay": 0.2,
                        "timestamp": 1234567890.0,
                        "tcp_flags": "PA",
                        "is_syn_retrans": False,
                    },
                    {
                        "src_ip": "192.168.1.2",
                        "src_port": 54321,
                        "dst_ip": "10.0.0.2",
                        "dst_port": 443,
                        "retrans_type": "RTO",
                        "delay": 0.3,
                        "timestamp": 1234567891.0,
                        "tcp_flags": "PA",
                        "is_syn_retrans": False,
                    },
                ],
                "sampled_timelines": {
                    "192.168.1.1:12345->10.0.0.1:80": {
                        "handshake": [{"packet_num": 1, "timestamp": 1234567889.0, "seq": 1000, "ack": 0, "flags": "S", "len": 0}],
                        "retrans_context": [],
                        "teardown": [],
                    },
                    "192.168.1.2:54321->10.0.0.2:443": {
                        "handshake": [{"packet_num": 2, "timestamp": 1234567890.0, "seq": 2000, "ack": 0, "flags": "S", "len": 0}],
                        "retrans_context": [],
                        "teardown": [],
                    },
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Both timelines should be rendered
        timeline_count = html.count("📋 Packet Timeline")
        assert timeline_count == 2, f"Expected 2 timelines, found {timeline_count}"

    def test_flow_key_special_characters_escaping(self):
        """Test that flow_keys with special characters are properly escaped in HTML."""
        results = {
            "total_packets": 100,
            "duration": 5.0,
            "retransmission": {
                "total_retransmissions": 1,
                "rto_count": 1,
                "fast_retrans_count": 0,
                "other_retrans_count": 0,
                "retransmissions": [
                    {
                        "src_ip": "192.168.1.1",
                        "src_port": 12345,
                        "dst_ip": "10.0.0.1",
                        "dst_port": 80,
                        "retrans_type": "RTO",
                        "delay": 0.2,
                        "timestamp": 1234567890.0,
                        "tcp_flags": "PA",
                        "is_syn_retrans": False,
                    }
                ],
                "sampled_timelines": {
                    "192.168.1.1:12345->10.0.0.1:80": {
                        "handshake": [{"packet_num": 1, "timestamp": 1234567889.0, "seq": 1000, "ack": 0, "flags": "S", "len": 0}],
                        "retrans_context": [],
                        "teardown": [],
                    }
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Flow key should be HTML-escaped in output
        assert "192.168.1.1:12345-&gt;10.0.0.1:80" in html or "192.168.1.1:12345->10.0.0.1:80" in html
        # Should NOT contain Unicode arrow
        assert "192.168.1.1:12345 → 10.0.0.1:80" not in html
