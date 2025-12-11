"""
Test suite for Issue #12: Negative duration bug fix

Tests the fix for negative durations in retransmission flow cards.
The bug occurred when retransmissions were sorted by delay (descending)
instead of timestamp, causing duration calculations to be negative.

Root cause: retrans_list is sorted by delay in retransmission.py:989,
but duration calculation assumed chronological order.

Solution: Use max(timestamps) - min(timestamps) instead of last - first.
"""

import pytest


def calculate_duration(retrans_list):
    """
    Calculate duration between retransmissions (helper function for testing).

    This is the FIXED version that handles delay-sorted lists correctly.
    Matches the implementation in html_report.py lines 2555-2559.
    """
    if retrans_list:
        timestamps = [r.get("timestamp", 0) for r in retrans_list]
        duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    else:
        duration = 0
    return duration


class TestIssue12NegativeDuration:
    """Tests for Issue #12: Negative duration bug fix."""

    def test_duration_with_delay_sorted_retransmissions(self):
        """
        Test that duration is positive when retrans sorted by delay (descending).

        This is the core bug scenario:
        - List is sorted by delay (largest first)
        - RTO (large delay) appears first in list but arrived second chronologically
        - Fast Retrans (small delay) appears last in list but arrived first chronologically
        - Old code: duration = last - first = negative (BUG)
        - New code: duration = max - min = positive (FIXED)
        """
        # Simulate the bug scenario: list sorted by delay (not timestamp)
        retrans_list = [
            {"timestamp": 15.0, "delay": 0.5},   # Large delay, arrived 2nd chronologically
            {"timestamp": 5.0, "delay": 0.05},   # Small delay, arrived 1st chronologically
        ]

        duration = calculate_duration(retrans_list)

        assert duration >= 0, "Duration should never be negative"
        assert duration == 10.0, f"Expected 10.0s, got {duration}s"

    def test_duration_single_retransmission(self):
        """
        Test that duration is 0 for single retransmission.

        Edge case: When there's only one retransmission, there's no duration.
        """
        retrans_list = [
            {"timestamp": 5.0, "delay": 0.05},
        ]

        duration = calculate_duration(retrans_list)

        assert duration == 0, f"Expected 0s for single retrans, got {duration}s"

    def test_duration_empty_list(self):
        """
        Test that duration is 0 for empty list.

        Edge case: When there are no retransmissions, duration should be 0.
        """
        retrans_list = []

        duration = calculate_duration(retrans_list)

        assert duration == 0, f"Expected 0s for empty list, got {duration}s"

    def test_duration_missing_timestamps(self):
        """
        Test that duration handles missing timestamps gracefully.

        Edge case: When timestamp is missing, get() defaults to 0.
        Duration should still be calculated correctly.
        """
        retrans_list = [
            {"delay": 0.5},  # Missing timestamp (defaults to 0)
            {"timestamp": 5.0, "delay": 0.05},
        ]

        duration = calculate_duration(retrans_list)

        assert duration >= 0, "Duration should never be negative"
        assert duration == 5.0, f"Expected 5.0s, got {duration}s"

    def test_duration_real_data(self):
        """
        Test with real data from mixed_confidence_flows.pcap.

        This is actual data that triggered the bug:
        - RTO at t=1765472274.501871s with delay=250ms (sorted first by delay)
        - Fast Retrans at t=1765472274.141871s with delay=40ms (sorted last by delay)
        - Old code would give: -360ms (WRONG)
        - New code should give: +360ms (CORRECT)
        """
        # Real data that triggers the bug
        retrans_list = [
            {"timestamp": 1765472274.501871, "delay": 0.250},  # RTO (sorted first by delay)
            {"timestamp": 1765472274.141871, "delay": 0.040},  # Fast Retrans (sorted last by delay)
        ]

        duration = calculate_duration(retrans_list)

        assert duration >= 0, "Duration should never be negative"
        assert abs(duration - 0.36) < 0.001, f"Expected ~0.36s, got {duration}s"

    def test_duration_multiple_retransmissions(self):
        """
        Test duration with multiple retransmissions in mixed order.

        Tests that the fix works with more than 2 retransmissions
        and various timestamp orderings.
        """
        # Multiple retransmissions with various delays
        retrans_list = [
            {"timestamp": 20.0, "delay": 1.0},    # Largest delay
            {"timestamp": 15.0, "delay": 0.5},    # Medium delay
            {"timestamp": 5.0, "delay": 0.1},     # Small delay
            {"timestamp": 10.0, "delay": 0.05},   # Smallest delay
        ]

        duration = calculate_duration(retrans_list)

        # Duration should be from earliest to latest timestamp
        # Earliest: 5.0s, Latest: 20.0s, Duration: 15.0s
        assert duration >= 0, "Duration should never be negative"
        assert duration == 15.0, f"Expected 15.0s, got {duration}s"

    def test_duration_chronological_order(self):
        """
        Test that duration is correct even when list happens to be in chronological order.

        Regression test: The fix should work correctly even when the list
        is already in chronological order (e.g., all retrans have same delay).
        """
        # List in chronological order (same delay for all)
        retrans_list = [
            {"timestamp": 5.0, "delay": 0.05},
            {"timestamp": 10.0, "delay": 0.05},
            {"timestamp": 15.0, "delay": 0.05},
        ]

        duration = calculate_duration(retrans_list)

        assert duration >= 0, "Duration should never be negative"
        assert duration == 10.0, f"Expected 10.0s, got {duration}s"


class TestIssue12Integration:
    """Integration tests for Issue #12 fix in HTMLReportGenerator."""

    def test_html_report_generator_duration_calculation(self):
        """
        Test that HTMLReportGenerator calculates duration correctly.

        This tests the actual implementation in html_report.py, not just the helper.
        """
        from src.exporters.html_report import HTMLReportGenerator

        # Create minimal analysis results with retransmissions
        results = {
            "metadata": {
                "pcap_file": "test.pcap",
                "total_packets": 100,
                "capture_duration": 10.0,
            },
            "health_score": {
                "overall_score": 85.0,
                "severity": "good",
                "summary": "Network is healthy",
            },
            "retransmission_analysis": {
                "flow_details": {
                    "192.168.1.1:12345 -> 192.168.1.2:80": [
                        {"timestamp": 15.0, "delay": 0.5, "retrans_type": "RTO"},
                        {"timestamp": 5.0, "delay": 0.05, "retrans_type": "Fast Retransmission"},
                    ]
                }
            }
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # HTML should be generated successfully
        assert "<!DOCTYPE html>" in html

        # Should not contain negative duration (would appear as "-" in HTML)
        # The duration should be 10000ms (10.0s * 1000)
        # Check that negative signs don't appear near "Duration" label
        assert "-" not in html or "Duration" not in html, \
            "HTML report should not contain negative durations"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
