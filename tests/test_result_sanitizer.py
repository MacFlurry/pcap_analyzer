"""
Test suite for Result Sanitizer

Tests null value replacement and empty structure generation.
"""

import pytest

from src.utils.result_sanitizer import get_empty_analyzer_result, sanitize_results, sanitize_value


class TestSanitizeValue:
    """Test single value sanitization"""

    def test_none_becomes_empty_dict_by_default(self):
        assert sanitize_value(None) == {}

    def test_none_becomes_empty_list(self):
        assert sanitize_value(None, list) == []

    def test_none_becomes_zero_int(self):
        assert sanitize_value(None, int) == 0

    def test_none_becomes_zero_float(self):
        assert sanitize_value(None, float) == 0.0

    def test_none_becomes_empty_string(self):
        assert sanitize_value(None, str) == ""

    def test_non_none_value_unchanged(self):
        assert sanitize_value(42) == 42
        assert sanitize_value("hello") == "hello"
        assert sanitize_value([1, 2, 3]) == [1, 2, 3]


class TestSanitizeResults:
    """Test result dictionary sanitization"""

    def test_empty_dict_unchanged(self):
        assert sanitize_results({}) == {}

    def test_null_count_becomes_zero(self):
        results = {"packet_count": None, "byte_count": None}
        sanitized = sanitize_results(results)
        assert sanitized["packet_count"] == 0
        assert sanitized["byte_count"] == 0

    def test_null_rate_becomes_zero_float(self):
        results = {"loss_rate": None, "rtt": None, "latency": None}
        sanitized = sanitize_results(results)
        assert sanitized["loss_rate"] == 0.0
        assert sanitized["rtt"] == 0.0
        assert sanitized["latency"] == 0.0

    def test_null_list_becomes_empty_list(self):
        results = {"gaps": None, "events": None, "flows": None}
        sanitized = sanitize_results(results)
        assert sanitized["gaps"] == []
        assert sanitized["events"] == []
        assert sanitized["flows"] == []

    def test_nested_dict_sanitized_recursively(self):
        results = {
            "global_statistics": {
                "median_rtt": 0.05,
                "stdev_rtt": None,  # Common case: only 1 sample
                "mean_rtt": 0.05,
            }
        }
        sanitized = sanitize_results(results)
        assert sanitized["global_statistics"]["stdev_rtt"] == 0.0
        assert sanitized["global_statistics"]["median_rtt"] == 0.05

    def test_list_of_dicts_sanitized_recursively(self):
        results = {
            "flows": [
                {"flow_id": "1", "rtt": 0.1, "stdev": None},
                {"flow_id": "2", "rtt": None, "stdev": 0.01},
            ]
        }
        sanitized = sanitize_results(results)
        assert sanitized["flows"][0]["stdev"] == 0.0
        assert sanitized["flows"][1]["rtt"] == 0.0

    def test_real_world_rtt_analyzer_result(self):
        """Test actual RTT analyzer output with null stdev"""
        results = {
            "flows": {
                "192.168.1.100:52341 -> 10.0.0.50:22": {
                    "packet_count": 1,
                    "mean_rtt": 0.208,
                    "median_rtt": 0.208,
                    "stdev_rtt": None,  # Only 1 measurement
                    "rtt_spikes": 0,
                }
            }
        }
        sanitized = sanitize_results(results)
        flow = sanitized["flows"]["192.168.1.100:52341 -> 10.0.0.50:22"]
        assert flow["stdev_rtt"] == 0.0
        assert flow["mean_rtt"] == 0.208

    def test_non_recursive_mode(self):
        """Test that non-recursive mode only sanitizes top level"""
        results = {
            "top_level": None,
            "nested": {"inner": None},
        }
        sanitized = sanitize_results(results, recursive=False)
        assert sanitized["top_level"] == {}
        assert sanitized["nested"]["inner"] is None  # Not sanitized

    def test_mixed_types_preserved(self):
        """Test that non-null values of various types are preserved"""
        results = {
            "string_val": "test",
            "int_val": 42,
            "float_val": 3.14,
            "bool_val": True,
            "list_val": [1, 2, 3],
            "dict_val": {"key": "value"},
        }
        sanitized = sanitize_results(results)
        assert sanitized == results


class TestGetEmptyAnalyzerResult:
    """Test empty analyzer result structures"""

    def test_ip_fragmentation_empty_structure(self):
        empty = get_empty_analyzer_result("ip_fragmentation")
        assert empty["total_fragments"] == 0
        assert empty["fragmentation_rate"] == 0.0
        assert empty["flows_with_fragmentation"] == []

    def test_asymmetric_traffic_empty_structure(self):
        empty = get_empty_analyzer_result("asymmetric_traffic")
        assert empty["asymmetric_flows"] == 0
        assert empty["asymmetry_rate"] == 0.0
        assert empty["worst_asymmetric_flows"] == []

    def test_sack_empty_structure(self):
        empty = get_empty_analyzer_result("sack")
        assert empty["total_tcp_packets"] == 0
        assert empty["sack_usage_pct"] == 0.0
        assert empty["sack_events"] == []

    def test_unknown_analyzer_returns_empty_dict(self):
        empty = get_empty_analyzer_result("unknown_analyzer")
        assert empty == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
