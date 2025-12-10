"""
Result Sanitizer - Ensures analyzer results have no null values

Replaces null/None values with sensible defaults to prevent:
- JSON rendering issues
- Template errors when accessing nested fields
- Inconsistent data structures across analyzers

Usage:
    from src.utils.result_sanitizer import sanitize_results
    results = analyzer.get_results()
    clean_results = sanitize_results(results)
"""

from typing import Any, Dict, List, Union


def sanitize_value(value: Any, default_type: type = dict) -> Any:
    """
    Sanitize a single value by replacing None with a sensible default.

    Args:
        value: Value to sanitize
        default_type: Type to use for default (dict, list, int, float, str)

    Returns:
        Sanitized value (never None)
    """
    if value is None:
        if default_type == dict:
            return {}
        elif default_type == list:
            return []
        elif default_type == int:
            return 0
        elif default_type == float:
            return 0.0
        elif default_type == str:
            return ""
        else:
            return default_type()

    return value


def sanitize_results(results: Dict[str, Any], recursive: bool = True) -> Dict[str, Any]:
    """
    Recursively sanitize analyzer results by replacing None values.

    Strategy:
    - None dict values -> {}
    - None list values -> []
    - None numeric values -> 0 or 0.0
    - None string values -> ""

    Args:
        results: Analyzer results dictionary
        recursive: Whether to recursively sanitize nested structures

    Returns:
        Sanitized results dictionary (safe for JSON/templates)
    """
    if not isinstance(results, dict):
        return results

    sanitized = {}

    for key, value in results.items():
        if value is None:
            # Infer type from key name
            if any(word in key.lower() for word in ["count", "packets", "bytes", "number"]):
                sanitized[key] = 0
            elif any(
                word in key.lower()
                for word in [
                    "rate",
                    "rtt",
                    "latency",
                    "duration",
                    "time",
                    "pct",
                    "ratio",
                    "stdev",
                    "std",
                    "deviation",
                    "jitter",
                ]
            ):
                sanitized[key] = 0.0
            elif any(word in key.lower() for word in ["list", "items", "events", "gaps", "flows"]):
                sanitized[key] = []
            else:
                # Default to empty dict for complex structures
                sanitized[key] = {}

        elif recursive and isinstance(value, dict):
            # Recursively sanitize nested dicts
            sanitized[key] = sanitize_results(value, recursive=True)

        elif recursive and isinstance(value, list):
            # Recursively sanitize list items
            sanitized[key] = [
                sanitize_results(item, recursive=True) if isinstance(item, dict) else item for item in value
            ]

        else:
            sanitized[key] = value

    return sanitized


def get_empty_analyzer_result(analyzer_type: str) -> Dict[str, Any]:
    """
    Get standard empty result structure for a given analyzer type.

    This ensures consistency when analyzers have no data to report.

    Args:
        analyzer_type: Type of analyzer (e.g., 'sack', 'ip_fragmentation')

    Returns:
        Empty result structure with all expected fields initialized
    """
    empty_structures = {
        "ip_fragmentation": {
            "total_fragments": 0,
            "fragmented_packets": 0,
            "fragmentation_rate": 0.0,
            "reassembly_timeouts": 0,
            "flows_with_fragmentation": [],
        },
        "asymmetric_traffic": {
            "asymmetric_flows": 0,
            "total_flows_analyzed": 0,
            "asymmetry_rate": 0.0,
            "worst_asymmetric_flows": [],
        },
        "sack": {
            "total_tcp_packets": 0,
            "sack_packets": 0,
            "sack_usage_pct": 0.0,
            "dsack_packets": 0,
            "dsack_rate": 0.0,
            "sack_events": [],
        },
    }

    return empty_structures.get(analyzer_type, {})
