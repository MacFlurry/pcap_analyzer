"""
Statistical utilities for calculating metrics from network data.

This module provides functions for calculating common statistical measures
used in network analysis and reporting.
"""

from typing import Dict, List

import numpy as np


def calculate_stats(values: list[float]) -> dict[str, float]:
    """
    Calculate comprehensive statistics for a list of values.

    Computes min, max, mean, median, percentiles (p50, p95, p99), and
    standard deviation for the provided values.

    Args:
        values: List of numeric values to analyze

    Returns:
        dict: Dictionary containing statistical measures:
            - min: Minimum value
            - max: Maximum value
            - mean: Average value
            - median: Middle value (same as p50)
            - p50: 50th percentile (median)
            - p95: 95th percentile
            - p99: 99th percentile
            - stddev: Sample standard deviation (using ddof=1)

        Returns empty dict if values list is empty.

    Examples:
        >>> calculate_stats([1.0, 2.0, 3.0, 4.0, 5.0])
        {
            'min': 1.0,
            'max': 5.0,
            'mean': 3.0,
            'median': 3.0,
            'p50': 3.0,
            'p95': 4.8,
            'p99': 4.96,
            'stddev': 1.58...
        }

        >>> calculate_stats([])
        {}
    """
    if not values:
        return {}

    arr = np.array(values)

    return {
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "mean": float(np.mean(arr)),
        "median": float(np.median(arr)),
        "p50": float(np.percentile(arr, 50)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "stddev": float(np.std(arr, ddof=1)),  # Sample standard deviation
    }
