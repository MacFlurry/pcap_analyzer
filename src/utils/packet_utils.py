"""
Packet utilities for safe attribute extraction and protocol detection.

This module provides functions for safely extracting information from
Scapy packets and detecting protocols.
"""

from typing import Any


def safe_get_time(packet: Any) -> float:
    """
    Safely extract timestamp from a packet.

    Handles various edge cases where packet.time might not be available
    or might not be a valid float.

    Args:
        packet: Scapy packet object

    Returns:
        float: Packet timestamp in seconds since epoch, or 0.0 if unavailable
    """
    try:
        return float(packet.time)
    except (AttributeError, TypeError, ValueError):
        return 0.0


def get_protocol(packet: Any) -> str:
    """
    Detect the highest-level protocol in a packet.

    Checks for common protocols in order of specificity (most specific first).
    Returns the highest-level protocol found in the packet.

    Args:
        packet: Scapy packet object

    Returns:
        str: Protocol name ('TCP', 'UDP', 'ICMP', 'IP', or 'Other')
    """
    if packet.haslayer('TCP'):
        return 'TCP'
    elif packet.haslayer('UDP'):
        return 'UDP'
    elif packet.haslayer('ICMP'):
        return 'ICMP'
    elif packet.haslayer('IP'):
        return 'IP'
    else:
        return 'Other'
