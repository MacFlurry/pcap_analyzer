"""
Shared utilities module for PCAP analyzers.

This module provides common functionality used across multiple analyzers
to eliminate code duplication and ensure consistency.
"""

from .flow_utils import normalize_flow_key
from .packet_utils import get_protocol, safe_get_time
from .stats import calculate_stats
from .tcp_utils import ACK, FIN, PSH, RST, SYN, is_ack, is_fin, is_rst, is_syn, is_synack

__all__ = [
    # TCP utilities
    "SYN",
    "ACK",
    "FIN",
    "RST",
    "PSH",
    "is_syn",
    "is_synack",
    "is_ack",
    "is_fin",
    "is_rst",
    # Flow utilities
    "normalize_flow_key",
    # Packet utilities
    "safe_get_time",
    "get_protocol",
    # Statistics utilities
    "calculate_stats",
]
