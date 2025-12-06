"""
Shared utilities module for PCAP analyzers.

This module provides common functionality used across multiple analyzers
to eliminate code duplication and ensure consistency.
"""

from .tcp_utils import (
    SYN, ACK, FIN, RST, PSH,
    is_syn, is_synack, is_ack, is_fin, is_rst
)

from .flow_utils import normalize_flow_key

from .packet_utils import safe_get_time, get_protocol

from .stats import calculate_stats

__all__ = [
    # TCP utilities
    'SYN', 'ACK', 'FIN', 'RST', 'PSH',
    'is_syn', 'is_synack', 'is_ack', 'is_fin', 'is_rst',

    # Flow utilities
    'normalize_flow_key',

    # Packet utilities
    'safe_get_time', 'get_protocol',

    # Statistics utilities
    'calculate_stats'
]
