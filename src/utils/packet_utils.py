"""
Packet utilities for safe attribute extraction and protocol detection.

This module provides functions for safely extracting information from
Scapy packets and detecting protocols.
"""

from typing import Any, Optional


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
    if packet.haslayer("TCP"):
        return "TCP"
    elif packet.haslayer("UDP"):
        return "UDP"
    elif packet.haslayer("ICMP"):
        return "ICMP"
    elif packet.haslayer("IP"):
        return "IP"
    else:
        return "Other"


def get_ip_layer(packet: Any) -> Optional[Any]:
    """
    Get the IP layer from a packet, supporting both IPv4 and IPv6.

    This function provides a unified way to extract the IP layer regardless
    of whether the packet uses IPv4 or IPv6. This is critical for IPv6 support
    across all analyzers.

    Args:
        packet: Scapy packet object

    Returns:
        IPv4 or IPv6 layer if present, None otherwise

    Example:
        >>> ip = get_ip_layer(packet)
        >>> if ip:
        >>>     src_ip = ip.src
        >>>     dst_ip = ip.dst
    """
    if packet.haslayer("IP"):
        return packet["IP"]
    elif packet.haslayer("IPv6"):
        return packet["IPv6"]
    return None


def get_src_ip(packet: Any) -> str:
    """
    Extract source IP address from packet (IPv4 or IPv6).

    Args:
        packet: Scapy packet object

    Returns:
        str: Source IP address, or "N/A" if not available
    """
    ip = get_ip_layer(packet)
    if ip:
        return ip.src
    return "N/A"


def get_dst_ip(packet: Any) -> str:
    """
    Extract destination IP address from packet (IPv4 or IPv6).

    Args:
        packet: Scapy packet object

    Returns:
        str: Destination IP address, or "N/A" if not available
    """
    ip = get_ip_layer(packet)
    if ip:
        return ip.dst
    return "N/A"


def has_ip_layer(packet: Any) -> bool:
    """
    Check if packet has an IP layer (IPv4 or IPv6).

    Args:
        packet: Scapy packet object

    Returns:
        bool: True if packet has IPv4 or IPv6 layer
    """
    return bool(packet.haslayer("IP") or packet.haslayer("IPv6"))
