"""
Flow utilities for network flow identification and tracking.

This module provides standardized flow key generation to ensure
consistent flow identification across all analyzers.
"""

from typing import Optional


def normalize_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    bidirectional: bool = True
) -> str:
    """
    Generate a standardized flow key for tracking network flows.

    This function creates a consistent identifier for network flows that can be
    used to track related packets. In bidirectional mode, it ensures that packets
    from A->B and B->A map to the same flow key by sorting the endpoints.

    Args:
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source port number (optional, defaults to 0)
        dst_port: Destination port number (optional, defaults to 0)
        bidirectional: If True, make flow key bidirectional by sorting endpoints.
                      If False, create directional flow key (A->B != B->A)

    Returns:
        str: Standardized flow key in format:
             - Bidirectional: "ip1:port1<->ip2:port2" (sorted)
             - Directional: "src_ip:src_port->dst_ip:dst_port"

    Examples:
        >>> normalize_flow_key("10.0.0.1", "10.0.0.2", 80, 443)
        "10.0.0.1:80<->10.0.0.2:443"

        >>> normalize_flow_key("10.0.0.2", "10.0.0.1", 443, 80)
        "10.0.0.1:80<->10.0.0.2:443"  # Same as above (bidirectional)

        >>> normalize_flow_key("10.0.0.1", "10.0.0.2", 80, 443, bidirectional=False)
        "10.0.0.1:80->10.0.0.2:443"
    """
    # Use 0 as default port if not specified
    src_port_val = src_port if src_port is not None else 0
    dst_port_val = dst_port if dst_port is not None else 0

    if bidirectional:
        # Sort endpoints to make bidirectional flows map to same key
        # Compare by (IP, port) tuple to ensure consistent ordering
        if (src_ip, src_port_val) <= (dst_ip, dst_port_val):
            return f"{src_ip}:{src_port_val}<->{dst_ip}:{dst_port_val}"
        else:
            return f"{dst_ip}:{dst_port_val}<->{src_ip}:{src_port_val}"
    else:
        # Directional flow key
        return f"{src_ip}:{src_port_val}->{dst_ip}:{dst_port_val}"
