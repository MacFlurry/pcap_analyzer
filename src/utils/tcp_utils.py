"""
TCP utilities for flag checking and TCP-specific operations.

This module provides constants and functions for working with TCP flags,
ensuring proper operator precedence and consistent behavior across analyzers.
"""

from typing import Any

# TCP flag constants (from RFC 793)
SYN = 0x02  # Synchronize sequence numbers
ACK = 0x10  # Acknowledgment field significant
FIN = 0x01  # No more data from sender
RST = 0x04  # Reset the connection
PSH = 0x08  # Push function


def is_syn(tcp: Any) -> bool:
    """
    Check if packet is a SYN packet (SYN flag set, ACK flag not set).

    This represents the first packet in a TCP three-way handshake.

    Args:
        tcp: TCP layer object with a flags attribute

    Returns:
        bool: True if SYN is set and ACK is not set, False otherwise
    """
    return (tcp.flags & SYN) and not (tcp.flags & ACK)


def is_synack(tcp: Any) -> bool:
    """
    Check if packet is a SYN-ACK packet (both SYN and ACK flags set).

    This represents the second packet in a TCP three-way handshake.

    Args:
        tcp: TCP layer object with a flags attribute

    Returns:
        bool: True if both SYN and ACK are set, False otherwise
    """
    return (tcp.flags & SYN) and (tcp.flags & ACK)


def is_ack(tcp: Any) -> bool:
    """
    Check if packet has the ACK flag set.

    Args:
        tcp: TCP layer object with a flags attribute

    Returns:
        bool: True if ACK flag is set, False otherwise
    """
    return bool(tcp.flags & ACK)


def is_fin(tcp: Any) -> bool:
    """
    Check if packet has the FIN flag set.

    FIN packets are used to gracefully close TCP connections.

    Args:
        tcp: TCP layer object with a flags attribute

    Returns:
        bool: True if FIN flag is set, False otherwise
    """
    return bool(tcp.flags & FIN)


def is_rst(tcp: Any) -> bool:
    """
    Check if packet has the RST flag set.

    RST packets are used to abruptly terminate TCP connections,
    often indicating errors or refused connections.

    Args:
        tcp: TCP layer object with a flags attribute

    Returns:
        bool: True if RST flag is set, False otherwise
    """
    return bool(tcp.flags & RST)
