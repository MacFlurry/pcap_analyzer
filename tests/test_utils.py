"""
Unit tests for utility modules.
"""

import pytest
from scapy.all import IP, TCP, Ether, IPv6

from src.utils.packet_utils import get_dst_ip, get_ip_layer, get_src_ip, has_ip_layer
from src.utils.tcp_utils import ACK, FIN, RST, SYN, get_tcp_logical_length, is_ack, is_fin, is_rst, is_syn, is_synack


class TestPacketUtils:
    """Tests for packet utility functions."""

    def test_get_ip_layer_ipv4(self, sample_tcp_packet):
        """Test get_ip_layer with IPv4 packet."""
        ip_layer = get_ip_layer(sample_tcp_packet)
        assert ip_layer is not None
        assert hasattr(ip_layer, "src")
        assert hasattr(ip_layer, "dst")

    def test_get_ip_layer_ipv6(self, sample_ipv6_packet):
        """Test get_ip_layer with IPv6 packet."""
        ip_layer = get_ip_layer(sample_ipv6_packet)
        assert ip_layer is not None
        assert hasattr(ip_layer, "src")
        assert hasattr(ip_layer, "dst")

    def test_get_ip_layer_no_ip(self):
        """Test get_ip_layer with packet without IP layer."""
        packet = Ether()
        ip_layer = get_ip_layer(packet)
        assert ip_layer is None

    def test_get_src_ip_ipv4(self, sample_tcp_packet):
        """Test get_src_ip with IPv4 packet."""
        src_ip = get_src_ip(sample_tcp_packet)
        assert src_ip == "192.168.1.100"

    def test_get_dst_ip_ipv4(self, sample_tcp_packet):
        """Test get_dst_ip with IPv4 packet."""
        dst_ip = get_dst_ip(sample_tcp_packet)
        assert dst_ip == "192.168.1.1"

    def test_get_src_ip_ipv6(self, sample_ipv6_packet):
        """Test get_src_ip with IPv6 packet."""
        src_ip = get_src_ip(sample_ipv6_packet)
        assert src_ip == "2001:db8::1"

    def test_get_dst_ip_ipv6(self, sample_ipv6_packet):
        """Test get_dst_ip with IPv6 packet."""
        dst_ip = get_dst_ip(sample_ipv6_packet)
        assert dst_ip == "2001:db8::2"

    def test_get_src_ip_no_ip(self):
        """Test get_src_ip with packet without IP layer."""
        packet = Ether()
        src_ip = get_src_ip(packet)
        assert src_ip == "N/A"

    def test_has_ip_layer_ipv4(self, sample_tcp_packet):
        """Test has_ip_layer with IPv4 packet."""
        assert has_ip_layer(sample_tcp_packet) is True

    def test_has_ip_layer_ipv6(self, sample_ipv6_packet):
        """Test has_ip_layer with IPv6 packet."""
        assert has_ip_layer(sample_ipv6_packet) is True

    def test_has_ip_layer_no_ip(self):
        """Test has_ip_layer with packet without IP layer."""
        packet = Ether()
        assert has_ip_layer(packet) is False


class TestTCPUtils:
    """Tests for TCP utility functions."""

    def test_is_syn_true(self, sample_tcp_syn_packet):
        """Test is_syn with SYN packet."""
        tcp = sample_tcp_syn_packet[TCP]
        assert is_syn(tcp) is True

    def test_is_syn_false_synack(self, sample_tcp_synack_packet):
        """Test is_syn with SYN-ACK packet (should be False)."""
        tcp = sample_tcp_synack_packet[TCP]
        assert is_syn(tcp) is False  # SYN-ACK is not pure SYN

    def test_is_synack_true(self, sample_tcp_synack_packet):
        """Test is_synack with SYN-ACK packet."""
        tcp = sample_tcp_synack_packet[TCP]
        assert is_synack(tcp) is True

    def test_is_synack_false(self, sample_tcp_syn_packet):
        """Test is_synack with pure SYN packet."""
        tcp = sample_tcp_syn_packet[TCP]
        assert is_synack(tcp) is False

    def test_is_ack_true(self, sample_tcp_ack_packet):
        """Test is_ack with ACK packet."""
        tcp = sample_tcp_ack_packet[TCP]
        assert is_ack(tcp) is True

    def test_is_ack_false(self, sample_tcp_syn_packet):
        """Test is_ack with SYN packet (no ACK flag)."""
        tcp = sample_tcp_syn_packet[TCP]
        assert is_ack(tcp) is False

    def test_is_fin_true(self, sample_tcp_fin_packet):
        """Test is_fin with FIN packet."""
        tcp = sample_tcp_fin_packet[TCP]
        assert is_fin(tcp) is True

    def test_is_fin_false(self, sample_tcp_syn_packet):
        """Test is_fin with SYN packet."""
        tcp = sample_tcp_syn_packet[TCP]
        assert is_fin(tcp) is False

    def test_is_rst_true(self, sample_tcp_rst_packet):
        """Test is_rst with RST packet."""
        tcp = sample_tcp_rst_packet[TCP]
        assert is_rst(tcp) is True

    def test_is_rst_false(self, sample_tcp_syn_packet):
        """Test is_rst with SYN packet."""
        tcp = sample_tcp_syn_packet[TCP]
        assert is_rst(tcp) is False

    def test_get_tcp_logical_length_data_only(self, sample_tcp_data_packet):
        """Test logical length with data packet (no SYN/FIN)."""
        tcp = sample_tcp_data_packet[TCP]
        length = get_tcp_logical_length(tcp)
        # Should be payload length only (no SYN/FIN)
        assert length == len(tcp.payload)

    def test_get_tcp_logical_length_syn(self, sample_tcp_syn_packet):
        """Test logical length with SYN packet."""
        tcp = sample_tcp_syn_packet[TCP]
        length = get_tcp_logical_length(tcp)
        # SYN with no data = 1
        assert length == 1

    def test_get_tcp_logical_length_fin(self):
        """Test logical length with FIN packet."""
        packet = Ether() / IP() / TCP(flags="F")
        tcp = packet[TCP]
        length = get_tcp_logical_length(tcp)
        # FIN with no data = 1
        assert length == 1

    def test_get_tcp_logical_length_syn_with_data(self):
        """Test logical length with SYN packet containing data."""
        packet = Ether() / IP() / TCP(flags="S") / b"DATA"
        tcp = packet[TCP]
        length = get_tcp_logical_length(tcp)
        # SYN (1) + data length (4) = 5
        assert length == 5

    def test_get_tcp_logical_length_fin_with_data(self):
        """Test logical length with FIN packet containing data."""
        packet = Ether() / IP() / TCP(flags="FA") / b"LAST"
        tcp = packet[TCP]
        length = get_tcp_logical_length(tcp)
        # FIN (1) + data length (4) = 5
        assert length == 5

    def test_get_tcp_logical_length_pure_ack(self, sample_tcp_ack_packet):
        """Test logical length with pure ACK packet."""
        tcp = sample_tcp_ack_packet[TCP]
        length = get_tcp_logical_length(tcp)
        # Pure ACK with no data or SYN/FIN = 0
        assert length == 0

    def test_tcp_flags_constants(self):
        """Test that TCP flag constants are correct."""
        assert SYN == 0x02
        assert ACK == 0x10
        assert FIN == 0x01
        assert RST == 0x04
