"""
Pytest configuration and shared fixtures for PCAP Analyzer tests.
"""

import pytest
from scapy.all import IP, TCP, UDP, DNS, ICMP, Ether, Packet
from typing import List


@pytest.fixture
def sample_tcp_packet() -> Packet:
    """Create a sample TCP packet for testing."""
    return Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S", seq=1000)


@pytest.fixture
def sample_tcp_syn_packet() -> Packet:
    """Create a TCP SYN packet."""
    return Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S", seq=1000)


@pytest.fixture
def sample_tcp_synack_packet() -> Packet:
    """Create a TCP SYN-ACK packet."""
    return Ether() / IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)


@pytest.fixture
def sample_tcp_ack_packet() -> Packet:
    """Create a TCP ACK packet."""
    return Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="A", seq=1001, ack=2001)


@pytest.fixture
def sample_tcp_data_packet() -> Packet:
    """Create a TCP data packet."""
    return Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / b"GET / HTTP/1.1\r\n"


@pytest.fixture
def sample_tcp_fin_packet() -> Packet:
    """Create a TCP FIN packet."""
    return Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="FA", seq=1017, ack=2001)


@pytest.fixture
def sample_tcp_rst_packet() -> Packet:
    """Create a TCP RST packet."""
    return Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="R", seq=1001)


@pytest.fixture
def sample_udp_packet() -> Packet:
    """Create a sample UDP packet."""
    return Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53210, dport=53)


@pytest.fixture
def sample_dns_query() -> Packet:
    """Create a DNS query packet."""
    return Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53210, dport=53) / DNS(rd=1, qd=DNS.DNSQR(qname="example.com"))


@pytest.fixture
def sample_dns_response() -> Packet:
    """Create a DNS response packet."""
    return Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=53210) / DNS(
        qr=1,
        qd=DNS.DNSQR(qname="example.com"),
        an=DNS.DNSRR(rrname="example.com", rdata="93.184.216.34")
    )


@pytest.fixture
def sample_icmp_packet() -> Packet:
    """Create an ICMP echo request packet."""
    return Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / ICMP(type=8, code=0)


@pytest.fixture
def sample_ipv6_packet() -> Packet:
    """Create an IPv6 packet."""
    from scapy.all import IPv6
    return Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=12345, dport=80, flags="S", seq=1000)


@pytest.fixture
def tcp_handshake_packets(sample_tcp_syn_packet, sample_tcp_synack_packet, sample_tcp_ack_packet) -> List[Packet]:
    """Create a complete TCP handshake sequence."""
    return [sample_tcp_syn_packet, sample_tcp_synack_packet, sample_tcp_ack_packet]


@pytest.fixture
def tcp_connection_packets(tcp_handshake_packets, sample_tcp_data_packet, sample_tcp_fin_packet) -> List[Packet]:
    """Create a complete TCP connection with data transfer and close."""
    return tcp_handshake_packets + [sample_tcp_data_packet, sample_tcp_fin_packet]


@pytest.fixture
def retransmission_packets() -> List[Packet]:
    """Create packets demonstrating a retransmission."""
    # Original data packet
    pkt1 = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / b"DATA1"
    # Retransmission of same data
    pkt2 = Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="PA", seq=1001, ack=2001) / b"DATA1"
    return [pkt1, pkt2]


@pytest.fixture
def mock_timestamp():
    """Mock timestamp for testing time-based analyzers."""
    return 1638360000.0  # 2021-12-01 12:00:00 UTC
