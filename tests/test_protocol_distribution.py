"""
Test suite for Protocol Distribution Analyzer

Tests protocol distribution analysis including:
- Layer 3 protocol breakdown (IP, IPv6, ARP, etc.)
- Layer 4 protocol breakdown (TCP, UDP, ICMP, etc.)
- Port distribution analysis
- Top talkers identification
- Protocol usage statistics
"""

import pytest
from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether, IPv6


class TestProtocolDistributionBasics:
    """Test basic protocol distribution functionality."""

    def test_empty_packets_returns_empty_results(self):
        """Test analyzer handles empty packet list."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze([])

        assert results["total_packets"] == 0
        assert results["layer3_distribution"] == {}
        assert results["layer4_distribution"] == {}

    def test_single_tcp_packet_detected(self):
        """Test analyzer detects single TCP packet."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80)]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 1
        assert results["layer3_distribution"]["IPv4"] == 1
        assert results["layer4_distribution"]["TCP"] == 1

    def test_single_udp_packet_detected(self):
        """Test analyzer detects single UDP packet."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=53, dport=12345)]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 1
        assert results["layer3_distribution"]["IPv4"] == 1
        assert results["layer4_distribution"]["UDP"] == 1

    def test_icmp_packet_detected(self):
        """Test analyzer detects ICMP packets."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / ICMP()]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 1
        assert results["layer3_distribution"]["IPv4"] == 1
        assert results["layer4_distribution"]["ICMP"] == 1

    def test_ipv6_packet_detected(self):
        """Test analyzer detects IPv6 packets."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=12345, dport=80)]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 1
        assert results["layer3_distribution"]["IPv6"] == 1
        assert results["layer4_distribution"]["TCP"] == 1

    def test_arp_packet_detected(self):
        """Test analyzer detects ARP packets."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [Ether() / ARP(pdst="192.168.1.1")]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 1
        assert results["layer3_distribution"]["ARP"] == 1


class TestProtocolDistributionMixedTraffic:
    """Test protocol distribution with mixed traffic."""

    def test_mixed_tcp_udp_traffic(self):
        """Test distribution of TCP and UDP traffic."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / TCP(sport=12346, dport=443),
            Ether() / IP() / UDP(sport=53, dport=12345),
            Ether() / IP() / UDP(sport=53, dport=12346),
            Ether() / IP() / UDP(sport=53, dport=12347),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 5
        assert results["layer4_distribution"]["TCP"] == 2
        assert results["layer4_distribution"]["UDP"] == 3
        assert results["layer4_percentages"]["TCP"] == 40.0
        assert results["layer4_percentages"]["UDP"] == 60.0

    def test_ipv4_ipv6_mix(self):
        """Test distribution of IPv4 and IPv6 traffic."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / TCP(sport=12346, dport=80),
            Ether() / IPv6() / TCP(sport=12345, dport=80),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["total_packets"] == 3
        assert results["layer3_distribution"]["IPv4"] == 2
        assert results["layer3_distribution"]["IPv6"] == 1
        assert results["layer3_percentages"]["IPv4"] == pytest.approx(66.67, rel=0.01)
        assert results["layer3_percentages"]["IPv6"] == pytest.approx(33.33, rel=0.01)


class TestPortDistribution:
    """Test port distribution analysis."""

    def test_tcp_port_distribution(self):
        """Test TCP destination port distribution."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / TCP(sport=12346, dport=80),
            Ether() / IP() / TCP(sport=12347, dport=443),
            Ether() / IP() / TCP(sport=12348, dport=443),
            Ether() / IP() / TCP(sport=12349, dport=22),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["tcp_port_distribution"][80] == 2
        assert results["tcp_port_distribution"][443] == 2
        assert results["tcp_port_distribution"][22] == 1

    def test_udp_port_distribution(self):
        """Test UDP destination port distribution."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / UDP(sport=12345, dport=53),
            Ether() / IP() / UDP(sport=12346, dport=53),
            Ether() / IP() / UDP(sport=12347, dport=123),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["udp_port_distribution"][53] == 2
        assert results["udp_port_distribution"][123] == 1

    def test_top_tcp_ports_identified(self):
        """Test top TCP ports are identified correctly."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = []
        # Create 100 packets to port 80
        for i in range(100):
            packets.append(Ether() / IP() / TCP(sport=10000 + i, dport=80))
        # Create 50 packets to port 443
        for i in range(50):
            packets.append(Ether() / IP() / TCP(sport=20000 + i, dport=443))
        # Create 10 packets to port 22
        for i in range(10):
            packets.append(Ether() / IP() / TCP(sport=30000 + i, dport=22))

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        # Top 3 ports should be [80, 443, 22]
        assert len(results["top_tcp_ports"]) >= 3
        assert results["top_tcp_ports"][0]["port"] == 80
        assert results["top_tcp_ports"][0]["count"] == 100
        assert results["top_tcp_ports"][1]["port"] == 443
        assert results["top_tcp_ports"][1]["count"] == 50
        assert results["top_tcp_ports"][2]["port"] == 22
        assert results["top_tcp_ports"][2]["count"] == 10


class TestProtocolStatistics:
    """Test protocol usage statistics."""

    def test_protocol_bytes_calculation(self):
        """Test total bytes per protocol are calculated."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80) / (b"A" * 100),
            Ether() / IP() / TCP(sport=12346, dport=80) / (b"B" * 200),
            Ether() / IP() / UDP(sport=53, dport=12345) / (b"C" * 50),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        # TCP should have more bytes than UDP
        assert "protocol_bytes" in results
        assert results["protocol_bytes"]["TCP"] > results["protocol_bytes"]["UDP"]

    def test_unique_flows_counted(self):
        """Test unique flows are counted per protocol."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            # Flow 1: 192.168.1.1:12345 -> 10.0.0.1:80
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            # Flow 2: 192.168.1.2:12346 -> 10.0.0.1:80
            Ether() / IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=12346, dport=80),
            # UDP Flow: 192.168.1.1:53 -> 10.0.0.1:12345
            Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=53, dport=12345),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert results["unique_flows"]["TCP"] == 2
        assert results["unique_flows"]["UDP"] == 1


class TestServiceIdentification:
    """Test well-known service identification."""

    def test_http_traffic_identified(self):
        """Test HTTP traffic on port 80 is identified."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / TCP(sport=12346, dport=80),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert "service_distribution" in results
        assert "HTTP" in results["service_distribution"]
        assert results["service_distribution"]["HTTP"] == 2

    def test_https_traffic_identified(self):
        """Test HTTPS traffic on port 443 is identified."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / TCP(sport=12345, dport=443),
            Ether() / IP() / TCP(sport=12346, dport=443),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert "HTTPS" in results["service_distribution"]
        assert results["service_distribution"]["HTTPS"] == 2

    def test_dns_traffic_identified(self):
        """Test DNS traffic on port 53 is identified."""
        from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer

        packets = [
            Ether() / IP() / UDP(sport=12345, dport=53),
            Ether() / IP() / UDP(sport=12346, dport=53),
        ]

        analyzer = ProtocolDistributionAnalyzer()
        results = analyzer.analyze(packets)

        assert "DNS" in results["service_distribution"]
        assert results["service_distribution"]["DNS"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
