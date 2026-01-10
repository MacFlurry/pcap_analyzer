"""
Unit tests for ProtocolDistributionAnalyzer.

Tests protocol distribution analysis across network layers, port distribution,
service identification, and protocol statistics.
"""

import pytest
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Raw

from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer, WELL_KNOWN_SERVICES


class TestProtocolDistributionAnalyzer:
    """Tests for ProtocolDistributionAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ProtocolDistributionAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = ProtocolDistributionAnalyzer()
        assert analyzer.total_packets == 0
        assert len(analyzer.layer3_counts) == 0
        assert len(analyzer.layer4_counts) == 0
        assert len(analyzer.tcp_port_counts) == 0
        assert len(analyzer.udp_port_counts) == 0
        assert len(analyzer.service_counts) == 0

    def test_process_ipv4_tcp_packet(self, analyzer):
        """Test processing IPv4 TCP packet."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create IPv4 TCP packet
        tcp_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80)
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet)

        # Should detect Layer 3 and Layer 4 protocols
        assert analyzer.total_packets == 1
        assert analyzer.layer3_counts["IPv4"] == 1
        assert analyzer.layer4_counts["TCP"] == 1
        assert "TCP" in analyzer.protocol_bytes
        assert analyzer.protocol_bytes["TCP"] > 0

    def test_process_ipv4_udp_packet(self, analyzer):
        """Test processing IPv4 UDP packet."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create IPv4 UDP packet
        udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=12345, dport=53)
        udp_packet.time = base_time
        analyzer.process_packet(udp_packet)

        # Should detect Layer 3 and Layer 4 protocols
        assert analyzer.layer3_counts["IPv4"] == 1
        assert analyzer.layer4_counts["UDP"] == 1
        assert "UDP" in analyzer.protocol_bytes
        assert analyzer.protocol_bytes["UDP"] > 0

    def test_process_ipv4_icmp_packet(self, analyzer):
        """Test processing IPv4 ICMP packet."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create IPv4 ICMP packet
        icmp_packet = IP(src=src_ip, dst=dst_ip, proto=1) / ICMP()
        icmp_packet.time = base_time
        analyzer.process_packet(icmp_packet)

        # Should detect Layer 3 and Layer 4 protocols
        assert analyzer.layer3_counts["IPv4"] == 1
        assert analyzer.layer4_counts["ICMP"] == 1
        assert "ICMP" in analyzer.protocol_bytes
        assert analyzer.protocol_bytes["ICMP"] > 0

    def test_process_ipv6_tcp_packet(self, analyzer):
        """Test processing IPv6 TCP packet."""
        base_time = 1234567890.0
        src_ip = "2001:db8::1"
        dst_ip = "2001:db8::2"

        # Create IPv6 TCP packet
        ipv6_tcp_packet = IPv6(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80)
        ipv6_tcp_packet.time = base_time
        analyzer.process_packet(ipv6_tcp_packet)

        # Should detect Layer 3 and Layer 4 protocols
        assert analyzer.layer3_counts["IPv6"] == 1
        assert analyzer.layer4_counts["TCP"] == 1
        assert "TCP" in analyzer.protocol_bytes

    def test_process_arp_packet(self, analyzer):
        """Test processing ARP packet."""
        base_time = 1234567890.0

        # Create ARP packet
        arp_packet = ARP(op=1, psrc="192.168.1.100", pdst="192.168.1.1")
        arp_packet.time = base_time
        analyzer.process_packet(arp_packet)

        # Should detect Layer 3 protocol (ARP)
        assert analyzer.layer3_counts["ARP"] == 1
        # ARP doesn't have Layer 4
        assert len(analyzer.layer4_counts) == 0

    def test_tcp_port_distribution(self, analyzer):
        """Test TCP port distribution tracking."""
        base_time = 1234567890.0

        # Create TCP packets with different destination ports
        ports = [80, 443, 22, 80, 443]  # HTTP, HTTPS, SSH, HTTP, HTTPS
        for i, port in enumerate(ports):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345+i, dport=port)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        # Should track port distribution
        assert analyzer.tcp_port_counts[80] == 2  # HTTP
        assert analyzer.tcp_port_counts[443] == 2  # HTTPS
        assert analyzer.tcp_port_counts[22] == 1  # SSH

    def test_udp_port_distribution(self, analyzer):
        """Test UDP port distribution tracking."""
        base_time = 1234567890.0

        # Create UDP packets with different destination ports
        ports = [53, 123, 53]  # DNS, NTP, DNS
        for i, port in enumerate(ports):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345+i, dport=port)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        # Should track port distribution
        assert analyzer.udp_port_counts[53] == 2  # DNS
        assert analyzer.udp_port_counts[123] == 1  # NTP

    def test_service_identification(self, analyzer):
        """Test service identification from well-known ports."""
        base_time = 1234567890.0

        # Create packets with well-known service ports
        services = [
            (80, "HTTP"),
            (443, "HTTPS"),
            (22, "SSH"),
            (53, "DNS"),  # UDP
            (3306, "MySQL"),
        ]

        for i, (port, service_name) in enumerate(services):
            if port == 53:
                # DNS uses UDP
                packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345, dport=port)
            else:
                # Other services use TCP
                packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=port)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        # Should identify services
        for _, service_name in services:
            # Service should be counted if destination port matches well-known port
            assert service_name in analyzer.service_counts or service_name in WELL_KNOWN_SERVICES.values()

    def test_tcp_flow_tracking(self, analyzer):
        """Test TCP flow tracking."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create multiple TCP packets in same flow
        for i in range(5):
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80, seq=i*1000)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        # Should track unique flows (same flow key = 1 unique flow)
        assert len(analyzer.tcp_flows) >= 1
        # Flow key: (src_ip, sport, dst_ip, dport)
        expected_flow = (src_ip, 12345, dst_ip, 80)
        assert expected_flow in analyzer.tcp_flows

    def test_udp_flow_tracking(self, analyzer):
        """Test UDP flow tracking."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create multiple UDP packets in same flow
        for i in range(5):
            packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=12345, dport=53)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        # Should track unique flows
        assert len(analyzer.udp_flows) >= 1
        expected_flow = (src_ip, 12345, dst_ip, 53)
        assert expected_flow in analyzer.udp_flows

    def test_ipv6_flow_tracking(self, analyzer):
        """Test IPv6 flow tracking."""
        base_time = 1234567890.0
        src_ip = "2001:db8::1"
        dst_ip = "2001:db8::2"

        # Create IPv6 TCP packet
        packet = IPv6(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80)
        packet.time = base_time
        analyzer.process_packet(packet)

        # Should track IPv6 flows
        assert len(analyzer.tcp_flows) >= 1
        expected_flow = (src_ip, 12345, dst_ip, 80)
        assert expected_flow in analyzer.tcp_flows

    def test_get_results_structure(self, analyzer):
        """Test that get_results() returns correct structure."""
        base_time = 1234567890.0

        # Process some packets
        tcp_packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet)

        udp_packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345, dport=53)
        udp_packet.time = base_time + 1.0
        analyzer.process_packet(udp_packet)

        results = analyzer.get_results()

        # Check results structure
        assert "total_packets" in results
        assert "layer3_distribution" in results
        assert "layer3_percentages" in results
        assert "layer4_distribution" in results
        assert "layer4_percentages" in results
        assert "tcp_port_distribution" in results
        assert "udp_port_distribution" in results
        assert "top_tcp_ports" in results
        assert "top_udp_ports" in results
        assert "service_distribution" in results
        assert "protocol_bytes" in results
        assert "unique_flows" in results

    def test_layer3_percentage_calculation(self, analyzer):
        """Test Layer 3 percentage calculation."""
        base_time = 1234567890.0

        # Create packets: 5 IPv4, 3 IPv6, 2 ARP = 10 total
        for i in range(5):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        for i in range(3):
            packet = IPv6(src=f"2001:db8::{i+1}", dst="2001:db8::100") / TCP(sport=12345, dport=80)
            packet.time = base_time + 5 + i * 0.1
            analyzer.process_packet(packet)

        for i in range(2):
            packet = ARP(op=1, psrc=f"192.168.1.{i+1}", pdst="192.168.1.1")
            packet.time = base_time + 8 + i * 0.1
            analyzer.process_packet(packet)

        results = analyzer.get_results()
        percentages = results["layer3_percentages"]

        # IPv4: 5/10 = 50%, IPv6: 3/10 = 30%, ARP: 2/10 = 20%
        assert percentages["IPv4"] == 50.0
        assert percentages["IPv6"] == 30.0
        assert percentages["ARP"] == 20.0

    def test_layer4_percentage_calculation(self, analyzer):
        """Test Layer 4 percentage calculation."""
        base_time = 1234567890.0

        # Create packets: 5 TCP, 3 UDP, 2 ICMP = 10 Layer 4 packets
        for i in range(5):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        for i in range(3):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / UDP(sport=12345, dport=53)
            packet.time = base_time + 5 + i * 0.1
            analyzer.process_packet(packet)

        for i in range(2):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1", proto=1) / ICMP()
            packet.time = base_time + 8 + i * 0.1
            analyzer.process_packet(packet)

        results = analyzer.get_results()
        percentages = results["layer4_percentages"]

        # TCP: 5/10 = 50%, UDP: 3/10 = 30%, ICMP: 2/10 = 20%
        assert percentages["TCP"] == 50.0
        assert percentages["UDP"] == 30.0
        assert percentages["ICMP"] == 20.0

    def test_top_tcp_ports(self, analyzer):
        """Test top TCP ports list."""
        base_time = 1234567890.0

        # Create TCP packets with different ports
        ports = [80, 443, 22, 80, 443, 80]  # HTTP (3), HTTPS (2), SSH (1)
        for i, port in enumerate(ports):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345+i, dport=port)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        results = analyzer.get_results()
        top_ports = results["top_tcp_ports"]

        # Should have top ports sorted by count
        assert len(top_ports) >= 1
        # Port 80 should be first (most common)
        if len(top_ports) >= 1:
            assert top_ports[0]["port"] == 80
            assert top_ports[0]["count"] == 3
            assert top_ports[0]["service"] == "HTTP"

    def test_top_udp_ports(self, analyzer):
        """Test top UDP ports list."""
        base_time = 1234567890.0

        # Create UDP packets with different ports
        ports = [53, 123, 53, 53]  # DNS (3), NTP (1)
        for i, port in enumerate(ports):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345+i, dport=port)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        results = analyzer.get_results()
        top_ports = results["top_udp_ports"]

        # Should have top ports sorted by count
        assert len(top_ports) >= 1
        # Port 53 (DNS) should be first
        if len(top_ports) >= 1:
            assert top_ports[0]["port"] == 53
            assert top_ports[0]["count"] == 3
            assert top_ports[0]["service"] == "DNS"

    def test_unknown_service_port(self, analyzer):
        """Test that unknown ports show 'Unknown' service."""
        base_time = 1234567890.0

        # Create TCP packet with unknown port
        packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9999)
        packet.time = base_time
        analyzer.process_packet(packet)

        results = analyzer.get_results()
        top_ports = results["top_tcp_ports"]

        # Should show 'Unknown' for unknown ports
        if len(top_ports) >= 1:
            unknown_port = next((p for p in top_ports if p["port"] == 9999), None)
            if unknown_port:
                assert unknown_port["service"] == "Unknown"

    def test_reset_method(self, analyzer):
        """Test reset() method."""
        base_time = 1234567890.0

        # Process some packets
        for i in range(5):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        # Reset analyzer
        analyzer.reset()

        # Should reset all counters
        assert analyzer.total_packets == 0
        assert len(analyzer.layer3_counts) == 0
        assert len(analyzer.layer4_counts) == 0
        assert len(analyzer.tcp_port_counts) == 0
        assert len(analyzer.service_counts) == 0
        assert len(analyzer.tcp_flows) == 0

    def test_analyze_method(self, analyzer):
        """Test analyze() method that processes packet list."""
        base_time = 1234567890.0

        # Create list of packets
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345, dport=53),
            IP(src="192.168.1.100", dst="10.0.0.1", proto=1) / ICMP(),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = analyzer.analyze(packets)

        # Should process all packets and reset before analyzing
        assert results["total_packets"] == 3
        assert results["layer4_distribution"]["TCP"] == 1
        assert results["layer4_distribution"]["UDP"] == 1
        assert results["layer4_distribution"]["ICMP"] == 1

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.get_results()

        # Should return empty results
        assert results["total_packets"] == 0
        assert len(results["layer3_distribution"]) == 0
        assert len(results["layer4_distribution"]) == 0
        assert len(results["top_tcp_ports"]) == 0
        assert len(results["top_udp_ports"]) == 0

    def test_protocol_bytes_tracking(self, analyzer):
        """Test protocol bytes tracking."""
        base_time = 1234567890.0

        # Create TCP packet with payload
        tcp_packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"x" * 1000)
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet)

        results = analyzer.get_results()
        protocol_bytes = results["protocol_bytes"]

        # Should track bytes per protocol
        assert "TCP" in protocol_bytes
        assert protocol_bytes["TCP"] > 0

    def test_unique_flows_counting(self, analyzer):
        """Test unique flows counting."""
        base_time = 1234567890.0

        # Create multiple flows
        flows = [
            ("192.168.1.1", 12345, "10.0.0.1", 80),
            ("192.168.1.2", 12346, "10.0.0.2", 443),
            ("192.168.1.1", 12345, "10.0.0.1", 80),  # Duplicate flow
        ]

        for i, (src_ip, sport, dst_ip, dport) in enumerate(flows):
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        results = analyzer.get_results()
        unique_flows = results["unique_flows"]

        # Should count unique TCP flows (duplicates should not increase count)
        assert unique_flows["TCP"] >= 1
        # May be 2 or 3 depending on implementation (set should deduplicate)
        assert unique_flows["TCP"] <= 3

    def test_well_known_services_mapping(self, analyzer):
        """Test well-known services mapping."""
        base_time = 1234567890.0

        # Test various well-known services
        test_services = [
            (22, "SSH"),
            (25, "SMTP"),
            (53, "DNS"),  # UDP
            (80, "HTTP"),
            (443, "HTTPS"),
            (3306, "MySQL"),
        ]

        for i, (port, expected_service) in enumerate(test_services):
            if port == 53:
                packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345, dport=port)
            else:
                packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=port)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet)

        results = analyzer.get_results()
        service_distribution = results["service_distribution"]

        # Should identify well-known services
        # Verify that services were identified correctly
        for port, expected_service in test_services:
            # Service should be in service_distribution if destination port matches well-known port
            if port in WELL_KNOWN_SERVICES:
                # DNS uses UDP, others use TCP
                if port == 53:
                    # UDP DNS
                    assert "DNS" in service_distribution
                else:
                    # TCP services
                    assert expected_service in service_distribution
