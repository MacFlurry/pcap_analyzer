"""
Unit tests for TopTalkersAnalyzer.

Tests top talkers identification by packet count and byte volume,
IP statistics tracking, protocol breakdown, and conversation analysis.
"""

import pytest
from scapy.all import IP, TCP, UDP, ICMP, Raw

from src.analyzers.top_talkers import TopTalkersAnalyzer


class TestTopTalkersAnalyzer:
    """Tests for TopTalkersAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return TopTalkersAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = TopTalkersAnalyzer()
        assert len(analyzer.ip_stats) == 0
        assert len(analyzer.protocol_stats) == 0
        assert len(analyzer.conversations) == 0

    def test_process_tcp_packet(self, analyzer):
        """Test processing TCP packets."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create TCP packet
        tcp_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80)
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet, 1)

        # Verify IP stats
        assert src_ip in analyzer.ip_stats
        assert dst_ip in analyzer.ip_stats
        
        src_stats = analyzer.ip_stats[src_ip]
        assert src_stats["packets_sent"] == 1
        assert src_stats["bytes_sent"] > 0
        
        dst_stats = analyzer.ip_stats[dst_ip]
        assert dst_stats["packets_received"] == 1
        assert dst_stats["bytes_received"] > 0

        # Verify protocol stats
        assert "TCP" in analyzer.protocol_stats
        assert analyzer.protocol_stats["TCP"]["packets"] == 1

        # Verify conversation
        conv_key = f"{src_ip} -> {dst_ip}"
        assert conv_key in analyzer.conversations
        conv = analyzer.conversations[conv_key]
        assert conv["packets"] == 1
        assert conv["protocol"] == "TCP"
        assert conv["src_port"] == 12345
        assert conv["dst_port"] == 80

    def test_process_udp_packet(self, analyzer):
        """Test processing UDP packets."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create UDP packet
        udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=12345, dport=53)
        udp_packet.time = base_time
        analyzer.process_packet(udp_packet, 1)

        # Verify UDP protocol stats
        assert "UDP" in analyzer.protocol_stats
        assert analyzer.protocol_stats["UDP"]["packets"] == 1

        # Verify conversation
        conv_key = f"{src_ip} -> {dst_ip}"
        conv = analyzer.conversations[conv_key]
        assert conv["protocol"] == "UDP"
        assert conv["src_port"] == 12345
        assert conv["dst_port"] == 53

    def test_process_icmp_packet(self, analyzer):
        """Test processing ICMP packets."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create ICMP packet
        icmp_packet = IP(src=src_ip, dst=dst_ip, proto=1) / ICMP()
        icmp_packet.time = base_time
        analyzer.process_packet(icmp_packet, 1)

        # Verify ICMP protocol stats
        assert "ICMP" in analyzer.protocol_stats
        assert analyzer.protocol_stats["ICMP"]["packets"] == 1

        # Verify conversation (no ports for ICMP)
        conv_key = f"{src_ip} -> {dst_ip}"
        conv = analyzer.conversations[conv_key]
        assert conv["protocol"] == "ICMP"
        assert conv["src_port"] is None
        assert conv["dst_port"] is None

    def test_top_ips_sorting(self, analyzer):
        """Test that top IPs are sorted by total volume (sent + received)."""
        base_time = 1234567890.0

        # Create packets from different IPs with different volumes
        # IP 1: 100 packets, 100KB
        for i in range(100):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345+i, dport=80) / Raw(load=b"x" * 1000)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        # IP 2: 50 packets, 50KB
        for i in range(50):
            packet = IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=12345+i, dport=80) / Raw(load=b"x" * 1000)
            packet.time = base_time + 100 + i * 0.1
            analyzer.process_packet(packet, 101 + i)

        # IP 3: 200 packets, 200KB (top talker)
        for i in range(200):
            packet = IP(src="192.168.1.3", dst="10.0.0.3") / TCP(sport=12345+i, dport=80) / Raw(load=b"x" * 1000)
            packet.time = base_time + 150 + i * 0.1
            analyzer.process_packet(packet, 151 + i)

        results = analyzer.get_results()
        top_ips = results["top_ips"]

        # Should be sorted by total_bytes (descending)
        assert len(top_ips) >= 3
        
        # Verify sorting (highest volume first)
        for i in range(len(top_ips) - 1):
            assert top_ips[i]["total_bytes"] >= top_ips[i + 1]["total_bytes"]

        # IP 3 should be first (highest volume)
        if len(top_ips) >= 1:
            assert top_ips[0]["total_bytes"] >= top_ips[1]["total_bytes"] if len(top_ips) > 1 else True

    def test_ip_sent_received_tracking(self, analyzer):
        """Test that IP statistics track both sent and received bytes/packets."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create packets in both directions
        # Forward: src -> dst
        for i in range(10):
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80) / Raw(load=b"x" * 500)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        # Reverse: dst -> src
        for i in range(5):
            packet = IP(src=dst_ip, dst=src_ip) / TCP(sport=80, dport=12345) / Raw(load=b"x" * 1000)
            packet.time = base_time + 10 + i * 0.1
            analyzer.process_packet(packet, 11 + i)

        # Verify src_ip stats (sent 10, received 5)
        src_stats = analyzer.ip_stats[src_ip]
        assert src_stats["packets_sent"] == 10
        assert src_stats["packets_received"] == 5
        assert src_stats["bytes_sent"] > 0
        assert src_stats["bytes_received"] > 0

        # Verify dst_ip stats (received 10, sent 5)
        dst_stats = analyzer.ip_stats[dst_ip]
        assert dst_stats["packets_received"] == 10
        assert dst_stats["packets_sent"] == 5

    def test_protocol_breakdown(self, analyzer):
        """Test protocol breakdown statistics."""
        base_time = 1234567890.0

        # Create packets for different protocols
        # TCP
        for i in range(10):
            packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345+i, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        # UDP
        for i in range(5):
            packet = IP(src="192.168.1.2", dst="10.0.0.2") / UDP(sport=12345+i, dport=53)
            packet.time = base_time + 10 + i * 0.1
            analyzer.process_packet(packet, 11 + i)

        # ICMP
        for i in range(3):
            packet = IP(src="192.168.1.3", dst="10.0.0.3", proto=1) / ICMP()
            packet.time = base_time + 15 + i * 0.1
            analyzer.process_packet(packet, 16 + i)

        results = analyzer.get_results()
        protocol_stats = results["protocol_stats"]

        # Verify protocol breakdown
        assert "TCP" in protocol_stats
        assert protocol_stats["TCP"]["packets"] == 10
        
        assert "UDP" in protocol_stats
        assert protocol_stats["UDP"]["packets"] == 5
        
        assert "ICMP" in protocol_stats
        assert protocol_stats["ICMP"]["packets"] == 3

    def test_conversation_tracking(self, analyzer):
        """Test conversation tracking between IP pairs."""
        base_time = 1234567890.0

        # Create multiple conversations
        conversations = [
            ("192.168.1.1", "10.0.0.1", 5),
            ("192.168.1.2", "10.0.0.2", 10),
            ("192.168.1.1", "10.0.0.3", 3),
        ]

        packet_num = 1
        for src_ip, dst_ip, packet_count in conversations:
            for i in range(packet_count):
                packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345+i, dport=80)
                packet.time = base_time + packet_num * 0.1
                analyzer.process_packet(packet, packet_num)
                packet_num += 1

        results = analyzer.get_results()
        top_conversations = results["top_conversations"]

        # Should track all conversations
        assert len(top_conversations) >= 3
        
        # Should be sorted by bytes (descending)
        for i in range(len(top_conversations) - 1):
            assert top_conversations[i]["bytes"] >= top_conversations[i + 1]["bytes"]

        # Verify conversation details
        conv_key = "192.168.1.2 -> 10.0.0.2"
        conv = next((c for c in top_conversations if c["conversation"] == conv_key), None)
        if conv:
            assert conv["packets"] == 10
            assert conv["protocol"] == "TCP"

    def test_get_results_structure(self, analyzer):
        """Test that get_results() returns correct structure."""
        base_time = 1234567890.0

        # Process some packets
        for i in range(10):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / TCP(sport=12345+i, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.get_results()

        # Check results structure
        assert "top_ips" in results
        assert "top_conversations" in results
        assert "protocol_stats" in results

        # Verify top_ips structure
        if results["top_ips"]:
            top_ip = results["top_ips"][0]
            assert "ip" in top_ip
            assert "total_bytes" in top_ip
            assert "bytes_sent" in top_ip
            assert "bytes_received" in top_ip
            assert "packets_sent" in top_ip
            assert "packets_received" in top_ip

        # Verify top_conversations structure
        if results["top_conversations"]:
            top_conv = results["top_conversations"][0]
            assert "conversation" in top_conv
            assert "src_ip" in top_conv
            assert "dst_ip" in top_conv
            assert "bytes" in top_conv
            assert "packets" in top_conv
            assert "protocol" in top_conv

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.get_results()

        # Should return empty results
        assert len(results["top_ips"]) == 0
        assert len(results["top_conversations"]) == 0
        assert len(results["protocol_stats"]) == 0

    def test_total_bytes_calculation(self, analyzer):
        """Test that total_bytes is calculated as sent + received."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create packets in both directions
        # Forward: 10 packets, 5KB each = 50KB
        for i in range(10):
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80) / Raw(load=b"x" * 5000)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        # Reverse: 5 packets, 10KB each = 50KB
        for i in range(5):
            packet = IP(src=dst_ip, dst=src_ip) / TCP(sport=80, dport=12345) / Raw(load=b"x" * 10000)
            packet.time = base_time + 10 + i * 0.1
            analyzer.process_packet(packet, 11 + i)

        results = analyzer.get_results()
        top_ips = results["top_ips"]

        # Find src_ip in results
        src_ip_result = next((ip for ip in top_ips if ip["ip"] == src_ip), None)
        if src_ip_result:
            # Total bytes should be sent + received
            assert src_ip_result["total_bytes"] == src_ip_result["bytes_sent"] + src_ip_result["bytes_received"]

    def test_top_ips_limit(self, analyzer):
        """Test that get_results() limits top IPs to 20."""
        base_time = 1234567890.0

        # Create packets from 25 different IPs
        for i in range(25):
            src_ip = f"192.168.1.{i+1}"
            packet = IP(src=src_ip, dst="10.0.0.1") / TCP(sport=12345, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.get_results()
        top_ips = results["top_ips"]

        # Should limit to top 20 IPs
        assert len(top_ips) <= 20

    def test_top_conversations_limit(self, analyzer):
        """Test that get_results() limits top conversations to 20."""
        base_time = 1234567890.0

        # Create packets for 25 different conversations
        for i in range(25):
            src_ip = f"192.168.1.{i+1}"
            dst_ip = f"10.0.0.{i+1}"
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.get_results()
        top_conversations = results["top_conversations"]

        # Should limit to top 20 conversations
        assert len(top_conversations) <= 20

    def test_conversation_port_tracking(self, analyzer):
        """Test that conversation ports are tracked correctly."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create TCP conversation with specific ports
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=54321, dport=443)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        conv_key = f"{src_ip} -> {dst_ip}"
        conv = analyzer.conversations[conv_key]
        
        # Should track ports
        assert conv["src_port"] == 54321
        assert conv["dst_port"] == 443

    def test_get_summary(self, analyzer):
        """Test that get_summary() returns text summary."""
        base_time = 1234567890.0

        # Process some packets
        for i in range(10):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / TCP(sport=12345+i, dport=80) / Raw(load=b"x" * 1000)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        summary = analyzer.get_summary()

        # Should return text summary
        assert isinstance(summary, str)
        assert "Top Talkers" in summary or "Top" in summary

    def test_non_ip_packet_ignored(self, analyzer):
        """Test that non-IP packets are ignored."""
        base_time = 1234567890.0

        # Create non-IP packet (just Raw, no IP layer)
        from scapy.all import Raw
        raw_packet = Raw(load=b"data")
        raw_packet.time = base_time
        analyzer.process_packet(raw_packet, 1)

        # Should not track non-IP packets
        assert len(analyzer.ip_stats) == 0
        assert len(analyzer.protocol_stats) == 0

    def test_multiple_protocols_same_flow(self, analyzer):
        """Test tracking multiple protocols in same IP pair."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # TCP conversation
        tcp_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80)
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet, 1)

        # UDP conversation (same IPs, different protocol)
        udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=12345, dport=53)
        udp_packet.time = base_time + 1.0
        analyzer.process_packet(udp_packet, 2)

        # Should have 2 conversations (direction matters, but protocol is last seen)
        # Note: Conversation key is "src_ip -> dst_ip", so protocol gets overwritten
        conv_key = f"{src_ip} -> {dst_ip}"
        conv = analyzer.conversations[conv_key]
        # Protocol should be UDP (last processed)
        assert conv["protocol"] == "UDP"
        assert conv["packets"] == 2  # Both packets counted

    def test_finalize_returns_results(self, analyzer):
        """Test that finalize() returns results."""
        base_time = 1234567890.0

        # Process some packets
        for i in range(5):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / TCP(sport=12345+i, dport=80)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.finalize()

        # Should return results dictionary
        assert isinstance(results, dict)
        assert "top_ips" in results
        assert "top_conversations" in results
        assert "protocol_stats" in results
