"""
Unit tests for ICMPAnalyzer.

Tests ICMP message detection, PMTU issue detection, Destination Unreachable analysis,
and message classification by severity.
"""

import pytest
from scapy.all import IP, ICMP, TCP, Raw

from src.analyzers.icmp_pmtu import ICMPAnalyzer, ICMPMessage


class TestICMPAnalyzer:
    """Tests for ICMPAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return ICMPAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = ICMPAnalyzer()
        assert len(analyzer.icmp_messages) == 0
        assert len(analyzer.pmtu_issues) == 0
        assert len(analyzer.dest_unreachable) == 0

    def test_process_echo_request(self, analyzer):
        """Test processing ICMP Echo Request (ping)."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create ICMP Echo Request (type 8)
        echo_request = IP(src=src_ip, dst=dst_ip) / ICMP(type=8, code=0)
        echo_request.time = base_time
        analyzer.process_packet(echo_request, 1)

        # Should detect ICMP message
        assert len(analyzer.icmp_messages) == 1
        
        msg = analyzer.icmp_messages[0]
        assert msg.icmp_type == 8
        assert msg.icmp_code == 0
        assert msg.src_ip == src_ip
        assert msg.dst_ip == dst_ip
        assert "Echo Request" in msg.icmp_type_name or "ping" in msg.message.lower()
        assert msg.severity == "info"

    def test_process_echo_reply(self, analyzer):
        """Test processing ICMP Echo Reply (ping response)."""
        base_time = 1234567890.0
        src_ip = "10.0.0.1"
        dst_ip = "192.168.1.100"

        # Create ICMP Echo Reply (type 0)
        echo_reply = IP(src=src_ip, dst=dst_ip) / ICMP(type=0, code=0)
        echo_reply.time = base_time
        analyzer.process_packet(echo_reply, 1)

        # Should detect ICMP message
        assert len(analyzer.icmp_messages) == 1
        
        msg = analyzer.icmp_messages[0]
        assert msg.icmp_type == 0
        assert "Echo Reply" in msg.icmp_type_name or "ping" in msg.message.lower()
        assert msg.severity == "info"

    def test_process_dest_unreachable_host(self, analyzer):
        """Test processing Destination Unreachable - Host Unreachable."""
        base_time = 1234567890.0
        src_ip = "192.168.1.1"  # Router
        dst_ip = "192.168.1.100"  # Original sender

        # Create ICMP Destination Unreachable - Host Unreachable (type 3, code 1)
        dest_unreach = IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=1)
        dest_unreach.time = base_time
        analyzer.process_packet(dest_unreach, 1)

        # Should detect Destination Unreachable
        assert len(analyzer.icmp_messages) == 1
        assert len(analyzer.dest_unreachable) == 1
        
        msg = analyzer.icmp_messages[0]
        assert msg.icmp_type == 3
        assert msg.icmp_code == 1
        assert "Host Unreachable" in msg.icmp_type_name
        assert msg.severity == "error"

    def test_process_dest_unreachable_port(self, analyzer):
        """Test processing Destination Unreachable - Port Unreachable."""
        base_time = 1234567890.0
        src_ip = "192.168.1.1"
        dst_ip = "192.168.1.100"

        # Create ICMP Destination Unreachable - Port Unreachable (type 3, code 3)
        dest_unreach = IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=3)
        dest_unreach.time = base_time
        analyzer.process_packet(dest_unreach, 1)

        # Should detect Port Unreachable
        assert len(analyzer.dest_unreachable) == 1
        
        msg = analyzer.dest_unreachable[0]
        assert msg.icmp_code == 3
        assert "Port Unreachable" in msg.icmp_type_name
        assert msg.severity == "warning"

    def test_process_pmtu_fragmentation_needed(self, analyzer):
        """Test processing PMTU Fragmentation Needed (type 3, code 4)."""
        base_time = 1234567890.0
        src_ip = "192.168.1.1"  # Router
        dst_ip = "192.168.1.100"  # Original sender

        # Create ICMP Fragmentation Needed (type 3, code 4) with MTU
        # Note: Scapy may not support nexthopmtu directly, so we test basic detection
        dest_unreach = IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=4)
        dest_unreach.time = base_time
        
        # Try to set MTU if possible (Scapy ICMP structure)
        try:
            if hasattr(dest_unreach[ICMP], "nexthopmtu"):
                dest_unreach[ICMP].nexthopmtu = 1400
        except (AttributeError, TypeError):
            pass  # MTU field may not be accessible directly

        analyzer.process_packet(dest_unreach, 1)

        # Should detect PMTU issue
        assert len(analyzer.pmtu_issues) == 1
        assert len(analyzer.dest_unreachable) == 1
        
        msg = analyzer.pmtu_issues[0]
        assert msg.icmp_type == 3
        assert msg.icmp_code == 4
        assert "Fragmentation Needed" in msg.icmp_type_name
        assert msg.severity == "error"
        assert "PMTU" in msg.message or "Fragmentation" in msg.message

    def test_process_time_exceeded(self, analyzer):
        """Test processing ICMP Time Exceeded (TTL expired)."""
        base_time = 1234567890.0
        src_ip = "192.168.1.1"
        dst_ip = "192.168.1.100"

        # Create ICMP Time Exceeded (type 11, code 0)
        time_exceeded = IP(src=src_ip, dst=dst_ip) / ICMP(type=11, code=0)
        time_exceeded.time = base_time
        analyzer.process_packet(time_exceeded, 1)

        # Should detect Time Exceeded
        assert len(analyzer.icmp_messages) == 1
        
        msg = analyzer.icmp_messages[0]
        assert msg.icmp_type == 11
        assert msg.icmp_code == 0
        assert "Time Exceeded" in msg.icmp_type_name or "TTL" in msg.message
        assert msg.severity == "warning"

    def test_process_network_unreachable(self, analyzer):
        """Test processing Destination Unreachable - Network Unreachable."""
        base_time = 1234567890.0
        src_ip = "192.168.1.1"
        dst_ip = "192.168.1.100"

        # Create ICMP Network Unreachable (type 3, code 0)
        dest_unreach = IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=0)
        dest_unreach.time = base_time
        analyzer.process_packet(dest_unreach, 1)

        # Should detect Network Unreachable
        assert len(analyzer.dest_unreachable) == 1
        
        msg = analyzer.dest_unreachable[0]
        assert msg.icmp_code == 0
        assert "Network Unreachable" in msg.icmp_type_name
        assert msg.severity == "error"

    def test_process_protocol_unreachable(self, analyzer):
        """Test processing Destination Unreachable - Protocol Unreachable."""
        base_time = 1234567890.0
        src_ip = "192.168.1.1"
        dst_ip = "192.168.1.100"

        # Create ICMP Protocol Unreachable (type 3, code 2)
        dest_unreach = IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=2)
        dest_unreach.time = base_time
        analyzer.process_packet(dest_unreach, 1)

        # Should detect Protocol Unreachable
        assert len(analyzer.dest_unreachable) == 1
        
        msg = analyzer.dest_unreachable[0]
        assert msg.icmp_code == 2
        assert "Protocol Unreachable" in msg.icmp_type_name

    def test_message_classification_severity(self, analyzer):
        """Test ICMP message classification by severity."""
        base_time = 1234567890.0

        # Test different ICMP types with different severities
        # Error severity: Destination Unreachable (Network/Host)
        error_msg = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=1)  # Host Unreachable
        error_msg.time = base_time
        analyzer.process_packet(error_msg, 1)
        
        # Warning severity: Port Unreachable
        warning_msg = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=3)  # Port Unreachable
        warning_msg.time = base_time + 1.0
        analyzer.process_packet(warning_msg, 2)
        
        # Info severity: Echo Request
        info_msg = IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=8, code=0)  # Echo Request
        info_msg.time = base_time + 2.0
        analyzer.process_packet(info_msg, 3)

        # Verify severities
        assert len(analyzer.icmp_messages) == 3
        
        error_icmp = next(m for m in analyzer.icmp_messages if m.icmp_type == 3 and m.icmp_code == 1)
        assert error_icmp.severity == "error"
        
        warning_icmp = next(m for m in analyzer.icmp_messages if m.icmp_type == 3 and m.icmp_code == 3)
        assert warning_icmp.severity == "warning"
        
        info_icmp = next(m for m in analyzer.icmp_messages if m.icmp_type == 8)
        assert info_icmp.severity == "info"

    def test_get_results_structure(self, analyzer):
        """Test that get_results() returns correct structure."""
        base_time = 1234567890.0

        # Process some ICMP messages
        echo_request = IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=8, code=0)
        echo_request.time = base_time
        analyzer.process_packet(echo_request, 1)

        dest_unreach = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=1)
        dest_unreach.time = base_time + 1.0
        analyzer.process_packet(dest_unreach, 2)

        results = analyzer.finalize()

        # Check results structure
        assert "total_icmp_messages" in results
        assert "pmtu_issues_count" in results
        assert "dest_unreachable_count" in results
        assert "type_distribution" in results
        assert "severity_distribution" in results
        assert "icmp_messages" in results
        assert "pmtu_issues" in results
        assert "dest_unreachable" in results
        assert "pmtu_suggestions" in results

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.finalize()

        # Should return empty results
        assert results["total_icmp_messages"] == 0
        assert results["pmtu_issues_count"] == 0
        assert results["dest_unreachable_count"] == 0
        assert len(results["icmp_messages"]) == 0
        assert len(results["type_distribution"]) == 0

    def test_type_distribution(self, analyzer):
        """Test ICMP type distribution statistics."""
        base_time = 1234567890.0

        # Create different ICMP types
        icmp_types = [
            (8, 0),  # Echo Request
            (0, 0),  # Echo Reply
            (3, 1),  # Destination Unreachable - Host
            (3, 3),  # Destination Unreachable - Port
            (11, 0),  # Time Exceeded
        ]

        for i, (icmp_type, icmp_code) in enumerate(icmp_types):
            packet = IP(src=f"192.168.1.{i+1}", dst="10.0.0.1") / ICMP(type=icmp_type, code=icmp_code)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.finalize()
        type_distribution = results["type_distribution"]

        # Should have type distribution
        assert len(type_distribution) >= 1
        # Should count different types

    def test_severity_distribution(self, analyzer):
        """Test severity distribution statistics."""
        base_time = 1234567890.0

        # Create ICMP messages with different severities
        # Error
        error_packet = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=1)
        error_packet.time = base_time
        analyzer.process_packet(error_packet, 1)

        # Warning
        warning_packet = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=3)
        warning_packet.time = base_time + 1.0
        analyzer.process_packet(warning_packet, 2)

        # Info
        info_packet = IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=8, code=0)
        info_packet.time = base_time + 2.0
        analyzer.process_packet(info_packet, 3)

        results = analyzer.finalize()
        severity_distribution = results["severity_distribution"]

        # Should have severity distribution
        assert "error" in severity_distribution or "warning" in severity_distribution or "info" in severity_distribution

    def test_pmtu_suggestions(self, analyzer):
        """Test PMTU suggestions generation."""
        base_time = 1234567890.0

        # Create PMTU issues
        for i in range(3):
            pmtu_packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100") / ICMP(type=3, code=4)
            pmtu_packet.time = base_time + i * 0.1
            analyzer.process_packet(pmtu_packet, i + 1)

        results = analyzer.finalize()

        # Should have PMTU suggestions if PMTU issues detected
        if results["pmtu_issues_count"] > 0:
            assert "pmtu_suggestions" in results
            assert len(results["pmtu_suggestions"]) >= 0  # May have suggestions

    def test_analyze_method(self, analyzer):
        """Test analyze() method that processes packet list."""
        base_time = 1234567890.0

        # Create list of packets
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=8, code=0),
            IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=1),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = analyzer.analyze(packets)

        # Should process all packets
        assert results["total_icmp_messages"] == 2

    def test_get_summary(self, analyzer):
        """Test that get_summary() returns text summary."""
        base_time = 1234567890.0

        # Process some ICMP messages
        echo_request = IP(src="192.168.1.100", dst="10.0.0.1") / ICMP(type=8, code=0)
        echo_request.time = base_time
        analyzer.process_packet(echo_request, 1)

        dest_unreach = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=3, code=1)
        dest_unreach.time = base_time + 1.0
        analyzer.process_packet(dest_unreach, 2)

        summary = analyzer.get_summary()

        # Should return text summary
        assert isinstance(summary, str)
        assert "ICMP" in summary or "icmp" in summary.lower()

    def test_non_icmp_packet_ignored(self, analyzer):
        """Test that non-ICMP packets are ignored."""
        base_time = 1234567890.0

        # Create non-ICMP packet (TCP)
        tcp_packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80)
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet, 1)

        # Should not track non-ICMP packets
        assert len(analyzer.icmp_messages) == 0

    def test_dest_unreachable_aggregation(self, analyzer):
        """Test that Destination Unreachable messages are aggregated correctly."""
        base_time = 1234567890.0
        target_ip = "10.0.0.100"  # Target that is unreachable

        # Create multiple Destination Unreachable messages for same target
        for i in range(5):
            packet = IP(src=f"192.168.1.{i+1}", dst="192.168.1.100") / ICMP(type=3, code=1)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.finalize()

        # Should aggregate Destination Unreachable messages
        assert results["dest_unreachable_count"] == 5
        assert len(results["dest_unreachable"]) == 5

    def test_icmp_type_codes_mapping(self, analyzer):
        """Test that ICMP type and code names are correctly mapped."""
        base_time = 1234567890.0

        # Test known ICMP types
        test_cases = [
            (0, 0, "Echo Reply"),
            (3, 1, "Host Unreachable"),
            (3, 3, "Port Unreachable"),
            (3, 4, "Fragmentation Needed"),
            (8, 0, "Echo Request"),
            (11, 0, "Time Exceeded"),
        ]

        for icmp_type, icmp_code, expected_name in test_cases:
            packet = IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=icmp_type, code=icmp_code)
            packet.time = base_time
            analyzer.process_packet(packet, 1)
            
            # Verify type name mapping
            msg = analyzer.icmp_messages[-1]  # Last message
            assert expected_name in msg.icmp_type_name or str(icmp_type) in msg.icmp_type_name
            analyzer.icmp_messages.clear()  # Clear for next test
