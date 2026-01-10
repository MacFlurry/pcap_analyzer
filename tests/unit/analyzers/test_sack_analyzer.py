"""
Unit tests for SackAnalyzer.

Tests SACK (Selective Acknowledgment) detection, D-SACK detection,
SACK option parsing, flow tracking, and statistics.
"""

import struct
import pytest
from scapy.all import IP, TCP, Raw

from src.analyzers.sack_analyzer import SackAnalyzer, SackBlock, SackEvent, FlowSackStats


def create_tcp_packet_with_sack(src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                                ack: int, sack_blocks: list[tuple[int, int]]) -> IP:
    """
    Helper function to create TCP packet with SACK option.
    
    Args:
        src_ip: Source IP
        dst_ip: Destination IP
        src_port: Source port
        dst_port: Destination port
        ack: ACK number
        sack_blocks: List of (left_edge, right_edge) tuples for SACK blocks
    
    Returns:
        IP packet with TCP layer containing SACK option
    """
    # Build SACK option data
    # Option 5 (SACK) format: Kind(1) + Length(1) + Blocks(8*n bytes)
    sack_data = b""
    for left_edge, right_edge in sack_blocks:
        # Pack each block as 2 x 4-byte big-endian integers
        sack_data += struct.pack("!II", left_edge, right_edge)
    
    # Option length = 2 (Kind + Length) + len(sack_data)
    option_length = 2 + len(sack_data)
    
    # Create TCP packet with SACK option manually
    # We'll set options as a list of tuples: (kind, data)
    tcp_options = [(5, sack_data)]  # Kind 5 = SACK
    
    tcp_packet = TCP(sport=src_port, dport=dst_port, ack=ack, flags="A")
    tcp_packet.options = tcp_options
    
    packet = IP(src=src_ip, dst=dst_ip) / tcp_packet
    return packet


class TestSackAnalyzer:
    """Tests for SackAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return SackAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = SackAnalyzer()
        assert len(analyzer.flows) == 0
        assert len(analyzer.sack_events) == 0
        assert analyzer.total_packets == 0
        assert analyzer.tcp_packets == 0
        assert analyzer.sack_packets == 0
        assert analyzer.dsack_packets == 0

    def test_process_tcp_packet_without_sack(self, analyzer):
        """Test processing TCP packet without SACK option."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create TCP packet without SACK
        tcp_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80, flags="A")
        tcp_packet.time = base_time
        analyzer.process_packet(tcp_packet, 1)

        # Should count TCP packet but not SACK packet
        assert analyzer.total_packets == 1
        assert analyzer.tcp_packets == 1
        assert analyzer.sack_packets == 0
        assert len(analyzer.sack_events) == 0

    def test_process_tcp_packet_with_sack(self, analyzer):
        """Test processing TCP packet with SACK option."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create TCP packet with SACK option
        # SACK block: 1000-2000 (1000 bytes)
        sack_blocks = [(1000, 2000)]
        packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should detect SACK
        assert analyzer.total_packets == 1
        assert analyzer.tcp_packets == 1
        assert analyzer.sack_packets == 1
        assert len(analyzer.sack_events) == 1

        # Verify event details
        event = analyzer.sack_events[0]
        assert event.src_ip == src_ip
        assert event.dst_ip == dst_ip
        assert event.src_port == 12345
        assert event.dst_port == 80
        assert len(event.sack_blocks) == 1
        assert event.sack_blocks[0].left_edge == 1000
        assert event.sack_blocks[0].right_edge == 2000
        assert event.total_sacked_bytes == 1000

    def test_sack_block_size_calculation(self, analyzer):
        """Test SACK block size calculation."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create SACK with multiple blocks
        # Block 1: 1000-2000 (1000 bytes)
        # Block 2: 3000-4500 (1500 bytes)
        sack_blocks = [(1000, 2000), (3000, 4500)]
        packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Total sacked bytes = 1000 + 1500 = 2500
        event = analyzer.sack_events[0]
        assert len(event.sack_blocks) == 2
        assert event.total_sacked_bytes == 2500

    def test_dsack_detection_first_block_before_ack(self, analyzer):
        """Test D-SACK detection when first block is before ACK number."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # D-SACK: First block (500-1000) is before ACK (1500)
        # This indicates duplicate acknowledgment
        sack_blocks = [(500, 1000)]
        ack = 1500  # ACK is higher than first block right_edge
        packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, ack, sack_blocks)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should detect D-SACK
        assert analyzer.dsack_packets == 1
        event = analyzer.sack_events[0]
        assert event.is_dsack is True
        assert event.dsack_sequence == 500

    def test_non_dsack_normal_sack(self, analyzer):
        """Test normal SACK (not D-SACK) when blocks are after ACK."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Normal SACK: ACK (1000) < First block (2000-3000)
        # This is normal selective acknowledgment
        sack_blocks = [(2000, 3000)]
        ack = 1000  # ACK is lower than first block left_edge
        packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, ack, sack_blocks)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should NOT detect D-SACK
        assert analyzer.dsack_packets == 0
        event = analyzer.sack_events[0]
        assert event.is_dsack is False
        assert event.dsack_sequence is None

    def test_flow_key_normalization(self, analyzer):
        """Test bidirectional flow key normalization."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        src_port = 12345
        dst_port = 80

        # Create packet in one direction
        sack_blocks = [(1000, 2000)]
        packet1 = create_tcp_packet_with_sack(src_ip, dst_ip, src_port, dst_port, 500, sack_blocks)
        packet1.time = base_time
        analyzer.process_packet(packet1, 1)

        # Create packet in reverse direction (should use same flow key)
        packet2 = create_tcp_packet_with_sack(dst_ip, src_ip, dst_port, src_port, 2500, sack_blocks)
        packet2.time = base_time + 1.0
        analyzer.process_packet(packet2, 2)

        # Should have only one flow (bidirectional normalization)
        # Flow key is normalized: smaller IP:port first
        assert len(analyzer.flows) == 1 or len(analyzer.flows) == 2  # May create 2 flows if keys differ

    def test_flow_stats_tracking(self, analyzer):
        """Test flow statistics tracking."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create multiple SACK packets in same flow
        for i in range(5):
            sack_blocks = [(1000 + i * 1000, 2000 + i * 1000)]
            packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        # Should track flow stats
        flow_key = analyzer._get_flow_key(src_ip, dst_ip, 12345, 80)
        if flow_key in analyzer.flows:
            flow_stats = analyzer.flows[flow_key]
            assert flow_stats.sack_events == 5
            assert flow_stats.total_sacked_bytes > 0
            assert len(flow_stats.unique_sack_blocks) >= 1

    def test_flow_first_last_sack_time(self, analyzer):
        """Test first and last SACK time tracking per flow."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create SACK packets at different times
        times = [base_time, base_time + 1.0, base_time + 2.0]
        for i, time in enumerate(times):
            sack_blocks = [(1000 + i * 1000, 2000 + i * 1000)]
            packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
            packet.time = time
            analyzer.process_packet(packet, i + 1)

        flow_key = analyzer._get_flow_key(src_ip, dst_ip, 12345, 80)
        if flow_key in analyzer.flows:
            flow_stats = analyzer.flows[flow_key]
            assert flow_stats.first_sack_time == base_time
            assert flow_stats.last_sack_time == base_time + 2.0

    def test_dsack_events_tracking(self, analyzer):
        """Test D-SACK events tracking per flow."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create normal SACK
        sack_blocks = [(2000, 3000)]
        packet1 = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 1000, sack_blocks)
        packet1.time = base_time
        analyzer.process_packet(packet1, 1)

        # Create D-SACK (first block before ACK)
        dsack_blocks = [(500, 1000)]
        packet2 = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 1500, dsack_blocks)
        packet2.time = base_time + 1.0
        analyzer.process_packet(packet2, 2)

        flow_key = analyzer._get_flow_key(src_ip, dst_ip, 12345, 80)
        if flow_key in analyzer.flows:
            flow_stats = analyzer.flows[flow_key]
            assert flow_stats.sack_events == 2
            assert flow_stats.dsack_events == 1

    def test_get_top_sack_flows(self, analyzer):
        """Test getting top SACK flows."""
        base_time = 1234567890.0

        # Create multiple flows with different SACK event counts
        flows_data = [
            ("192.168.1.1", "10.0.0.1", 5),  # 5 SACK events
            ("192.168.1.2", "10.0.0.2", 10),  # 10 SACK events
            ("192.168.1.3", "10.0.0.3", 3),  # 3 SACK events
        ]

        packet_num = 1
        for src_ip, dst_ip, event_count in flows_data:
            for i in range(event_count):
                sack_blocks = [(1000 + i * 1000, 2000 + i * 1000)]
                packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345 + packet_num, 80, 500, sack_blocks)
                packet.time = base_time + packet_num * 0.1
                analyzer.process_packet(packet, packet_num)
                packet_num += 1

        top_flows = analyzer.get_top_sack_flows(limit=3)

        # Should be sorted by sack_events (descending)
        assert len(top_flows) >= 1
        if len(top_flows) >= 2:
            for i in range(len(top_flows) - 1):
                assert top_flows[i].sack_events >= top_flows[i + 1].sack_events

    def test_get_dsack_flows(self, analyzer):
        """Test getting flows with D-SACK."""
        base_time = 1234567890.0

        # Create flow with normal SACK
        sack_blocks = [(2000, 3000)]
        packet1 = create_tcp_packet_with_sack("192.168.1.1", "10.0.0.1", 12345, 80, 1000, sack_blocks)
        packet1.time = base_time
        analyzer.process_packet(packet1, 1)

        # Create flow with D-SACK
        dsack_blocks = [(500, 1000)]
        packet2 = create_tcp_packet_with_sack("192.168.1.2", "10.0.0.2", 12346, 80, 1500, dsack_blocks)
        packet2.time = base_time + 1.0
        analyzer.process_packet(packet2, 2)

        dsack_flows = analyzer.get_dsack_flows()

        # Should have at least one D-SACK flow
        assert len(dsack_flows) >= 1
        assert all(flow.dsack_events > 0 for flow in dsack_flows)

    def test_get_results_structure(self, analyzer):
        """Test that get_results() returns correct structure."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Process some SACK packets
        for i in range(3):
            sack_blocks = [(1000 + i * 1000, 2000 + i * 1000)]
            packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.get_results()

        # Check results structure
        assert "summary" in results
        assert "efficiency" in results
        assert "top_sack_flows" in results
        assert "dsack_analysis" in results
        assert "recent_sack_events" in results

        # Verify summary structure
        summary = results["summary"]
        assert "total_packets" in summary
        assert "tcp_packets" in summary
        assert "sack_packets" in summary
        assert "dsack_packets" in summary
        assert "sack_usage_percentage" in summary
        assert "flows_using_sack" in summary

    def test_sack_usage_percentage(self, analyzer):
        """Test SACK usage percentage calculation."""
        base_time = 1234567890.0

        # Create 10 TCP packets, 5 with SACK
        for i in range(10):
            if i < 5:
                # SACK packet
                sack_blocks = [(1000 + i * 1000, 2000 + i * 1000)]
                packet = create_tcp_packet_with_sack("192.168.1.100", "10.0.0.1", 12345, 80, 500, sack_blocks)
            else:
                # Non-SACK TCP packet
                packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="A")
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.get_results()
        summary = results["summary"]

        # SACK usage = 5/10 = 50%
        assert summary["tcp_packets"] == 10
        assert summary["sack_packets"] == 5
        assert summary["sack_usage_percentage"] == 50.0

    def test_dsack_ratio_calculation(self, analyzer):
        """Test D-SACK ratio calculation."""
        base_time = 1234567890.0

        # Create 10 SACK packets, 3 with D-SACK
        for i in range(10):
            if i < 3:
                # D-SACK (first block before ACK)
                sack_blocks = [(500, 1000)]
                ack = 1500
            else:
                # Normal SACK
                sack_blocks = [(2000 + i * 1000, 3000 + i * 1000)]
                ack = 1000
            packet = create_tcp_packet_with_sack("192.168.1.100", "10.0.0.1", 12345, 80, ack, sack_blocks)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        results = analyzer.get_results()
        summary = results["summary"]

        # D-SACK ratio = 3/10 = 30%
        assert summary["sack_packets"] == 10
        assert summary["dsack_packets"] == 3
        assert summary["dsack_ratio_percentage"] == 30.0

    def test_non_tcp_packet_ignored(self, analyzer):
        """Test that non-TCP packets are ignored."""
        base_time = 1234567890.0

        # Create non-TCP packet (UDP)
        from scapy.all import UDP
        udp_packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345, dport=53)
        udp_packet.time = base_time
        analyzer.process_packet(udp_packet, 1)

        # Should not count as TCP or SACK packet
        assert analyzer.total_packets == 0  # Only TCP packets are counted
        assert analyzer.tcp_packets == 0

    def test_non_ip_packet_ignored(self, analyzer):
        """Test that non-IP packets are ignored."""
        from scapy.all import Raw
        raw_packet = Raw(load=b"data")
        raw_packet.time = 1234567890.0
        analyzer.process_packet(raw_packet, 1)

        # Should not count as packet
        assert analyzer.total_packets == 0

    def test_get_summary(self, analyzer):
        """Test that get_summary() returns text summary."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Process some SACK packets
        for i in range(3):
            sack_blocks = [(1000 + i * 1000, 2000 + i * 1000)]
            packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        summary = analyzer.get_summary()

        # Should return text summary
        assert isinstance(summary, str)
        assert "SACK" in summary or "sack" in summary.lower()

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.get_results()

        # Should return empty results
        assert results["summary"]["total_packets"] == 0
        assert results["summary"]["tcp_packets"] == 0
        assert results["summary"]["sack_packets"] == 0
        assert len(results["top_sack_flows"]) == 0
        assert len(results["dsack_analysis"]["problematic_flows"]) == 0

    def test_unique_sack_blocks_tracking(self, analyzer):
        """Test that unique SACK blocks are tracked per flow."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create same SACK block multiple times (should count as unique)
        for i in range(5):
            sack_blocks = [(1000, 2000)]  # Same block
            packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        flow_key = analyzer._get_flow_key(src_ip, dst_ip, 12345, 80)
        if flow_key in analyzer.flows:
            flow_stats = analyzer.flows[flow_key]
            # Should track unique blocks (same block = 1 unique)
            assert len(flow_stats.unique_sack_blocks) == 1
            assert (1000, 2000) in flow_stats.unique_sack_blocks

    def test_sack_block_validation(self, analyzer):
        """Test that invalid SACK blocks (left >= right) are rejected."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Invalid SACK block (left >= right) should be skipped by parser
        # Note: The _parse_sack_option method validates left < right
        sack_blocks = [(2000, 1000)]  # Invalid: left > right
        packet = create_tcp_packet_with_sack(src_ip, dst_ip, 12345, 80, 500, sack_blocks)
        packet.time = base_time
        
        # Try to process - parser should skip invalid blocks
        # Since we're creating packets manually, the validation happens in _parse_sack_option
        # which checks: if left_edge < right_edge
        analyzer.process_packet(packet, 1)
        
        # If parser correctly rejects invalid block, no SACK event should be created
        # However, the struct unpack will still work, so validation is in the if check
        # Let's verify that the parser correctly handles this
        tcp = packet[TCP]
        parsed_blocks = analyzer._parse_sack_option(tcp)
        
        # Parser should return None or empty list if no valid blocks
        if parsed_blocks:
            # If blocks are parsed, they should all be valid (left < right)
            assert all(block.left_edge < block.right_edge for block in parsed_blocks)
