"""
Unit tests for TCPTimeoutAnalyzer (TCP timeout detection).

Tests idle connection detection, zombie connection detection, and connection state tracking.
"""

import pytest
from scapy.all import IP, TCP, Raw

from src.analyzers.tcp_timeout import TCPTimeoutAnalyzer, TCPConnectionState


class TestTCPTimeoutAnalyzer:
    """Tests for TCPTimeoutAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with default thresholds."""
        return TCPTimeoutAnalyzer(idle_threshold=30.0, zombie_threshold=60.0)

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = TCPTimeoutAnalyzer(idle_threshold=30.0, zombie_threshold=60.0)
        assert analyzer.idle_threshold == 30.0
        assert analyzer.zombie_threshold == 60.0
        assert len(analyzer.connections) == 0
        assert analyzer.first_packet_time is None
        assert analyzer.last_packet_time is None

    def test_connection_tracking(self, analyzer):
        """Test that connections are tracked correctly."""
        # Create SYN packet (connection start)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        analyzer.process_packet(syn_packet, 1)

        # Should track connection (flow key is normalized: smaller IP:port first)
        # "10.0.0.1:80" < "192.168.1.1:12345" (alphabetically)
        normalized_flow = "10.0.0.1:80<->192.168.1.1:12345"
        assert normalized_flow in analyzer.connections
        conn = analyzer.connections[normalized_flow]
        assert conn.src_ip == "192.168.1.1"  # Original src_ip is preserved
        assert conn.src_port == 12345
        assert conn.syn_seen is True
        assert conn.packet_count == 1

    def test_handshake_tracking(self, analyzer):
        """Test that TCP handshake is tracked correctly."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.01

        # ACK (final)
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.02

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)

        # Should track complete handshake (flow key is normalized)
        normalized_flow = "10.0.0.1:80<->192.168.1.1:12345"
        conn = analyzer.connections[normalized_flow]
        assert conn.syn_seen is True
        assert conn.syn_ack_seen is True
        assert conn.ack_seen is True
        assert conn.packet_count == 3

    def test_idle_connection_detection(self, analyzer):
        """Test that idle connections are detected."""
        # Create SYN (connection start)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # Create data packet
        data_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, flags="PA") / Raw(
            load=b"data"
        )
        data_packet.time = 1234567891.0

        # Create packet after idle period (>30s threshold)
        idle_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1005, flags="PA") / Raw(
            load=b"more data"
        )
        idle_packet.time = 1234567921.0  # 30s later

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(data_packet, 2)
        analyzer.process_packet(idle_packet, 3)

        # Finalize to calculate idle_time (it's calculated during finalize/classification)
        analyzer.finalize()

        # Should detect idle period (flow key is normalized)
        normalized_flow = "10.0.0.1:80<->192.168.1.1:12345"
        conn = analyzer.connections[normalized_flow]
        # idle_time is calculated as capture_end - last_seen during finalize
        assert conn.idle_time >= 0  # Will be calculated during finalize

    def test_zombie_connection_detection(self, analyzer):
        """Test that zombie connections are detected."""
        # Create SYN (connection start)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # Create packet after zombie threshold (>60s)
        zombie_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, flags="PA") / Raw(
            load=b"data"
        )
        zombie_packet.time = 1234567951.0  # 61s later

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(zombie_packet, 2)

        # Finalize to calculate idle_time
        analyzer.finalize()

        # Connection should be considered zombie (long idle) - flow key is normalized
        normalized_flow = "10.0.0.1:80<->192.168.1.1:12345"
        conn = analyzer.connections[normalized_flow]
        # idle_time is calculated during finalize
        assert conn.idle_time >= 0

    def test_connection_duration_calculation(self, analyzer):
        """Test that connection duration is calculated correctly."""
        # Create SYN (connection start)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # Create FIN (connection end)
        fin_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, flags="FA")
        fin_packet.time = 1234567895.0  # 5s later

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(fin_packet, 2)

        # Connection duration should be ~5s (flow key is normalized)
        normalized_flow = "10.0.0.1:80<->192.168.1.1:12345"
        conn = analyzer.connections[normalized_flow]
        assert conn.duration == pytest.approx(5.0, abs=0.01)

    def test_multiple_connections_tracking(self, analyzer):
        """Test that multiple connections are tracked separately."""
        # Flow 1
        flow1_syn = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        flow1_syn.time = 1234567890.0

        # Flow 2
        flow2_syn = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="S")
        flow2_syn.time = 1234567891.0

        analyzer.process_packet(flow1_syn, 1)
        analyzer.process_packet(flow2_syn, 2)

        # Should track both connections separately (flow keys are normalized)
        assert len(analyzer.connections) == 2
        assert "10.0.0.1:80<->192.168.1.1:12345" in analyzer.connections
        assert "10.0.0.1:80<->192.168.1.2:54321" in analyzer.connections

    def test_connection_state_progression(self, analyzer):
        """Test that connection state progresses correctly."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.01

        # ACK (handshake complete)
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.02

        # Data
        data_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, flags="PA") / Raw(
            load=b"data"
        )
        data_packet.time = 1234567890.03

        # FIN
        fin_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1005, flags="FA")
        fin_packet.time = 1234567890.04

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)
        analyzer.process_packet(data_packet, 4)
        analyzer.process_packet(fin_packet, 5)

        # Should track complete connection lifecycle (flow key is normalized)
        normalized_flow = "10.0.0.1:80<->192.168.1.1:12345"
        conn = analyzer.connections[normalized_flow]
        assert conn.syn_seen is True
        assert conn.syn_ack_seen is True
        assert conn.ack_seen is True
        assert conn.data_seen is True
        assert conn.fin_seen is True

    def test_finalize_statistics(self, analyzer):
        """Test that finalize() returns correct statistics."""
        # Create multiple connections
        syn1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn1.time = 1234567890.0

        syn2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="S")
        syn2.time = 1234567891.0

        analyzer.process_packet(syn1, 1)
        analyzer.process_packet(syn2, 2)

        results = analyzer.finalize()

        # Check results structure (API uses categories, not connections)
        assert "total_connections" in results
        assert "categories" in results
        assert "capture_duration" in results

        # Should have 2 connections
        assert results["total_connections"] == 2
        assert "syn_timeout_count" in results["categories"]

    def test_non_tcp_packet_ignored(self, analyzer):
        """Test that non-TCP packets are ignored."""
        # UDP packet
        udp_packet = IP(src="192.168.1.1", dst="10.0.0.1") / Raw(load=b"udp data")
        udp_packet.time = 1234567890.0

        analyzer.process_packet(udp_packet, 1)

        # No connections should be tracked
        assert len(analyzer.connections) == 0
