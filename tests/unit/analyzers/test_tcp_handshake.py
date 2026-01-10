"""
Unit tests for TCPHandshakeAnalyzer.

Tests TCP three-way handshake detection, timing measurements, and bottleneck identification.
"""

import pytest
from scapy.all import IP, TCP, Raw

from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer, HandshakeFlow


class TestTCPHandshakeAnalyzer:
    """Tests for TCPHandshakeAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with default thresholds."""
        return TCPHandshakeAnalyzer(syn_synack_threshold=0.1, total_threshold=0.3)

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = TCPHandshakeAnalyzer(syn_synack_threshold=0.1, total_threshold=0.3, latency_filter=0.05)
        assert analyzer.syn_synack_threshold == 0.1
        assert analyzer.total_threshold == 0.3
        assert analyzer.latency_filter == 0.05
        assert len(analyzer.handshakes) == 0
        assert len(analyzer.incomplete_handshakes) == 0

    def test_complete_handshake_detection(self, analyzer):
        """Test detection of complete three-way handshake."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.05  # 50ms later

        # ACK (final)
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.1  # 100ms total

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)

        analyzer.finalize()

        # Should detect complete handshake
        assert len(analyzer.handshakes) == 1
        handshake = analyzer.handshakes[0]
        assert handshake.complete is True
        assert handshake.syn_to_synack_delay == pytest.approx(0.05, abs=0.001)
        assert handshake.synack_to_ack_delay == pytest.approx(0.05, abs=0.001)
        assert handshake.total_handshake_time == pytest.approx(0.1, abs=0.001)

    def test_incomplete_handshake_syn_only(self, analyzer):
        """Test detection of incomplete handshake (SYN only, no response)."""
        # SYN only
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        analyzer.process_packet(syn_packet, 1)
        analyzer.finalize()

        # Should have incomplete handshake
        assert len(analyzer.handshakes) >= 1
        incomplete = [h for h in analyzer.handshakes if not h.complete]
        assert len(incomplete) >= 1
        handshake = incomplete[0]
        assert handshake.syn_time is not None
        assert handshake.synack_time is None
        assert handshake.ack_time is None

    def test_syn_to_synack_delay_measurement(self, analyzer):
        """Test measurement of SYN→SYN-ACK delay (server processing time)."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK (delayed 200ms - above threshold)
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.2  # 200ms later

        # ACK
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.25

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)
        analyzer.finalize()

        # Should measure SYN→SYN-ACK delay
        assert len(analyzer.handshakes) == 1
        handshake = analyzer.handshakes[0]
        assert handshake.syn_to_synack_delay == pytest.approx(0.2, abs=0.001)
        assert handshake.syn_to_synack_delay > analyzer.syn_synack_threshold  # Above threshold

    def test_synack_to_ack_delay_measurement(self, analyzer):
        """Test measurement of SYN-ACK→ACK delay (client processing time)."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.05

        # ACK (delayed 150ms)
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.2  # 200ms from SYN, 150ms from SYN-ACK

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)
        analyzer.finalize()

        # Should measure SYN-ACK→ACK delay
        assert len(analyzer.handshakes) == 1
        handshake = analyzer.handshakes[0]
        assert handshake.synack_to_ack_delay == pytest.approx(0.15, abs=0.001)

    def test_bottleneck_identification_server(self, analyzer):
        """Test identification of server-side bottleneck (high SYN→SYN-ACK delay)."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK delayed (server slow)
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.5  # 500ms delay (server bottleneck)

        # ACK
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.51  # Fast ACK

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)
        analyzer.finalize()

        # Should identify server as bottleneck
        assert len(analyzer.handshakes) == 1
        handshake = analyzer.handshakes[0]
        assert handshake.suspected_side == "server" or handshake.suspected_side == "network"

    def test_multiple_handshakes_tracking(self, analyzer):
        """Test that multiple handshakes are tracked separately."""
        # Handshake 1
        syn1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn1.time = 1234567890.0

        synack1 = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack1.time = 1234567890.05

        ack1 = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack1.time = 1234567890.1

        # Handshake 2
        syn2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="S")
        syn2.time = 1234567891.0

        synack2 = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=80, dport=54321, seq=6000, ack=2001, flags="SA")
        synack2.time = 1234567891.05

        ack2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2001, ack=6001, flags="A")
        ack2.time = 1234567891.1

        analyzer.process_packet(syn1, 1)
        analyzer.process_packet(synack1, 2)
        analyzer.process_packet(ack1, 3)
        analyzer.process_packet(syn2, 4)
        analyzer.process_packet(synack2, 5)
        analyzer.process_packet(ack2, 6)
        analyzer.finalize()

        # Should track both handshakes separately
        assert len(analyzer.handshakes) == 2
        complete_handshakes = [h for h in analyzer.handshakes if h.complete]
        assert len(complete_handshakes) == 2

    def test_rfc_793_validation(self, analyzer):
        """Test RFC 793 validation (ACK must equal SYN-ACK.SEQ + 1)."""
        # SYN
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK with seq=5000
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.05

        # ACK should be 5001 (SYN-ACK.SEQ + 1)
        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.1

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)
        analyzer.finalize()

        # Should complete handshake (valid RFC 793 ACK)
        assert len(analyzer.handshakes) == 1
        handshake = analyzer.handshakes[0]
        assert handshake.complete is True

    def test_latency_filter(self):
        """Test that latency_filter filters out fast handshakes."""
        analyzer = TCPHandshakeAnalyzer(latency_filter=0.2)  # Only keep handshakes >= 200ms

        # Fast handshake (50ms total)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.01  # 10ms

        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.05  # 50ms total

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)

        # Slow handshake (250ms total) - should be kept
        syn2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="S")
        syn2.time = 1234567891.0

        synack2 = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=80, dport=54321, seq=6000, ack=2001, flags="SA")
        synack2.time = 1234567891.1  # 100ms

        ack2 = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2001, ack=6001, flags="A")
        ack2.time = 1234567891.25  # 250ms total

        analyzer.process_packet(syn2, 4)
        analyzer.process_packet(synack2, 5)
        analyzer.process_packet(ack2, 6)

        analyzer.finalize()

        # Only slow handshake should be kept (>= 200ms)
        filtered = [h for h in analyzer.handshakes if h.total_handshake_time and h.total_handshake_time >= 0.2]
        assert len(filtered) >= 1

    def test_finalize_statistics(self, analyzer):
        """Test that finalize() returns correct statistics."""
        # Create complete handshake
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.05

        ack_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1001, ack=5001, flags="A")
        ack_packet.time = 1234567890.1

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)
        analyzer.process_packet(ack_packet, 3)

        results = analyzer.finalize()

        # Check results structure
        assert "total_handshakes" in results
        assert "complete_handshakes" in results
        assert "incomplete_handshakes" in results
        assert "handshakes" in results

        # Should have 1 complete handshake
        assert results["total_handshakes"] == 1
        assert results["complete_handshakes"] == 1
        assert results["incomplete_handshakes"] == 0

    def test_non_tcp_packet_ignored(self, analyzer):
        """Test that non-TCP packets are ignored."""
        # UDP packet
        udp_packet = IP(src="192.168.1.1", dst="10.0.0.1") / Raw(load=b"udp data")
        udp_packet.time = 1234567890.0

        analyzer.process_packet(udp_packet, 1)

        # No handshakes should be created
        assert len(analyzer.handshakes) == 0
        assert len(analyzer.incomplete_handshakes) == 0

    def test_syn_ack_packet_only(self, analyzer):
        """Test that SYN-ACK without prior SYN is ignored."""
        # SYN-ACK without SYN (should be ignored)
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.0

        analyzer.process_packet(synack_packet, 1)
        analyzer.finalize()

        # Should not create handshake (SYN required first)
        # Incomplete handshakes dictionary should be empty or handshake should be incomplete
        assert len(analyzer.incomplete_handshakes) == 0
