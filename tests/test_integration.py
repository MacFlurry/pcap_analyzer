"""
Integration tests for PCAP Analyzer.

These tests verify that multiple components work together correctly.
"""

import pytest

from src.analyzers.retransmission import RetransmissionAnalyzer
from src.analyzers.rtt_analyzer import RTTAnalyzer
from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer


@pytest.mark.integration
class TestAnalyzerIntegration:
    """Integration tests for analyzer components."""

    def test_multiple_analyzers_same_packets(self, tcp_connection_packets):
        """Test that multiple analyzers can process the same packets."""
        # Set timestamps
        for i, pkt in enumerate(tcp_connection_packets):
            pkt.time = 1.0 + i * 0.05

        # Create multiple analyzers
        handshake_analyzer = TCPHandshakeAnalyzer()
        retrans_analyzer = RetransmissionAnalyzer()
        rtt_analyzer = RTTAnalyzer()

        # All analyzers should process without errors
        handshake_results = handshake_analyzer.analyze(tcp_connection_packets)
        retrans_results = retrans_analyzer.analyze(tcp_connection_packets)
        rtt_results = rtt_analyzer.analyze(tcp_connection_packets)

        # Verify basic structure
        assert isinstance(handshake_results, dict)
        assert isinstance(retrans_results, dict)
        assert isinstance(rtt_results, dict)

        # Handshake should be detected
        assert handshake_results["total_handshakes"] >= 1

    def test_analyzer_with_retransmissions(self, retransmission_packets):
        """Test retransmission analyzer detects retransmissions."""
        # Set timestamps
        retransmission_packets[0].time = 1.0
        retransmission_packets[1].time = 1.5  # Retransmission after 500ms

        analyzer = RetransmissionAnalyzer()
        results = analyzer.analyze(retransmission_packets)

        # Should detect at least one retransmission
        assert results["total_retransmissions"] >= 1

    def test_rtt_measurement_with_data_exchange(self):
        """Test RTT measurement with actual data exchange."""
        from scapy.all import IP, TCP, Ether

        # Create packets with data exchange
        packets = []

        # Client sends data
        pkt1 = (
            Ether()
            / IP(src="192.168.1.100", dst="192.168.1.1")
            / TCP(sport=12345, dport=80, flags="PA", seq=1000, ack=2000)
            / b"REQUEST"
        )
        pkt1.time = 1.0
        packets.append(pkt1)

        # Server ACKs
        pkt2 = (
            Ether()
            / IP(src="192.168.1.1", dst="192.168.1.100")
            / TCP(sport=80, dport=12345, flags="A", seq=2000, ack=1007)  # ACK seq+len
        )
        pkt2.time = 1.05  # 50ms RTT
        packets.append(pkt2)

        analyzer = RTTAnalyzer()
        results = analyzer.analyze(packets)

        # Should have RTT measurements
        assert results["total_measurements"] >= 1
        if results["total_measurements"] > 0:
            # Check RTT is reasonable (50ms)
            assert results["global_statistics"]["min_rtt"] > 0
            assert results["global_statistics"]["min_rtt"] < 1.0  # Less than 1 second

    @pytest.mark.slow
    def test_large_packet_sequence(self):
        """Test analyzers with a larger sequence of packets."""
        from scapy.all import IP, TCP, Ether

        packets = []
        base_time = 1.0

        # Create 100 packets
        for i in range(100):
            pkt = (
                Ether()
                / IP(src="192.168.1.100", dst="192.168.1.1")
                / TCP(sport=12345, dport=80, flags="PA", seq=1000 + i * 100, ack=2000)
                / f"DATA{i}".encode()
            )
            pkt.time = base_time + i * 0.01  # 10ms intervals
            packets.append(pkt)

        # Process with multiple analyzers
        retrans_analyzer = RetransmissionAnalyzer()
        rtt_analyzer = RTTAnalyzer()

        retrans_results = retrans_analyzer.analyze(packets)
        rtt_results = rtt_analyzer.analyze(packets)

        # Should process successfully
        assert isinstance(retrans_results, dict)
        assert "total_retransmissions" in retrans_results
        assert isinstance(rtt_results, dict)


@pytest.mark.integration
class TestAnalyzerFactory:
    """Integration tests for the analyzer factory."""

    def test_factory_creates_analyzers(self):
        """Test that factory can create all analyzer types."""
        from pathlib import Path

        from src.analyzer_factory import AnalyzerFactory
        from src.config import Config

        # Get a valid config
        config_path = Path(__file__).parent.parent / "config.yaml"
        if not config_path.exists():
            pytest.skip("config.yaml not found - skipping factory test")

        config = Config(str(config_path))

        # Create analyzers using factory
        analyzer_dict, analyzer_list = AnalyzerFactory.create_analyzers(config)

        # Should create all 17 analyzers
        assert len(analyzer_list) == 17
        assert len(analyzer_dict) == 17

        # Check that key analyzers exist
        assert "handshake" in analyzer_dict
        assert "retransmission" in analyzer_dict
        assert "rtt" in analyzer_dict


@pytest.mark.integration
class TestEndToEnd:
    """End-to-end integration tests."""

    def test_full_analysis_pipeline(self, tcp_connection_packets):
        """Test complete analysis pipeline from packets to results."""
        # Set timestamps
        for i, pkt in enumerate(tcp_connection_packets):
            pkt.time = 1.0 + i * 0.05

        # Create all analyzers
        analyzers = [TCPHandshakeAnalyzer(), RetransmissionAnalyzer(), RTTAnalyzer()]

        # Process all packets through all analyzers
        for analyzer in analyzers:
            for i, packet in enumerate(tcp_connection_packets):
                if hasattr(analyzer, "process_packet"):
                    analyzer.process_packet(packet, i)

        # Finalize and get results
        results = []
        for analyzer in analyzers:
            if hasattr(analyzer, "finalize"):
                results.append(analyzer.finalize())

        # Should have results from all analyzers
        assert len(results) == 3
        assert all(isinstance(r, dict) for r in results)
