"""
Unit tests for RTTAnalyzer (Round Trip Time analysis).

Tests RTT measurement, statistics calculation, and flow tracking.
"""

import pytest
from unittest.mock import Mock, patch
from scapy.all import IP, TCP, Raw

from src.analyzers.rtt_analyzer import RTTAnalyzer, RTTMeasurement, FlowRTTStats


class TestRTTAnalyzer:
    """Tests for RTTAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with default thresholds."""
        return RTTAnalyzer(rtt_warning=0.1, rtt_critical=0.5)

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = RTTAnalyzer(rtt_warning=0.1, rtt_critical=0.5, latency_filter=0.2)
        assert analyzer.rtt_warning == 0.1
        assert analyzer.rtt_critical == 0.5
        assert analyzer.latency_filter == 0.2
        assert len(analyzer.measurements) == 0
        assert len(analyzer.flow_stats) == 0

    def test_rtt_measurement_basic(self, analyzer):
        """Test basic RTT measurement: data packet + ACK."""
        # Create data packet (client -> server)
        data_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="PA") / Raw(
            load=b"GET / HTTP/1.1\r\n"
        )
        data_packet.time = 1234567890.0

        # Create ACK packet (server -> client) that acknowledges the data
        ack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1050, flags="A")
        ack_packet.time = 1234567890.1  # 100ms later

        # Process packets
        analyzer.process_packet(data_packet, 1)
        analyzer.process_packet(ack_packet, 2)

        # Should have one RTT measurement
        assert len(analyzer.measurements) == 1
        measurement = analyzer.measurements[0]
        assert measurement.rtt == pytest.approx(0.1, abs=0.01)  # 100ms
        assert measurement.flow_key == "192.168.1.1:12345->10.0.0.1:80"
        assert measurement.seq_num == 1000
        assert measurement.ack_num == 1050
        assert measurement.data_packet_num == 1
        assert measurement.ack_packet_num == 2

    def test_rtt_measurement_multiple_flows(self, analyzer):
        """Test RTT measurement for multiple flows."""
        # Flow 1: Client 1 -> Server
        flow1_data = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="PA") / Raw(
            load=b"data1"
        )
        flow1_data.time = 1234567890.0

        flow1_ack = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1005, flags="A")
        flow1_ack.time = 1234567890.05  # 50ms

        # Flow 2: Client 2 -> Server
        flow2_data = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="PA") / Raw(
            load=b"data2"
        )
        flow2_data.time = 1234567890.1

        flow2_ack = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=80, dport=54321, seq=6000, ack=2005, flags="A")
        flow2_ack.time = 1234567890.25  # 150ms

        # Process packets
        analyzer.process_packet(flow1_data, 1)
        analyzer.process_packet(flow1_ack, 2)
        analyzer.process_packet(flow2_data, 3)
        analyzer.process_packet(flow2_ack, 4)

        # Should have two RTT measurements
        assert len(analyzer.measurements) == 2
        assert analyzer.measurements[0].rtt == pytest.approx(0.05, abs=0.01)  # 50ms
        assert analyzer.measurements[1].rtt == pytest.approx(0.15, abs=0.01)  # 150ms

    def test_rtt_measurement_no_payload(self, analyzer):
        """Test that packets without payload are not tracked for RTT."""
        # SYN packet (no payload)
        syn_packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        syn_packet.time = 1234567890.0

        # SYN-ACK (no payload)
        synack_packet = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        synack_packet.time = 1234567890.05

        analyzer.process_packet(syn_packet, 1)
        analyzer.process_packet(synack_packet, 2)

        # No RTT measurements (no payload in packets)
        assert len(analyzer.measurements) == 0

    def test_rtt_measurement_latency_filter(self):
        """Test that latency filter only keeps measurements above threshold."""
        analyzer = RTTAnalyzer(rtt_warning=0.1, rtt_critical=0.5, latency_filter=0.2)

        # Low latency flow (should be filtered out)
        low_rtt_data = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="PA") / Raw(
            load=b"data"
        )
        low_rtt_data.time = 1234567890.0

        low_rtt_ack = IP(src="10.0.0.1", dst="192.168.1.1") / TCP(sport=80, dport=12345, seq=5000, ack=1004, flags="A")
        low_rtt_ack.time = 1234567890.05  # 50ms (below filter)

        # High latency flow (should be kept)
        high_rtt_data = IP(src="192.168.1.2", dst="10.0.0.1") / TCP(sport=54321, dport=80, seq=2000, flags="PA") / Raw(
            load=b"data"
        )
        high_rtt_data.time = 1234567890.1

        high_rtt_ack = IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=80, dport=54321, seq=6000, ack=2004, flags="A")
        high_rtt_ack.time = 1234567890.35  # 250ms (above filter)

        analyzer.process_packet(low_rtt_data, 1)
        analyzer.process_packet(low_rtt_ack, 2)
        analyzer.process_packet(high_rtt_data, 3)
        analyzer.process_packet(high_rtt_ack, 4)

        # Only high latency measurement should be kept
        assert len(analyzer.measurements) == 1
        assert analyzer.measurements[0].rtt == pytest.approx(0.25, abs=0.01)

    def test_finalize_statistics(self, analyzer):
        """Test that finalize() calculates correct statistics."""
        # Create multiple RTT measurements for one flow
        flow_key = "192.168.1.1:12345->10.0.0.1:80"

        # Add measurements manually for testing
        analyzer.measurements = [
            RTTMeasurement(timestamp=1234567890.0, rtt=0.05, flow_key=flow_key, seq_num=1000, ack_num=1005, data_packet_num=1, ack_packet_num=2),
            RTTMeasurement(timestamp=1234567891.0, rtt=0.10, flow_key=flow_key, seq_num=2000, ack_num=2005, data_packet_num=3, ack_packet_num=4),
            RTTMeasurement(timestamp=1234567892.0, rtt=0.15, flow_key=flow_key, seq_num=3000, ack_num=3005, data_packet_num=5, ack_packet_num=6),
        ]

        results = analyzer.finalize()

        # Check results structure (API uses flow_statistics, not flow_stats)
        assert "total_measurements" in results
        assert "flow_statistics" in results
        assert "global_statistics" in results

        # Check flow statistics
        assert results["total_measurements"] == 3
        assert len(results["flow_statistics"]) == 1

        flow_stat = results["flow_statistics"][0]
        assert flow_stat["flow_key"] == flow_key
        assert flow_stat["measurements_count"] == 3
        assert flow_stat["min_rtt"] == pytest.approx(0.05, abs=0.001)
        assert flow_stat["max_rtt"] == pytest.approx(0.15, abs=0.001)
        assert flow_stat["mean_rtt"] == pytest.approx(0.10, abs=0.001)  # (0.05 + 0.10 + 0.15) / 3
        assert flow_stat["median_rtt"] == pytest.approx(0.10, abs=0.001)

    def test_rtt_spikes_detection(self, analyzer):
        """Test that RTT spikes are detected when above warning threshold."""
        flow_key = "192.168.1.1:12345->10.0.0.1:80"

        # Normal RTT (below warning)
        analyzer.measurements.append(
            RTTMeasurement(timestamp=1234567890.0, rtt=0.05, flow_key=flow_key, seq_num=1000, ack_num=1005, data_packet_num=1, ack_packet_num=2)
        )

        # RTT spike (above warning 0.1s)
        analyzer.measurements.append(
            RTTMeasurement(timestamp=1234567891.0, rtt=0.15, flow_key=flow_key, seq_num=2000, ack_num=2005, data_packet_num=3, ack_packet_num=4)
        )

        # Critical RTT (above critical 0.5s)
        analyzer.measurements.append(
            RTTMeasurement(timestamp=1234567892.0, rtt=0.6, flow_key=flow_key, seq_num=3000, ack_num=3005, data_packet_num=5, ack_packet_num=6)
        )

        results = analyzer.finalize()
        flow_stat = results["flow_statistics"][0]

        # Should detect 2 spikes (0.15 and 0.6 are above warning 0.1)
        assert flow_stat["rtt_spikes"] == 2

    def test_cleanup_stale_segments(self, analyzer):
        """Test that unacked segments older than timeout are cleaned up."""
        flow_key = "192.168.1.1:12345->10.0.0.1:80"

        # Add a stale segment (older than 60s timeout)
        analyzer._unacked_segments[flow_key][1000] = (1, 1234567890.0, 100)  # Old timestamp

        # Add a recent measurement to establish current_time reference
        analyzer.measurements.append(
            RTTMeasurement(timestamp=1234567951.0, rtt=0.05, flow_key=flow_key, seq_num=2000, ack_num=2005, data_packet_num=2, ack_packet_num=3)
        )

        # Trigger cleanup by calling finalize (which calls _cleanup_stale_segments)
        analyzer.finalize()

        # Stale segment should be cleaned up (older than 60s)
        # Note: cleanup uses measurements[-1].timestamp as current_time
        if flow_key in analyzer._unacked_segments:
            assert 1000 not in analyzer._unacked_segments[flow_key]

    def test_non_tcp_packet_ignored(self, analyzer):
        """Test that non-TCP packets are ignored."""
        # UDP packet
        udp_packet = IP(src="192.168.1.1", dst="10.0.0.1") / Raw(load=b"udp data")
        udp_packet.time = 1234567890.0

        analyzer.process_packet(udp_packet, 1)

        # No measurements should be created
        assert len(analyzer.measurements) == 0
        assert len(analyzer._unacked_segments) == 0
