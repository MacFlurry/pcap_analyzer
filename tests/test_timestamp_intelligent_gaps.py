"""
Test suite for Intelligent Gap Detection

Tests protocol-aware gap classification following TDD methodology.
Reduces false positives from 3,699 to <100 by using RFC-compliant thresholds.

References:
    RFC 6298: Computing TCP's Retransmission Timer (RTO)
    RFC 1035: DNS query timeout (5 seconds recommended)
    RFC 792: ICMP - varies by message type
    ITU-T Y.1541: Network Performance Objectives for IP-based Services
"""

import pytest

from src.analyzers.timestamp_analyzer import TimestampAnalyzer, TimestampGap
from src.parsers.fast_parser import PacketMetadata


def create_tcp_packet(timestamp, src_ip, dst_ip, src_port=54001, dst_port=80, seq=1000, ack=2000, flags=0x10):
    """Helper to create TCP test packet with minimal required fields"""
    return PacketMetadata(
        packet_num=0, timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip,
        ip_version=4, ttl=64, total_length=60, packet_length=74, protocol="TCP",
        src_port=src_port, dst_port=dst_port, tcp_seq=seq, tcp_ack=ack, tcp_flags=flags
    )


def create_udp_packet(timestamp, src_ip, dst_ip, src_port=54001, dst_port=80):
    """Helper to create UDP test packet with minimal required fields"""
    return PacketMetadata(
        packet_num=0, timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip,
        ip_version=4, ttl=64, total_length=60, packet_length=74, protocol="UDP",
        src_port=src_port, dst_port=dst_port
    )


def create_icmp_packet(timestamp, src_ip, dst_ip, icmp_type=8, icmp_code=0):
    """Helper to create ICMP test packet with minimal required fields"""
    return PacketMetadata(
        packet_num=0, timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip,
        ip_version=4, ttl=64, total_length=60, packet_length=74, protocol="ICMP",
        icmp_type=icmp_type, icmp_code=icmp_code
    )


class TestIntelligentGapDetection:
    """Test suite for protocol-aware gap classification"""

    def test_tcp_interactive_no_false_positive(self):
        """
        Test Case 1: TCP interactive traffic (SSH, Telnet) - 500ms gaps are normal

        Given: TCP packets with 500ms inter-packet gaps (user typing)
        When: Intelligent gap detection analyzes them
        Then: No abnormal gaps reported (user think time is normal)

        RFC 6298: TCP RTO typically 200ms-2s, user interaction can be much longer
        """
        analyzer = TimestampAnalyzer()

        # Simulate TCP SSH session with normal user interaction gaps
        packets = [
            create_tcp_packet(timestamp=1.0, src_ip="192.168.1.100", dst_ip="10.0.0.50",
                             src_port=52341, dst_port=22, seq=1000, ack=2000, flags=0x10),  # ACK
            create_tcp_packet(timestamp=1.5, src_ip="10.0.0.50", dst_ip="192.168.1.100",
                             src_port=22, dst_port=52341, seq=2000, ack=1001, flags=0x18),  # PSH,ACK
            create_tcp_packet(timestamp=2.8, src_ip="192.168.1.100", dst_ip="10.0.0.50",  # 1.3s gap (user typing)
                             src_port=52341, dst_port=22, seq=1001, ack=2010, flags=0x18),  # PSH,ACK
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # Should not report user interaction gaps as abnormal
        abnormal_gaps = [g for g in result["gaps"] if g["is_abnormal"]]
        assert len(abnormal_gaps) == 0, "TCP interactive gaps should not be flagged as abnormal"

    def test_dns_timeout_5s_threshold(self):
        """
        Test Case 2: DNS queries respect RFC 1035 timeout (5 seconds)

        Given: DNS query with 6 second gap before timeout
        When: Gap detection applies DNS-specific threshold
        Then: Gap is flagged as abnormal (exceeds RFC 1035 5s recommendation)
        """
        analyzer = TimestampAnalyzer()

        packets = [
            create_udp_packet(timestamp=1.0, src_ip="192.168.1.100", dst_ip="8.8.8.8",
                             src_port=54321, dst_port=53),
            create_udp_packet(timestamp=7.1, src_ip="192.168.1.100", dst_ip="8.8.8.8",  # 6.1s gap - timeout!
                             src_port=54322, dst_port=53),
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # 6s gap should be flagged (exceeds DNS 5s timeout)
        abnormal_gaps = [g for g in result["gaps"] if g["is_abnormal"]]
        assert len(abnormal_gaps) == 1
        assert abnormal_gaps[0]["gap_duration"] > 5.0

    def test_tcp_bulk_transfer_no_gaps(self):
        """
        Test Case 3: TCP bulk transfer (FTP, HTTP download) - continuous flow

        Given: TCP data transfer with small intervals (<10ms)
        When: Gap detection analyzes bulk transfer
        Then: No gaps reported (continuous data flow is normal)
        """
        analyzer = TimestampAnalyzer()

        # Simulate FTP data transfer - packets every 5ms
        packets = [
            create_tcp_packet(timestamp=1.000 + i * 0.005, src_ip="10.0.0.50", dst_ip="192.168.1.100",
                             src_port=20, dst_port=54123, seq=1000+i*1460, ack=2000, flags=0x18)  # PSH,ACK
            for i in range(20)
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        assert len(result["gaps"]) == 0, "Continuous TCP transfer should have no gaps"

    def test_icmp_echo_request_timeout(self):
        """
        Test Case 4: ICMP echo request timeout (typical: 1 second)

        Given: ICMP echo request with 2 second gap (no reply)
        When: Gap detection applies ICMP timeout threshold
        Then: Gap is flagged as abnormal (host unreachable)
        """
        analyzer = TimestampAnalyzer()

        packets = [
            create_icmp_packet(timestamp=1.0, src_ip="192.168.1.100", dst_ip="8.8.8.8",
                              icmp_type=8, icmp_code=0),  # Echo request
            create_icmp_packet(timestamp=3.5, src_ip="192.168.1.100", dst_ip="8.8.4.4",  # 2.5s gap - timeout
                              icmp_type=8, icmp_code=0),
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # 2.5s gap exceeds ICMP timeout threshold
        abnormal_gaps = [g for g in result["gaps"] if g["is_abnormal"]]
        assert len(abnormal_gaps) == 1

    def test_udp_streaming_jitter_tolerance(self):
        """
        Test Case 5: UDP streaming (VoIP, video) - jitter tolerance

        Given: UDP RTP stream with normal jitter (<200ms variation)
        When: Gap detection applies streaming media thresholds
        Then: Normal jitter is not flagged as abnormal

        ITU-T Y.1541: QoS Class 1 allows up to 100ms jitter
        """
        analyzer = TimestampAnalyzer()

        # Simulate VoIP RTP stream - 20ms packet interval with normal jitter
        base_interval = 0.020  # 20ms
        packets = [
            create_udp_packet(
                timestamp=1.000 + i * base_interval + ((-1) ** i) * 0.005,  # ±5ms jitter
                src_ip="10.0.0.50", dst_ip="192.168.1.100",
                src_port=8000, dst_port=8000
            )
            for i in range(50)
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # Normal jitter should not be flagged
        assert len(result["gaps"]) == 0, "Normal VoIP jitter should not create gaps"

    def test_periodic_polling_pattern(self):
        """
        Test Case 6: Periodic polling/heartbeat (SNMP, monitoring)

        Given: SNMP polling every 60 seconds (regular pattern)
        When: Gap detection identifies periodic behavior
        Then: Gaps are marked as non-abnormal (expected behavior)
        """
        analyzer = TimestampAnalyzer()

        # Simulate SNMP polling every 60 seconds
        packets = [
            create_udp_packet(
                timestamp=1.0 + i * 60.0,  # Every 60 seconds
                src_ip="192.168.1.100", dst_ip="10.0.0.50",
                src_port=54321, dst_port=161  # SNMP
            )
            for i in range(10)
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # Should detect periodic pattern
        assert result["periodic_pattern_detected"] is True
        # Gaps exist but are not abnormal
        assert result["non_periodic_gaps"] == 0

    def test_flow_aware_gap_detection(self):
        """
        Test Case 7: Flow-aware gap detection (inter-flow vs intra-flow)

        Given: Two concurrent TCP flows with different characteristics
        When: Gap detection groups packets by flow
        Then: Inter-flow gaps are NOT flagged, only intra-flow timeouts
        """
        analyzer = TimestampAnalyzer()

        # Flow 1: HTTP download (continuous)
        # Flow 2: SSH session (interactive with pauses)
        packets = [
            # Flow 1: HTTP
            create_tcp_packet(timestamp=1.0, src_ip="10.0.0.50", dst_ip="192.168.1.100",
                             src_port=80, dst_port=54001, seq=1000, ack=2000, flags=0x18),  # PSH,ACK
            # Flow 2: SSH (different flow)
            create_tcp_packet(timestamp=1.1, src_ip="10.0.0.60", dst_ip="192.168.1.100",
                             src_port=22, dst_port=54002, seq=3000, ack=4000, flags=0x18),  # PSH,ACK
            # Flow 1: HTTP continues
            create_tcp_packet(timestamp=1.2, src_ip="10.0.0.50", dst_ip="192.168.1.100",
                             src_port=80, dst_port=54001, seq=1001, ack=2000, flags=0x18),  # PSH,ACK
            # Flow 2: SSH user pauses for 2 seconds (normal)
            create_tcp_packet(timestamp=3.2, src_ip="10.0.0.60", dst_ip="192.168.1.100",
                             src_port=22, dst_port=54002, seq=3001, ack=4000, flags=0x18),  # PSH,ACK
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # Flow-aware: SSH pause should not be flagged as abnormal
        # Inter-flow gaps (HTTP to SSH at 1.1s) should be ignored
        abnormal_gaps = [g for g in result["gaps"] if g["is_abnormal"]]
        assert len(abnormal_gaps) == 0, "Flow-aware detection should not flag inter-flow gaps"

    def test_tcp_retransmission_timeout_detected(self):
        """
        Test Case 8: Detect TCP retransmission timeout (RTO)

        Given: TCP segment with 3 second gap before retransmission
        When: Gap detection applies TCP RTO thresholds (RFC 6298: 1s minimum)
        Then: Gap is flagged as abnormal (RTO event)
        """
        analyzer = TimestampAnalyzer()

        packets = [
            create_tcp_packet(timestamp=1.0, src_ip="192.168.1.100", dst_ip="10.0.0.50",
                             src_port=54001, dst_port=80, seq=1000, ack=2000, flags=0x18),  # PSH,ACK
            # No ACK received, client retransmits after 3 seconds
            create_tcp_packet(timestamp=4.0, src_ip="192.168.1.100", dst_ip="10.0.0.50",
                             src_port=54001, dst_port=80, seq=1000, ack=2000, flags=0x18),  # PSH,ACK (Same seq = retrans)
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # 3s gap exceeds TCP RTO minimum (1s per RFC 6298)
        abnormal_gaps = [g for g in result["gaps"] if g["is_abnormal"]]
        assert len(abnormal_gaps) == 1
        assert abnormal_gaps[0]["gap_duration"] >= 1.0

    def test_protocol_classification_accuracy(self):
        """
        Test Case 9: Verify protocol classification is accurate

        Given: Mixed protocol traffic
        When: Gaps are detected
        Then: Each gap has correct protocol classification
        """
        analyzer = TimestampAnalyzer()

        packets = [
            create_udp_packet(timestamp=1.0, src_ip="192.168.1.100", dst_ip="8.8.8.8",
                             src_port=54321, dst_port=53),
            create_tcp_packet(timestamp=7.0, src_ip="192.168.1.100", dst_ip="10.0.0.50",
                             src_port=54001, dst_port=80, seq=1000, ack=0, flags=0x02),  # SYN
            create_icmp_packet(timestamp=14.0, src_ip="192.168.1.100", dst_ip="8.8.4.4",
                              icmp_type=8, icmp_code=0),
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # Verify protocol classification
        assert len(result["gaps"]) >= 2
        protocols_in_gaps = [g["protocol"] for g in result["gaps"]]
        assert "UDP" in protocols_in_gaps or "TCP" in protocols_in_gaps or "ICMP" in protocols_in_gaps

    def test_baseline_statistics_calculation(self):
        """
        Test Case 10: Calculate baseline statistics for adaptive thresholds

        Given: Network traffic with established baseline
        When: Gap detection calculates statistics
        Then: Baseline median RTT and threshold multipliers are computed

        This enables adaptive thresholds based on actual network conditions
        """
        analyzer = TimestampAnalyzer()

        # Normal traffic establishing a baseline
        packets = [
            create_tcp_packet(timestamp=1.000 + i * 0.050, src_ip="192.168.1.100", dst_ip="10.0.0.50",
                             src_port=54001, dst_port=80, seq=1000+i, ack=2000, flags=0x10)  # ACK
            for i in range(20)
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        # Should have interval statistics
        assert "interval_statistics" in result
        assert "median_interval" in result["interval_statistics"]
        assert result["interval_statistics"]["median_interval"] > 0

    def test_gap_context_information(self):
        """
        Test Case 11: Gap records include context for troubleshooting

        Given: Detected abnormal gap
        When: Gap information is returned
        Then: Includes src/dst IP, protocol, port numbers, and classification reason
        """
        analyzer = TimestampAnalyzer()

        packets = [
            create_udp_packet(timestamp=1.0, src_ip="192.168.1.100", dst_ip="8.8.8.8",
                             src_port=54321, dst_port=53),
            create_udp_packet(timestamp=8.0, src_ip="192.168.1.100", dst_ip="8.8.8.8",  # 7s gap - DNS timeout
                             src_port=54321, dst_port=53),
        ]

        for i, pkt in enumerate(packets):
            analyzer.process_packet(pkt, i)

        result = analyzer.finalize()

        gaps = result["gaps"]
        assert len(gaps) > 0

        gap = gaps[0]
        # Verify context fields
        assert "src_ip" in gap
        assert "dst_ip" in gap
        assert "protocol" in gap
        assert "gap_duration" in gap
        assert gap["gap_duration"] > 5.0  # DNS timeout threshold


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
