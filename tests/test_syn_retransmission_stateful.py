"""
Test cases for stateful SYN retransmission detection.

Validates that the analyzer correctly distinguishes:
- TRUE retransmissions (same ISN)
- Port reuse (different ISN)

These tests ensure compliance with RFC 793 and alignment with
Wireshark's tcp.analysis.retransmission behavior.
"""

import pytest
from scapy.all import Ether, IP, TCP

from src.analyzers.syn_retransmission import SYNRetransmissionAnalyzer


class TestStatefulSYNRetransmission:
    """Test stateful SYN retransmission detection."""

    def test_port_reuse_not_counted_as_retransmission(self):
        """
        Port reuse with different ISN should NOT be counted as retransmission.

        Scenario:
          1. SYN (src_port=50000, seq=1000) @ t=0
          2. SYN (src_port=50000, seq=2000) @ t=0.01 (NEW connection, port reused)

        Expected: 0 retransmissions detected (different ISN)

        This validates that the analyzer correctly handles rapid port reuse
        scenarios common in Kubernetes and high-traffic environments.
        """
        analyzer = SYNRetransmissionAnalyzer()

        # Packet 1: First SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Packet 2: Second SYN with DIFFERENT seq (port reuse)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=2000)
        pkt2.time = 1.01  # 10ms later

        results = analyzer.analyze([pkt1, pkt2])

        # Should detect NO retransmissions (different ISN = port reuse)
        assert results["total_syn_retransmissions"] == 0, "Port reuse with different ISN should not be flagged as retransmission"

    def test_same_isn_counted_as_retransmission(self):
        """
        Same ISN with same flow should BE counted as retransmission.

        Scenario:
          1. SYN (src_port=50000, seq=1000) @ t=0
          2. SYN (src_port=50000, seq=1000) @ t=1.0 (SAME ISN = retransmission)

        Expected: 1 retransmission detected

        This validates RFC 793 compliance: retransmission MUST have the same
        Initial Sequence Number (ISN).
        """
        analyzer = SYNRetransmissionAnalyzer()

        # Packet 1: First SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Packet 2: Retransmission with SAME seq
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt2.time = 2.0  # 1s later (RFC 6298 initial RTO)

        results = analyzer.analyze([pkt1, pkt2])

        # Should detect 1 retransmission (same ISN)
        assert results["total_syn_retransmissions"] == 1, "Same ISN should be counted as retransmission"
        assert len(results["all_retransmissions"]) == 1
        assert results["all_retransmissions"][0]["retransmission_count"] == 1

    def test_rapid_port_reuse_scenario(self):
        """
        Kubernetes/high-traffic scenario: rapid port reuse within seconds.

        Should NOT create false positives.

        Scenario:
          - 10 rapid connections on same port with different ISNs
          - Each connection 10ms apart

        Expected: 0 retransmissions (all different ISNs = legitimate port reuse)

        This simulates real-world high-traffic scenarios where ephemeral ports
        are rapidly recycled, ensuring no false positives are generated.
        """
        analyzer = SYNRetransmissionAnalyzer()

        packets = []
        base_time = 1.0

        # Simulate 10 rapid connections on same port with different ISNs
        for i in range(10):
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
                sport=50000, dport=80, flags="S", seq=1000 + i * 100  # Different ISNs
            )
            pkt.time = base_time + i * 0.01  # 10ms apart
            packets.append(pkt)

        results = analyzer.analyze(packets)

        # Should detect NO retransmissions (all different ISNs = legitimate port reuse)
        assert (
            results["total_syn_retransmissions"] == 0
        ), "Rapid port reuse with different ISNs should not be flagged as retransmissions"

    def test_multiple_retransmissions_same_connection(self):
        """
        Multiple retransmissions on same connection with same ISN.

        Scenario:
          1. SYN (seq=1000) @ t=0
          2. SYN (seq=1000) @ t=1.0 (retransmission #1)
          3. SYN (seq=1000) @ t=3.0 (retransmission #2)

        Expected: 2 retransmissions detected

        This validates that multiple retransmissions with the same ISN are
        correctly counted, following RFC 6298 exponential backoff patterns.
        """
        analyzer = SYNRetransmissionAnalyzer()

        # Packet 1: First SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Packet 2: First retransmission (1s later)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt2.time = 2.0

        # Packet 3: Second retransmission (2s later)
        pkt3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt3.time = 4.0

        results = analyzer.analyze([pkt1, pkt2, pkt3])

        # Should detect 2 retransmissions
        assert results["total_syn_retransmissions"] == 1  # 1 connection with retransmissions
        assert results["all_retransmissions"][0]["retransmission_count"] == 2

    def test_port_reuse_after_successful_connection(self):
        """
        Port reuse after a successful connection completes.

        Scenario:
          1. Connection A: SYN (seq=1000) @ t=0
          2. Connection A: SYN/ACK received @ t=0.05
          3. Connection B: SYN (seq=2000) @ t=0.1 (NEW connection, port reused)

        Expected: 0 retransmissions (different ISN = new connection)

        This validates that completed connections don't interfere with
        detection of new connections on the same port.
        """
        analyzer = SYNRetransmissionAnalyzer()

        # Connection A: SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Connection A: SYN/ACK
        pkt2 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001)
        pkt2.time = 1.05

        # Connection B: New SYN with different ISN (port reuse)
        pkt3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=2000)
        pkt3.time = 1.1

        results = analyzer.analyze([pkt1, pkt2, pkt3])

        # Should detect NO retransmissions (different ISN after completed connection)
        assert results["total_syn_retransmissions"] == 0

    def test_retransmission_followed_by_port_reuse(self):
        """
        True retransmission followed by port reuse with different ISN.

        Scenario:
          1. SYN (seq=1000) @ t=0
          2. SYN (seq=1000) @ t=1.0 (retransmission)
          3. SYN/ACK received @ t=1.1 (connection completes)
          4. SYN (seq=2000) @ t=2.0 (NEW connection, port reused)

        Expected: 1 retransmission for first connection, 0 for second

        This validates that the analyzer correctly handles the transition
        from retransmission detection to port reuse detection.
        """
        analyzer = SYNRetransmissionAnalyzer()

        # Packet 1: First SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Packet 2: Retransmission (same ISN)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt2.time = 2.0

        # Packet 3: SYN/ACK to complete the first connection
        pkt3 = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001)
        pkt3.time = 2.1

        # Packet 4: New connection (different ISN, port reused)
        pkt4 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=2000)
        pkt4.time = 3.0

        results = analyzer.analyze([pkt1, pkt2, pkt3, pkt4])

        # Should detect 1 retransmission (first connection) but not flag the new connection
        assert results["total_syn_retransmissions"] == 1
        assert results["all_retransmissions"][0]["initial_seq"] == 1000
        assert results["all_retransmissions"][0]["retransmission_count"] == 1

    def test_different_flows_independent(self):
        """
        Different flows (different ports) should be tracked independently.

        Scenario:
          1. Flow A: SYN (sport=50000, seq=1000) @ t=0
          2. Flow B: SYN (sport=50001, seq=1000) @ t=0.01
          3. Flow A: SYN (sport=50000, seq=1000) @ t=1.0 (retransmission)

        Expected: 1 retransmission (only Flow A)

        This validates that different flows don't interfere with each other.
        """
        analyzer = SYNRetransmissionAnalyzer()

        # Flow A: First SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Flow B: First SYN (different port, same seq OK)
        pkt2 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50001, dport=80, flags="S", seq=1000)
        pkt2.time = 1.01

        # Flow A: Retransmission
        pkt3 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt3.time = 2.0

        results = analyzer.analyze([pkt1, pkt2, pkt3])

        # Should detect 1 retransmission (Flow A only)
        assert results["total_syn_retransmissions"] == 1
        assert results["all_retransmissions"][0]["src_port"] == 50000

    def test_rfc_6298_exponential_backoff(self):
        """
        Test RFC 6298 compliant exponential backoff pattern.

        Scenario:
          1. SYN (seq=1000) @ t=0
          2. SYN (seq=1000) @ t=1.0 (1s later - initial RTO)
          3. SYN (seq=1000) @ t=3.0 (2s later - doubled RTO)
          4. SYN (seq=1000) @ t=7.0 (4s later - doubled RTO)

        Expected: RFC compliant pattern detected

        This validates that the analyzer recognizes RFC 6298 compliant
        retransmission patterns.
        """
        analyzer = SYNRetransmissionAnalyzer()

        packets = []

        # Initial SYN
        pkt1 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0
        packets.append(pkt1)

        # Retransmissions with exponential backoff
        times = [2.0, 4.0, 8.0]  # 1s, 2s, 4s intervals
        for t in times:
            pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=80, flags="S", seq=1000)
            pkt.time = t
            packets.append(pkt)

        results = analyzer.analyze(packets)

        # Should detect 3 retransmissions with RFC compliant pattern
        assert results["total_syn_retransmissions"] == 1
        retrans = results["all_retransmissions"][0]
        assert retrans["retransmission_count"] == 3

        # Check RFC analysis
        rfc_analysis = retrans["rfc_analysis"]
        assert rfc_analysis["initial_rto"] >= 1.0, "Initial RTO should be >= 1s per RFC 6298"
        assert rfc_analysis["backoff_compliant"] is True, "Should follow exponential backoff"
