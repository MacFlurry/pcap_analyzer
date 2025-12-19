"""
Test cases for TCP retransmission detection with port reuse scenarios.

Validates that the RetransmissionAnalyzer correctly handles:
- Port reuse with different ISN (should NOT flag as retransmission)
- True retransmissions with same ISN (SHOULD flag as retransmission)
- RST-triggered port reuse (should reset flow state)
- Rapid connection recycling (Kubernetes/Docker environments)

Bug Report Reference: "Rapport de Validation : Correctif des Faux Positifs 'TCP Retransmission'"
- Before fix: 11,574 false positives
- After fix: 0 false positives
- Root cause: _seen_segments not cleared on new connection detection

RFC Compliance:
- RFC 793: TCP connection uniqueness (4-tuple + ISN)
- RFC 2581: Retransmission detection (connection-scoped)
- RFC 6298: RTO calculation (requires accurate retransmission detection)
"""

import pytest
from scapy.all import Ether, IP, TCP, Raw

from src.analyzers.retransmission import RetransmissionAnalyzer


class TestRetransmissionPortReuse:
    """Test retransmission detection with port reuse scenarios."""

    def test_port_reuse_different_isn_zero_retransmissions(self):
        """
        Port reuse with different ISN should NOT trigger false positives.

        Scenario:
          1. Connection 1: SYN (seq=1000) + Data (seq=1001, len=100) + FIN
          2. Connection 2: SYN (seq=2000, DIFFERENT ISN) + Data (seq=2001, len=100)

        Expected: 0 retransmissions detected

        This is the PRIMARY bug scenario from the incident report.
        Before fix: Data packet from Connection 2 matched _seen_segments from Connection 1
        After fix: _seen_segments cleared on new connection (different ISN)
        """
        analyzer = RetransmissionAnalyzer()

        # Connection 1: SYN
        pkt1 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Connection 1: Data packet
        pkt2 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001) / Raw(load=b"A" * 100)
        pkt2.time = 1.05

        # Connection 1: FIN
        pkt3 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="FA", seq=1101)
        pkt3.time = 1.1

        # Connection 2: New SYN with DIFFERENT ISN (port reuse)
        pkt4 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=2000)
        pkt4.time = 1.15

        # Connection 2: Data packet with DIFFERENT sequence space
        pkt5 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=2001) / Raw(load=b"B" * 100)
        pkt5.time = 1.2

        results = analyzer.analyze([pkt1, pkt2, pkt3, pkt4, pkt5])

        # Should detect NO retransmissions (different ISN = new connection)
        assert results["total_retransmissions"] == 0, (
            f"Port reuse with different ISN should not create false positives. "
            f"Got {results['total_retransmissions']} retransmissions instead of 0"
        )

    def test_same_isn_detects_true_retransmission(self):
        """
        True retransmission with same ISN SHOULD be detected.

        Scenario:
          1. SYN (seq=1000)
          2. Data packet 1 (seq=1001, len=100) @ t=1.0
          3. Data packet 1 RETRANSMITTED (seq=1001, len=100) @ t=1.3 (SAME seq)

        Expected: 1 retransmission detected

        This validates that the fix doesn't break legitimate retransmission detection.
        """
        analyzer = RetransmissionAnalyzer()

        # SYN
        pkt1 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Original data packet
        pkt2 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001) / Raw(load=b"A" * 100)
        pkt2.time = 1.05

        # Retransmission of the same data (SAME seq, SAME len)
        pkt3 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001) / Raw(load=b"A" * 100)
        pkt3.time = 1.35  # 300ms later (RTO)

        results = analyzer.analyze([pkt1, pkt2, pkt3])

        # Should detect 1 retransmission
        assert results["total_retransmissions"] == 1, (
            f"Same ISN retransmission should be detected. "
            f"Got {results['total_retransmissions']} instead of 1"
        )
        assert results["rto_count"] == 1, "Should be classified as RTO (300ms delay)"

    def test_rst_triggered_port_reuse_clears_state(self):
        """
        RST packets should trigger flow state cleanup.

        RST packets bypass TIME-WAIT, allowing immediate port reuse.
        This is a CRITICAL edge case for false positives.

        Scenario:
          1. Connection 1: SYN (seq=1000) + Data (seq=1001, len=50)
          2. RST packet (connection abort)
          3. Connection 2: SYN (seq=3000, different ISN) + Data (seq=3001, len=50)

        Expected: 0 retransmissions detected

        Before fix: RST not handled, _seen_segments contains old data
        After fix: RST triggers _reset_flow_state(), clearing all history
        """
        analyzer = RetransmissionAnalyzer()

        # Connection 1: SYN
        pkt1 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Connection 1: Data packet
        pkt2 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001) / Raw(load=b"X" * 50)
        pkt2.time = 1.05

        # RST packet (connection aborted)
        pkt3 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="R", seq=1051)
        pkt3.time = 1.1

        # Connection 2: New SYN IMMEDIATELY after RST (different ISN)
        pkt4 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=3000)
        pkt4.time = 1.11  # Only 10ms after RST

        # Connection 2: Data packet
        pkt5 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=3001) / Raw(load=b"Y" * 50)
        pkt5.time = 1.15

        results = analyzer.analyze([pkt1, pkt2, pkt3, pkt4, pkt5])

        # Should detect NO retransmissions (RST cleared state)
        assert results["total_retransmissions"] == 0, (
            f"RST should trigger state cleanup. "
            f"Got {results['total_retransmissions']} retransmissions instead of 0"
        )

    def test_rapid_kubernetes_style_port_recycling(self):
        """
        Kubernetes/Docker scenario: 10 rapid connections on same port.

        Simulates high-traffic containerized environment with rapid port reuse.

        Scenario:
          - 10 sequential connections on same 4-tuple
          - Each connection: SYN + Data packet
          - Different ISN for each connection
          - 5ms interval between connections

        Expected: 0 retransmissions detected

        This validates the fix handles real-world containerized workloads.
        """
        analyzer = RetransmissionAnalyzer()

        packets = []
        base_time = 1.0

        for i in range(10):
            conn_time = base_time + (i * 0.005)  # 5ms apart
            isn = 1000 + (i * 1000)  # Different ISN each time

            # SYN for this connection
            syn_pkt = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=isn)
            syn_pkt.time = conn_time
            packets.append(syn_pkt)

            # Data packet for this connection
            data_pkt = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=isn + 1) / Raw(load=b"D" * 100)
            data_pkt.time = conn_time + 0.001
            packets.append(data_pkt)

        results = analyzer.analyze(packets)

        # Should detect NO retransmissions (all different ISNs)
        assert results["total_retransmissions"] == 0, (
            f"Rapid port reuse should not create false positives. "
            f"Got {results['total_retransmissions']} retransmissions instead of 0"
        )

    def test_overlapping_sequence_numbers_different_isn(self):
        """
        Overlapping sequence numbers with different ISNs should NOT match.

        Scenario:
          1. Connection 1: SYN (seq=5000) + Data (seq=5001, len=100)
          2. Connection 2: SYN (seq=10000) + Data (seq=5001, len=100, SAME seq by coincidence)

        Expected: 0 retransmissions detected

        This edge case tests that seq number alone isn't sufficient for matching;
        ISN tracking prevents false positives even when seq numbers coincidentally align.
        """
        analyzer = RetransmissionAnalyzer()

        # Connection 1: SYN
        pkt1 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=5000)
        pkt1.time = 1.0

        # Connection 1: Data packet (seq=5001)
        pkt2 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=5001) / Raw(load=b"A" * 100)
        pkt2.time = 1.05

        # Connection 1: FIN
        pkt3 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="FA", seq=5101)
        pkt3.time = 1.1

        # Connection 2: New SYN with different ISN
        pkt4 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=10000)
        pkt4.time = 1.15

        # Connection 2: Data packet with SAME seq as Connection 1 (coincidence)
        # This should NOT be flagged as retransmission (different connection)
        pkt5 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=5001) / Raw(load=b"B" * 100)
        pkt5.time = 1.2

        results = analyzer.analyze([pkt1, pkt2, pkt3, pkt4, pkt5])

        # Should detect NO retransmissions (different ISNs = different connections)
        assert results["total_retransmissions"] == 0, (
            f"Overlapping seq numbers with different ISNs should not match. "
            f"Got {results['total_retransmissions']} retransmissions instead of 0"
        )

    def test_multiple_retransmissions_same_connection(self):
        """
        Multiple retransmissions within the same connection should be detected.

        Scenario:
          1. SYN (seq=1000)
          2. Data packet 1 (seq=1001, len=100) @ t=1.0
          3. Data packet 2 (seq=1101, len=100) @ t=1.05
          4. Retransmit packet 1 (seq=1001, len=100) @ t=1.3 (RTO)
          5. Retransmit packet 2 (seq=1101, len=100) @ t=1.35 (RTO)

        Expected: 2 retransmissions detected

        This ensures the fix doesn't break detection of multiple retransmissions
        within a single connection lifecycle.
        """
        analyzer = RetransmissionAnalyzer()

        # SYN
        pkt1 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Original data packet 1
        pkt2 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001) / Raw(load=b"A" * 100)
        pkt2.time = 1.05

        # Original data packet 2
        pkt3 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1101) / Raw(load=b"B" * 100)
        pkt3.time = 1.1

        # Retransmit packet 1
        pkt4 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001) / Raw(load=b"A" * 100)
        pkt4.time = 1.35  # 300ms after original

        # Retransmit packet 2
        pkt5 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1101) / Raw(load=b"B" * 100)
        pkt5.time = 1.4  # 300ms after original

        results = analyzer.analyze([pkt1, pkt2, pkt3, pkt4, pkt5])

        # Should detect 2 retransmissions
        assert results["total_retransmissions"] == 2, (
            f"Should detect 2 retransmissions. "
            f"Got {results['total_retransmissions']} instead"
        )
        assert results["rto_count"] == 2, "Both should be classified as RTO (300ms delay)"

    def test_bidirectional_port_reuse_with_server_data(self):
        """
        BIDIRECTIONAL TEST: Port reuse with server sending data.

        This tests the CRITICAL gap identified in the audit report:
        "Il ne réinitialisait pas l'état du sens inverse (ACKs du serveur)"

        Scenario:
          1. Connection 1: Full 3-way handshake + bidirectional data (client AND server)
          2. Server sends data (seq=5001, len=200) creating reverse flow state
          3. Connection closes
          4. Connection 2: Port reuse with different ISNs
          5. Server sends data with LOWER seq than Connection 1 (seq=4001)

        Without bidirectional cleanup:
          - _highest_seq[reverse_key] = 5201 (from Connection 1)
          - Server packet seq=4001 < 5201 → FALSE POSITIVE

        Expected: 0 retransmissions (different ISN = new connection)
        """
        analyzer = RetransmissionAnalyzer()

        # ========== CONNECTION 1: Bidirectional traffic ==========

        # Client SYN (ISN = 1000)
        pkt1 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=1000)
        pkt1.time = 1.0

        # Server SYN-ACK (ISN = 5000)
        pkt2 = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="SA", seq=5000, ack=1001)
        pkt2.time = 1.01

        # Client ACK
        pkt3 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001, ack=5001)
        pkt3.time = 1.02

        # Client sends data
        pkt4 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1001, ack=5001) / Raw(load=b"C" * 100)
        pkt4.time = 1.03

        # Server ACKs client data
        pkt5 = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="A", seq=5001, ack=1101)
        pkt5.time = 1.04

        # Server sends data (CREATES REVERSE FLOW STATE)
        pkt6 = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="A", seq=5001, ack=1101) / Raw(load=b"S" * 200)
        pkt6.time = 1.05

        # Client ACKs server data
        pkt7 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=1101, ack=5201)
        pkt7.time = 1.06

        # Connection 1 FIN
        pkt8 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="FA", seq=1101, ack=5201)
        pkt8.time = 1.1

        # ========== CONNECTION 2: Port reuse with DIFFERENT ISNs ==========

        # Client SYN (NEW ISN = 2000, different from 1000)
        pkt9 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=2000)
        pkt9.time = 1.15

        # Server SYN-ACK (NEW ISN = 4000, LOWER than old 5000!)
        pkt10 = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="SA", seq=4000, ack=2001)
        pkt10.time = 1.16

        # Client ACK
        pkt11 = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=2001, ack=4001)
        pkt11.time = 1.17

        # Server sends data (seq=4001, LOWER than old highest_seq=5201)
        # Without bidirectional cleanup: seq=4001 < highest_seq[reverse_key]=5201 → FALSE POSITIVE
        pkt12 = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="A", seq=4001, ack=2001) / Raw(load=b"T" * 200)
        pkt12.time = 1.18

        results = analyzer.analyze([pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11, pkt12])

        # Should detect NO retransmissions (different ISNs = new connection)
        # Before fix: Would detect 1 false positive (pkt12 flagged due to stale reverse state)
        # After fix: 0 retransmissions (bidirectional cleanup clears reverse state)
        assert results["total_retransmissions"] == 0, (
            f"Bidirectional port reuse should not create false positives. "
            f"Got {results['total_retransmissions']} retransmissions instead of 0. "
            f"This indicates stale reverse flow state was not cleaned."
        )

    def test_bidirectional_rapid_connections(self):
        """
        BIDIRECTIONAL TEST: Rapid bidirectional connections with port reuse.

        Scenario:
          - 5 rapid connections on same port
          - Each connection has FULL bidirectional traffic
          - Server sends different amounts of data each time
          - Validates complete state cleanup between connections

        Expected: 0 retransmissions across all 5 connections
        """
        analyzer = RetransmissionAnalyzer()

        packets = []
        base_time = 1.0

        for i in range(5):
            conn_time = base_time + (i * 0.1)  # 100ms apart
            client_isn = 1000 + (i * 1000)     # Different client ISN each time
            server_isn = 5000 + (i * 500)      # Different server ISN each time

            # 3-way handshake
            syn = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="S", seq=client_isn)
            syn.time = conn_time
            packets.append(syn)

            synack = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="SA", seq=server_isn, ack=client_isn + 1)
            synack.time = conn_time + 0.01
            packets.append(synack)

            ack = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=client_isn + 1, ack=server_isn + 1)
            ack.time = conn_time + 0.02
            packets.append(ack)

            # Client data
            client_data = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=client_isn + 1, ack=server_isn + 1) / Raw(load=b"C" * 100)
            client_data.time = conn_time + 0.03
            packets.append(client_data)

            # Server ACK
            server_ack = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="A", seq=server_isn + 1, ack=client_isn + 101)
            server_ack.time = conn_time + 0.04
            packets.append(server_ack)

            # Server data (different length each time)
            server_data_len = 150 + (i * 50)  # 150, 200, 250, 300, 350
            server_data = Ether() / IP(src="10.0.2.10", dst="10.0.1.5") / TCP(sport=80, dport=50000, flags="A", seq=server_isn + 1, ack=client_isn + 101) / Raw(load=b"S" * server_data_len)
            server_data.time = conn_time + 0.05
            packets.append(server_data)

            # Client final ACK
            client_final_ack = Ether() / IP(src="10.0.1.5", dst="10.0.2.10") / TCP(sport=50000, dport=80, flags="A", seq=client_isn + 101, ack=server_isn + 1 + server_data_len)
            client_final_ack.time = conn_time + 0.06
            packets.append(client_final_ack)

        results = analyzer.analyze(packets)

        # Should detect NO retransmissions across all 5 bidirectional connections
        assert results["total_retransmissions"] == 0, (
            f"Rapid bidirectional connections should not create false positives. "
            f"Got {results['total_retransmissions']} retransmissions instead of 0"
        )
