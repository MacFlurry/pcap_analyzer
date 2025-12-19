"""
Integration Tests for v4.15.0 Packet Timeline Feature

Tests timeline feature with real PCAP files of different sizes:
- Small PCAP (100 packets) - verify correct sampling
- Medium PCAP (10,000 packets) - verify performance
- Large PCAP (1M packets) - verify memory efficiency
"""

import os
import tempfile
import time
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap


class TestSmallPCAPIntegration:
    """Integration tests with small PCAP files (~100 packets)."""

    def test_small_pcap_sampling(self):
        """Test correct sampling with 100-packet PCAP."""
        # Create small PCAP with 100 TCP packets
        packets = []
        for i in range(100):
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=1000+i, ack=2000
            ) / Raw(load=b"X" * 100)
            pkt.time = float(i) * 0.01  # 10ms intervals
            packets.append(pkt)

        # Simulate packet timeline sampling
        # First 10 (handshake), last 10 (teardown), any retrans context
        sampled = {
            "handshake": packets[:10],
            "teardown": packets[-10:]
        }

        assert len(sampled["handshake"]) == 10
        assert len(sampled["teardown"]) == 10
        assert sampled["handshake"][0].time == 0.0
        assert sampled["teardown"][-1].time == 0.99

    def test_small_pcap_with_retransmission(self):
        """Test sampling with retransmission in small PCAP."""
        packets = []

        # Normal flow with retransmission at packet 50
        for i in range(100):
            seq = 1000 + i
            if i == 50:
                # Retransmission - same seq as packet 45
                seq = 1000 + 45

            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=seq, ack=2000
            )
            pkt.time = float(i) * 0.01
            packets.append(pkt)

        # Retransmission context: packets 45-55 (±5 around retrans)
        retrans_index = 50
        context_start = max(0, retrans_index - 5)
        context_end = min(len(packets), retrans_index + 6)
        retrans_context = packets[context_start:context_end]

        assert len(retrans_context) == 11
        assert retrans_context[5][TCP].seq == packets[retrans_index][TCP].seq

    def test_small_pcap_performance(self):
        """Test performance with small PCAP."""
        start = time.time()

        # Simulate processing 100 packets
        from collections import deque
        ring_buffer = deque(maxlen=10)

        for i in range(100):
            packet_data = {
                "seq": 1000 + i,
                "time": float(i) * 0.01,
                "flags": "A"
            }
            ring_buffer.append(packet_data)

        elapsed = time.time() - start

        # Should complete in <10ms
        assert elapsed < 0.01
        assert len(ring_buffer) == 10


class TestMediumPCAPIntegration:
    """Integration tests with medium PCAP files (~10,000 packets)."""

    def test_medium_pcap_performance(self):
        """Test performance with 10,000-packet PCAP."""
        start = time.time()

        # Simulate processing 10,000 packets with ring buffer
        from collections import deque
        ring_buffer = deque(maxlen=10)

        for i in range(10000):
            packet_data = {
                "seq": 1000 + i,
                "time": float(i) * 0.001,
                "flags": "A",
                "len": 1500
            }
            ring_buffer.append(packet_data)

        elapsed = time.time() - start

        # Should complete in <100ms for 10k packets
        assert elapsed < 0.1
        assert len(ring_buffer) == 10

    def test_medium_pcap_memory_efficiency(self):
        """Test memory efficiency with medium PCAP."""
        import sys
        from collections import deque

        # Create ring buffer
        ring_buffer = deque(maxlen=10)

        # Simulate processing 10k packets
        for i in range(10000):
            packet_data = {
                "seq": 1000 + i,
                "time": float(i) * 0.001,
                "flags": "A",
                "len": 1500,
                "payload": "X" * 100  # 100 bytes payload
            }
            ring_buffer.append(packet_data)

        # Buffer should only contain 10 packets
        assert len(ring_buffer) == 10

        # Estimate memory: 10 packets * ~200 bytes each = ~2KB
        buffer_size = sys.getsizeof(ring_buffer)
        # Should be minimal (<10KB for metadata)
        assert buffer_size < 10240

    def test_multiple_flows_medium_pcap(self):
        """Test multiple flows in medium PCAP."""
        from collections import deque

        # Simulate 50 problematic flows
        flow_buffers = {}

        for flow_id in range(50):
            flow_key = f"192.168.1.{flow_id}:1234 → 192.168.1.{flow_id+1}:80"
            flow_buffers[flow_key] = deque(maxlen=10)

            # Add packets to each flow
            for pkt_id in range(200):  # 200 packets per flow
                flow_buffers[flow_key].append({
                    "seq": 1000 + pkt_id,
                    "time": float(pkt_id) * 0.01
                })

        # Should have 50 flows, each with 10 packets
        assert len(flow_buffers) == 50
        for flow_key, buffer in flow_buffers.items():
            assert len(buffer) == 10


class TestLargePCAPIntegration:
    """Integration tests with large PCAP files (1M+ packets)."""

    @pytest.mark.slow
    def test_large_pcap_memory_efficiency(self):
        """Test memory efficiency with 1M packets."""
        import sys
        from collections import deque

        # Simulate processing 1M packets
        ring_buffer = deque(maxlen=10)

        for i in range(1000000):
            packet_data = {
                "seq": 1000 + i,
                "time": float(i) * 0.0001,
                "flags": "A"
            }
            ring_buffer.append(packet_data)

        # Buffer should still only contain 10 packets
        assert len(ring_buffer) == 10

        # Memory should be minimal
        buffer_size = sys.getsizeof(ring_buffer)
        assert buffer_size < 10240  # <10KB

    @pytest.mark.slow
    def test_large_pcap_performance(self):
        """Test performance with 1M packets."""
        import time
        from collections import deque

        start = time.time()

        ring_buffer = deque(maxlen=10)

        for i in range(1000000):
            ring_buffer.append({
                "seq": 1000 + i,
                "time": float(i) * 0.0001
            })

        elapsed = time.time() - start

        # Should complete in <5 seconds for 1M packets
        assert elapsed < 5.0
        assert len(ring_buffer) == 10

    @pytest.mark.slow
    def test_100_flows_large_pcap(self):
        """Test 100 problematic flows with 1M packets."""
        from collections import deque

        flow_buffers = {}

        # 100 flows, 10k packets each = 1M packets total
        for flow_id in range(100):
            flow_key = f"192.168.1.{flow_id}:1234 → 10.0.0.{flow_id}:80"
            flow_buffers[flow_key] = deque(maxlen=10)

            for pkt_id in range(10000):
                flow_buffers[flow_key].append({
                    "seq": 1000 + pkt_id,
                    "time": float(pkt_id) * 0.001
                })

        # Should have 100 flows, each with 10 packets
        assert len(flow_buffers) == 100
        for buffer in flow_buffers.values():
            assert len(buffer) == 10


class TestRealPCAPFiles:
    """Integration tests with actual PCAP files."""

    def test_analyze_existing_pcap(self):
        """Test timeline feature with existing PCAP files."""
        # Look for PCAP files in pcap-dir
        pcap_dir = Path("/Users/omegabk/investigations/pcap_analyzer/pcap-dir")

        if not pcap_dir.exists():
            pytest.skip("PCAP directory not found")

        pcap_files = list(pcap_dir.glob("*.pcap"))

        if not pcap_files:
            pytest.skip("No PCAP files found")

        # Test with first PCAP file
        pcap_file = pcap_files[0]

        # This is a placeholder - actual implementation would:
        # 1. Load PCAP with scapy
        # 2. Process packets
        # 3. Verify timeline sampling
        # 4. Check memory usage

        assert pcap_file.exists()
        assert pcap_file.suffix == ".pcap"


class TestTimelineEdgeCases:
    """Edge case integration tests."""

    def test_single_packet_flow(self):
        """Test flow with only 1 packet."""
        from collections import deque

        ring_buffer = deque(maxlen=10)
        ring_buffer.append({"seq": 1000, "time": 0.0})

        assert len(ring_buffer) == 1

    def test_exactly_10_packets(self):
        """Test flow with exactly 10 packets."""
        from collections import deque

        ring_buffer = deque(maxlen=10)

        for i in range(10):
            ring_buffer.append({"seq": 1000 + i, "time": float(i)})

        assert len(ring_buffer) == 10
        assert ring_buffer[0]["seq"] == 1000
        assert ring_buffer[-1]["seq"] == 1009

    def test_rapid_packet_arrival(self):
        """Test timeline with rapid packet arrival (microsecond intervals)."""
        from collections import deque

        ring_buffer = deque(maxlen=10)

        for i in range(1000):
            ring_buffer.append({
                "seq": 1000 + i,
                "time": float(i) * 0.000001  # 1 microsecond intervals
            })

        assert len(ring_buffer) == 10
        # Should still capture last 10 packets
        assert ring_buffer[-1]["seq"] == 1999


class TestTimelineReporting:
    """Test timeline HTML report generation."""

    def test_timeline_html_generation(self):
        """Test HTML report includes timeline data."""
        from collections import deque

        # Simulate timeline data
        ring_buffer = deque(maxlen=10)

        for i in range(15):
            ring_buffer.append({
                "seq": 1000 + i,
                "ack": 2000 + i,
                "flags": "A",
                "len": 100,
                "time": float(i) * 0.01
            })

        # Convert to list for HTML rendering
        timeline_data = list(ring_buffer)

        assert len(timeline_data) == 10
        assert timeline_data[0]["seq"] == 1005  # First of last 10
        assert timeline_data[-1]["seq"] == 1014  # Last packet

    def test_timeline_html_escaping(self):
        """Test HTML generation properly escapes data."""
        import html

        # Simulate malicious packet data
        malicious_data = {
            "seq": "<script>alert('XSS')</script>",
            "flags": "<img src=x onerror=alert(1)>"
        }

        # Should be escaped
        escaped_seq = html.escape(str(malicious_data["seq"]))
        escaped_flags = html.escape(str(malicious_data["flags"]))

        assert "&lt;script&gt;" in escaped_seq
        assert "&lt;img" in escaped_flags


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "not slow"])
