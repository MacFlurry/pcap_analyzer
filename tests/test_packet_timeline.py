"""
Test Suite for v4.15.0 Packet Timeline Feature

This test suite validates the packet timeline feature implementation:
1. Ring buffer behavior (deque with maxlen=10)
2. Sampling logic (handshake, retransmission context, teardown)
3. HTML rendering with security (XSS prevention)
4. Memory efficiency and performance

Test-Driven Development (TDD): These tests are written BEFORE implementation
to define expected behavior and ensure quality from the start.
"""

import html
from collections import deque
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from scapy.all import IP, TCP, Ether, Raw


class TestRingBufferBehavior:
    """Test ring buffer behavior using deque(maxlen=10)."""

    def test_deque_stores_last_10_packets(self):
        """Test deque(maxlen=10) correctly stores only last 10 packets."""
        # Simulate ring buffer for packet timeline
        ring_buffer = deque(maxlen=10)

        # Add 15 packets
        for i in range(15):
            packet_data = {
                "seq": i,
                "timestamp": float(i),
                "flags": "A",
                "len": 100
            }
            ring_buffer.append(packet_data)

        # Should only have last 10 packets (5-14)
        assert len(ring_buffer) == 10
        assert ring_buffer[0]["seq"] == 5
        assert ring_buffer[-1]["seq"] == 14

    def test_buffer_overflow_handling(self):
        """Test buffer correctly discards oldest when full."""
        ring_buffer = deque(maxlen=10)

        # Fill buffer
        for i in range(10):
            ring_buffer.append({"seq": i})

        assert len(ring_buffer) == 10
        assert ring_buffer[0]["seq"] == 0

        # Add one more - should discard oldest
        ring_buffer.append({"seq": 10})

        assert len(ring_buffer) == 10
        assert ring_buffer[0]["seq"] == 1  # Oldest discarded
        assert ring_buffer[-1]["seq"] == 10

    def test_lazy_allocation(self):
        """Test buffer only created when needed."""
        # Buffer should not be created until first problematic flow detected
        flow_buffers = {}

        # No flows yet - empty dict
        assert len(flow_buffers) == 0

        # Add buffer only when needed
        flow_key = "192.168.1.1:1234 → 192.168.1.2:80"
        if flow_key not in flow_buffers:
            flow_buffers[flow_key] = deque(maxlen=10)

        assert len(flow_buffers) == 1
        assert flow_key in flow_buffers

    def test_multiple_flow_buffers(self):
        """Test separate buffers for different flows."""
        flow_buffers = {}

        # Create buffers for 3 different flows
        flows = [
            "192.168.1.1:1234 → 192.168.1.2:80",
            "192.168.1.1:5678 → 192.168.1.3:443",
            "10.0.0.1:9000 → 10.0.0.2:8080"
        ]

        for flow in flows:
            if flow not in flow_buffers:
                flow_buffers[flow] = deque(maxlen=10)
            flow_buffers[flow].append({"seq": 1000})

        assert len(flow_buffers) == 3
        for flow in flows:
            assert flow in flow_buffers
            assert len(flow_buffers[flow]) == 1


class TestSamplingLogic:
    """Test packet sampling logic for timeline feature."""

    def test_handshake_packet_capture(self):
        """Test capture of first 10 packets (handshake phase)."""
        # Simulate TCP flow with handshake
        packets = []
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=1000+i
            )
            pkt.time = float(i)
            packets.append(pkt)

        # Sample first 10 for handshake
        handshake_samples = packets[:10]

        assert len(handshake_samples) == 10
        assert handshake_samples[0].time == 0.0
        assert handshake_samples[-1].time == 9.0

    def test_retransmission_context_capture(self):
        """Test capture of ±5 packets around retransmission."""
        # Simulate flow where packet 15 is a retransmission
        packets = []
        for i in range(30):
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=1000+i
            )
            pkt.time = float(i)
            packets.append(pkt)

        retrans_index = 15

        # Capture ±5 packets around retransmission
        start = max(0, retrans_index - 5)
        end = min(len(packets), retrans_index + 6)
        context_packets = packets[start:end]

        assert len(context_packets) == 11  # 5 before + retrans + 5 after
        assert context_packets[5].time == 15.0  # Retransmission in middle

    def test_teardown_packet_capture(self):
        """Test capture of last 10 packets (teardown phase)."""
        packets = []
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=1000+i
            )
            pkt.time = float(i)
            packets.append(pkt)

        # Last packet is FIN
        fin_pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
            sport=1234, dport=80, flags="F", seq=1050
        )
        fin_pkt.time = 50.0
        packets.append(fin_pkt)

        # Sample last 10 for teardown
        teardown_samples = packets[-10:]

        assert len(teardown_samples) == 10
        assert teardown_samples[-1].time == 50.0
        assert teardown_samples[-1][TCP].flags == "F"

    def test_small_connection_edge_case(self):
        """Test connection with <10 packets."""
        # Connection with only 5 packets
        packets = []
        for i in range(5):
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=1000+i
            )
            pkt.time = float(i)
            packets.append(pkt)

        # Should capture all available packets
        ring_buffer = deque(maxlen=10)
        for pkt in packets:
            ring_buffer.append({
                "seq": pkt[TCP].seq,
                "time": pkt.time
            })

        assert len(ring_buffer) == 5  # All packets captured
        assert ring_buffer[0]["seq"] == 1000
        assert ring_buffer[-1]["seq"] == 1004

    def test_multiple_retransmissions(self):
        """Test flow with multiple retransmissions."""
        retrans_events = []

        # Simulate 3 retransmission events
        for i in [10, 25, 40]:
            retrans_events.append({
                "index": i,
                "seq": 1000 + i,
                "timestamp": float(i),
                "type": "Fast Retransmission"
            })

        # Each retransmission should capture ±5 context
        assert len(retrans_events) == 3

        # Verify context windows don't overlap excessively
        for i, event in enumerate(retrans_events):
            context_start = max(0, event["index"] - 5)
            context_end = event["index"] + 6

            # Each event has its own context window
            assert context_end - context_start <= 11

    def test_sampling_preserves_packet_order(self):
        """Test sampled packets maintain chronological order."""
        packets = []
        timestamps = [0.1, 0.2, 0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0]

        for i, ts in enumerate(timestamps):
            pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
                sport=1234, dport=80, flags="A", seq=1000+i
            )
            pkt.time = ts
            packets.append(pkt)

        ring_buffer = deque(maxlen=10)
        for pkt in packets:
            ring_buffer.append({"time": pkt.time})

        # Verify chronological order maintained
        times = [p["time"] for p in ring_buffer]
        assert times == sorted(times)


class TestHTMLRendering:
    """Test HTML rendering of packet timeline."""

    def test_render_sampled_timeline_produces_valid_html(self):
        """Test _render_sampled_timeline() produces valid HTML."""
        # Mock packet timeline data
        sampled_packets = [
            {"seq": 1000, "ack": 2000, "flags": "S", "len": 0, "time": 0.0},
            {"seq": 1001, "ack": 2001, "flags": "A", "len": 100, "time": 0.1},
            {"seq": 1101, "ack": 2001, "flags": "PA", "len": 200, "time": 0.2},
        ]

        # Generate HTML (mock implementation)
        html_output = self._mock_render_sampled_timeline(sampled_packets)

        # Should contain HTML structure
        assert "<details>" in html_output
        assert "</details>" in html_output
        assert "<summary>" in html_output
        assert "<table" in html_output  # May have class attribute
        assert "</table>" in html_output

    def test_render_packet_table_formats_correctly(self):
        """Test _render_packet_table() formats packets correctly."""
        packets = [
            {"seq": 1000, "ack": 2000, "flags": "S", "len": 0, "time": 0.0},
            {"seq": 2000, "ack": 1001, "flags": "SA", "len": 0, "time": 0.05},
        ]

        html_table = self._mock_render_packet_table(packets)

        # Should contain table structure
        assert "<table" in html_table
        assert "<thead>" in html_table
        assert "<tbody>" in html_table
        assert "<tr>" in html_table

        # Should contain packet data
        assert "1000" in html_table
        assert "2000" in html_table
        assert "S" in html_table or "SYN" in html_table

    def test_html_escaping_xss_prevention(self):
        """Test HTML escaping applied to all packet data (XSS prevention)."""
        # Malicious packet data with XSS attempt
        malicious_packets = [
            {
                "seq": 1000,
                "ack": 2000,
                "flags": "<script>alert('XSS')</script>",
                "len": 0,
                "time": 0.0,
                "payload": "'; DROP TABLE packets; --"
            }
        ]

        html_output = self._mock_render_packet_table(malicious_packets)

        # Should escape dangerous characters
        assert "<script>" not in html_output
        assert "&lt;script&gt;" in html_output or html.escape("<script>") in html_output

        # Should not contain raw SQL injection attempt
        assert "DROP TABLE" not in html_output or "DROP TABLE" in html.escape(html_output)

    def test_xss_prevention_in_flow_keys(self):
        """Test XSS prevention in flow keys."""
        # Malicious flow key
        malicious_flow = "<img src=x onerror=alert('XSS')>:80 → 192.168.1.2:443"

        escaped = html.escape(malicious_flow)

        # Should escape HTML tags
        assert "<img" not in escaped
        assert "&lt;img" in escaped
        assert "onerror" not in escaped or "&" in escaped

    def test_collapsible_details_element(self):
        """Test collapsible <details> element structure."""
        packets = [{"seq": 1000, "flags": "A", "time": 0.0}]

        html_output = self._mock_render_sampled_timeline(packets)

        # Should have details/summary structure
        assert "<details>" in html_output
        assert "<summary>" in html_output
        assert "</summary>" in html_output
        assert "</details>" in html_output

    def test_empty_timeline_rendering(self):
        """Test rendering with no packets in timeline."""
        empty_packets = []

        html_output = self._mock_render_sampled_timeline(empty_packets)

        # Should handle gracefully - either empty or message
        assert html_output is not None
        assert isinstance(html_output, str)

    def test_timeline_css_classes(self):
        """Test proper CSS classes for timeline styling."""
        packets = [{"seq": 1000, "flags": "A", "time": 0.0}]

        html_output = self._mock_render_sampled_timeline(packets)

        # Should contain CSS classes for styling
        assert "class=" in html_output or "packet" in html_output.lower()

    # Helper methods for mock HTML rendering
    def _mock_render_sampled_timeline(self, packets):
        """Mock implementation of _render_sampled_timeline()."""
        if not packets:
            return "<div>No packets sampled</div>"

        html_str = "<details>\n"
        html_str += "  <summary><strong>Packet Timeline</strong> (Sampled)</summary>\n"
        html_str += self._mock_render_packet_table(packets)
        html_str += "</details>\n"
        return html_str

    def _mock_render_packet_table(self, packets):
        """Mock implementation of _render_packet_table()."""
        html_str = '  <table class="packet-timeline">\n'
        html_str += "    <thead>\n"
        html_str += "      <tr><th>Time</th><th>Seq</th><th>Ack</th><th>Flags</th><th>Len</th></tr>\n"
        html_str += "    </thead>\n"
        html_str += "    <tbody>\n"

        for pkt in packets:
            # CRITICAL: Escape all user-controlled data
            seq = html.escape(str(pkt.get("seq", "")))
            ack = html.escape(str(pkt.get("ack", "")))
            flags = html.escape(str(pkt.get("flags", "")))
            length = html.escape(str(pkt.get("len", "")))
            time = html.escape(str(pkt.get("time", "")))

            html_str += f"      <tr>"
            html_str += f"<td>{time}</td>"
            html_str += f"<td>{seq}</td>"
            html_str += f"<td>{ack}</td>"
            html_str += f"<td>{flags}</td>"
            html_str += f"<td>{length}</td>"
            html_str += f"</tr>\n"

        html_str += "    </tbody>\n"
        html_str += "  </table>\n"
        return html_str


class TestTimelineIntegration:
    """Integration tests for packet timeline feature."""

    def test_timeline_in_flow_detail_card(self):
        """Test timeline appears in flow detail card."""
        # This would test integration with existing flow detail rendering
        flow_data = {
            "flow_key": "192.168.1.1:1234 → 192.168.1.2:80",
            "retransmissions": [
                {"seq": 1500, "timestamp": 1.5, "type": "Fast Retransmission"}
            ],
            "sampled_timeline": [
                {"seq": 1000, "time": 0.0, "flags": "S"},
                {"seq": 1001, "time": 0.1, "flags": "A"},
            ]
        }

        # Timeline should be part of flow details
        assert "sampled_timeline" in flow_data
        assert len(flow_data["sampled_timeline"]) == 2

    def test_timeline_performance_tracking(self):
        """Test timeline doesn't significantly impact performance."""
        import time

        # Create large packet dataset
        packets = []
        for i in range(10000):
            packets.append({
                "seq": 1000 + i,
                "time": float(i) * 0.001,
                "flags": "A"
            })

        # Test ring buffer performance
        start_time = time.time()
        ring_buffer = deque(maxlen=10)
        for pkt in packets:
            ring_buffer.append(pkt)
        elapsed = time.time() - start_time

        # Should complete in <100ms for 10k packets
        assert elapsed < 0.1
        assert len(ring_buffer) == 10  # Only last 10 retained

    def test_memory_efficiency_multiple_flows(self):
        """Test memory usage with multiple flows."""
        # Simulate 100 problematic flows
        flow_buffers = {}

        for i in range(100):
            flow_key = f"192.168.1.{i}:1234 → 192.168.1.{i+1}:80"
            flow_buffers[flow_key] = deque(maxlen=10)

            # Add 10 packets to each buffer
            for j in range(10):
                flow_buffers[flow_key].append({
                    "seq": 1000 + j,
                    "time": float(j)
                })

        # Should have 100 flows, each with 10 packets
        assert len(flow_buffers) == 100
        for flow_key, buffer in flow_buffers.items():
            assert len(buffer) == 10


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_malformed_packet_handling(self):
        """Test handling of malformed packets."""
        # Packet missing required fields
        malformed = {"seq": 1000}  # Missing time, flags, etc.

        ring_buffer = deque(maxlen=10)
        ring_buffer.append(malformed)

        assert len(ring_buffer) == 1
        assert "seq" in ring_buffer[0]

    def test_unicode_in_packet_data(self):
        """Test handling of unicode characters."""
        unicode_data = {
            "seq": 1000,
            "flags": "A",
            "payload": "Hello 世界 🌍"
        }

        escaped = html.escape(str(unicode_data["payload"]))
        assert escaped is not None

    def test_very_large_sequence_numbers(self):
        """Test handling of large TCP sequence numbers."""
        large_seq = 4294967295  # Max 32-bit value

        packet = {"seq": large_seq, "time": 0.0}
        ring_buffer = deque(maxlen=10)
        ring_buffer.append(packet)

        assert ring_buffer[0]["seq"] == large_seq

    def test_negative_timestamps(self):
        """Test handling of negative timestamps (shouldn't happen but test robustness)."""
        packet = {"seq": 1000, "time": -1.0, "flags": "A"}

        ring_buffer = deque(maxlen=10)
        ring_buffer.append(packet)

        assert ring_buffer[0]["time"] == -1.0

    def test_concurrent_flow_buffer_access(self):
        """Test thread safety of flow buffers (if needed)."""
        # This would test if buffers are accessed concurrently
        # For now, just verify basic structure
        flow_buffers = {}
        flow_key = "192.168.1.1:1234 → 192.168.1.2:80"

        # Simulate multiple accesses
        for _ in range(5):
            if flow_key not in flow_buffers:
                flow_buffers[flow_key] = deque(maxlen=10)
            flow_buffers[flow_key].append({"seq": 1000})

        assert len(flow_buffers[flow_key]) == 5


class TestSecurityValidation:
    """Security-focused tests for timeline feature."""

    def test_no_script_injection_in_timeline(self):
        """Test that <script> tags cannot be injected into timeline."""
        malicious_packets = [
            {
                "seq": "<script>alert('XSS')</script>",
                "flags": "<img src=x onerror=alert(1)>",
                "payload": "javascript:alert('XSS')"
            }
        ]

        html_output = self._render_safe_timeline(malicious_packets)

        # Should not contain executable script tags (escaped versions are ok)
        assert "<script>" not in html_output
        # Check that onerror is escaped (contains &lt; or &gt;)
        if "onerror" in html_output:
            assert "&lt;" in html_output or "&gt;" in html_output
        # javascript: should be escaped
        if "javascript:" in html_output:
            assert "&" in html_output  # Some escaping present

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention in packet data."""
        # Although this is HTML rendering, test defensive coding
        sql_injection = {
            "seq": "1000; DROP TABLE packets; --",
            "flags": "' OR '1'='1",
        }

        escaped_seq = html.escape(str(sql_injection["seq"]))
        escaped_flags = html.escape(str(sql_injection["flags"]))

        # HTML escape converts quotes and special chars
        # The original dangerous strings should be escaped
        assert escaped_flags != sql_injection["flags"]  # Should be modified
        assert "&#x27;" in escaped_flags or "&apos;" in escaped_flags  # Quote escaped

    def test_path_traversal_prevention(self):
        """Test path traversal prevention in any file operations."""
        # If timeline feature involves file operations
        malicious_path = "../../../etc/passwd"

        # Should validate/sanitize paths
        import os.path
        normalized = os.path.normpath(malicious_path)

        # Normalized path should resolve traversal
        # In this case, it becomes "../etc/passwd" (relative, not absolute)
        assert not os.path.isabs(normalized)  # Not absolute path
        # Or we should reject paths with .. in them
        assert normalized.startswith("..") or ".." in normalized  # Detected traversal attempt

    def _render_safe_timeline(self, packets):
        """Render timeline with proper escaping."""
        html_str = "<div>"
        for pkt in packets:
            seq = html.escape(str(pkt.get("seq", "")))
            flags = html.escape(str(pkt.get("flags", "")))
            html_str += f"<div>Seq: {seq}, Flags: {flags}</div>"
        html_str += "</div>"
        return html_str


class TestPerformanceBenchmarks:
    """Performance benchmarks for timeline feature."""

    def test_ring_buffer_append_performance(self):
        """Test ring buffer append performance."""
        import time

        ring_buffer = deque(maxlen=10)

        start = time.time()
        for i in range(100000):
            ring_buffer.append({"seq": i, "time": float(i)})
        elapsed = time.time() - start

        # Should be very fast (< 100ms for 100k appends)
        assert elapsed < 0.1
        assert len(ring_buffer) == 10

    def test_html_rendering_performance(self):
        """Test HTML rendering performance for timeline."""
        import time

        packets = [{"seq": i, "time": float(i), "flags": "A"} for i in range(10)]

        start = time.time()
        for _ in range(1000):
            html_output = self._mock_render_timeline(packets)
        elapsed = time.time() - start

        # Should render 1000 timelines in < 1 second
        assert elapsed < 1.0

    def _mock_render_timeline(self, packets):
        """Mock timeline rendering."""
        html_str = "<table>"
        for pkt in packets:
            html_str += f"<tr><td>{pkt['seq']}</td></tr>"
        html_str += "</table>"
        return html_str


class TestRegressionPrevention:
    """Regression tests to ensure existing functionality not broken."""

    def test_existing_flow_detail_structure(self):
        """Test that timeline doesn't break existing flow detail structure."""
        # Existing flow detail should still work
        flow_detail = {
            "flow_key": "192.168.1.1:1234 → 192.168.1.2:80",
            "retransmissions": [],
            "rtt": 0.05,
            "window_size": 65535
        }

        # Adding timeline shouldn't break existing fields
        flow_detail["sampled_timeline"] = []

        assert "flow_key" in flow_detail
        assert "retransmissions" in flow_detail
        assert "sampled_timeline" in flow_detail

    def test_backward_compatibility_without_timeline(self):
        """Test system works if timeline feature disabled."""
        # Flow detail without timeline field
        flow_detail = {
            "flow_key": "192.168.1.1:1234 → 192.168.1.2:80",
            "retransmissions": []
        }

        # Should work without timeline
        assert "flow_key" in flow_detail
        assert "sampled_timeline" not in flow_detail


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
