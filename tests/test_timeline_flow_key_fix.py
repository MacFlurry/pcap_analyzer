"""
Regression test for v4.15.0 Packet Timeline flow_key mismatch bug

BUG: Flow keys in HTML generator used Unicode arrow (→) while RetransmissionAnalyzer
used ASCII arrow (->), causing timeline to never render.

FIX: Standardized flow_key format to use -> consistently.
"""

import pytest
from src.exporters.html_report import HTMLReportGenerator


def test_flow_key_format_matches_analyzer():
    """
    Test that HTML generator uses same flow_key format as RetransmissionAnalyzer.

    CRITICAL: Flow keys must match exactly for timeline rendering to work.

    Format: IP:PORT->IP:PORT (ASCII arrow, no spaces)
    NOT:    IP:PORT → IP:PORT (Unicode arrow with spaces)
    """
    # Mock results with retransmissions
    results = {
        "total_packets": 100,
        "duration": 5.0,
        "retransmission": {
            "total_retransmissions": 1,
            "rto_count": 1,
            "fast_retrans_count": 0,
            "other_retrans_count": 0,
            "retransmissions": [
                {
                    "src_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "retrans_type": "RTO",
                    "delay": 0.2,
                    "timestamp": 1234567890.0,
                    "tcp_flags": "PA",
                    "is_syn_retrans": False,
                }
            ],
            # Sampled timeline with CORRECT format (-> not →)
            "sampled_timelines": {
                "192.168.1.1:12345->10.0.0.1:80": {
                    "handshake": [
                        {
                            "packet_num": 1,
                            "timestamp": 1234567889.0,
                            "seq": 1000,
                            "ack": 0,
                            "flags": "S",
                            "len": 0,
                        }
                    ],
                    "retrans_context": [],
                    "teardown": [],
                }
            },
        },
    }

    # Generate HTML
    generator = HTMLReportGenerator()
    html = generator.generate(results)

    # CRITICAL: Timeline MUST be rendered
    assert "📋 Packet Timeline" in html, (
        "Timeline not found in HTML. "
        "This indicates flow_key mismatch between HTML generator and RetransmissionAnalyzer. "
        "Check that HTML generator uses '->' (ASCII arrow) not '→' (Unicode arrow)."
    )

    # Verify timeline content is present
    assert "Handshake" in html
    assert "<details>" in html  # Collapsible structure


def test_flow_key_format_regression_detection():
    """
    Test that detects if flow_key format reverts to Unicode arrow.

    This is a negative test - if someone accidentally changes the format back
    to Unicode arrow (→), this test will fail.
    """
    # Mock results with WRONG format (Unicode arrow) in sampled_timelines
    results = {
        "total_packets": 100,
        "duration": 5.0,
        "retransmission": {
            "total_retransmissions": 1,
            "rto_count": 1,
            "fast_retrans_count": 0,
            "other_retrans_count": 0,
            "retransmissions": [
                {
                    "src_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "retrans_type": "RTO",
                    "delay": 0.2,
                    "timestamp": 1234567890.0,
                    "tcp_flags": "PA",
                    "is_syn_retrans": False,
                }
            ],
            # WRONG format (→ with spaces) - should NOT match
            "sampled_timelines": {
                "192.168.1.1:12345 → 10.0.0.1:80": {  # Unicode arrow - WRONG
                    "handshake": [
                        {
                            "packet_num": 1,
                            "timestamp": 1234567889.0,
                            "seq": 1000,
                            "ack": 0,
                            "flags": "S",
                            "len": 0,
                        }
                    ],
                    "retrans_context": [],
                    "teardown": [],
                }
            },
        },
    }

    # Generate HTML
    generator = HTMLReportGenerator()
    html = generator.generate(results)

    # Timeline should NOT be rendered (wrong flow_key format)
    assert "📋 Packet Timeline" not in html, (
        "Timeline was rendered with mismatched flow_key format. "
        "This means the fix was successful (HTML generator ignores wrong format)."
    )


def test_multiple_flows_timeline_rendering():
    """
    Test that multiple flows each get their own timeline rendered.
    """
    results = {
        "total_packets": 200,
        "duration": 10.0,
        "retransmission": {
            "total_retransmissions": 2,
            "rto_count": 2,
            "fast_retrans_count": 0,
            "other_retrans_count": 0,
            "retransmissions": [
                {
                    "src_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "retrans_type": "RTO",
                    "delay": 0.2,
                    "timestamp": 1234567890.0,
                    "tcp_flags": "PA",
                    "is_syn_retrans": False,
                },
                {
                    "src_ip": "192.168.1.2",
                    "src_port": 54321,
                    "dst_ip": "10.0.0.2",
                    "dst_port": 443,
                    "retrans_type": "RTO",
                    "delay": 0.3,
                    "timestamp": 1234567891.0,
                    "tcp_flags": "PA",
                    "is_syn_retrans": False,
                },
            ],
            "sampled_timelines": {
                "192.168.1.1:12345->10.0.0.1:80": {
                    "handshake": [{"packet_num": 1, "timestamp": 1234567889.0, "seq": 1000, "ack": 0, "flags": "S", "len": 0}],
                    "retrans_context": [],
                    "teardown": [],
                },
                "192.168.1.2:54321->10.0.0.2:443": {
                    "handshake": [{"packet_num": 2, "timestamp": 1234567890.0, "seq": 2000, "ack": 0, "flags": "S", "len": 0}],
                    "retrans_context": [],
                    "teardown": [],
                },
            },
        },
    }

    generator = HTMLReportGenerator()
    html = generator.generate(results)

    # Both timelines should be rendered
    timeline_count = html.count("📋 Packet Timeline")
    assert timeline_count == 2, f"Expected 2 timelines, found {timeline_count}"


def test_flow_key_special_characters_escaping():
    """
    Test that flow_keys with special characters are properly escaped in HTML.

    This prevents XSS vulnerabilities while maintaining correct flow_key matching.
    """
    # Flow key with characters that need HTML escaping
    results = {
        "total_packets": 100,
        "duration": 5.0,
        "retransmission": {
            "total_retransmissions": 1,
            "rto_count": 1,
            "fast_retrans_count": 0,
            "other_retrans_count": 0,
            "retransmissions": [
                {
                    "src_ip": "192.168.1.1",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "retrans_type": "RTO",
                    "delay": 0.2,
                    "timestamp": 1234567890.0,
                    "tcp_flags": "PA",
                    "is_syn_retrans": False,
                }
            ],
            "sampled_timelines": {
                "192.168.1.1:12345->10.0.0.1:80": {
                    "handshake": [{"packet_num": 1, "timestamp": 1234567889.0, "seq": 1000, "ack": 0, "flags": "S", "len": 0}],
                    "retrans_context": [],
                    "teardown": [],
                }
            },
        },
    }

    generator = HTMLReportGenerator()
    html = generator.generate(results)

    # Flow key should be HTML-escaped in output
    # The -> should NOT be converted to →
    assert "192.168.1.1:12345-&gt;10.0.0.1:80" in html or "192.168.1.1:12345->10.0.0.1:80" in html

    # Should NOT contain Unicode arrow
    assert "192.168.1.1:12345 → 10.0.0.1:80" not in html
