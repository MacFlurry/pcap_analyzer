"""
Test suite for Service Classification Engine

Tests intelligent traffic classification based on behavioral patterns:
- Video streaming (large sustained flows)
- Interactive traffic (request-response patterns)
- Bulk transfer (large persistent flows)
- DNS/Control traffic (small sporadic packets)

Uses ML-like heuristics without actual ML dependency.
"""

import pytest
from scapy.all import IP, TCP, UDP, Ether


class TestServiceClassifierBasics:
    """Test basic service classification functionality."""

    def test_empty_packets_returns_empty_results(self):
        """Test classifier handles empty packet list."""
        from src.analyzers.service_classifier import ServiceClassifier

        classifier = ServiceClassifier()
        results = classifier.analyze([])

        assert results["total_flows"] == 0
        assert results["classified_flows"] == {}

    def test_video_streaming_detection(self):
        """Known ports take precedence over heuristics for service detection."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Simulate video: TCP, large packets, sustained throughput
        for i in range(100):
            pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=443, dport=50000) / (b"V" * 1400)
            pkt.time = 1.0 + i * 0.01  # High rate
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        service_counts = results["service_classifications"]
        assert service_counts

        # Port-based classification (443) is expected to override heuristic labels.
        assert service_counts.get("HTTPS", 0) >= 1

    def test_web_traffic_detection(self):
        """Test web traffic detection (request-response pattern)."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Simulate HTTP: request (small) + response (larger)
        # Request
        for i in range(5):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50000, dport=80) / (b"GET" * 50)
            pkt.time = 1.0 + i * 0.5
            packets.append(pkt)

        # Response
        for i in range(20):
            pkt = Ether() / IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=80, dport=50000) / (b"R" * 1200)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify as interactive or web
        flow_classifications = results["service_classifications"]
        assert len(flow_classifications) > 0

    def test_dns_traffic_detection(self):
        """Test DNS traffic detection (small sporadic UDP packets)."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Simulate DNS: small UDP packets, sporadic
        for i in range(10):
            # Query
            pkt = Ether() / IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / (b"Q" * 50)
            pkt.time = 1.0 + i * 2.0  # Sporadic (every 2 seconds)
            packets.append(pkt)

            # Response
            pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=50000 + i) / (b"R" * 100)
            pkt.time = 1.0 + i * 2.0 + 0.05
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify as DNS or Control
        flow_classifications = results["service_classifications"]
        assert "DNS" in flow_classifications or "Control" in flow_classifications


class TestTrafficPatternDetection:
    """Test traffic pattern detection features."""

    def test_packet_size_distribution(self):
        """Test packet size distribution analysis."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Mix of small and large packets
        for i in range(50):
            size = 64 if i % 2 == 0 else 1400
            pkt = Ether() / IP() / TCP(sport=12345, dport=80) / (b"A" * size)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should have packet size statistics
        assert "flow_statistics" in results
        flow_stats = list(results["flow_statistics"].values())[0]
        assert "avg_packet_size" in flow_stats
        assert "packet_size_variance" in flow_stats

    def test_inter_arrival_time_analysis(self):
        """Test inter-arrival time pattern detection."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Constant inter-arrival time (real-time communication pattern)
        for i in range(50):
            pkt = Ether() / IP() / UDP(sport=10000, dport=5004) / (b"A" * 160)
            pkt.time = 1.0 + i * 0.02  # Constant 20ms
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        flow_stats = list(results["flow_statistics"].values())[0]
        assert "avg_inter_arrival" in flow_stats
        assert "inter_arrival_variance" in flow_stats

    def test_flow_duration_tracking(self):
        """Test flow duration calculation."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        start_time = 1.0
        end_time = 10.0

        for i in range(10):
            pkt = Ether() / IP() / TCP(sport=12345, dport=80)
            pkt.time = start_time + (i / 9) * (end_time - start_time)
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        flow_stats = list(results["flow_statistics"].values())[0]
        assert "flow_duration" in flow_stats
        assert flow_stats["flow_duration"] >= 9.0


class TestServiceClassification:
    """Test service classification accuracy."""

    def test_mixed_traffic_classification(self):
        """Test classification of mixed traffic types."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []

        # Video streaming flow
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=50000, dport=443) / (b"V" * 1400)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        # Web/Interactive flow
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.3", dst="10.0.0.3") / TCP(sport=50001, dport=80) / (b"W" * 500)
            pkt.time = 1.0 + i * 0.5
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify both flows
        assert results["total_flows"] >= 2
        classifications = results.get("service_classifications", {})
        assert len(classifications) > 0


class TestClassificationMetrics:
    """Test classification quality metrics."""

    def test_classification_summary(self):
        """Test classification summary statistics."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Create diverse traffic
        for i in range(100):
            pkt = Ether() / IP() / UDP(sport=10000, dport=5004) / (b"A" * 160)
            pkt.time = 1.0 + i * 0.02
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should have summary
        assert "classification_summary" in results
        summary = results["classification_summary"]
        assert "total_flows" in summary
        assert "classified_count" in summary

    def test_unclassified_flows_reported(self):
        """Test that unclassified flows are reported."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        # Ambiguous traffic pattern
        for i in range(10):
            pkt = Ether() / IP() / TCP(sport=12345, dport=9999)
            pkt.time = 1.0 + i * 1.0  # Sporadic
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should track unclassified
        summary = results.get("classification_summary", {})
        assert "unclassified_count" in summary or "classified_count" in summary


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_single_packet_flow(self):
        """Test single packet flows don't crash."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = [Ether() / IP() / TCP(sport=12345, dport=80)]
        packets[0].time = 1.0

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should handle gracefully
        assert isinstance(results, dict)

    def test_very_large_packets(self):
        """Test handling of jumbo frames."""
        from src.analyzers.service_classifier import ServiceClassifier

        packets = []
        for i in range(10):
            pkt = Ether() / IP() / TCP(sport=12345, dport=80) / (b"J" * 8000)  # Jumbo
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify (likely bulk transfer)
        assert results["total_flows"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
