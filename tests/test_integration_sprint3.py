"""
Sprint 3 Integration Tests

Tests end-to-end functionality of Sprint 3 features:
- Service Classification Engine
- Integration with protocol distribution
- Integration with jitter analysis
- Combined intelligence features

Ensures all Sprint 3 components work together correctly.
"""

import json

import pytest
from scapy.all import IP, TCP, UDP, Ether

from src.analyzers.jitter_analyzer import JitterAnalyzer
from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer
from src.analyzers.service_classifier import ServiceClassifier
from src.utils.result_sanitizer import sanitize_results


@pytest.mark.integration
class TestServiceClassifierIntegration:
    """Integration tests for Service Classifier."""

    def test_streaming_flow_classification(self):
        """Test end-to-end streaming flow classification."""
        packets = []

        # Simulate video streaming: Large packets, sustained throughput
        for i in range(100):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=50000, dport=443) / (b"V" * 1400)
            pkt.time = 1.0 + i * 0.01  # High rate
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify as Streaming
        assert results["total_flows"] == 1
        assert results["classification_summary"]["classified_count"] >= 1

        # Check service type
        service_types = results["service_classifications"]
        assert "Streaming" in service_types or "Bulk" in service_types

    def test_mixed_service_classification(self):
        """Test classification of multiple service types."""
        packets = []

        # Streaming flow (TCP, large, sustained)
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=50000, dport=443) / (b"S" * 1400)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        # Interactive/Web flow (TCP, moderate size)
        for i in range(30):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=50001, dport=80) / (b"W" * 500)
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        # DNS flow (UDP, small, sporadic)
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.3", dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / (b"D" * 100)
            pkt.time = 1.0 + i * 2.0  # Sporadic
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify multiple types
        assert results["total_flows"] >= 3
        service_types = results["service_classifications"]
        assert len(service_types) >= 2  # At least 2 different types


@pytest.mark.integration
class TestServiceClassifierWithProtocolDistribution:
    """Test Service Classifier integration with Protocol Distribution."""

    def test_combined_protocol_and_service_analysis(self):
        """Test combining protocol distribution with service classification."""
        packets = []

        # Create mixed traffic
        # HTTP traffic
        for i in range(30):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50000 + i, dport=80) / (b"H" * 500)
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        # DNS traffic
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.101", dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / (b"D" * 100)
            pkt.time = 1.0 + i * 2.0
            packets.append(pkt)

        # Analyze with both
        protocol_analyzer = ProtocolDistributionAnalyzer()
        service_classifier = ServiceClassifier()

        protocol_results = protocol_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        # Protocol distribution should show TCP and UDP
        assert "TCP" in protocol_results["layer4_distribution"]
        assert "UDP" in protocol_results["layer4_distribution"]

        # Service classifier should identify both types
        assert service_results["total_flows"] >= 2


@pytest.mark.integration
class TestServiceClassifierWithJitter:
    """Test Service Classifier integration with Jitter Analyzer."""

    def test_streaming_with_jitter_analysis(self):
        """Test streaming classification correlates with jitter."""
        packets = []

        # Video streaming with some jitter
        for i in range(100):
            pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.50") / TCP(sport=50000, dport=443) / (b"V" * 1400)
            # Add occasional jitter spikes
            jitter = 0.01 if i % 10 == 0 else 0.0
            pkt.time = 1.0 + i * 0.01 + jitter
            packets.append(pkt)

        service_classifier = ServiceClassifier()
        jitter_analyzer = JitterAnalyzer()

        service_results = service_classifier.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)

        # Should classify as Streaming
        service_types = service_results["service_classifications"]
        assert "Streaming" in service_types or "Bulk" in service_types or len(service_types) > 0

        # Should also detect jitter
        assert jitter_results["total_flows"] >= 1


@pytest.mark.integration
class TestEndToEndSprint3Pipeline:
    """End-to-end integration tests for Sprint 3 pipeline."""

    def test_full_pipeline_all_sprint3_features(self):
        """Test complete pipeline with all Sprint 3 features."""
        packets = []

        # Create realistic diverse traffic
        # 1. Video streaming
        for i in range(80):
            pkt = Ether() / IP(src="192.168.1.20", dst="10.0.0.20") / TCP(sport=50000, dport=443) / (b"S" * 1400)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        # 2. Web browsing
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.30", dst="10.0.0.30") / TCP(sport=51000, dport=80) / (b"W" * 600)
            pkt.time = 1.0 + i * 0.5
            packets.append(pkt)

        # 3. DNS queries
        for i in range(10):
            pkt = Ether() / IP(src="192.168.1.40", dst="8.8.8.8") / UDP(sport=52000 + i, dport=53) / (b"D" * 80)
            pkt.time = 1.0 + i * 3.0
            packets.append(pkt)

        # Analyze with all Sprint 3 components
        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()
        service_classifier = ServiceClassifier()

        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        # Verify protocol distribution
        assert protocol_results["total_packets"] == 110
        assert "TCP" in protocol_results["layer4_distribution"]
        assert "UDP" in protocol_results["layer4_distribution"]

        # Verify jitter analysis
        assert jitter_results["total_flows"] >= 3

        # Verify service classification
        assert service_results["total_flows"] >= 3
        assert service_results["classification_summary"]["classified_count"] >= 2

        # Verify different service types detected
        service_types = service_results["service_classifications"]
        assert len(service_types) >= 2  # At least 2 different services

    def test_json_serialization_sprint3(self):
        """Test JSON serialization of all Sprint 3 results."""
        packets = [
            Ether() / IP() / UDP(sport=10000, dport=5004) / (b"V" * 160),
            Ether() / IP() / TCP(sport=50000, dport=443) / (b"S" * 1400),
        ]
        for i, pkt in enumerate(packets):
            pkt.time = 1.0 + i * 0.1

        service_classifier = ServiceClassifier()
        service_results = service_classifier.analyze(packets)

        results = {"service_classification": service_results}

        # Should serialize without errors
        try:
            json_str = json.dumps(results)
            restored = json.loads(json_str)
            assert restored["service_classification"]["total_flows"] >= 0
        except (TypeError, ValueError) as e:
            pytest.fail(f"JSON serialization failed: {e}")

    def test_combined_results_sanitization(self):
        """Test that combined Sprint 2+3 results are sanitized."""
        packets = [
            Ether() / IP() / UDP(sport=10000, dport=5004) / (b"V" * 160),
        ]
        packets[0].time = 1.0

        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()
        service_classifier = ServiceClassifier()

        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        combined = {
            "protocol_distribution": protocol_results,
            "jitter": jitter_results,
            "service_classification": service_results,
        }

        # Sanitize
        sanitized = sanitize_results(combined)

        # Should have no null values
        assert sanitized["protocol_distribution"]["total_packets"] >= 0
        assert sanitized["jitter"]["total_flows"] >= 0
        assert sanitized["service_classification"]["total_flows"] >= 0


@pytest.mark.integration
class TestServiceClassificationAccuracy:
    """Test service classification accuracy with known patterns."""

    def test_dns_pattern_accuracy(self):
        """Test DNS detection accuracy with known port."""
        packets = []

        # DNS queries to port 53 (known port)
        for i in range(20):
            pkt = Ether() / IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=50000 + i, dport=53) / (b"D" * 100)
            pkt.time = 1.0 + i * 2.0  # Sporadic
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should have high classification rate
        summary = results["classification_summary"]
        assert summary["classification_rate"] >= 80.0  # At least 80%

        # Should classify as DNS (known port)
        service_types = results["service_classifications"]
        assert "DNS" in service_types

    def test_streaming_pattern_accuracy(self):
        """Test streaming detection accuracy."""
        packets = []

        # Video streaming: Large packets, sustained, TCP
        for i in range(100):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=50000, dport=443) / (b"S" * 1400)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        classifier = ServiceClassifier()
        results = classifier.analyze(packets)

        # Should classify as streaming or bulk
        service_types = results["service_classifications"]
        assert "Streaming" in service_types or "Bulk" in service_types


@pytest.mark.integration
class TestBackwardsCompatibilitySprint3:
    """Test Sprint 3 changes don't break existing functionality."""

    def test_sprint2_analyzers_still_work(self):
        """Test that Sprint 2 analyzers work alongside Sprint 3."""
        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / UDP(sport=10000, dport=5004) / (b"V" * 160),
        ]
        for i, pkt in enumerate(packets):
            pkt.time = 1.0 + i * 0.1

        # Sprint 2 analyzers
        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()

        # Sprint 3 analyzer
        service_classifier = ServiceClassifier()

        # All should work
        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        assert protocol_results["total_packets"] == 2
        assert jitter_results["total_flows"] >= 0
        assert service_results["total_flows"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
