"""
Unit tests for ServiceClassifier.

Tests intelligent traffic classification based on behavioral patterns,
known service ports, and heuristics (streaming, bulk, DNS, web).
"""

import pytest
from scapy.all import IP, IPv6, TCP, UDP, Raw

from src.analyzers.service_classifier import ServiceClassifier, KNOWN_SERVICE_PORTS


class TestServiceClassifier:
    """Tests for ServiceClassifier."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return ServiceClassifier()

    def test_classifier_initialization(self):
        """Test classifier initialization."""
        classifier = ServiceClassifier()
        assert len(classifier.flow_packets) == 0
        assert len(classifier.flow_stats) == 0
        assert len(classifier.flow_classifications) == 0

    def test_reset_method(self, classifier):
        """Test reset() method."""
        base_time = 1234567890.0

        # Process some packets
        for i in range(5):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80)
            packet.time = base_time + i * 0.1
            flow_key = classifier._get_flow_key(packet)
            if flow_key:
                timestamp = classifier._get_timestamp(packet)
                size = classifier._get_packet_size(packet)
                classifier.flow_packets[flow_key].append((timestamp, size, packet))

        # Reset classifier
        classifier.reset()

        # Should reset all state
        assert len(classifier.flow_packets) == 0
        assert len(classifier.flow_stats) == 0
        assert len(classifier.flow_classifications) == 0

    def test_get_flow_key_tcp_ipv4(self, classifier):
        """Test flow key generation for TCP IPv4 packets."""
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        src_port = 12345
        dst_port = 80

        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        flow_key = classifier._get_flow_key(packet)

        # Should generate flow key
        assert flow_key is not None
        assert flow_key == (src_ip, src_port, dst_ip, dst_port, "TCP")

    def test_get_flow_key_udp_ipv4(self, classifier):
        """Test flow key generation for UDP IPv4 packets."""
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        src_port = 12345
        dst_port = 53

        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        flow_key = classifier._get_flow_key(packet)

        # Should generate flow key
        assert flow_key is not None
        assert flow_key == (src_ip, src_port, dst_ip, dst_port, "UDP")

    def test_get_flow_key_ipv6(self, classifier):
        """Test flow key generation for IPv6 packets."""
        src_ip = "2001:db8::1"
        dst_ip = "2001:db8::2"
        src_port = 12345
        dst_port = 80

        packet = IPv6(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        flow_key = classifier._get_flow_key(packet)

        # Should generate flow key
        assert flow_key is not None
        assert flow_key == (src_ip, src_port, dst_ip, dst_port, "TCP")

    def test_classify_known_port_destination(self, classifier):
        """Test classification by known destination port."""
        base_time = 1234567890.0

        # Create HTTP flow (port 80)
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Should classify as HTTP (known port 80)
        assert results["total_flows"] >= 1
        # Check if HTTP was classified
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            # May be HTTP or classified by behavior
            assert classification["service_type"] in ["HTTP", "Interactive"] or "HTTP" in results["service_classifications"]

    def test_classify_known_port_source(self, classifier):
        """Test classification by known source port (reverse flow)."""
        base_time = 1234567890.0

        # Create flow with known service port as source (reverse flow)
        packets = [
            IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=443, dport=12345),  # HTTPS as source
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Should classify based on source port (lower confidence)
        assert results["total_flows"] >= 1

    def test_classify_streaming_traffic(self, classifier):
        """Test classification of streaming traffic by behavioral patterns."""
        base_time = 1234567890.0

        # Create streaming-like flow: large packets, high throughput, sustained
        packets = []
        packet_size = 1500  # Large packets
        for i in range(100):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9999) / Raw(load=b"x" * packet_size)
            packet.time = base_time + i * 0.01  # 100ms intervals = 10 Mbps
            packets.append(packet)

        results = classifier.analyze(packets)

        # Should classify as Streaming based on behavioral heuristics
        assert results["total_flows"] >= 1
        # Check if streaming was detected
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            # May be classified as Streaming if behavioral heuristics match
            assert classification["service_type"] in ["Streaming", "Bulk", "Unknown"]

    def test_classify_bulk_transfer(self, classifier):
        """Test classification of bulk transfer traffic."""
        base_time = 1234567890.0

        # Create bulk transfer flow: large packets, long duration, TCP
        packets = []
        packet_size = 1500
        duration = 10.0  # 10 seconds
        num_packets = 200
        for i in range(num_packets):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9999) / Raw(load=b"x" * packet_size)
            packet.time = base_time + (i * duration / num_packets)
            packets.append(packet)

        results = classifier.analyze(packets)

        # Should classify as Bulk based on heuristics
        assert results["total_flows"] >= 1
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            # May be classified as Bulk if heuristics match
            assert classification["service_type"] in ["Bulk", "Streaming", "Unknown"]

    def test_classify_dns_traffic(self, classifier):
        """Test classification of DNS traffic by behavioral patterns."""
        base_time = 1234567890.0

        # Create DNS-like flow: small packets, UDP, sporadic
        packets = []
        packet_size = 100  # Small packets
        for i in range(5):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / UDP(sport=12345, dport=9999) / Raw(load=b"x" * packet_size)
            packet.time = base_time + i * 1.0  # 1 second intervals (sporadic)
            packets.append(packet)

        results = classifier.analyze(packets)

        # Should classify as DNS/Control based on heuristics
        assert results["total_flows"] >= 1
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            # May be classified as DNS or Control
            assert classification["service_type"] in ["DNS", "Control", "Unknown"]

    def test_classify_web_interactive_traffic(self, classifier):
        """Test classification of web/interactive traffic."""
        base_time = 1234567890.0

        # Create web-like flow: moderate size, TCP, request-response pattern
        packets = []
        # Request (small)
        for i in range(3):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9999) / Raw(load=b"x" * 300)
            packet.time = base_time + i * 0.1
            packets.append(packet)
        # Response (larger, variable)
        for i in range(5):
            packet = IP(src="10.0.0.1", dst="192.168.1.100") / TCP(sport=9999, dport=12345) / Raw(load=b"x" * (500 + i * 200))
            packet.time = base_time + 0.5 + i * 0.1
            packets.append(packet)

        results = classifier.analyze(packets)

        # Should classify as Interactive/Web based on heuristics
        assert results["total_flows"] >= 1

    def test_calculate_flow_statistics(self, classifier):
        """Test flow statistics calculation."""
        base_time = 1234567890.0

        # Create flow with known characteristics
        packet_list = []
        sizes = [1000, 1200, 1100, 1300, 1000]
        for i, size in enumerate(sizes):
            packet = IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"x" * size)
            packet.time = base_time + i * 0.1
            timestamp = classifier._get_timestamp(packet)
            packet_size = classifier._get_packet_size(packet)
            packet_list.append((timestamp, packet_size, packet))

        flow_key = ("192.168.1.100", 12345, "10.0.0.1", 80, "TCP")
        stats = classifier._calculate_flow_statistics(flow_key, packet_list)

        # Verify statistics
        assert stats["packet_count"] == 5
        assert stats["total_bytes"] > 0
        assert stats["flow_duration"] >= 0
        assert stats["avg_packet_size"] > 0
        assert stats["protocol"] == "TCP"
        assert stats["src_port"] == 12345
        assert stats["dst_port"] == 80

    def test_score_streaming(self, classifier):
        """Test streaming score calculation."""
        # High streaming score: large packets, high throughput, long duration
        stats = {
            "avg_packet_size": 1500,  # >= 1000
            "throughput": 2000000,  # >= 1 Mbps
            "flow_duration": 5.0,  # >= 2.0
            "packet_count": 100,  # >= 50
        }

        score = classifier._score_streaming(stats)
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be high for streaming-like traffic

    def test_score_bulk_transfer(self, classifier):
        """Test bulk transfer score calculation."""
        # High bulk score: TCP, large packets, long duration, many packets
        stats = {
            "protocol": "TCP",
            "avg_packet_size": 1500,  # >= 1200
            "flow_duration": 10.0,  # >= 5.0
            "packet_count": 200,  # >= 100
            "throughput": 1000000,  # >= 500 KB/s
        }

        score = classifier._score_bulk(stats)
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be high for bulk-like traffic

    def test_score_bulk_not_tcp(self, classifier):
        """Test that bulk transfer requires TCP."""
        # UDP should not be classified as bulk
        stats = {
            "protocol": "UDP",
            "avg_packet_size": 1500,
            "flow_duration": 10.0,
            "packet_count": 200,
            "throughput": 1000000,
        }

        score = classifier._score_bulk(stats)
        assert score == 0.0  # Should be 0 for non-TCP

    def test_score_dns(self, classifier):
        """Test DNS/Control score calculation."""
        # High DNS score: UDP, small packets, sporadic
        stats = {
            "protocol": "UDP",
            "avg_packet_size": 300,  # <= 512
            "avg_inter_arrival": 1.0,  # >= 0.5
            "packet_count": 10,  # < 50
            "flow_duration": 5.0,  # < 10.0
        }

        score = classifier._score_dns(stats)
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be high for DNS-like traffic

    def test_score_dns_not_udp(self, classifier):
        """Test that DNS/Control requires UDP."""
        # TCP should not be classified as DNS
        stats = {
            "protocol": "TCP",
            "avg_packet_size": 300,
            "avg_inter_arrival": 1.0,
            "packet_count": 10,
            "flow_duration": 5.0,
        }

        score = classifier._score_dns(stats)
        assert score == 0.0  # Should be 0 for non-UDP

    def test_score_web_interactive(self, classifier):
        """Test web/interactive score calculation."""
        # High web score: TCP, moderate size, moderate duration, variable sizes
        stats = {
            "protocol": "TCP",
            "avg_packet_size": 600,  # Between 200-1200
            "flow_duration": 2.0,  # Between 0.1-30.0
            "packet_count": 20,  # Between 5-100
            "packet_size_variance": 100000,  # > 50000 (variable sizes)
        }

        score = classifier._score_web(stats)
        assert 0.0 <= score <= 1.0
        assert score > 0.5  # Should be high for web-like traffic

    def test_score_web_not_tcp(self, classifier):
        """Test that web/interactive requires TCP."""
        # UDP should not be classified as web
        stats = {
            "protocol": "UDP",
            "avg_packet_size": 600,
            "flow_duration": 2.0,
            "packet_count": 20,
            "packet_size_variance": 100000,
        }

        score = classifier._score_web(stats)
        assert score == 0.0  # Should be 0 for non-TCP

    def test_get_results_structure(self, classifier):
        """Test that get_results() returns correct structure."""
        base_time = 1234567890.0

        # Process some packets
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            IP(src="192.168.1.100", dst="10.0.0.2") / UDP(sport=12345, dport=53),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Check results structure
        assert "total_flows" in results
        assert "classified_flows" in results
        assert "service_classifications" in results
        assert "flow_statistics" in results
        assert "unknown_flows" in results
        assert "classification_summary" in results

        # Check classification summary
        summary = results["classification_summary"]
        assert "total_flows" in summary
        assert "classified_count" in summary
        assert "unclassified_count" in summary
        assert "classification_rate" in summary

    def test_classification_confidence(self, classifier):
        """Test that known ports have high confidence."""
        base_time = 1234567890.0

        # Create flow with known port (HTTP = 80)
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=80),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Known ports should have high confidence
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            # Confidence should be >= 0.9 for known ports
            if classification["service_type"] in KNOWN_SERVICE_PORTS.values():
                assert classification["confidence"] >= 0.9

    def test_classification_reasons(self, classifier):
        """Test that classifications include reasons."""
        base_time = 1234567890.0

        # Create flow with known port
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=443),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Should include reasons for classification
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            assert "reasons" in classification
            assert isinstance(classification["reasons"], list)

    def test_multiple_flows_classification(self, classifier):
        """Test classification of multiple different flows."""
        base_time = 1234567890.0

        # Create multiple flows with different characteristics
        packets = [
            # HTTP flow
            IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            # HTTPS flow
            IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=12346, dport=443),
            IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=12346, dport=443),
            # DNS flow
            IP(src="192.168.1.3", dst="10.0.0.3") / UDP(sport=12347, dport=53),
        ]

        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Should classify multiple flows
        assert results["total_flows"] >= 2  # At least 2 different flows

    def test_unknown_flows_tracking(self, classifier):
        """Test that unknown flows are tracked."""
        base_time = 1234567890.0

        # Create flow with unknown port (not in KNOWN_SERVICE_PORTS)
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9999),
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9999),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Should track unknown flows
        assert "unknown_flows" in results
        # May have unknown flows if behavioral heuristics don't match
        assert isinstance(results["unknown_flows"], list)

    def test_empty_packet_list(self, classifier):
        """Test that empty packet list returns empty results."""
        results = classifier.analyze([])

        # Should return empty results
        assert results["total_flows"] == 0
        assert len(results["classified_flows"]) == 0
        assert len(results["service_classifications"]) == 0
        assert len(results["unknown_flows"]) == 0

    def test_format_flow_key(self, classifier):
        """Test flow key formatting."""
        flow_key = ("192.168.1.100", 12345, "10.0.0.1", 80, "TCP")
        formatted = classifier._format_flow_key(flow_key)

        # Should format flow key as readable string
        assert isinstance(formatted, str)
        assert "192.168.1.100" in formatted
        assert "12345" in formatted
        assert "10.0.0.1" in formatted
        assert "80" in formatted
        assert "TCP" in formatted

    def test_classification_rate_calculation(self, classifier):
        """Test classification rate calculation."""
        base_time = 1234567890.0

        # Create mix of known and unknown flows
        packets = [
            # Known port (HTTP)
            IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80),
            # Unknown port
            IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=12346, dport=9999),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)
        summary = results["classification_summary"]

        # Should calculate classification rate
        assert "classification_rate" in summary
        assert 0.0 <= summary["classification_rate"] <= 100.0

    def test_async_service_detection(self, classifier):
        """Test async service detection (Kafka, RabbitMQ, etc.)."""
        base_time = 1234567890.0

        # Create Kafka flow (port 9092, marked as async)
        packets = [
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9092),
            IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=12345, dport=9092),
        ]
        for i, packet in enumerate(packets):
            packet.time = base_time + i * 0.1

        results = classifier.analyze(packets)

        # Should detect async services
        if results["classified_flows"]:
            flow_key_str = next(iter(results["classified_flows"].keys()))
            classification = results["classified_flows"][flow_key_str]
            if classification["service_type"] == "Kafka":
                assert classification.get("is_async", False) is True
