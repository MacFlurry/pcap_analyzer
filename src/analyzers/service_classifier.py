"""
Service Classification Engine

Intelligent traffic classification based on behavioral patterns rather than
just port numbers. Uses heuristics to identify traffic types:

Service Types:
- Video Streaming: Large packets, sustained throughput
- Web/Interactive: Request-response patterns, moderate size
- Bulk Transfer: Large persistent flows
- DNS/Control: Small sporadic packets

Classification Features:
- Packet size distribution (mean, variance)
- Inter-arrival time patterns
- Flow duration and packet count
- Protocol type (TCP/UDP)
- Bidirectional flow characteristics

References:
- Moore & Zuev (2005): Internet Traffic Classification Using Bayesian Analysis
- Nguyen & Armitage (2008): A Survey of Techniques for Internet Traffic Classification
"""

import statistics
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from scapy.all import IP, TCP, UDP, IPv6

# Classification thresholds
STREAMING_PKT_SIZE_MIN = 1000  # bytes
STREAMING_THROUGHPUT_MIN = 1000000  # 1 Mbps

WEB_REQUEST_SIZE_MAX = 500  # bytes
BULK_TRANSFER_SIZE_MIN = 1200  # bytes
BULK_TRANSFER_DURATION_MIN = 5.0  # seconds

DNS_PKT_SIZE_MAX = 512  # bytes
DNS_INTER_ARRIVAL_MIN = 0.5  # seconds (sporadic)

# Known service ports (prioritized over behavioral heuristics)
# Format: port -> (service_name, is_async)
KNOWN_SERVICE_PORTS = {
    # Message Brokers / Async Services
    9092: ("Kafka", True),
    9093: ("Kafka SSL", True),
    5672: ("RabbitMQ", True),
    5671: ("RabbitMQ SSL", True),
    # Databases
    6379: ("Redis", True),
    27017: ("MongoDB", True),
    27018: ("MongoDB Shard", True),
    27019: ("MongoDB Config", True),
    3306: ("MySQL", True),
    5432: ("PostgreSQL", True),
    # Search / Analytics
    9200: ("Elasticsearch", True),
    9300: ("Elasticsearch Cluster", True),
    # Common Web Services
    80: ("HTTP", False),
    443: ("HTTPS", False),
    8080: ("HTTP Alt", False),
    8443: ("HTTPS Alt", False),
    # DNS
    53: ("DNS", False),
    # SSH/Telnet
    22: ("SSH", False),
    23: ("Telnet", False),
    # FTP
    20: ("FTP Data", False),
    21: ("FTP Control", False),
    # Mail
    25: ("SMTP", False),
    110: ("POP3", False),
    143: ("IMAP", False),
    993: ("IMAPS", False),
    995: ("POP3S", False),
}


class ServiceClassifier:
    """
    Intelligent service classification based on traffic patterns.

    Uses behavioral heuristics to classify flows into service types
    without relying solely on port numbers.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all state."""
        self.flow_packets = defaultdict(list)  # Flow -> list of (timestamp, size, packet)
        self.flow_stats = {}  # Flow -> statistics
        self.flow_classifications = {}  # Flow -> (service_type, confidence)

    def analyze(self, packets: list) -> dict[str, Any]:
        """
        Classify flows based on behavioral patterns.

        Args:
            packets: List of scapy packets

        Returns:
            Dictionary with classification results
        """
        self.reset()

        # Group packets by flow
        for packet in packets:
            flow_key = self._get_flow_key(packet)
            if flow_key:
                timestamp = self._get_timestamp(packet)
                size = self._get_packet_size(packet)
                self.flow_packets[flow_key].append((timestamp, size, packet))

        # Calculate flow statistics
        for flow_key, packet_list in self.flow_packets.items():
            if len(packet_list) > 0:
                self.flow_stats[flow_key] = self._calculate_flow_statistics(flow_key, packet_list)

        # Classify each flow
        for flow_key, stats in self.flow_stats.items():
            classification = self._classify_flow(stats)
            self.flow_classifications[flow_key] = classification

        return self.get_results()

    def _get_flow_key(self, packet) -> tuple:
        """Get flow identifier from packet."""
        if IP in packet and (TCP in packet or UDP in packet):
            ip = packet[IP]
            if TCP in packet:
                tcp_udp = packet[TCP]
                proto = "TCP"
            else:
                tcp_udp = packet[UDP]
                proto = "UDP"

            return (ip.src, tcp_udp.sport, ip.dst, tcp_udp.dport, proto)

        elif IPv6 in packet and (TCP in packet or UDP in packet):
            ip = packet[IPv6]
            if TCP in packet:
                tcp_udp = packet[TCP]
                proto = "TCP"
            else:
                tcp_udp = packet[UDP]
                proto = "UDP"

            return (ip.src, tcp_udp.sport, ip.dst, tcp_udp.dport, proto)

        return None

    def _get_timestamp(self, packet) -> float:
        """Get timestamp from packet."""
        return float(packet.time) if hasattr(packet, "time") else 0.0

    def _get_packet_size(self, packet) -> int:
        """Get packet size safely."""
        try:
            return len(packet)
        except Exception:
            return 1500  # Default MTU

    def _calculate_flow_statistics(self, flow_key: tuple, packet_list: list[tuple]) -> dict:
        """Calculate statistical features for a flow."""
        timestamps = [p[0] for p in packet_list]
        sizes = [p[1] for p in packet_list]

        # Extract ports from flow_key
        # flow_key format: (src_ip, src_port, dst_ip, dst_port, proto)
        src_port = flow_key[1]
        dst_port = flow_key[3]

        # Basic stats
        packet_count = len(packet_list)
        total_bytes = sum(sizes)
        flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

        # Packet size statistics
        avg_packet_size = statistics.mean(sizes)
        if len(sizes) > 1:
            packet_size_variance = statistics.variance(sizes)
            packet_size_stdev = statistics.stdev(sizes)
        else:
            packet_size_variance = 0.0
            packet_size_stdev = 0.0

        # Inter-arrival time statistics
        inter_arrivals = []
        for i in range(1, len(timestamps)):
            inter_arrivals.append(timestamps[i] - timestamps[i - 1])

        if len(inter_arrivals) > 0:
            avg_inter_arrival = statistics.mean(inter_arrivals)
            if len(inter_arrivals) > 1:
                inter_arrival_variance = statistics.variance(inter_arrivals)
            else:
                inter_arrival_variance = 0.0
        else:
            avg_inter_arrival = 0.0
            inter_arrival_variance = 0.0

        # Throughput
        throughput = total_bytes / flow_duration if flow_duration > 0 else 0.0

        # Protocol
        proto = flow_key[4]

        return {
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "flow_duration": flow_duration,
            "avg_packet_size": avg_packet_size,
            "packet_size_variance": packet_size_variance,
            "packet_size_stdev": packet_size_stdev,
            "avg_inter_arrival": avg_inter_arrival,
            "inter_arrival_variance": inter_arrival_variance,
            "throughput": throughput,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
        }

    def _classify_flow(self, stats: dict) -> dict:
        """
        Classify flow based on statistics.

        Returns dict with service_type and confidence score.
        """
        service_type = "Unknown"
        confidence = 0.0
        reasons = []
        is_async = False

        # PRIORITY 1: Check known service ports (source or destination)
        src_port = stats.get("src_port", 0)
        dst_port = stats.get("dst_port", 0)

        # Check destination port first (most common case)
        if dst_port in KNOWN_SERVICE_PORTS:
            service_name, is_async = KNOWN_SERVICE_PORTS[dst_port]
            service_type = service_name
            confidence = 1.0  # High confidence for known ports
            reasons = [f"Known port {dst_port}"]
        # Then check source port (for reverse flows)
        elif src_port in KNOWN_SERVICE_PORTS:
            service_name, is_async = KNOWN_SERVICE_PORTS[src_port]
            service_type = service_name
            confidence = 0.9  # Slightly lower confidence for source port match
            reasons = [f"Known source port {src_port}"]
        else:
            # PRIORITY 2: Use behavioral heuristics if port unknown
            # Video streaming detection
            streaming_score = self._score_streaming(stats)
            if streaming_score > confidence:
                service_type = "Streaming"
                confidence = streaming_score
                reasons = ["Large packets", "Sustained throughput"]

            # Bulk transfer detection
            bulk_score = self._score_bulk(stats)
            if bulk_score > confidence:
                service_type = "Bulk"
                confidence = bulk_score
                reasons = ["Large packets", "Long duration", "TCP"]

            # DNS/Control detection
            dns_score = self._score_dns(stats)
            if dns_score > confidence:
                service_type = "DNS" if "53" in str(dst_port) else "Control"
                confidence = dns_score
                reasons = ["Small packets", "Sporadic", "UDP"]

            # Interactive/Web detection
            web_score = self._score_web(stats)
            if web_score > confidence:
                service_type = "Interactive"
                confidence = web_score
                reasons = ["Moderate size", "TCP"]

        return {
            "service_type": service_type,
            "confidence": confidence,
            "reasons": reasons,
            "stats": stats,
            "is_async": is_async,  # For jitter severity adjustment
        }

    def _score_streaming(self, stats: dict) -> float:
        """Score streaming likelihood (0-1)."""
        score = 0.0

        # Large packets
        if stats["avg_packet_size"] >= STREAMING_PKT_SIZE_MIN:
            score += 0.4

        # High throughput
        if stats["throughput"] >= STREAMING_THROUGHPUT_MIN:
            score += 0.3

        # Sustained duration
        if stats["flow_duration"] >= 2.0:
            score += 0.2

        # Many packets
        if stats["packet_count"] >= 50:
            score += 0.1

        return min(score, 1.0)

    def _score_bulk(self, stats: dict) -> float:
        """Score bulk transfer likelihood (0-1)."""
        score = 0.0

        # Must be TCP
        if stats["protocol"] != "TCP":
            return 0.0

        # Large packets
        if stats["avg_packet_size"] >= BULK_TRANSFER_SIZE_MIN:
            score += 0.4

        # Long duration
        if stats["flow_duration"] >= BULK_TRANSFER_DURATION_MIN:
            score += 0.3

        # Many packets
        if stats["packet_count"] >= 100:
            score += 0.2

        # High throughput
        if stats["throughput"] >= 500000:  # 500 KB/s
            score += 0.1

        return min(score, 1.0)

    def _score_dns(self, stats: dict) -> float:
        """Score DNS/Control traffic likelihood (0-1)."""
        score = 0.0

        # Must be UDP
        if stats["protocol"] != "UDP":
            return 0.0

        # Small packets
        if stats["avg_packet_size"] <= DNS_PKT_SIZE_MAX:
            score += 0.4

        # Sporadic (high inter-arrival variance or large avg)
        if stats["avg_inter_arrival"] >= DNS_INTER_ARRIVAL_MIN:
            score += 0.3

        # Few packets
        if stats["packet_count"] < 50:
            score += 0.2

        # Short duration
        if stats["flow_duration"] < 10.0 or stats["packet_count"] < 10:
            score += 0.1

        return min(score, 1.0)

    def _score_web(self, stats: dict) -> float:
        """Score web/interactive traffic likelihood (0-1)."""
        score = 0.0

        # Must be TCP
        if stats["protocol"] != "TCP":
            return 0.0

        # Moderate packet size
        if 200 <= stats["avg_packet_size"] <= 1200:
            score += 0.3

        # Moderate duration
        if 0.1 <= stats["flow_duration"] <= 30.0:
            score += 0.2

        # Moderate packet count
        if 5 <= stats["packet_count"] <= 100:
            score += 0.3

        # Variable packet sizes (request/response pattern)
        if stats["packet_size_variance"] > 50000:
            score += 0.2

        return min(score, 1.0)

    def _format_flow_key(self, flow_key: tuple) -> str:
        """Format flow key as readable string."""
        src_ip, src_port, dst_ip, dst_port, proto = flow_key
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})"

    def get_results(self) -> dict[str, Any]:
        """
        Get classification results.

        Returns:
            Dictionary with classification results
        """
        # Count services
        service_counts = defaultdict(int)
        for flow_key, classification in self.flow_classifications.items():
            service_type = classification["service_type"]
            service_counts[service_type] += 1

        # Classified flows with details
        classified_flows = {}
        for flow_key, classification in self.flow_classifications.items():
            flow_key_str = self._format_flow_key(flow_key)
            classified_flows[flow_key_str] = {
                "service_type": classification["service_type"],
                "confidence": classification["confidence"],
                "reasons": classification["reasons"],
                "is_async": classification.get("is_async", False),
                "packet_count": classification["stats"]["packet_count"],
                "avg_packet_size": classification["stats"]["avg_packet_size"],
                "flow_duration": classification["stats"]["flow_duration"],
            }

        # Flow statistics (detailed)
        flow_statistics = {}
        for flow_key, stats in self.flow_stats.items():
            flow_key_str = self._format_flow_key(flow_key)
            flow_statistics[flow_key_str] = stats

        # Summary
        total_flows = len(self.flow_packets)
        classified_count = sum(1 for c in self.flow_classifications.values() if c["service_type"] != "Unknown")
        unclassified_count = total_flows - classified_count

        # Extract unknown flows with port information for analysis
        unknown_flows = []
        for flow_key, classification in self.flow_classifications.items():
            if classification["service_type"] == "Unknown":
                # flow_key format: (src_ip, src_port, dst_ip, dst_port, proto)
                unknown_flows.append(
                    {
                        "src_ip": flow_key[0],
                        "src_port": flow_key[1],
                        "dst_ip": flow_key[2],
                        "dst_port": flow_key[3],
                        "proto": flow_key[4],
                        "packet_count": classification["stats"]["packet_count"],
                        "avg_packet_size": classification["stats"]["avg_packet_size"],
                    }
                )

        return {
            "total_flows": total_flows,
            "classified_flows": classified_flows,
            "service_classifications": dict(service_counts),
            "flow_statistics": flow_statistics,
            "unknown_flows": unknown_flows,
            "classification_summary": {
                "total_flows": total_flows,
                "classified_count": classified_count,
                "unclassified_count": unclassified_count,
                "classification_rate": (classified_count / total_flows * 100) if total_flows > 0 else 0.0,
            },
        }
