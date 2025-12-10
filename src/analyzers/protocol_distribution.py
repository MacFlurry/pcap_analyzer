"""
Protocol Distribution Analyzer

Analyzes the distribution of network protocols across layers:
- Layer 3: IPv4, IPv6, ARP, etc.
- Layer 4: TCP, UDP, ICMP, etc.
- Port distribution for TCP and UDP
- Service identification (HTTP, HTTPS, DNS, SSH, etc.)
- Protocol usage statistics (bytes, flows)

Useful for:
- Understanding traffic composition
- Identifying dominant protocols
- Detecting unusual protocol usage
- Network troubleshooting
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Set

from scapy.all import ARP, ICMP, IP, TCP, UDP, IPv6

# Well-known service ports
WELL_KNOWN_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class ProtocolDistributionAnalyzer:
    """
    Analyzes protocol distribution across network layers.

    Tracks:
    - Layer 3 protocols (IPv4, IPv6, ARP)
    - Layer 4 protocols (TCP, UDP, ICMP)
    - Port distribution
    - Service identification
    - Protocol statistics (bytes, flows)
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all counters."""
        self.total_packets = 0
        self.layer3_counts = Counter()
        self.layer4_counts = Counter()
        self.tcp_port_counts = Counter()
        self.udp_port_counts = Counter()
        self.service_counts = Counter()
        self.protocol_bytes = defaultdict(int)
        self.tcp_flows: Set[tuple] = set()
        self.udp_flows: Set[tuple] = set()

    def analyze(self, packets: List) -> Dict[str, Any]:
        """
        Analyze protocol distribution in packet list.

        Args:
            packets: List of scapy packets

        Returns:
            Dictionary with protocol distribution statistics
        """
        self.reset()

        for packet in packets:
            self.process_packet(packet)

        return self.get_results()

    def process_packet(self, packet):
        """Process a single packet."""
        self.total_packets += 1

        # Safe packet size calculation
        try:
            packet_size = len(packet)
        except Exception:
            # If packet can't be built (e.g., IPv6 MAC resolution), estimate size
            packet_size = 1500  # Default MTU

        # Layer 3 analysis
        if IP in packet:
            self.layer3_counts["IPv4"] += 1

            # Layer 4 analysis for IPv4
            if TCP in packet:
                self.layer4_counts["TCP"] += 1
                self.protocol_bytes["TCP"] += packet_size
                self._process_tcp_packet(packet)

            elif UDP in packet:
                self.layer4_counts["UDP"] += 1
                self.protocol_bytes["UDP"] += packet_size
                self._process_udp_packet(packet)

            elif ICMP in packet:
                self.layer4_counts["ICMP"] += 1
                self.protocol_bytes["ICMP"] += packet_size

        elif IPv6 in packet:
            self.layer3_counts["IPv6"] += 1

            # Layer 4 analysis for IPv6
            if TCP in packet:
                self.layer4_counts["TCP"] += 1
                self.protocol_bytes["TCP"] += packet_size
                self._process_tcp_packet(packet)

            elif UDP in packet:
                self.layer4_counts["UDP"] += 1
                self.protocol_bytes["UDP"] += packet_size
                self._process_udp_packet(packet)

        elif ARP in packet:
            self.layer3_counts["ARP"] += 1

    def _process_tcp_packet(self, packet):
        """Process TCP-specific information."""
        tcp = packet[TCP]
        dport = tcp.dport
        sport = tcp.sport

        # Track port distribution
        self.tcp_port_counts[dport] += 1

        # Track unique flows
        if IP in packet:
            flow_key = (packet[IP].src, sport, packet[IP].dst, dport)
            self.tcp_flows.add(flow_key)
        elif IPv6 in packet:
            flow_key = (packet[IPv6].src, sport, packet[IPv6].dst, dport)
            self.tcp_flows.add(flow_key)

        # Identify service
        service = WELL_KNOWN_SERVICES.get(dport)
        if service:
            self.service_counts[service] += 1

    def _process_udp_packet(self, packet):
        """Process UDP-specific information."""
        udp = packet[UDP]
        dport = udp.dport
        sport = udp.sport

        # Track port distribution
        self.udp_port_counts[dport] += 1

        # Track unique flows
        if IP in packet:
            flow_key = (packet[IP].src, sport, packet[IP].dst, dport)
            self.udp_flows.add(flow_key)
        elif IPv6 in packet:
            flow_key = (packet[IPv6].src, sport, packet[IPv6].dst, dport)
            self.udp_flows.add(flow_key)

        # Identify service
        service = WELL_KNOWN_SERVICES.get(dport)
        if service:
            self.service_counts[service] += 1

    def get_results(self) -> Dict[str, Any]:
        """
        Get analysis results.

        Returns:
            Dictionary with protocol distribution statistics
        """
        # Calculate percentages
        layer3_percentages = {}
        if self.total_packets > 0:
            for protocol, count in self.layer3_counts.items():
                layer3_percentages[protocol] = (count / self.total_packets) * 100

        layer4_percentages = {}
        layer4_total = sum(self.layer4_counts.values())
        if layer4_total > 0:
            for protocol, count in self.layer4_counts.items():
                layer4_percentages[protocol] = (count / layer4_total) * 100

        # Get top ports
        top_tcp_ports = [
            {"port": port, "count": count, "service": WELL_KNOWN_SERVICES.get(port, "Unknown")}
            for port, count in self.tcp_port_counts.most_common(10)
        ]

        top_udp_ports = [
            {"port": port, "count": count, "service": WELL_KNOWN_SERVICES.get(port, "Unknown")}
            for port, count in self.udp_port_counts.most_common(10)
        ]

        return {
            "total_packets": self.total_packets,
            "layer3_distribution": dict(self.layer3_counts),
            "layer3_percentages": layer3_percentages,
            "layer4_distribution": dict(self.layer4_counts),
            "layer4_percentages": layer4_percentages,
            "tcp_port_distribution": dict(self.tcp_port_counts),
            "udp_port_distribution": dict(self.udp_port_counts),
            "top_tcp_ports": top_tcp_ports,
            "top_udp_ports": top_udp_ports,
            "service_distribution": dict(self.service_counts),
            "protocol_bytes": dict(self.protocol_bytes),
            "unique_flows": {"TCP": len(self.tcp_flows), "UDP": len(self.udp_flows)},
        }
