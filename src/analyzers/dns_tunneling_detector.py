"""
DNS Tunneling Detector - Identifies data exfiltration via DNS

Detects DNS tunneling patterns used for:
- Command & Control (C2) communication
- Data exfiltration
- Firewall/proxy bypass
- Covert channels

Indicators:
- Unusually long DNS queries (>50 characters)
- High entropy in subdomain names (base64, hex encoding)
- Excessive DNS query volume from single source
- Non-standard TXT/NULL record requests
- Regular beacon patterns
- Subdomains with suspicious patterns (random strings)
"""

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple

from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, Packet, UDP

from .base_analyzer import BaseAnalyzer


@dataclass
class TunnelingEvent:
    """Represents a detected DNS tunneling activity"""
    source_ip: str
    domain: str
    start_time: float
    end_time: float
    query_count: int
    avg_query_length: float
    max_query_length: int
    avg_entropy: float
    suspicious_patterns: List[str]
    record_types: Dict[str, int]
    severity: str


class DNSTunnelingDetector(BaseAnalyzer):
    """
    Detects DNS tunneling and data exfiltration attempts.

    Detection criteria:
    - Query length > 50 characters
    - High entropy subdomains (>3.5 bits per character)
    - High query frequency (>10 queries/min to same domain)
    - Unusual record types (TXT, NULL, with large payloads)
    - Base64/Hex encoded subdomains
    """

    # Common legitimate domains to whitelist
    WHITELIST_DOMAINS = {
        "google.com", "googleapis.com", "gstatic.com",
        "microsoft.com", "windows.com", "office.com",
        "apple.com", "icloud.com",
        "amazon.com", "amazonaws.com", "cloudfront.net",
        "facebook.com", "fbcdn.net",
        "akamai.net", "cloudflare.com",
        "ubuntu.com", "debian.org", "fedoraproject.org",
        "mozilla.org", "firefox.com",
        # Kubernetes internal domains
        "cluster.local", "svc.cluster.local", "pod.cluster.local"
    }

    def __init__(self,
                 query_length_threshold: int = 50,
                 entropy_threshold: float = 3.5,
                 query_rate_threshold: float = 10.0,  # queries per minute
                 time_window: float = 60.0,  # 1 minute
                 include_localhost: bool = False):
        """
        Initialize DNS tunneling detector.

        Args:
            query_length_threshold: Min query length to flag as suspicious
            entropy_threshold: Min Shannon entropy to flag (bits per char)
            query_rate_threshold: Min queries per minute to flag
            time_window: Time window for rate calculation (seconds)
            include_localhost: Include localhost traffic (default: False)
        """
        super().__init__()
        self.query_length_threshold = query_length_threshold
        self.entropy_threshold = entropy_threshold
        self.query_rate_threshold = query_rate_threshold
        self.time_window = time_window
        self.include_localhost = include_localhost

        # Track DNS queries by source IP and domain
        # {(src_ip, domain): [query_details]}
        self.dns_queries: DefaultDict[Tuple, List[Dict]] = defaultdict(list)

        # Detected tunneling events
        self.tunneling_events: List[TunnelingEvent] = []

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        """Check if an IP address is localhost."""
        if ip in ["::1", "::ffff:127.0.0.1"]:
            return True
        if ip.startswith("127."):
            return True
        return False

    @staticmethod
    def _calculate_entropy(string: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Higher entropy suggests random/encoded data.
        English text: ~4.0-4.5 bits/char
        Base64: ~6.0 bits/char
        Random: ~7.0-8.0 bits/char
        """
        if not string:
            return 0.0

        # Count character frequencies
        freq = Counter(string.lower())
        length = len(string)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    @staticmethod
    def _extract_subdomain(query_name: str) -> str:
        """Extract the leftmost subdomain from a query."""
        parts = query_name.rstrip(".").split(".")
        if len(parts) > 2:
            # Return everything except TLD and domain
            return ".".join(parts[:-2])
        return parts[0] if parts else ""

    @staticmethod
    def _is_whitelisted(domain: str, whitelist: Set[str]) -> bool:
        """Check if domain matches whitelist."""
        domain = domain.lower().rstrip(".")

        # Exact match
        if domain in whitelist:
            return True

        # Check if any whitelisted domain is a suffix
        for white_domain in whitelist:
            if domain.endswith("." + white_domain) or domain == white_domain:
                return True

        return False

    @staticmethod
    def _detect_encoding_pattern(subdomain: str) -> List[str]:
        """Detect encoding patterns in subdomain."""
        patterns = []

        # Base64 pattern (alphanumeric + / and =)
        if re.match(r'^[A-Za-z0-9+/=]{8,}$', subdomain):
            patterns.append("base64")

        # Hex encoding pattern
        if re.match(r'^[0-9a-fA-F]{16,}$', subdomain):
            patterns.append("hex")

        # UUID pattern (used in some C2)
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', subdomain):
            patterns.append("uuid")

        # Long random alphanumeric
        if len(subdomain) > 20 and re.match(r'^[a-z0-9]+$', subdomain):
            # Check if it looks random (few repeated chars)
            char_freq = Counter(subdomain)
            if len(char_freq) > len(subdomain) * 0.5:  # High diversity
                patterns.append("random")

        return patterns

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Process a single packet for DNS tunneling detection."""
        if not packet.haslayer(DNS):
            return

        dns = packet[DNS]
        timestamp = float(packet.time)

        # Only analyze DNS queries (not responses)
        if dns.qr != 0:  # qr=0 means query, qr=1 means response
            return

        # Extract source IP
        src_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
        else:
            return

        # Filter localhost unless explicitly included
        if not self.include_localhost:
            if self._is_localhost(src_ip):
                return

        # Process DNS questions
        if dns.qd:
            for i in range(dns.qdcount):
                query = dns.qd if not isinstance(dns.qd, list) else dns.qd[i] if i < len(dns.qd) else dns.qd

                if query and hasattr(query, 'qname'):
                    query_name = query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname)
                    query_type = query.qtype if hasattr(query, 'qtype') else 1

                    # Extract base domain (e.g., "example.com" from "sub.example.com")
                    parts = query_name.rstrip(".").split(".")
                    if len(parts) >= 2:
                        base_domain = ".".join(parts[-2:])
                    else:
                        base_domain = query_name

                    # Skip whitelisted domains
                    if self._is_whitelisted(base_domain, self.WHITELIST_DOMAINS):
                        continue

                    # Calculate query characteristics
                    subdomain = self._extract_subdomain(query_name)
                    query_length = len(query_name)
                    entropy = self._calculate_entropy(subdomain) if subdomain else 0.0
                    patterns = self._detect_encoding_pattern(subdomain)

                    # Store query details
                    key = (src_ip, base_domain)
                    self.dns_queries[key].append({
                        "timestamp": timestamp,
                        "query_name": query_name,
                        "subdomain": subdomain,
                        "query_length": query_length,
                        "entropy": entropy,
                        "patterns": patterns,
                        "record_type": query_type
                    })

    def finalize(self) -> Dict[str, Any]:
        """
        Analyze DNS query patterns and detect tunneling.

        Returns:
            Dictionary with detected tunneling events
        """
        # Analyze each source-domain combination
        for key, queries in self.dns_queries.items():
            if len(queries) < 3:  # Need at least 3 queries to establish pattern
                continue

            src_ip, domain = key
            self._analyze_tunneling_pattern(src_ip, domain, queries)

        return self.get_results()

    def _analyze_tunneling_pattern(self, src_ip: str, domain: str,
                                   queries: List[Dict]) -> None:
        """Analyze queries for tunneling indicators."""
        if len(queries) < 3:
            return

        # Sort by timestamp
        queries.sort(key=lambda x: x["timestamp"])

        start_time = queries[0]["timestamp"]
        end_time = queries[-1]["timestamp"]
        duration = end_time - start_time

        if duration == 0:
            duration = 0.001

        # Calculate statistics
        query_count = len(queries)
        query_rate = (query_count / duration) * 60  # queries per minute

        lengths = [q["query_length"] for q in queries]
        entropies = [q["entropy"] for q in queries if q["entropy"] > 0]

        avg_length = sum(lengths) / len(lengths)
        max_length = max(lengths)
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0

        # Collect all patterns
        all_patterns = []
        for q in queries:
            all_patterns.extend(q["patterns"])

        suspicious_patterns = list(set(all_patterns))

        # Count record types
        record_types = defaultdict(int)
        for q in queries:
            rtype = q["record_type"]
            type_name = self._get_record_type_name(rtype)
            record_types[type_name] += 1

        # Determine if suspicious
        is_suspicious = False
        reasons = []

        # Check long queries
        if avg_length > self.query_length_threshold:
            is_suspicious = True
            reasons.append(f"long_queries (avg: {avg_length:.0f} chars)")

        # Check high entropy
        if avg_entropy > self.entropy_threshold:
            is_suspicious = True
            reasons.append(f"high_entropy (avg: {avg_entropy:.2f} bits/char)")

        # Check high query rate
        if query_rate > self.query_rate_threshold:
            is_suspicious = True
            reasons.append(f"high_rate ({query_rate:.1f} queries/min)")

        # Check encoding patterns
        if suspicious_patterns:
            is_suspicious = True
            reasons.append(f"encoding: {', '.join(suspicious_patterns)}")

        # Check unusual record types (TXT, NULL often used for tunneling)
        unusual_types = {"TXT", "NULL", "AAAA", "MX"}
        if any(rtype in unusual_types for rtype in record_types.keys()):
            unusual_count = sum(count for rtype, count in record_types.items() if rtype in unusual_types)
            if unusual_count > query_count * 0.2:  # >20% unusual
                is_suspicious = True
                reasons.append(f"unusual_records ({unusual_count} {list(unusual_types & set(record_types.keys()))})")

        if is_suspicious:
            # Calculate severity
            severity = self._calculate_severity(
                avg_length,
                avg_entropy,
                query_rate,
                query_count,
                len(suspicious_patterns)
            )

            event = TunnelingEvent(
                source_ip=src_ip,
                domain=domain,
                start_time=start_time,
                end_time=end_time,
                query_count=query_count,
                avg_query_length=avg_length,
                max_query_length=max_length,
                avg_entropy=avg_entropy,
                suspicious_patterns=reasons,
                record_types=dict(record_types),
                severity=severity
            )
            self.tunneling_events.append(event)

    @staticmethod
    def _get_record_type_name(qtype: int) -> str:
        """Get DNS record type name from numeric code."""
        type_map = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            10: "NULL",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            255: "ANY"
        }
        return type_map.get(qtype, f"TYPE{qtype}")

    def _calculate_severity(self, avg_length: float, avg_entropy: float,
                           query_rate: float, query_count: int,
                           pattern_count: int) -> str:
        """Calculate severity based on multiple indicators."""
        severity = "low"
        score = 0

        # Score based on query length
        if avg_length > 100:
            score += 3
        elif avg_length > 75:
            score += 2
        elif avg_length > 50:
            score += 1

        # Score based on entropy
        if avg_entropy > 5.0:  # Very high (likely base64/random)
            score += 3
        elif avg_entropy > 4.5:
            score += 2
        elif avg_entropy > 3.5:
            score += 1

        # Score based on query rate
        if query_rate > 50:
            score += 3
        elif query_rate > 30:
            score += 2
        elif query_rate > 10:
            score += 1

        # Score based on volume
        if query_count > 100:
            score += 2
        elif query_count > 50:
            score += 1

        # Score based on encoding patterns
        score += min(pattern_count, 2)

        # Determine severity
        if score >= 9:
            severity = "critical"
        elif score >= 6:
            severity = "high"
        elif score >= 3:
            severity = "medium"

        return severity

    def get_results(self) -> Dict[str, Any]:
        """Get detection results."""
        # Sort by severity and query count
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_events = sorted(
            self.tunneling_events,
            key=lambda e: (severity_order[e.severity], -e.query_count)
        )

        # Count by severity and domain
        severity_counts = defaultdict(int)
        domain_counts = defaultdict(int)

        for event in sorted_events:
            severity_counts[event.severity] += 1
            domain_counts[event.domain] += 1

        # Format events for output
        formatted_events = []
        for event in sorted_events[:20]:  # Top 20
            formatted_events.append({
                "source_ip": event.source_ip,
                "domain": event.domain,
                "severity": event.severity,
                "start_time": event.start_time,
                "duration": event.end_time - event.start_time,
                "query_count": event.query_count,
                "avg_query_length": event.avg_query_length,
                "max_query_length": event.max_query_length,
                "avg_entropy": event.avg_entropy,
                "suspicious_patterns": event.suspicious_patterns,
                "record_types": event.record_types
            })

        return {
            "total_tunneling_detected": len(self.tunneling_events),
            "severity_breakdown": dict(severity_counts),
            "domain_breakdown": dict(sorted(
                domain_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "tunneling_events": formatted_events,
            "detection_thresholds": {
                "query_length_threshold": self.query_length_threshold,
                "entropy_threshold": self.entropy_threshold,
                "query_rate_threshold": self.query_rate_threshold,
                "time_window": self.time_window
            }
        }

    def get_summary(self) -> str:
        """Get one-line summary of DNS tunneling detection."""
        results = self.get_results()
        total = results["total_tunneling_detected"]

        if total == 0:
            return "✓ Aucun tunneling DNS détecté."

        severity = results["severity_breakdown"]
        critical = severity.get("critical", 0)
        high = severity.get("high", 0)

        summary = f"🔴 {total} tunneling DNS détecté(s)"
        if critical > 0 or high > 0:
            summary += f" ({critical} critique(s), {high} élevé(s))"

        return summary
