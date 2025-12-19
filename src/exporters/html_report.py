"""
HTML Report Generator

Generates professional, self-contained HTML reports with:
- Executive summary
- Health score visualization
- Protocol distribution charts
- Jitter analysis visualization
- Service classification charts
- Responsive design
- No external dependencies (embedded CSS/JS)
"""

from typing import Any


class HTMLReportGenerator:
    """Generates HTML reports from analysis results."""

    # Known async services where high jitter is expected
    KNOWN_ASYNC_SERVICES = {
        9092: ("Kafka", "🐘", "Message broker using async batching"),
        9093: ("Kafka SSL", "🐘", "Secure Kafka with async batching"),
        5672: ("RabbitMQ", "🐰", "Message queue with async processing"),
        5671: ("RabbitMQ SSL", "🐰", "Secure RabbitMQ with async processing"),
        6379: ("Redis", "📦", "In-memory cache with async replication"),
        27017: ("MongoDB", "🍃", "NoSQL database with async operations"),
        9200: ("Elasticsearch", "🔍", "Search engine with batch indexing"),
        5432: ("PostgreSQL", "🐘", "Database with async replication"),
        3306: ("MySQL", "🐬", "Database with async replication"),
    }

    # Interactive terminal/shell services (TCP-based, jitter causes perceived latency)
    INTERACTIVE_SERVICES = {
        22: ("SSH", "🔐", "Secure shell (RFC 4253)"),
        23: ("Telnet", "📟", "Terminal protocol"),
        3389: ("RDP", "🖥️", "Remote Desktop Protocol"),
        5900: ("VNC", "🖥️", "Virtual Network Computing"),
    }

    # Request-response services (tolerant to jitter due to TCP buffering)
    REQUEST_RESPONSE_SERVICES = {
        80: ("HTTP", "🌐", "Web traffic"),
        443: ("HTTPS", "🔒", "Secure web traffic"),
        8080: ("HTTP Alt", "🌐", "Alternative HTTP"),
        8443: ("HTTPS Alt", "🔒", "Alternative HTTPS"),
        53: ("DNS", "🔍", "Domain Name System (RFC 1035)"),
    }

    # Broadcast/multicast services (jitter irrelevant - no reliability requirement)
    BROADCAST_SERVICES = {
        5353: ("mDNS", "🔍", "Multicast DNS / Bonjour (RFC 6762)"),
        1900: ("SSDP", "📡", "Simple Service Discovery Protocol (UPnP)"),
        137: ("NetBIOS", "📡", "NetBIOS Name Service"),
        138: ("NetBIOS-DG", "📡", "NetBIOS Datagram Service"),
    }

    def __init__(self):
        pass

    def _format_duration(self, duration: float) -> str:
        """
        Format duration intelligently based on magnitude.

        Args:
            duration: Duration in seconds

        Returns:
            Formatted duration string with appropriate unit
        """
        if duration < 1.0:
            return f"{duration * 1000:.1f}ms"
        elif duration < 60:
            return f"{duration:.2f}s"
        elif duration < 3600:
            minutes = int(duration / 60)
            seconds = duration % 60
            return f"{minutes}m {seconds:.1f}s"
        else:
            hours = int(duration / 3600)
            minutes = int((duration % 3600) / 60)
            return f"{hours}h {minutes}m"

    def _identify_service(self, port: int) -> tuple[str, str, str, bool, str]:
        """
        Identify service and whether high jitter is expected.

        Args:
            port: Port number to identify

        Returns:
            Tuple of (service_name, emoji, description, expect_high_jitter, service_type)
            service_type: "async", "interactive", "request-response", "broadcast", or "unknown"
        """
        if port in self.KNOWN_ASYNC_SERVICES:
            name, emoji, description = self.KNOWN_ASYNC_SERVICES[port]
            return (name, emoji, description, True, "async")  # High jitter expected
        elif port in self.INTERACTIVE_SERVICES:
            name, emoji, description = self.INTERACTIVE_SERVICES[port]
            return (name, emoji, description, False, "interactive")  # Jitter causes perceived latency
        elif port in self.BROADCAST_SERVICES:
            name, emoji, description = self.BROADCAST_SERVICES[port]
            return (name, emoji, description, True, "broadcast")  # Jitter irrelevant for broadcast
        elif port in self.REQUEST_RESPONSE_SERVICES:
            name, emoji, description = self.REQUEST_RESPONSE_SERVICES[port]
            return (name, emoji, description, False, "request-response")  # Tolerant to jitter
        return ("Unknown", "❓", "Unknown service", False, "unknown")

    def _generate_jitter_interpretation(
        self,
        mean_jitter_ms: float,
        max_jitter_ms: float,
        packet_count: int,
        severity: str,
        service_name: str,
        expect_high_jitter: bool,
        service_type: str = "unknown",
    ) -> str:
        """Generate concise jitter interpretation (v4.5.0 style)."""

        # Concise impact based on service type
        if service_type == "broadcast" or expect_high_jitter:
            impact_text = "Normal behavior (no impact)"
        elif max_jitter_ms > 10000:
            impact_text = "Severe delays (unusable for real-time)"
        elif max_jitter_ms > 1000:
            impact_text = "Noticeable delays (degraded UX)"
        elif max_jitter_ms > 100:
            impact_text = "Minor delays (acceptable for most apps)"
        else:
            impact_text = "Minimal impact"

        # Build concise HTML (3 lines)
        html = f"""
                            <div class="jitter-interpretation">
                                <p style="margin: 4px 0;">Jitter: {max_jitter_ms:.1f}ms max, {mean_jitter_ms:.1f}ms avg ({packet_count} packets)</p>
                                <p style="margin: 4px 0;">Service: {service_name} ({service_type})</p>
                                <p style="margin: 4px 0;">Impact: {impact_text}</p>
                            </div>
        """

        return html

    def _generate_wireshark_commands(
        self,
        src_ip: str,
        src_port: str,
        dst_ip: str,
        dst_port: str,
        flow_type: str = "general",
        seq_num: int = None,
    ) -> dict[str, str]:
        """
        Generate Wireshark display filter and tshark extraction command.

        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            flow_type: Type of flow - 'general', 'retransmission', 'window_zero', 'syn'
            seq_num: TCP sequence number (for retransmission type)

        Returns:
            Dictionary with 'display_filter' and 'tshark_extract' keys
        """
        # Detect IPv6 vs IPv4
        is_ipv6 = ":" in src_ip and src_ip.count(":") > 1

        # Build base filter
        if is_ipv6:
            base_filter = (
                f"ipv6.src == {src_ip} && ipv6.dst == {dst_ip} && "
                f"tcp.srcport == {src_port} && tcp.dstport == {dst_port}"
            )
        else:
            base_filter = (
                f"ip.src == {src_ip} && ip.dst == {dst_ip} && "
                f"tcp.srcport == {src_port} && tcp.dstport == {dst_port}"
            )

        # Add flow-type-specific filters
        if flow_type == "retransmission":
            if seq_num is not None:
                display_filter = f"tcp.seq == {seq_num} && {base_filter}"
                type_filter = f" and tcp.seq == {seq_num}"
            else:
                display_filter = f"tcp.analysis.retransmission && {base_filter}"
                type_filter = " and tcp.analysis.retransmission"
        elif flow_type == "window_zero":
            display_filter = f"tcp.window_size == 0 && {base_filter}"
            type_filter = " and tcp.window_size == 0"
        elif flow_type == "syn":
            display_filter = f"tcp.flags.syn == 1 && {base_filter}"
            type_filter = " and tcp.flags.syn == 1"
        else:
            # General flow
            display_filter = base_filter
            type_filter = ""

        # Build tshark extraction command
        # Combine IP and port filters into a single -Y clause
        if is_ipv6:
            combined_filter = f"ipv6.src == {src_ip} and ipv6.dst == {dst_ip} and tcp.srcport == {src_port} and tcp.dstport == {dst_port}{type_filter}"
        else:
            combined_filter = f"ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.srcport == {src_port} and tcp.dstport == {dst_port}{type_filter}"

        tshark_cmd = (
            f"tshark -r input.pcap -Y '{combined_filter}' "
            f"-T fields -e frame.number -e frame.time_relative -e tcp.seq -e tcp.ack -e tcp.len"
        )

        return {
            "display_filter": display_filter,
            "tshark_extract": tshark_cmd,
        }

    def _generate_retransmission_interpretation(
        self,
        total_retrans: int,
        rto_count: int,
        fast_retrans: int,
        generic_retrans: int,
        syn_retrans_count: int,
        duration: float,
        retrans_per_second: float,
        flow_confidence: str,
    ) -> str:
        """
        Generate natural language interpretation of retransmission metrics.

        Args:
            total_retrans: Total number of retransmissions
            rto_count: Number of RTO retransmissions
            fast_retrans: Number of fast retransmissions
            generic_retrans: Number of generic retransmissions (50-200ms delay)
            syn_retrans_count: Number of SYN retransmissions (handshake failures)
            duration: Flow duration in seconds
            retrans_per_second: Rate of retransmissions per second
            flow_confidence: Confidence level (confidence-high/medium/low)

        Returns:
            HTML string with interpretation
        """

        # Determine dominant mechanism (including generic and SYN retransmissions)
        # Priority: SYN retransmissions (handshake failures) are handled separately
        dominant_mechanism = "mixed"
        dominant_count = 0

        # Special case: If ALL retransmissions are SYN retransmissions (connection failures)
        if syn_retrans_count > 0 and syn_retrans_count == total_retrans:
            dominant_mechanism = "SYN Retransmission"
            dominant_count = syn_retrans_count
        elif rto_count > fast_retrans and rto_count > generic_retrans and rto_count > 0:
            dominant_mechanism = "RTO"
            dominant_count = rto_count
        elif fast_retrans > rto_count and fast_retrans > generic_retrans and fast_retrans > 0:
            dominant_mechanism = "Fast Retransmission"
            dominant_count = fast_retrans
        elif generic_retrans > rto_count and generic_retrans > fast_retrans and generic_retrans > 0:
            dominant_mechanism = "Generic"
            dominant_count = generic_retrans
        elif rto_count == fast_retrans and rto_count > 0:
            dominant_mechanism = "mixed"
            dominant_count = total_retrans

        # What happened
        if dominant_mechanism == "SYN Retransmission":
            # SYN retransmissions indicate connection establishment failures
            what_happened = (
                f"<strong>⚠️ Connection Failed:</strong> This flow never completed the TCP handshake. "
                f"The initial SYN packet was retransmitted <strong>{syn_retrans_count} time{'s' if syn_retrans_count != 1 else ''}</strong> "
                f"with no response from the server. This indicates the destination server is <strong>unreachable</strong>, "
                f"<strong>not listening on this port</strong>, or <strong>network connectivity issues</strong> prevented the connection."
            )
        elif dominant_mechanism == "RTO":
            percentage = (rto_count / total_retrans * 100) if total_retrans > 0 else 0
            what_happened = (
                f"This flow experienced <strong>{total_retrans} retransmission{'s' if total_retrans != 1 else ''}</strong> "
                f"over {self._format_duration(duration)}. <strong>{rto_count} ({percentage:.0f}%)</strong> were "
                f"<strong>RTO (Retransmission Timeout)</strong> events, where TCP waited for acknowledgment but received none."
            )
        elif dominant_mechanism == "Fast Retransmission":
            percentage = (fast_retrans / total_retrans * 100) if total_retrans > 0 else 0
            what_happened = (
                f"This flow experienced <strong>{total_retrans} retransmission{'s' if total_retrans != 1 else ''}</strong> "
                f"over {self._format_duration(duration)}. <strong>{fast_retrans} ({percentage:.0f}%)</strong> were "
                f"<strong>Fast Retransmissions</strong>, triggered by duplicate ACKs indicating out-of-order delivery."
            )
        elif dominant_mechanism == "Generic":
            percentage = (generic_retrans / total_retrans * 100) if total_retrans > 0 else 0
            what_happened = (
                f"This flow experienced <strong>{total_retrans} retransmission{'s' if total_retrans != 1 else ''}</strong> "
                f"over {self._format_duration(duration)}. <strong>{generic_retrans} ({percentage:.0f}%)</strong> were "
                f"<strong>Generic Retransmissions</strong> (delay between 50-200ms), likely due to moderate network congestion or packet loss."
            )
        else:
            # Build mixed mechanism message including SYN retransmissions if present
            mechanisms_list = []
            if syn_retrans_count > 0:
                mechanisms_list.append(f"{syn_retrans_count} SYN retransmission{'s' if syn_retrans_count != 1 else ''}")
            if rto_count > 0:
                mechanisms_list.append(f"{rto_count} RTO event{'s' if rto_count != 1 else ''}")
            if fast_retrans > 0:
                mechanisms_list.append(f"{fast_retrans} Fast Retransmission{'s' if fast_retrans != 1 else ''}")
            if generic_retrans > 0:
                mechanisms_list.append(f"{generic_retrans} Generic Retransmission{'s' if generic_retrans != 1 else ''}")

            mechanisms_str = ", ".join(mechanisms_list)
            what_happened = (
                f"This flow experienced <strong>{total_retrans} retransmission{'s' if total_retrans != 1 else ''}</strong> "
                f"over {self._format_duration(duration)}, with a <strong>mix of mechanisms</strong>: {mechanisms_str}."
            )

        # Format retransmission display based on duration
        # For very short flows (< 1 sec), don't show per-second rate as it's misleading
        # Instead, show absolute count with actual duration
        if duration < 1.0:
            retrans_display = f"<strong>{total_retrans} retransmissions</strong> in {self._format_duration(duration)}"
        else:
            retrans_display = f"<strong>{total_retrans} retransmissions</strong> (<strong>{retrans_per_second:.1f} per second</strong>)"

        # Why flagged - using absolute counts and rate per second
        # Special case: SYN retransmissions (connection failures) are always HIGH severity
        if dominant_mechanism == "SYN Retransmission":
            severity_level = "HIGH"
            why_flagged = (
                f"<strong>Why flagged {severity_level}:</strong> The TCP connection <strong>never established</strong>. "
                f"SYN retransmissions indicate the server is unreachable or not accepting connections on this port. "
                f"This is a <strong>critical connectivity failure</strong>."
            )
        elif total_retrans > 50 or retrans_per_second > 5:
            severity_level = "HIGH"
            if duration > 0:
                why_flagged = (
                    f"<strong>Why flagged {severity_level}:</strong> This flow experienced {retrans_display}, "
                    "indicating <strong>significant packet loss or network congestion</strong>. "
                    "This high frequency suggests persistent network issues."
                )
            else:
                why_flagged = (
                    f"<strong>Why flagged {severity_level}:</strong> <strong>{total_retrans} retransmissions</strong> "
                    "indicates <strong>significant packet loss or network congestion</strong>."
                )
        elif total_retrans > 20 or retrans_per_second > 2:
            severity_level = "MODERATE"
            if duration > 0:
                why_flagged = (
                    f"<strong>Why flagged {severity_level}:</strong> This flow experienced {retrans_display}, "
                    "suggesting <strong>intermittent packet loss</strong> or network congestion issues."
                )
            else:
                why_flagged = (
                    f"<strong>Why flagged {severity_level}:</strong> <strong>{total_retrans} retransmissions</strong> "
                    "suggests <strong>intermittent packet loss</strong> or network congestion issues."
                )
        else:
            severity_level = "LOW"
            if duration > 0:
                why_flagged = (
                    f"<strong>Why flagged {severity_level}:</strong> This flow experienced {retrans_display}, "
                    "which is relatively low and within acceptable range for most networks."
                )
            else:
                why_flagged = (
                    f"<strong>Why flagged {severity_level}:</strong> <strong>{total_retrans} retransmissions</strong> "
                    "is relatively low and within acceptable range for most networks."
                )

        # Impact and probable cause based on mechanism
        if dominant_mechanism == "SYN Retransmission":
            impact = (
                "<strong>Impact & Probable Cause:</strong> "
                "<span style='color: #dc3545;'>⚠ CRITICAL - Connection Failed</span>. "
                "SYN retransmissions occur during TCP handshake when the server doesn't respond to connection attempts. "
                "<strong>This is ALWAYS timeout-based (RTO), NEVER fast retransmit</strong> "
                "(no ACKs possible during handshake). "
                "<strong>Typical causes:</strong>"
                "<br>• <strong>Server unreachable</strong> (host down, wrong IP, routing issues)"
                "<br>• <strong>Port not listening</strong> (service not running, firewall blocking)"
                "<br>• <strong>Network connectivity</strong> (firewall dropping SYN, routing black hole)"
                "<br>• <strong>RFC 6298 Compliance:</strong> Initial RTO should be ≥ 1 second"
            )
        elif dominant_mechanism == "RTO":
            impact = (
                "<strong>Impact & Probable Cause:</strong> "
                "RTO events cause <span style='color: #dc3545;'>⚠ significant delays</span> "
                "(typically 200ms-3s per event) as TCP conservatively backs off. "
                "This usually indicates <strong>packet loss due to:</strong> "
                "<br>• Network congestion (router/switch buffer overflow)"
                "<br>• Unreliable network path (WiFi interference, lossy links)"
                "<br>• ACK loss (acknowledgments not reaching sender)"
            )
        elif dominant_mechanism == "Fast Retransmission":
            impact = (
                "<strong>Impact & Probable Cause:</strong> "
                "Fast Retransmissions cause <span style='color: #ffc107;'>⚠ moderate performance impact</span> "
                "as TCP quickly recovers using duplicate ACKs. "
                "This typically indicates <strong>out-of-order packet delivery</strong> due to:"
                "<br>• Network path changes (load balancing, routing changes)"
                "<br>• Packet reordering (multipath routing, priority queuing)"
                "<br>• Selective packet loss (not entire window dropped)"
            )
        else:
            impact = (
                "<strong>Impact & Probable Cause:</strong> "
                "Mixed mechanisms suggest <span style='color: #ffc107;'>⚠ variable network conditions</span>. "
                "This could indicate:"
                "<br>• Intermittent congestion (sometimes severe, sometimes mild)"
                "<br>• Path instability (routing changes during connection)"
                "<br>• Multiple network issues affecting the connection"
            )

        # Pattern clarity note
        if "high" in flow_confidence:
            pattern_note = "<br><br><em>✓ Pattern Clarity: <strong>High</strong> - Clear, consistent retransmission pattern makes root cause analysis more straightforward.</em>"
        elif "medium" in flow_confidence:
            pattern_note = "<br><br><em>~ Pattern Clarity: <strong>Medium</strong> - Mostly consistent pattern, but limited sample size or some variation makes definitive analysis challenging.</em>"
        else:
            pattern_note = "<br><br><em>⚠ Pattern Clarity: <strong>Low</strong> - Mixed mechanisms suggest multiple concurrent issues. Detailed packet-level analysis recommended.</em>"

        # Build HTML
        html = f"""
                            <div class="retrans-interpretation">
                                <div class="interpretation-header">
                                    <strong>📊 What does this mean?</strong>
                                </div>
                                <div class="interpretation-body">
                                    <p style="margin: 8px 0;">{what_happened}</p>
                                    <p style="margin: 8px 0;">{why_flagged}</p>
                                    <p style="margin: 8px 0;">{impact}{pattern_note}</p>
                                </div>
                            </div>
        """

        return html

    def _generate_rtt_interpretation(
        self,
        mean_rtt: float,
        max_rtt: float,
        flows_with_high_rtt: int,
    ) -> str:
        """Generate concise RTT interpretation (v4.5.0 style)."""

        # Concise impact
        if max_rtt > 300:
            impact_text = "High impact (real-time apps unusable)"
        elif max_rtt > 150:
            impact_text = "Moderate impact (degraded UX)"
        elif max_rtt > 100:
            impact_text = "Minor impact (acceptable)"
        else:
            impact_text = "Minimal impact"

        # Build concise HTML (3 lines)
        html = f"""
                            <div class="jitter-interpretation">
                                <p style="margin: 4px 0;">RTT: {max_rtt:.1f}ms max, {mean_rtt:.1f}ms avg</p>
                                <p style="margin: 4px 0;">Flows affected: {flows_with_high_rtt}</p>
                                <p style="margin: 4px 0;">Impact: {impact_text}</p>
                            </div>
        """

        return html

    def generate(self, results: dict[str, Any]) -> str:
        """
        Generate HTML report from analysis results with tabbed navigation.

        Args:
            results: Dictionary containing analysis results

        Returns:
            HTML string
        """
        html_parts = []

        # HTML header
        html_parts.append(self._generate_header(results))

        # Body start
        html_parts.append("<body>")
        html_parts.append('<div class="container">')

        # Title
        html_parts.append(self._generate_title(results))

        # Tabbed Navigation (Pure CSS - no JavaScript required)
        html_parts.append('<div class="tabs-container">')

        # Radio buttons (hidden, manage state)
        html_parts.append('  <input type="radio" name="report-tabs" id="tab-overview" class="tab-radio" checked>')
        html_parts.append('  <input type="radio" name="report-tabs" id="tab-qos" class="tab-radio">')
        html_parts.append('  <input type="radio" name="report-tabs" id="tab-tcp" class="tab-radio">')
        html_parts.append('  <input type="radio" name="report-tabs" id="tab-dns" class="tab-radio">')
        html_parts.append('  <input type="radio" name="report-tabs" id="tab-security" class="tab-radio">')
        html_parts.append('  <input type="radio" name="report-tabs" id="tab-network" class="tab-radio">')

        # Tab labels (clickable headers)
        html_parts.append('  <div class="tabs-nav">')
        html_parts.append('    <label for="tab-overview" class="tab-label">📊 Overview</label>')
        html_parts.append('    <label for="tab-qos" class="tab-label">🏥 QoS Analysis</label>')
        html_parts.append('    <label for="tab-tcp" class="tab-label">🔌 TCP Analysis</label>')
        html_parts.append('    <label for="tab-dns" class="tab-label">🌐 DNS Analysis</label>')
        html_parts.append('    <label for="tab-security" class="tab-label">🔒 Security</label>')
        html_parts.append('    <label for="tab-network" class="tab-label">📡 Network</label>')
        html_parts.append("  </div>")

        # Tab contents wrapper
        html_parts.append('  <div class="tab-contents">')

        # Tab 1: Overview (Executive Summary + Health Score)
        html_parts.append('    <div class="tab-content" data-tab="tab-overview">')
        html_parts.append(self._generate_summary(results))
        if "health_score" in results:
            html_parts.append(self._generate_health_score_section(results))
        html_parts.append("  </div>")

        # Tab 2: QoS Analysis (Jitter, RTT, etc.)
        html_parts.append('    <div class="tab-content" data-tab="tab-qos">')
        if "jitter" in results:
            html_parts.append(self._generate_jitter_section(results))
        else:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No QoS metrics available in this capture.</p>")
            html_parts.append("    </div>")
        html_parts.append("  </div>")

        # Tab 3: TCP Analysis (Retransmissions, RTT, Window, Handshakes)
        html_parts.append('    <div class="tab-content" data-tab="tab-tcp">')
        has_tcp = (
            "retransmission" in results or "rtt" in results or "tcp_window" in results or "tcp_handshake" in results
        )
        if has_tcp:
            html_parts.append(self._generate_tcp_section(results))
        else:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No TCP analysis data available in this capture.</p>")
            html_parts.append("    </div>")
        html_parts.append("  </div>")

        # Tab 4: DNS Analysis (Queries, Timeouts, Problematic Domains)
        html_parts.append('    <div class="tab-content" data-tab="tab-dns">')
        if "dns" in results:
            html_parts.append(self._generate_dns_section(results))
        else:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No DNS analysis data available in this capture.</p>")
            html_parts.append("    </div>")
        html_parts.append("  </div>")

        # Tab 5: Security (Port Scans, Brute Force, DDoS, DNS Tunneling)
        html_parts.append('    <div class="tab-content" data-tab="tab-security">')
        has_security = (
            "port_scan_detection" in results
            or "brute_force_detection" in results
            or "ddos_detection" in results
            or "dns_tunneling_detection" in results
        )
        if has_security:
            html_parts.append(self._generate_security_section(results))
        else:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>✅ No security threats detected in this capture.</p>")
            html_parts.append("    </div>")
        html_parts.append("  </div>")

        # Tab 6: Network (Protocol Distribution + Service Classification)
        html_parts.append('    <div class="tab-content" data-tab="tab-network">')
        if "protocol_distribution" in results:
            html_parts.append(self._generate_protocol_section(results))
        if "service_classification" in results:
            html_parts.append(self._generate_service_section(results))
        if "protocol_distribution" not in results and "service_classification" not in results:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No network analysis data available.</p>")
            html_parts.append("    </div>")
        html_parts.append("    </div>")

        # Close tab-contents wrapper
        html_parts.append("  </div>")

        # Close tabs container
        html_parts.append("</div>")

        # Footer
        html_parts.append("</div>")
        html_parts.append("</body>")
        html_parts.append("</html>")

        return "\n".join(html_parts)

    def save(self, results: dict[str, Any], output_path: str):
        """
        Generate and save HTML report to file.

        Args:
            results: Dictionary containing analysis results
            output_path: Path to save HTML file
        """
        html = self.generate(results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _generate_header(self, results: dict[str, Any]) -> str:
        """Generate HTML header with embedded CSS."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Analysis Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2.5em;
        }

        h2 {
            color: #34495e;
            margin-top: 40px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3498db;
            font-size: 1.8em;
        }

        h3 {
            color: #555;
            margin-top: 20px;
            margin-bottom: 10px;
            font-size: 1.3em;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .metric-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }

        .metric-label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
            margin-top: 5px;
        }

        .health-score {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 8px;
            margin: 20px 0;
        }

        .health-score-value {
            font-size: 4em;
            font-weight: bold;
            margin: 10px 0;
        }

        .health-score-label {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .health-score-description {
            font-size: 0.95em;
            opacity: 0.85;
            margin-top: 8px;
            font-weight: 400;
        }

        .severity-excellent { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .severity-good { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .severity-warning { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        .severity-fair { background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }
        .severity-poor { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .severity-critical { background: linear-gradient(135deg, #4e54c8 0%, #8f94fb 100%); }

        .component-scores {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }

        .component-score-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
        }

        .component-name {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 8px;
        }

        .progress-bar {
            width: 100%;
            height: 24px;
            background: #e0e0e0;
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #3498db 0%, #2ecc71 100%);
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
        }

        .chart-container {
            margin: 20px 0;
        }

        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .bar-chart-row {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .bar-label {
            min-width: 100px;
            font-weight: 500;
            color: #555;
        }

        .bar-container {
            flex: 1;
            height: 30px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: visible;
            position: relative;
            display: flex;
            align-items: center;
        }

        .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, #3498db 0%, #2980b9 100%);
            border-radius: 4px;
            min-width: 2px;
        }

        .bar-value {
            margin-left: 8px;
            color: #2c3e50;
            font-size: 0.9em;
            font-weight: 500;
            white-space: nowrap;
        }

        .data-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            margin: 20px 0;
            border-radius: 8px;
            overflow: visible;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .data-table th {
            background: #f8f9fa;
            color: #2c3e50;
            padding: 16px 20px;
            text-align: left;
            font-weight: 600;
            font-size: 0.95em;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #3498db;
        }

        .data-table td {
            padding: 14px 20px;
            border-bottom: 1px solid #e8e8e8;
            vertical-align: middle;
            font-size: 0.92em;
        }

        .data-table td code {
            background: #f5f7fa;
            padding: 4px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.9em;
            color: #2d3748;
        }

        .data-table tbody tr {
            transition: all 0.2s ease;
        }

        .data-table tbody tr:hover {
            background: #f8fafc;
            transform: scale(1.01);
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .data-table tbody tr:last-child td {
            border-bottom: none;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .badge-success { background: #d4edda; color: #155724; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-low { background: #17a2b8; color: white; }

        .service-badge {
            display: inline-block;
            padding: 4px 10px;
            background: #e3f2fd;
            color: #1565c0;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
            margin-right: 6px;
        }

        .no-issues {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
            color: #155724;
            font-size: 1.1em;
        }

        .security-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .security-card {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .security-card h4 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.1em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 8px;
        }

        @media (max-width: 768px) {
            .container {
                padding: 20px;
            }

            h1 {
                font-size: 2em;
            }

            .summary-grid {
                grid-template-columns: 1fr;
            }

            .health-score-value {
                font-size: 3em;
            }
        }

        /* Tabbed Navigation Styles */
        .tabs-container {
            margin: 30px 0;
        }

        /* Pure CSS Tabs - No JavaScript Required */

        /* Hide radio buttons */
        .tab-radio {
            position: absolute;
            opacity: 0;
            pointer-events: none;
        }

        .tabs-nav {
            display: flex;
            border-bottom: 2px solid #e0e0e0;
            margin-bottom: 0;
            gap: 5px;
            flex-wrap: wrap;
        }

        .tab-label {
            padding: 12px 24px;
            background: #f5f5f5;
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-size: 1em;
            font-weight: 500;
            color: #666;
            transition: all 0.3s ease;
            border-radius: 6px 6px 0 0;
            user-select: none;
        }

        .tab-label:hover {
            background: #e8e8e8;
            color: #333;
        }

        /* Active tab styling (when radio is checked) */
        #tab-overview:checked ~ .tabs-nav label[for="tab-overview"],
        #tab-qos:checked ~ .tabs-nav label[for="tab-qos"],
        #tab-tcp:checked ~ .tabs-nav label[for="tab-tcp"],
        #tab-dns:checked ~ .tabs-nav label[for="tab-dns"],
        #tab-security:checked ~ .tabs-nav label[for="tab-security"],
        #tab-network:checked ~ .tabs-nav label[for="tab-network"] {
            background: white;
            color: #3498db;
            border-bottom-color: #3498db;
        }

        /* Hide all tab contents by default */
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        /* Show content when corresponding radio is checked */
        #tab-overview:checked ~ .tab-contents .tab-content[data-tab="tab-overview"],
        #tab-qos:checked ~ .tab-contents .tab-content[data-tab="tab-qos"],
        #tab-tcp:checked ~ .tab-contents .tab-content[data-tab="tab-tcp"],
        #tab-dns:checked ~ .tab-contents .tab-content[data-tab="tab-dns"],
        #tab-security:checked ~ .tab-contents .tab-content[data-tab="tab-security"],
        #tab-network:checked ~ .tab-contents .tab-content[data-tab="tab-network"] {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ================================================
           RETRANSMISSION DISPLAY ENHANCEMENTS
           ================================================ */

        /* Confidence Badges */
        .confidence-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 16px;
            font-size: 0.9em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            vertical-align: middle;
            border: 1px solid transparent;
        }

        .confidence-badge.confidence-high {
            background: #d5f4e6;
            color: #155724;
            border-color: #27ae60;
        }

        .confidence-badge.confidence-medium {
            background: #fef5e7;
            color: #856404;
            border-color: #f39c12;
        }

        .confidence-badge.confidence-low {
            background: #ecf0f1;
            color: #555;
            border-color: #95a5a6;
        }

        .badge-icon {
            font-size: 1.1em;
            line-height: 1;
        }

        /* Confidence Overview Box */
        .confidence-overview-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 20px;
            margin: 20px 0;
            border-radius: 6px;
            color: #1a1a1a;
        }

        .confidence-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .confidence-header h4 {
            margin: 0;
            color: #2c3e50;
            font-size: 1.1em;
        }

        .confidence-details {
            margin-top: 10px;
        }

        .confidence-reason {
            margin: 0 0 10px 0;
            font-size: 0.95em;
            color: #333;
        }

        .confidence-factors {
            list-style: none;
            margin-left: 0;
            padding-left: 0;
        }

        .confidence-factors li {
            margin: 8px 0;
            padding-left: 25px;
            position: relative;
            color: #333;
            font-size: 0.9em;
        }

        .factor-icon {
            position: absolute;
            left: 0;
            color: #27ae60;
            font-weight: bold;
        }

        /* Mechanisms Reference Box */
        /* Collapsible Section Enhancements (Pure CSS - No JavaScript) */
        .collapsible-section {
            margin: 30px 0;
            border-radius: 8px;
            overflow: visible;
        }

        /* Hide checkbox (used only for state management) */
        .collapsible-checkbox {
            display: none;
        }

        .collapsible-header {
            cursor: pointer;
            user-select: none;
            padding: 18px;
            background: #3498db;
            color: white;
            border-radius: 8px 8px 0 0;
            transition: background 0.2s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .collapsible-header:hover {
            background: #2980b9;
        }

        .collapsible-header:focus {
            outline: 2px solid white;
            outline-offset: -4px;
        }

        .toggle-icon {
            display: inline-block;
            width: 20px;
            font-weight: bold;
            transition: transform 0.3s ease;
        }

        /* When checkbox is checked: rotate arrow */
        .collapsible-checkbox:checked + .collapsible-header .toggle-icon {
            transform: rotate(90deg);
        }

        .header-title {
            font-weight: 600;
            font-size: 1.05em;
            flex: 1;
        }

        .header-info {
            font-size: 0.85em;
            opacity: 0.9;
        }

        /* Default: content hidden */
        .collapsible-content {
            display: none;
            background: white;
            border-radius: 0 0 8px 8px;
            border: 1px solid #e0e0e0;
            border-top: none;
        }

        /* When checkbox is checked: show content */
        .collapsible-checkbox:checked ~ .collapsible-content {
            display: block;
        }

        .content-inner {
            padding: 20px;
        }

        /* Flow Detail Cards */
        .flow-detail-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            margin-bottom: 20px;
            overflow: visible;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .flow-detail-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .flow-header {
            background: #f8f9fa;
            padding: 16px;
            border-bottom: 2px solid #e0e0e0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }

        .flow-title {
            flex: 1;
            min-width: 300px;
        }

        .flow-label {
            display: block;
            font-size: 0.85em;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }

        .flow-key {
            font-family: 'Courier New', monospace;
            background: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.9em;
            color: #2c3e50;
        }

        .flow-badges {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .flow-body {
            padding: 20px;
        }

        .flow-stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }

        .flow-stat {
            background: #f8f9fa;
            padding: 12px;
            border-radius: 4px;
            border-left: 3px solid #3498db;
        }

        .stat-label {
            display: block;
            font-size: 0.8em;
            color: #999;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }

        .stat-value {
            display: block;
            font-size: 1.4em;
            font-weight: 700;
            color: #2c3e50;
        }

        /* Jitter Interpretation Section */
        .jitter-interpretation {
            background: linear-gradient(135deg, #f8f9fa 0%, #e8f4f8 100%);
            border-left: 4px solid #3498db;
            border-radius: 6px;
            padding: 16px;
            margin: 16px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .interpretation-header {
            color: #2c3e50;
            font-size: 0.95em;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 2px solid #3498db;
        }

        .interpretation-body {
            color: #555;
            font-size: 0.9em;
            line-height: 1.6;
        }

        .interpretation-body p {
            margin: 8px 0;
        }

        .interpretation-body strong {
            color: #2c3e50;
        }

        /* Retransmission Interpretation Section */
        .retrans-interpretation {
            background: linear-gradient(135deg, #fff5f5 0%, #ffe8e8 100%);
            border-left: 4px solid #e74c3c;
            border-radius: 6px;
            padding: 16px;
            margin: 16px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .retrans-interpretation .interpretation-header {
            border-bottom: 2px solid #e74c3c;
        }

        .flow-expand-btn {
            background: white;
            border: 2px solid #3498db;
            color: #3498db;
            padding: 12px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 8px;
            width: 100%;
            justify-content: center;
        }

        .flow-expand-btn:hover {
            background: #3498db;
            color: white;
        }

        .flow-expand-btn:focus {
            outline: 2px solid #3498db;
            outline-offset: 2px;
        }

        .flow-expand-btn.expanded {
            background: #3498db;
            color: white;
        }

        .expand-icon {
            display: inline-block;
            font-size: 1.2em;
            transition: transform 0.2s ease;
        }

        .flow-expand-btn.expanded .expand-icon {
            transform: rotate(45deg);
        }

        /* Pure CSS Flow Expand (No JavaScript Required) */
        .flow-expand-checkbox {
            display: none;
        }

        /* Flow Details (Expanded Content) */
        .flow-details-collapsible {
            margin-top: 20px;
        }

        /* Default: flow details hidden */
        .flow-details {
            display: none;
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
        }

        /* When checkbox is checked: show details, update button style, and rotate icon */
        .flow-expand-checkbox:checked ~ .flow-details {
            display: block;
        }

        .flow-expand-checkbox:checked + .flow-expand-btn {
            background: #3498db;
            color: white;
        }

        .flow-expand-checkbox:checked + .flow-expand-btn .expand-icon {
            transform: rotate(45deg);
        }

        .mechanism-breakdown,
        .timeline-section {
            margin-bottom: 25px;
        }

        .mechanism-breakdown h5,
        .timeline-section h5 {
            margin: 0 0 15px 0;
            color: #2c3e50;
            font-size: 1em;
            font-weight: 600;
            border-bottom: 2px solid #e0e0e0;
            padding-bottom: 8px;
        }

        .mechanism-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }

        .mechanism-table th,
        .mechanism-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
            font-size: 0.9em;
        }

        .mechanism-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }

        .mech-icon {
            margin-right: 8px;
        }

        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 40px;
        }

        .timeline-event {
            margin-bottom: 20px;
            position: relative;
        }

        .timeline-marker {
            position: absolute;
            left: -28px;
            top: 5px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            border: 2px solid #e0e0e0;
            background: white;
        }

        .timeline-rto .timeline-marker {
            background: #e74c3c;
            border-color: #e74c3c;
        }

        .timeline-fast .timeline-marker {
            background: #f39c12;
            border-color: #f39c12;
        }

        .timeline-success .timeline-marker {
            background: #27ae60;
            border-color: #27ae60;
        }

        .timeline-content {
            padding: 12px;
            background: #f8f9fa;
            border-radius: 4px;
        }

        .timeline-time {
            display: block;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #999;
            margin-bottom: 4px;
        }

        .timeline-type {
            display: block;
            font-weight: 600;
            color: #2c3e50;
            font-size: 0.95em;
        }

        .timeline-detail {
            display: block;
            font-size: 0.85em;
            color: #666;
            margin-top: 4px;
        }

        /* Wireshark Debug Section */
        .wireshark-section {
            margin-top: 16px;
            padding: 12px;
            background: #f8f9fa;
            border-left: 3px solid #17a2b8;
            border-radius: 4px;
        }

        .copy-code {
            display: inline-block;
            background: white;
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 8px 0;
            word-break: break-all;
        }

        .copy-btn {
            background: #17a2b8;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin-left: 8px;
            font-size: 0.9em;
            transition: background 0.3s ease;
        }

        .copy-btn:hover {
            background: #138496;
        }

        /* Tooltip Styles */
        .tooltip-wrapper {
            position: relative;
            display: inline-block;
        }

        .tooltip-icon {
            display: inline-block;
            margin-left: 5px;
            color: #6c757d;
            font-size: 0.85em;
            cursor: help;
        }

        .tooltip-text {
            visibility: hidden;
            position: absolute;
            z-index: 1000;
            background-color: #333;
            color: #fff;
            text-align: left;
            padding: 10px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            line-height: 1.4;
            width: 280px;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            opacity: 0;
            transition: opacity 0.3s;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }

        .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -5px;
            border-width: 5px;
            border-style: solid;
            border-color: #333 transparent transparent transparent;
        }

        .tooltip-wrapper:hover .tooltip-text {
            visibility: visible;
            opacity: 1;
        }

        /* Service Context Info */
        .service-context {
            margin-top: 12px;
            padding: 10px 12px;
            background: #e8f4f8;
            border-left: 3px solid #3498db;
            border-radius: 4px;
            font-size: 0.9em;
            color: #555;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .service-context .context-text {
            font-style: italic;
        }

        /* Severity Badges */
        .severity-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .severity-warning {
            background: #fef5e7;
            color: #856404;
            border: 1px solid #f39c12;
        }

        .severity-info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #17a2b8;
        }

        .severity-danger {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #e74c3c;
        }

        /* Utility Classes for Enhanced Metric Cards */
        .metric-danger {
            border-left: 4px solid #e74c3c;
        }

        .metric-warning {
            border-left: 4px solid #f39c12;
        }

        .metric-info {
            border-left: 4px solid #3498db;
        }

        .metric-icon {
            font-size: 1.8em;
            margin-bottom: 8px;
        }

        .metric-subtext {
            font-size: 0.85em;
            color: #666;
            margin: 6px 0;
        }

        /* Responsive Adjustments */
        @media (max-width: 768px) {
            .flow-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .flow-badges {
                width: 100%;
            }

            .flow-stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .collapsible-header {
                flex-wrap: wrap;
                gap: 8px;
            }

            .header-info {
                width: 100%;
                text-align: right;
            }

            .flow-title {
                min-width: 100%;
            }
        }

        @media (max-width: 480px) {
            .flow-stats-grid {
                grid-template-columns: 1fr;
            }
        }

        /* Reduced Motion Support (Accessibility) */
        @media (prefers-reduced-motion: reduce) {
            .collapsible-content,
            .flow-expand-btn,
            .flow-expand-btn .expand-icon {
                transition: none;
            }
        }

        /* Print Styles */
        @media print {
            .collapsible-header .toggle-icon {
                display: none;
            }

            .flow-expand-btn {
                display: none;
            }

            .flow-details {
                display: block !important;
                margin: 0;
            }

            .flow-detail-card {
                page-break-inside: avoid;
            }
        }

        /* Tooltip styles */
        .data-table th {
            position: relative;
        }

        .tooltip-container {
            position: relative;
            display: inline-block;
            margin-left: 6px;
            cursor: help;
            vertical-align: middle;
        }

        .tooltip-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 18px;
            height: 18px;
            background: #3498db;
            color: white;
            border-radius: 50%;
            font-size: 12px;
            font-weight: bold;
            line-height: 1;
            transition: all 0.2s ease;
        }

        .tooltip-icon:hover {
            background: #2980b9;
            transform: scale(1.1);
        }

        .tooltip-text {
            visibility: hidden;
            opacity: 0;
            width: 380px;
            background-color: #3a4a5c;
            color: #ffffff;
            text-align: center;
            border-radius: 6px;
            padding: 18px 24px;
            position: absolute;
            z-index: 9999;
            bottom: 160%;
            left: 50%;
            transform: translateX(-50%);
            transition: opacity 0.25s ease, visibility 0.25s ease;
            font-size: 14px;
            font-weight: 500;
            line-height: 1.5;
            letter-spacing: 0.3px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5);
            pointer-events: none;
            white-space: normal;
        }

        .tooltip-text::after {
            content: "";
            position: absolute;
            top: 100%;
            left: 50%;
            margin-left: -8px;
            border-width: 8px;
            border-style: solid;
            border-color: #3a4a5c transparent transparent transparent;
        }

        .tooltip-container:hover .tooltip-text {
            visibility: visible;
            opacity: 0.98;
        }

        .tooltip-text strong {
            color: #ffffff;
            display: block;
            margin-bottom: 8px;
            font-size: 15px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
    </style>
    <script>
        /* ==========================================
           RETRANSMISSION UI INTERACTIVITY
           ========================================== */

        // Copy to clipboard function
        function copyToClipboard(btn) {
            const code = btn.previousElementSibling;
            navigator.clipboard.writeText(code.textContent.trim()).then(() => {
                const originalText = btn.textContent;
                btn.textContent = '✓ Copied!';
                btn.style.background = '#28a745';
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '#17a2b8';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
                btn.textContent = '✗ Failed';
                setTimeout(() => btn.textContent = '📋 Copy', 2000);
            });
        }

        // Initialize event listeners for copy buttons (all expand buttons use Pure CSS now)
        function initializeEventListeners() {
            // Add click event listeners to copy buttons
            document.querySelectorAll('.copy-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    copyToClipboard(this);
                });
            });
        }

        // Initialize when DOM is ready (handle both cases: already loaded or still loading)
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeEventListeners);
        } else {
            // DOM already loaded, initialize immediately
            initializeEventListeners();
        }
    </script>
</head>"""

    def _generate_title(self, results: dict[str, Any]) -> str:
        """Generate report title."""
        metadata = results.get("metadata", {})
        pcap_file = metadata.get("pcap_file", "Unknown")

        return f"""
        <h1>📊 PCAP Analysis Report</h1>
        <p style="color: #666; font-size: 1.1em; margin-bottom: 30px;">File: <strong>{pcap_file}</strong></p>
        """

    def _generate_summary(self, results: dict[str, Any]) -> str:
        """Generate executive summary section."""
        metadata = results.get("metadata", {})
        total_packets = metadata.get("total_packets", 0)
        duration = metadata.get("capture_duration", 0)

        html = "<h2>📋 Executive Summary</h2>"
        html += '<div class="summary-grid">'

        # Total packets
        html += f"""
        <div class="metric-card">
            <div class="metric-label">Total Packets</div>
            <div class="metric-value">{total_packets:,}</div>
        </div>
        """

        # Capture duration
        if duration > 0:
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Duration</div>
                <div class="metric-value">{duration:.1f}s</div>
            </div>
            """

        # Packet rate
        if duration > 0 and total_packets > 0:
            pps = total_packets / duration
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Packet Rate</div>
                <div class="metric-value">{pps:.0f} pps</div>
            </div>
            """

        html += "</div>"
        return html

    def _generate_health_score_section(self, results: dict[str, Any]) -> str:
        """Generate health score visualization."""
        health_data = results.get("health_score", {})

        # Handle both dict and HealthScoreResult dataclass
        if hasattr(health_data, "overall_score"):
            score = health_data.overall_score
            severity = health_data.severity
            summary = getattr(health_data, "summary", "")
            component_scores = getattr(health_data, "component_scores", {})
        else:
            score = health_data.get("overall_score", 0)
            severity = health_data.get("severity", "unknown")
            summary = health_data.get("summary", "")
            component_scores = health_data.get("component_scores", {})

        # Dynamic icon and label based on severity
        severity_config = {
            "good": {
                "icon": "💚",
                "label": "Excellent Network Health",
                "description": "No significant issues detected in the network traffic",
            },
            "warning": {
                "icon": "⚠️",
                "label": "Minor Issues Detected",
                "description": "Check TCP Analysis, Jitter, and RTT sections for details",
            },
            "critical": {
                "icon": "🔴",
                "label": "Critical Issues Detected",
                "description": "Review TCP retransmissions, packet loss, and latency metrics",
            },
            "unknown": {
                "icon": "❓",
                "label": "Health Status Unknown",
                "description": "Insufficient data to calculate network health score",
            },
        }

        config = severity_config.get(severity, severity_config["unknown"])

        html = f"<h2>{config['icon']} Network Health Score</h2>"

        # Main health score
        severity_class = f"severity-{severity}"
        html += f"""
        <div class="health-score {severity_class}">
            <div class="health-score-label">Overall Health Score</div>
            <div class="health-score-value">{score:.1f}</div>
            <div class="health-score-label">{config['label']}</div>
            <div class="health-score-description">{config['description']}</div>
        """
        if summary:
            html += f'<p style="margin-top: 15px; opacity: 0.9;">{summary}</p>'
        html += "</div>"

        # Component scores
        if component_scores:
            html += "<h3>📊 Component Scores Breakdown</h3>"
            html += '<div class="component-scores">'

            for component, data in component_scores.items():
                comp_score = data.get("score", 0)
                reasons = data.get("reasons", [])

                # Determine color based on score
                if comp_score >= 80:
                    color = "#28a745"  # Green
                elif comp_score >= 60:
                    color = "#ffc107"  # Yellow
                elif comp_score >= 40:
                    color = "#fd7e14"  # Orange
                else:
                    color = "#dc3545"  # Red

                html += f"""
                <div class="component-score-card">
                    <div class="component-name">{component.replace('_', ' ').title()}</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {comp_score}%; background-color: {color};">{comp_score:.0f}%</div>
                    </div>
                """

                # Add reasons/details if available
                if reasons:
                    html += '<div style="margin-top: 8px; font-size: 0.85em; color: #666;">'
                    html += "<ul style='margin: 0; padding-left: 20px;'>"
                    for reason in reasons[:3]:  # Show top 3 reasons
                        html += f"<li>{reason}</li>"
                    html += "</ul>"
                    html += "</div>"

                html += "</div>"

            html += "</div>"

        return html

    def _generate_protocol_section(self, results: dict[str, Any]) -> str:
        """Generate protocol distribution section."""
        proto_data = results.get("protocol_distribution", {})

        html = "<h2>🌐 Protocol Distribution</h2>"

        # Layer 4 distribution
        layer4_dist = proto_data.get("layer4_distribution", {})
        if layer4_dist:
            html += "<h3>Transport Layer Protocols</h3>"
            html += '<div class="chart-container">'
            html += '<div class="bar-chart">'

            total = sum(layer4_dist.values())
            for proto, count in sorted(layer4_dist.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total * 100) if total > 0 else 0
                html += f"""
                <div class="bar-chart-row">
                    <div class="bar-label">{proto}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: {percentage}%"></div>
                        <div class="bar-value">{count:,} ({percentage:.1f}%)</div>
                    </div>
                </div>
                """

            html += "</div></div>"

        # Service distribution
        service_dist = proto_data.get("service_distribution", {})
        if service_dist:
            html += "<h3>Service Distribution</h3>"
            html += '<div class="chart-container">'
            html += '<div class="bar-chart">'

            total = sum(service_dist.values())
            sorted_services = sorted(service_dist.items(), key=lambda x: x[1], reverse=True)
            top_services = sorted_services[:10]

            # Display top 10 services
            for service, count in top_services:
                percentage = (count / total * 100) if total > 0 else 0
                html += f"""
                <div class="bar-chart-row">
                    <div class="bar-label">{service}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: {percentage}%"></div>
                        <div class="bar-value">{count:,} ({percentage:.1f}%)</div>
                    </div>
                </div>
                """

            # Add "Other" category if there are more services
            if len(sorted_services) > 10:
                other_count = sum(count for _, count in sorted_services[10:])
                other_percentage = (other_count / total * 100) if total > 0 else 0
                html += f"""
                <div class="bar-chart-row">
                    <div class="bar-label">Other ({len(sorted_services) - 10} services)</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: {other_percentage}%; background-color: #95a5a6;"></div>
                        <div class="bar-value">{other_count:,} ({other_percentage:.1f}%)</div>
                    </div>
                </div>
                """

            html += "</div></div>"

        return html

    def _generate_jitter_section(self, results: dict[str, Any]) -> str:
        """Generate jitter analysis section."""
        jitter_data = results.get("jitter", {})

        html = "<h2>📡 Jitter Analysis</h2>"

        # Global statistics
        global_stats = jitter_data.get("global_statistics", {})
        if global_stats:
            html += "<h3>Global Jitter Statistics</h3>"
            html += '<div class="summary-grid">'

            mean_jitter = global_stats.get("mean_jitter", 0)
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Mean Jitter</div>
                <div class="metric-value">{mean_jitter * 1000:.2f} ms</div>
            </div>
            """

            max_jitter = global_stats.get("max_jitter", 0)
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Max Jitter</div>
                <div class="metric-value">{max_jitter * 1000:.2f} ms</div>
            </div>
            """

            stdev_jitter = global_stats.get("stdev_jitter", 0)
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Std Dev Jitter</div>
                <div class="metric-value">{stdev_jitter * 1000:.2f} ms</div>
            </div>
            """

            html += "</div>"

            # Add contextual note only for very high jitter (> 10 seconds)
            # This indicates non-real-time capture with long gaps between packets
            mean_jitter_s = global_stats.get("mean_jitter", 0)
            if mean_jitter_s > 10.0:  # > 10 seconds
                metadata = results.get("metadata", {})
                duration = metadata.get("capture_duration", 0)
                duration_formatted = self._format_duration(duration)

                html += f"""
                <div style="background: #e7f3ff; border-left: 4px solid #2196F3; padding: 15px; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0 0 8px 0;"><strong>ℹ️ Capture Context</strong></p>
                    <p style="margin: 0; font-size: 0.95em; color: #1565C0;">
                        Note: Capture spans <strong>{duration_formatted}</strong>. Jitter includes packet gaps between sessions.
                        For real-time application analysis, use shorter capture windows (5-10 minutes).
                    </p>
                </div>
                """

        # Generate grouped jitter analysis by severity level
        html += self._generate_grouped_jitter_analysis(jitter_data)

        return html

    def _generate_service_section(self, results: dict[str, Any]) -> str:
        """Generate service classification section."""
        service_data = results.get("service_classification", {})

        html = "<h2>🧠 Service Classification</h2>"

        # Classification summary
        summary = service_data.get("classification_summary", {})
        if summary:
            total_flows = summary.get("total_flows", 0)
            classified = summary.get("classified_count", 0)
            rate = summary.get("classification_rate", 0)

            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Total Flows</div>
                <div class="metric-value">{total_flows}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Classified</div>
                <div class="metric-value">{classified}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Classification Rate</div>
                <div class="metric-value">{rate:.0f}%</div>
            </div>
            """
            html += "</div>"

        # Service types
        service_types = service_data.get("service_classifications", {})
        if service_types:
            html += "<h3>Service Type Distribution</h3>"
            html += '<div class="chart-container">'
            html += '<div class="bar-chart">'

            total = sum(service_types.values())
            for service, count in sorted(service_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total * 100) if total > 0 else 0
                html += f"""
                <div class="bar-chart-row">
                    <div class="bar-label">{service}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: {percentage}%"></div>
                        <div class="bar-value">{count} flows ({percentage:.1f}%)</div>
                    </div>
                </div>
                """

            html += "</div></div>"

            # Add contextual note if one service type dominates
            max_service = max(service_types.items(), key=lambda x: x[1])
            max_percentage = (max_service[1] / total * 100) if total > 0 else 0

            if max_percentage > 90:
                service_name = max_service[0]
                context_messages = {
                    "Control": "This indicates primarily <strong>network management traffic</strong> (DNS, mDNS, NTP, DHCP). "  # noqa: E501
                    "Common in passive monitoring or captures with minimal user activity.",
                    "Streaming": "This indicates heavy <strong>multimedia usage</strong> (video/audio streaming). "
                    "May require bandwidth optimization or QoS prioritization.",
                    "Interactive": "This indicates primarily <strong>web browsing and interactive applications</strong> (HTTP, SSH). "  # noqa: E501
                    "Typical of normal user activity with request/response patterns.",
                    "Bulk": "This indicates significant <strong>file transfer activity</strong> (FTP, large downloads). "  # noqa: E501
                    "May impact available bandwidth for real-time applications.",
                }

                message = context_messages.get(service_name, "")
                if message:
                    html += f"""
            <div style="background: #f0f8ff; border-left: 4px solid #2196F3; padding: 15px; margin: 15px 0; border-radius: 4px;">
                <p style="margin: 0 0 8px 0;"><strong>💡 Traffic Pattern Analysis</strong></p>
                <p style="margin: 0; font-size: 0.95em; color: #555;">
                    <strong>{service_name}</strong> dominates with {max_percentage:.1f}% of flows. {message}
                </p>
            </div>
            """

        # Unknown services breakdown
        unknown_flows = service_data.get("unknown_flows", [])
        if unknown_flows:
            unknown_count = len(unknown_flows)
            total_flows = summary.get("total_flows", 0)
            unknown_percentage = (unknown_count / total_flows * 100) if total_flows > 0 else 0

            html += f"<h3>❓ Unknown Service Classification ({unknown_count} flows, {unknown_percentage:.1f}%)</h3>"

            # Analyze port distribution in unknown flows
            port_distribution = {}
            for flow in unknown_flows:
                dst_port = flow.get("dst_port", 0)
                port_distribution[dst_port] = port_distribution.get(dst_port, 0) + 1

            if port_distribution:
                html += "<h4>Most Common Ports in Unknown Traffic</h4>"
                html += '<table class="data-table">'
                html += """
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Flow Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                """

                sorted_ports = sorted(port_distribution.items(), key=lambda x: x[1], reverse=True)[:10]
                for port, count in sorted_ports:
                    port_percentage = (count / unknown_count * 100) if unknown_count > 0 else 0
                    html += f"""
                    <tr>
                        <td><strong>{port}</strong></td>
                        <td>{count}</td>
                        <td>{port_percentage:.1f}%</td>
                    </tr>
                    """

                html += "</tbody></table>"

                # Add note about unknown services
                html += """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0 0 8px 0;"><strong>ℹ️ About Unknown Classification</strong></p>
                    <p style="margin: 0; font-size: 0.95em; color: #856404;">
                        Flows are classified as "Unknown" when they don't match known behavioral patterns.
                        This typically includes: custom applications, encrypted protocols, or non-standard port usage.
                        Review the port distribution above to identify potential application-specific traffic.
                    </p>
                </div>
                """

        return html

    def _generate_confidence_overview(self, retrans_data: dict) -> str:
        """Generate simplified confidence overview (v4.5.0 style)."""
        total_retrans = retrans_data.get("total_retransmissions", 0)
        retrans_list = retrans_data.get("retransmissions", [])

        # Determine overall confidence
        high_confidence_count = sum(1 for r in retrans_list if r.get("confidence") == "high")
        medium_confidence_count = sum(1 for r in retrans_list if r.get("confidence") == "medium")

        if high_confidence_count > len(retrans_list) * 0.6:
            confidence_emoji = "🟢"
            confidence_text = "High"
        elif high_confidence_count + medium_confidence_count > len(retrans_list) * 0.5:
            confidence_emoji = "🟡"
            confidence_text = "Medium"
        else:
            confidence_emoji = "🟠"
            confidence_text = "Low"

        # Concise HTML (no verbose explanations)
        html = f"""
        <div style="background: #f5f5f5; padding: 10px; margin: 15px 0; border-radius: 4px;">
            <p style="margin: 0;"><strong>Analysis Confidence:</strong> {confidence_emoji} {confidence_text} ({total_retrans:,} events, {high_confidence_count} high-confidence)</p>
        </div>
        """

        return html

    def _generate_grouped_retransmission_analysis(self, flows: dict, total_packets: int) -> str:
        """Generate retransmission analysis grouped by type (SYN, RTO, Fast Retrans, Generic, Mixed)."""
        # Classify each flow by dominant type
        flow_groups = {
            "syn": [],  # SYN retransmissions (connection failures)
            "rto": [],  # RTO retransmissions (packet loss)
            "fast": [],  # Fast retransmissions (out-of-order)
            "generic": [],  # Generic retransmissions
            "mixed": [],  # Mixed types (no clear dominant)
        }

        for flow_key, retrans_list in flows.items():
            # Count mechanisms
            syn_count = sum(1 for r in retrans_list if r.get("is_syn_retrans", False))
            rto_count = sum(
                1 for r in retrans_list if r.get("retrans_type") == "RTO" and not r.get("is_syn_retrans", False)
            )
            fast_count = sum(1 for r in retrans_list if r.get("retrans_type") == "Fast Retransmission")
            generic_count = sum(1 for r in retrans_list if r.get("retrans_type") == "Retransmission")
            total = len(retrans_list)

            # Determine dominant type (>= 80% threshold)
            if syn_count > 0 and syn_count == total:
                flow_groups["syn"].append((flow_key, retrans_list))
            elif rto_count >= total * 0.8:
                flow_groups["rto"].append((flow_key, retrans_list))
            elif fast_count >= total * 0.8:
                flow_groups["fast"].append((flow_key, retrans_list))
            elif generic_count >= total * 0.8:
                flow_groups["generic"].append((flow_key, retrans_list))
            else:
                flow_groups["mixed"].append((flow_key, retrans_list))

        # Sort each group by total retransmissions
        for group_type in flow_groups:
            flow_groups[group_type] = sorted(flow_groups[group_type], key=lambda x: len(x[1]), reverse=True)

        html = ""

        # Generate section for each type (only if flows exist)
        if flow_groups["syn"]:
            html += self._generate_retrans_type_section(
                "syn", "SYN Retransmissions (Connection Failures)", flow_groups["syn"], "#dc3545", "🔴"
            )

        if flow_groups["rto"]:
            html += self._generate_retrans_type_section(
                "rto", "RTO Retransmissions (Packet Loss)", flow_groups["rto"], "#ffc107", "🟡"
            )

        if flow_groups["fast"]:
            html += self._generate_retrans_type_section(
                "fast", "Fast Retransmissions (Out-of-Order Delivery)", flow_groups["fast"], "#28a745", "🟢"
            )

        if flow_groups["generic"]:
            html += self._generate_retrans_type_section(
                "generic", "Generic Retransmissions (Moderate Delay)", flow_groups["generic"], "#17a2b8", "🔵"
            )

        if flow_groups["mixed"]:
            html += self._generate_retrans_type_section(
                "mixed", "Mixed Retransmissions (Multiple Mechanisms)", flow_groups["mixed"], "#6c757d", "⚪"
            )

        return html

    def _analyze_root_cause(self, flows: list, type_key: str) -> dict:
        """Analyze root cause and patterns for flows."""
        result = {"root_cause": None, "action": None, "pattern": None, "tshark_filter": None}

        if not flows:
            return result

        # Extract all dest IPs and ports
        dest_ips = {}
        dest_ports = {}
        for flow_key, retrans_list in flows:
            # Parse flow_key: "src_ip:src_port → dst_ip:dst_port"
            parts = flow_key.split(" → ")
            if len(parts) == 2:
                dst_part = parts[1].strip()
                if ":" in dst_part:
                    dst_ip, dst_port = dst_part.rsplit(":", 1)
                    dest_ips[dst_ip] = dest_ips.get(dst_ip, 0) + 1
                    dest_ports[dst_port] = dest_ports.get(dst_port, 0) + 1

        # Check for common destination
        if dest_ips:
            most_common_ip = max(dest_ips.items(), key=lambda x: x[1])
            most_common_port = max(dest_ports.items(), key=lambda x: x[1]) if dest_ports else (None, 0)

            # Pattern detection
            if most_common_ip[1] == len(flows):
                result["pattern"] = f"All flows target {most_common_ip[0]}"

                # Check for reserved/special IPs
                ip = most_common_ip[0]
                ip_info = self._identify_ip_range(ip)

                if ip_info:
                    result["root_cause"] = f"{most_common_ip[0]} is {ip_info['name']} ({ip_info['rfc']})"
                    result["action"] = ip_info["action"]
                elif type_key == "syn":
                    result["root_cause"] = (
                        f"Server {most_common_ip[0]}:{most_common_port[0]} unreachable or not listening"
                    )
                    result["action"] = f"Verify server status and port {most_common_port[0]} availability"

                # Generate tshark filter
                result["tshark_filter"] = f"ip.dst == {most_common_ip[0]}"
                if type_key == "syn":
                    result["tshark_filter"] += " and tcp.flags.syn == 1"

            elif most_common_ip[1] >= len(flows) * 0.5:
                result["pattern"] = f"{most_common_ip[1]} flows target {most_common_ip[0]} (dominant pattern)"

        return result

    def _identify_ip_range(self, ip: str) -> dict:
        """Identify if IP is in a reserved/special range."""
        import ipaddress

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Reserved ranges
            ranges = {
                "192.0.2.0/24": {
                    "name": "TEST-NET-1 (Documentation/Testing)",
                    "rfc": "RFC 5737",
                    "action": "Remove hardcoded test IP from application config",
                },
                "198.51.100.0/24": {
                    "name": "TEST-NET-2 (Documentation/Testing)",
                    "rfc": "RFC 5737",
                    "action": "Remove hardcoded test IP from application config",
                },
                "203.0.113.0/24": {
                    "name": "TEST-NET-3 (Documentation/Testing)",
                    "rfc": "RFC 5737",
                    "action": "Remove hardcoded test IP from application config",
                },
                "0.0.0.0/8": {
                    "name": "Current Network (invalid destination)",
                    "rfc": "RFC 1122",
                    "action": "Fix application routing logic",
                },
                "127.0.0.0/8": {
                    "name": "Loopback",
                    "rfc": "RFC 1122",
                    "action": "Check if service should be local or remote",
                },
                "169.254.0.0/16": {
                    "name": "Link-Local (APIPA)",
                    "rfc": "RFC 3927",
                    "action": "Check DHCP configuration",
                },
                "10.0.0.0/8": {
                    "name": "Private Network",
                    "rfc": "RFC 1918",
                    "action": "Verify network routing and NAT",
                },
                "172.16.0.0/12": {
                    "name": "Private Network",
                    "rfc": "RFC 1918",
                    "action": "Verify network routing and NAT",
                },
                "192.168.0.0/16": {
                    "name": "Private Network",
                    "rfc": "RFC 1918",
                    "action": "Verify network routing and NAT",
                },
                "224.0.0.0/4": {"name": "Multicast", "rfc": "RFC 5771", "action": "Check multicast configuration"},
                "240.0.0.0/4": {"name": "Reserved (Future Use)", "rfc": "RFC 1112", "action": "Invalid destination IP"},
            }

            for range_str, info in ranges.items():
                network = ipaddress.ip_network(range_str)
                if ip_obj in network:
                    return info

        except ValueError:
            pass

        return None

    def _generate_root_cause_box(self, analysis: dict, type_key: str, flows: list) -> str:
        """Generate root cause analysis box."""
        html = '<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">'
        html += '<h4 style="margin: 0 0 10px 0; font-size: 1.1em;">🎯 Root Cause Analysis</h4>'

        if analysis["root_cause"]:
            html += f'<p style="margin: 5px 0; font-size: 1em;"><strong>Cause:</strong> {analysis["root_cause"]}</p>'

        if analysis["pattern"]:
            html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Pattern:</strong> {analysis["pattern"]}</p>'

        # Add RFC 6298 compliance for SYN
        if type_key == "syn":
            delays = []
            for _, retrans_list in flows:
                for r in retrans_list:
                    delays.append(r.get("delay", 0))
            if delays:
                min_delay = min(delays)
                max_delay = max(delays)
                avg_delay = sum(delays) / len(delays)
                num_samples = len(delays)

                # Only show RFC compliance check if we have enough samples (>= 5)
                if num_samples >= 5:
                    compliant = all(d >= 1.0 for d in delays)
                    if compliant:
                        compliance_icon = "✅"
                        compliance_msg = "Compliant"
                    else:
                        compliance_icon = "⚠️"
                        # Better messaging for non-compliance
                        if min_delay < 1.0:
                            compliance_msg = f"Short RTO detected ({min_delay:.3f}s < 1s RFC 6298 minimum)"
                        else:
                            compliance_msg = "Non-compliant"
                    html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>RFC 6298:</strong> {compliance_icon} {compliance_msg} (RTOs: {min_delay:.3f}s - {max_delay:.3f}s, avg: {avg_delay:.3f}s, n={num_samples})</p>'
                else:
                    # Limited data - don't assess compliance
                    html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>RFC 6298:</strong> ⚠️ Limited data ({num_samples} sample{"s" if num_samples != 1 else ""}) - RFC compliance not assessed (RTOs: {min_delay:.3f}s - {max_delay:.3f}s, avg: {avg_delay:.3f}s)</p>'

        html += "</div>"
        return html

    def _generate_type_explanation_concise(self, type_key: str, flows: list) -> str:
        """Generate concise explanation for a retransmission type."""
        explanations = {
            "syn": """
                <div style="background: #fff3cd; border-left: 4px solid #dc3545; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>SYN retrans = Connection failed</strong> (server unreachable)<br>
                    <strong>Type:</strong> RTO-based (no ACKs during handshake, never fast retransmit)<br>
                    <strong>Impact:</strong> <span style='color: #dc3545;'>CRITICAL</span> - Application cannot establish TCP connection
                    </p>
                </div>
            """,
            "rto": """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>RTO = Packet loss detected</strong> (no ACK received, timeout)<br>
                    <strong>Impact:</strong> <span style='color: #ffc107;'>HIGH</span> - Significant delays (200ms-3s per event)<br>
                    <strong>Causes:</strong> Network congestion, unreliable path, ACK loss
                    </p>
                </div>
            """,
            "fast": """
                <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Fast Retrans = Out-of-order delivery</strong> (duplicate ACKs)<br>
                    <strong>Impact:</strong> <span style='color: #28a745;'>MODERATE</span> - Quick recovery via duplicate ACKs<br>
                    <strong>Causes:</strong> Load balancing, multipath routing, packet reordering
                    </p>
                </div>
            """,
            "generic": """
                <div style="background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Generic Retrans = Moderate delay</strong> (50-200ms)<br>
                    <strong>Impact:</strong> <span style='color: #17a2b8;'>LOW</span> - Minor performance degradation
                    </p>
                </div>
            """,
            "mixed": """
                <div style="background: #e2e3e5; border-left: 4px solid #6c757d; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Mixed mechanisms</strong> - Complex network behavior<br>
                    <strong>Recommendation:</strong> Review individual flows for specific patterns
                    </p>
                </div>
            """,
        }

        return explanations.get(type_key, "")

    def _generate_quick_actions(self, analysis: dict, type_key: str) -> str:
        """Generate quick actions box."""
        if not analysis["action"] and type_key not in ["syn", "rto"]:
            return ""

        html = '<div style="background: #e7f3ff; border: 1px solid #2196F3; border-radius: 6px; padding: 15px; margin-bottom: 15px;">'
        html += '<h5 style="margin: 0 0 10px 0; color: #1976D2;">💡 Suggested Actions</h5>'
        html += '<ul style="margin: 5px 0; padding-left: 20px; font-size: 0.9em;">'

        if analysis["action"]:
            html += f'<li><strong>{analysis["action"]}</strong></li>'

        # Type-specific actions
        if type_key == "syn":
            html += '<li>Test connectivity: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">ping &lt;dest_ip&gt;</code> / <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">telnet &lt;dest_ip&gt; &lt;port&gt;</code></li>'
            html += "<li>Check firewall rules and routing tables</li>"
            html += "<li>Verify DNS resolution for target hostname</li>"
        elif type_key == "rto":
            html += '<li>Monitor network congestion with: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">netstat -s</code></li>'
            html += "<li>Check router/switch buffer utilization</li>"
            html += "<li>Consider QoS/traffic shaping if congestion persists</li>"

        html += "</ul>"
        html += "</div>"

        return html

    def _generate_tshark_command_box(self, tshark_filter: str) -> str:
        """Generate tshark command box with one-click copy."""
        html = '<div style="background: #263238; color: #aed581; padding: 15px; margin-bottom: 20px; border-radius: 6px; font-family: monospace; position: relative;">'
        html += '<div style="color: #81c784; margin-bottom: 8px; font-size: 0.85em;">📌 Tshark Command (click to select):</div>'
        html += f'<pre style="margin: 0; overflow-x: auto; cursor: text; user-select: all; background: #1e1e1e; padding: 10px; border-radius: 4px; font-size: 0.85em;" onclick="window.getSelection().selectAllChildren(this);">tshark -r &lt;file.pcap&gt; -Y \'{tshark_filter}\' -T fields -e frame.number -e frame.time_relative -e tcp.seq -e tcp.ack -e tcp.len -e tcp.flags.str</pre>'
        html += '<div style="color: #90caf9; margin-top: 8px; font-size: 0.8em;">💡 Click command to select, then Ctrl+C (Cmd+C) to copy</div>'
        html += "</div>"

        return html

    def _generate_retrans_type_section(self, type_key: str, title: str, flows: list, color: str, emoji: str) -> str:
        """Generate a section for one retransmission type with explanation + flow table."""
        flow_count = len(flows)
        total_retrans = sum(len(retrans_list) for _, retrans_list in flows)

        # Analyze root cause
        root_cause_analysis = self._analyze_root_cause(flows, type_key)

        html = '<div class="retrans-type-section" style="margin: 20px 0; border: 2px solid {color}; border-radius: 8px; overflow: hidden;">'.format(
            color=color
        )
        html += f'<div class="retrans-type-header" style="background: {color}; color: white; padding: 15px; font-weight: bold; font-size: 1.1em;">'
        html += f'{emoji} {title} — {flow_count} flow{"s" if flow_count != 1 else ""} ({total_retrans} retransmissions)'
        html += "</div>"
        html += '<div class="retrans-type-body" style="padding: 20px; background: #f8f9fa;">'

        # Add root cause analysis (if found)
        if root_cause_analysis["root_cause"] or root_cause_analysis["pattern"]:
            html += self._generate_root_cause_box(root_cause_analysis, type_key, flows)

        # Add concise explanation
        html += self._generate_type_explanation_concise(type_key, flows)

        # Add quick actions
        html += self._generate_quick_actions(root_cause_analysis, type_key)

        # Add tshark command (one-click copy)
        if root_cause_analysis["tshark_filter"]:
            html += self._generate_tshark_command_box(root_cause_analysis["tshark_filter"])

        # Add compact flow table
        html += self._generate_flow_table(flows, type_key)

        html += "</div>"
        html += "</div>"

        return html

    def _generate_type_explanation(self, type_key: str, flows: list) -> str:
        """Generate explanation for a retransmission type."""
        explanations = {
            "syn": """
                <div style="background: #fff3cd; border-left: 4px solid #dc3545; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <h4 style="margin: 0 0 10px 0;">⚠️ What does this mean?</h4>
                    <p style="margin: 8px 0;"><strong>Connection Failed:</strong> These flows never completed the TCP handshake.
                    The initial SYN packet was retransmitted with no response from the server. This indicates the destination server is
                    <strong>unreachable</strong>, <strong>not listening on this port</strong>, or <strong>network connectivity issues</strong>
                    prevented the connection.</p>

                    <p style="margin: 8px 0;"><strong>Why flagged HIGH:</strong> The TCP connection <strong>never established</strong>.
                    SYN retransmissions indicate the server is unreachable or not accepting connections on this port.
                    This is a <strong>critical connectivity failure</strong>.</p>

                    <p style="margin: 8px 0;"><strong>Impact & Probable Cause:</strong> <span style='color: #dc3545;'>⚠ CRITICAL - Connection Failed</span>.
                    SYN retransmissions occur during TCP handshake when the server doesn't respond to connection attempts.
                    <strong>This is ALWAYS timeout-based (RTO), NEVER fast retransmit</strong> (no ACKs possible during handshake).</p>

                    <p style="margin: 8px 0;"><strong>Typical causes:</strong></p>
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        <li><strong>Server unreachable</strong> (host down, wrong IP, routing issues)</li>
                        <li><strong>Port not listening</strong> (service not running, firewall blocking)</li>
                        <li><strong>Network connectivity</strong> (firewall dropping SYN, routing black hole)</li>
                        <li><strong>RFC 6298 Compliance:</strong> Initial RTO should be ≥ 1 second</li>
                    </ul>
                </div>
            """,
            "rto": """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <h4 style="margin: 0 0 10px 0;">📊 What does this mean?</h4>
                    <p style="margin: 8px 0;"><strong>Packet Loss Detected:</strong> These flows experienced RTO (Retransmission Timeout) events,
                    where TCP waited for acknowledgment but received none. This indicates <strong>packet loss</strong> during the established connection.</p>

                    <p style="margin: 8px 0;"><strong>Impact:</strong> RTO events cause <span style='color: #ffc107;'>⚠ significant delays</span>
                    (typically 200ms-3s per event) as TCP conservatively backs off.</p>

                    <p style="margin: 8px 0;"><strong>Typical causes:</strong></p>
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        <li><strong>Network congestion</strong> (router/switch buffer overflow)</li>
                        <li><strong>Unreliable network path</strong> (WiFi interference, lossy links)</li>
                        <li><strong>ACK loss</strong> (acknowledgments not reaching sender)</li>
                    </ul>
                </div>
            """,
            "fast": """
                <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <h4 style="margin: 0 0 10px 0;">✅ What does this mean?</h4>
                    <p style="margin: 8px 0;"><strong>Out-of-Order Delivery:</strong> These flows experienced Fast Retransmissions,
                    triggered by duplicate ACKs indicating packets arrived out-of-order.</p>

                    <p style="margin: 8px 0;"><strong>Impact:</strong> Fast Retransmissions cause <span style='color: #28a745;'>✓ moderate performance impact</span>
                    as TCP quickly recovers using duplicate ACKs.</p>

                    <p style="margin: 8px 0;"><strong>Typical causes:</strong></p>
                    <ul style="margin: 5px 0; padding-left: 20px;">
                        <li><strong>Network path changes</strong> (load balancing, routing changes)</li>
                        <li><strong>Packet reordering</strong> (multipath routing, priority queuing)</li>
                        <li><strong>Selective packet loss</strong> (not entire window dropped)</li>
                    </ul>
                </div>
            """,
            "generic": """
                <div style="background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <h4 style="margin: 0 0 10px 0;">ℹ️ What does this mean?</h4>
                    <p style="margin: 8px 0;"><strong>Moderate Delay Retransmissions:</strong> These flows experienced retransmissions
                    with delay between 50-200ms, likely due to moderate network congestion or packet loss.</p>

                    <p style="margin: 8px 0;"><strong>Impact:</strong> Moderate performance degradation, not as severe as RTO events.</p>
                </div>
            """,
            "mixed": """
                <div style="background: #e2e3e5; border-left: 4px solid #6c757d; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                    <h4 style="margin: 0 0 10px 0;">🔍 What does this mean?</h4>
                    <p style="margin: 8px 0;"><strong>Mixed Mechanisms:</strong> These flows experienced multiple retransmission types,
                    indicating complex network behavior. Requires detailed packet-level analysis to understand root causes.</p>

                    <p style="margin: 8px 0;"><strong>Recommendation:</strong> Review individual flow details below for specific patterns.</p>
                </div>
            """,
        }

        return explanations.get(type_key, "")

    def _generate_flow_table(self, flows: list, type_key: str) -> str:
        """Generate compact table of flows for a given type."""
        from datetime import datetime

        # Limit to top 10 flows
        flows_to_show = flows[:10]

        html = '<div style="overflow-x: auto; margin-bottom: 20px;">'
        html += '<table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #dee2e6;">'
        html += '<thead style="background: #e9ecef;">'
        html += "<tr>"
        html += '<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Flow</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">First Retrans</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Total Retrans</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Avg Delay</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Duration</th>'
        html += "</tr>"
        html += "</thead>"
        html += "<tbody>"

        for flow_key, retrans_list in flows_to_show:
            total_retrans = len(retrans_list)
            avg_delay = sum(r.get("delay", 0) for r in retrans_list) / total_retrans if total_retrans > 0 else 0

            # Calculate duration and first retransmission timestamp
            if retrans_list:
                timestamps = [r.get("timestamp", 0) for r in retrans_list]
                first_timestamp = min(timestamps)
                duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0

                # Format timestamp in ISO 8601 (YYYY-MM-DD HH:MM:SS.mmm)
                dt = datetime.fromtimestamp(first_timestamp)
                timestamp_iso = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Keep milliseconds
            else:
                duration = 0
                timestamp_iso = "N/A"

            html += '<tr style="border-bottom: 1px solid #dee2e6;">'
            html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{flow_key}</td>'
            html += f'<td style="padding: 10px; text-align: center; font-family: monospace; font-size: 0.85em; color: #555;">{timestamp_iso}</td>'
            html += f'<td style="padding: 10px; text-align: center;"><strong>{total_retrans}</strong></td>'
            html += f'<td style="padding: 10px; text-align: center;">{avg_delay*1000:.1f}ms</td>'
            html += f'<td style="padding: 10px; text-align: center;">{self._format_duration(duration)}</td>'
            html += "</tr>"

        html += "</tbody>"
        html += "</table>"
        html += "</div>"

        if len(flows) > 10:
            html += f'<p style="color: #6c757d; font-size: 0.9em; font-style: italic; margin-top: 10px;">Showing top 10 of {len(flows)} flows. See JSON report for complete data.</p>'

        return html

    def _analyze_window_root_cause(self, flows: list, type_key: str) -> dict:
        """
        Analyze root cause and patterns for TCP window issues.

        Args:
            flows: List of flow statistics dictionaries with zero window events
            type_key: Type identifier (e.g., 'window_zero')

        Returns:
            Dictionary containing:
            - root_cause: Identified root cause or None
            - action: Recommended action or None
            - pattern: Detected pattern or None
            - tshark_filter: tshark filter for investigation or None
            - severity: Severity level based on count × duration
        """
        result = {"root_cause": None, "action": None, "pattern": None, "tshark_filter": None, "severity": "low"}

        if not flows:
            return result

        # Extract receiver IPs and ports from flows
        receiver_ips = {}
        receiver_ports = {}
        total_events = 0
        total_duration = 0.0

        for flow in flows:
            # For window analysis, receiver is the dst_ip (the one with zero window)
            receiver_ip = flow.get("dst_ip")
            receiver_port = flow.get("dst_port")
            zero_count = flow.get("zero_window_count", 0)
            zero_duration = flow.get("zero_window_total_duration", 0.0)

            if receiver_ip:
                receiver_ips[receiver_ip] = receiver_ips.get(receiver_ip, 0) + 1
                total_events += zero_count
                total_duration += zero_duration

            if receiver_port:
                receiver_ports[str(receiver_port)] = receiver_ports.get(str(receiver_port), 0) + 1

        # Calculate severity based on count × duration
        severity_score = total_events * total_duration
        if severity_score > 100:  # High: many events with long duration
            result["severity"] = "high"
        elif severity_score > 20:  # Medium: moderate impact
            result["severity"] = "medium"
        else:
            result["severity"] = "low"

        # Pattern detection: Check if all flows target same receiver
        if receiver_ips:
            most_common_ip = max(receiver_ips.items(), key=lambda x: x[1])
            most_common_port = max(receiver_ports.items(), key=lambda x: x[1]) if receiver_ports else (None, 0)

            # All flows to same receiver IP
            if most_common_ip[1] == len(flows):
                result["pattern"] = f"All flows involve receiver {most_common_ip[0]}"

                # Check for reserved/special IPs using existing function
                receiver_ip = most_common_ip[0]
                ip_info = self._identify_ip_range(receiver_ip)

                if ip_info:
                    # Reserved IP range detected
                    result["root_cause"] = f"Receiver {receiver_ip} is {ip_info['name']} ({ip_info['rfc']})"
                    result["action"] = ip_info["action"]
                else:
                    # Real IP - application bottleneck
                    result["root_cause"] = f"Receiver {receiver_ip} application cannot process data fast enough"
                    result["action"] = f"Investigate application performance on {receiver_ip}"

                    # Add port-specific guidance
                    if most_common_port[0]:
                        result[
                            "action"
                        ] += f" (port {most_common_port[0]}). Check CPU, memory, disk I/O, and application logs"

                # Generate tshark filter for debugging
                result["tshark_filter"] = f"ip.dst == {receiver_ip} and tcp.window_size == 0"

            elif most_common_ip[1] >= len(flows) * 0.5:
                # Dominant pattern (50%+ flows to same receiver)
                result["pattern"] = (
                    f"{most_common_ip[1]} of {len(flows)} flows involve receiver {most_common_ip[0]} (dominant pattern)"
                )
                result["action"] = f"Focus investigation on receiver {most_common_ip[0]}"

        # RFC 7323 compliance note (window scaling)
        # Note: Window scale info is not in flow_statistics, but we can add a general reminder
        if not result["action"]:
            result["action"] = "Check RFC 7323 window scaling configuration and receiver application performance"

        return result

    def _generate_window_root_cause_box(self, analysis: dict, type_key: str, flows: list) -> str:
        """
        Generate root cause analysis box for TCP window issues.

        Args:
            analysis: Analysis results from _analyze_window_root_cause
            type_key: Type identifier (e.g., 'window_zero')
            flows: List of flow statistics

        Returns:
            HTML string for the root cause box
        """
        # Use consistent purple gradient (not aggressive red), vary only emoji/text by severity
        bg_gradient = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
        severity = analysis.get("severity", "low")
        if severity == "high":
            severity_emoji = "🔴"
            severity_text = "High Severity"
        elif severity == "medium":
            severity_emoji = "🟡"
            severity_text = "Medium Severity"
        else:
            severity_emoji = "🟢"
            severity_text = "Low Severity"

        html = f'<div style="background: {bg_gradient}; color: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">'
        html += '<h4 style="margin: 0 0 10px 0; font-size: 1.1em;">🎯 Root Cause Analysis</h4>'

        # Severity indicator
        html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Severity:</strong> {severity_emoji} {severity_text}</p>'

        # Root cause
        if analysis["root_cause"]:
            html += f'<p style="margin: 5px 0; font-size: 1em;"><strong>Cause:</strong> {analysis["root_cause"]}</p>'

        # Pattern
        if analysis["pattern"]:
            html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Pattern:</strong> {analysis["pattern"]}</p>'

        # RFC 7323 Window Scaling compliance note
        html += '<div style="background: rgba(255,255,255,0.15); padding: 10px; margin: 10px 0; border-radius: 5px; border-left: 3px solid rgba(255,255,255,0.5);">'
        html += '<p style="margin: 0; font-size: 0.9em;"><strong>📋 RFC 7323 Compliance:</strong></p>'
        html += '<p style="margin: 5px 0 0 0; font-size: 0.85em;">Window scaling must be negotiated in SYN/SYN-ACK. '
        html += "Verify both endpoints support RFC 7323 window scaling for optimal throughput on high-bandwidth networks.</p>"
        html += "</div>"

        # Recommended action
        if analysis["action"]:
            html += (
                '<div style="background: rgba(255,255,255,0.2); padding: 10px; margin-top: 10px; border-radius: 5px;">'
            )
            html += f'<p style="margin: 0; font-size: 0.9em;"><strong>💡 Recommended Action:</strong></p>'
            html += f'<p style="margin: 5px 0 0 0; font-size: 0.85em;">{analysis["action"]}</p>'
            html += "</div>"

        # Tshark filter
        if analysis["tshark_filter"]:
            html += '<div style="margin-top: 10px;">'
            html += '<p style="margin: 0 0 5px 0; font-size: 0.9em;"><strong>🔍 Tshark Filter:</strong></p>'
            html += '<div style="background: rgba(0,0,0,0.2); padding: 8px; border-radius: 4px; font-family: monospace; font-size: 0.85em; overflow-x: auto;">'
            html += f'<code style="color: #fff;">{analysis["tshark_filter"]}</code>'
            html += "</div>"
            html += "</div>"

        html += "</div>"
        return html

    def _generate_flow_detail_card(self, flow_key: str, retrans_list: list, index: int, flow_count: int) -> str:
        """Generate individual flow detail card with expandable analysis."""
        flow_label = f"Flow {index + 1}"
        total_retrans = len(retrans_list)

        # Count mechanisms
        syn_retrans_count = sum(1 for r in retrans_list if r.get("is_syn_retrans", False))
        rto_count = sum(1 for r in retrans_list if r.get("retrans_type") == "RTO")
        fast_retrans = sum(1 for r in retrans_list if r.get("retrans_type") == "Fast Retransmission")
        generic_retrans = sum(1 for r in retrans_list if r.get("retrans_type") == "Retransmission")
        other_count = total_retrans - rto_count - fast_retrans - generic_retrans

        # Determine overall confidence for this flow based on PATTERN CLARITY
        # HIGH confidence = Consistent single mechanism with sufficient sample size
        # MEDIUM confidence = Dominant pattern or uniform but small sample
        # LOW confidence = Mixed/unclear pattern

        confidence_counts = {"high": 0, "medium": 0, "low": 0}
        for r in retrans_list:
            conf = r.get("confidence", "low")
            if conf in confidence_counts:
                confidence_counts[conf] += 1

        # Use the corrected counts from validation above (don't recalculate from raw data)
        # The counts have been adjusted for flow duration constraints
        fast_count = fast_retrans
        spurious_count = confidence_counts["high"]  # Spurious = high confidence individual

        # Determine which mechanism is dominant (using corrected counts)
        max_mechanism_count = max(rto_count, fast_count, generic_retrans, spurious_count)
        mechanism_percentage = (max_mechanism_count / total_retrans * 100) if total_retrans > 0 else 0
        is_uniform = max_mechanism_count == total_retrans  # 100% of one mechanism

        # NEW LOGIC: Pattern Clarity
        if is_uniform and total_retrans >= 3:
            # 100% of single mechanism with sufficient sample
            flow_confidence = "confidence-high"
            flow_confidence_text = "High Confidence"
            flow_confidence_emoji = "🟢"
            flow_confidence_note = "Clear, consistent pattern"
        elif is_uniform and total_retrans >= 2:
            # 100% uniform but small sample (2 retransmissions)
            flow_confidence = "confidence-medium"
            flow_confidence_text = "Medium Confidence"
            flow_confidence_emoji = "🟡"
            flow_confidence_note = "Consistent pattern, small sample"
        elif mechanism_percentage >= 80:
            # Dominant mechanism (80%+)
            flow_confidence = "confidence-medium"
            flow_confidence_text = "Medium Confidence"
            flow_confidence_emoji = "🟡"
            flow_confidence_note = "Dominant pattern"
        else:
            # Mixed mechanisms
            flow_confidence = "confidence-low"
            flow_confidence_text = "Low Confidence"
            flow_confidence_emoji = "🟠"
            flow_confidence_note = "Mixed mechanisms, detailed analysis needed"

        # Calculate duration FIRST (needed for severity calculation)
        # Issue #12 Fix: Use min/max timestamps instead of first/last to handle delay-sorted lists
        # retrans_list is sorted by delay (descending) in retransmission.py:989, not by timestamp.
        # When high-delay retrans (RTO) occurs chronologically AFTER low-delay retrans (Fast Retrans),
        # using first/last would yield negative durations.
        # Example: RTO at t=15s (delay=500ms) sorted before Fast Retrans at t=5s (delay=50ms)
        # Old: last - first = 5 - 15 = -10s (WRONG)
        # New: max - min = 15 - 5 = 10s (CORRECT)
        if retrans_list:
            timestamps = [r.get("timestamp", 0) for r in retrans_list]
            duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        else:
            duration = 0

        # VALIDATION: Fix classification inconsistencies based on flow duration
        # Physical constraints: retransmission delays cannot exceed flow duration
        # - Flow < 50ms  → Only Fast Retransmission (≤ 50ms) is possible
        # - Flow < 200ms → No RTO (≥ 200ms) is possible, only Fast + Generic

        if duration < 0.050:  # Flow < 50ms
            # Reclassify: ALL → Fast Retransmission
            if rto_count > 0 or generic_retrans > 0:
                # Update counters
                fast_retrans = total_retrans
                rto_count = 0
                generic_retrans = 0
                other_count = 0

                # Update individual events for consistency
                for r in retrans_list:
                    if r.get("retrans_type") in ["RTO", "Retransmission"]:
                        r["retrans_type"] = "Fast Retransmission"

        elif duration < 0.200:  # Flow 50-200ms
            # Reclassify: RTO → Generic (cannot have 200ms+ delays in <200ms flow)
            if rto_count > 0:
                # Move RTO to Generic
                generic_retrans += rto_count
                rto_count = 0

                # Update individual events
                for r in retrans_list:
                    if r.get("retrans_type") == "RTO":
                        r["retrans_type"] = "Retransmission"  # Generic

        # Determine severity based on absolute count and rate per second
        # Note: We don't have per-flow packet count, so we use absolute thresholds
        retrans_per_second = total_retrans / duration if duration > 0 else total_retrans

        if total_retrans > 50 or (duration > 0 and retrans_per_second > 5):
            severity_level = "warning"
            severity_text = "⚠️ High Retrans Rate"
        elif total_retrans > 20 or (duration > 0 and retrans_per_second > 2):
            severity_level = "info"
            severity_text = "Moderate Retrans Rate"
        else:
            severity_level = "info"
            severity_text = "Low Retrans Rate"

        html = '<div class="flow-detail-card">'
        html += '  <div class="flow-header">'
        html += '    <div class="flow-title">'
        html += f'      <span class="flow-label">{flow_label}</span>'
        html += f'      <code class="flow-key">{flow_key}</code>'
        html += "    </div>"
        html += '    <div class="flow-badges">'
        html += f"""
        <span class="confidence-badge {flow_confidence}" title="{flow_confidence_note}">
            <span class="badge-icon">{flow_confidence_emoji}</span> {flow_confidence_text}
        </span>
        <span class="severity-badge severity-{severity_level}">
            {severity_text}
        </span>
        """
        html += "    </div>"
        html += "  </div>"
        html += '  <div class="flow-body">'
        html += '    <div class="flow-stats-grid">'
        html += f"""
          <div class="flow-stat">
              <span class="stat-label">Total Retrans</span>
              <span class="stat-value">{total_retrans}</span>
          </div>
          <div class="flow-stat">
              <span class="stat-label">RTO Events</span>
              <span class="stat-value">{rto_count}</span>
          </div>
          <div class="flow-stat">
              <span class="stat-label">Fast Retrans</span>
              <span class="stat-value">{fast_retrans}</span>
          </div>
          <div class="flow-stat">
              <span class="stat-label">Generic Retrans</span>
              <span class="stat-value">{generic_retrans}</span>
          </div>
          <div class="flow-stat">
              <span class="stat-label">Duration</span>
              <span class="stat-value">{self._format_duration(duration)}</span>
          </div>
        """
        html += "    </div>"

        # Add natural language interpretation
        html += self._generate_retransmission_interpretation(
            total_retrans=total_retrans,
            rto_count=rto_count,
            fast_retrans=fast_retrans,
            generic_retrans=generic_retrans,
            syn_retrans_count=syn_retrans_count,
            duration=duration,
            retrans_per_second=retrans_per_second,
            flow_confidence=flow_confidence,
        )

        # Collapsible detailed analysis (Pure CSS with checkbox)
        html += '    <div class="flow-details-collapsible">'
        html += f"""
          <input type="checkbox" id="flow-{index}" class="flow-expand-checkbox">
          <label for="flow-{index}" class="flow-expand-btn">
              <span class="expand-icon">+</span>
              View Detailed Analysis
          </label>
          <div class="flow-details">
        """

        # Mechanism breakdown table
        html += '        <div class="mechanism-breakdown">'
        html += "          <h5>Mechanisms in This Flow</h5>"
        html += '          <table class="mechanism-table">'
        html += """
                    <thead>
                        <tr>
                            <th>Mechanism</th>
                            <th>Count</th>
                            <th>Percentage</th>
                        </tr>
                    </thead>
                    <tbody>
        """

        if rto_count > 0:
            pct = rto_count / total_retrans * 100
            html += f"""
                        <tr>
                            <td><span class="mech-icon">⏱️</span> RTO Timeout</td>
                            <td>{rto_count}</td>
                            <td>{pct:.1f}%</td>
                        </tr>
            """

        if fast_retrans > 0:
            pct = fast_retrans / total_retrans * 100
            html += f"""
                        <tr>
                            <td><span class="mech-icon">⚡</span> Fast Retransmission</td>
                            <td>{fast_retrans}</td>
                            <td>{pct:.1f}%</td>
                        </tr>
            """

        if other_count > 0:
            pct = other_count / total_retrans * 100
            html += f"""
                        <tr>
                            <td><span class="mech-icon">📋</span> Generic Retransmission</td>
                            <td>{other_count}</td>
                            <td>{pct:.1f}%</td>
                        </tr>
            """

        html += "                    </tbody>"
        html += "          </table>"
        html += "        </div>"

        # Timeline of recent events (last 5)
        html += '        <div class="timeline-section">'
        html += "          <h5>Recent Retransmission Events (Last 5)</h5>"
        html += '          <div class="timeline">'

        # Parse flow_key for Wireshark filters
        # Format: "src_ip:src_port → dst_ip:dst_port"
        flow_parts = flow_key.replace(" → ", ":").split(":")
        if len(flow_parts) == 4:
            src_ip, src_port, dst_ip, dst_port = flow_parts
        else:
            src_ip, src_port, dst_ip, dst_port = "0.0.0.0", "0", "0.0.0.0", "0"

        for r in retrans_list[-5:]:
            retrans_type = r.get("retrans_type", "Unknown")
            timestamp = r.get("timestamp", 0)
            seq_num = r.get("seq_num", 0)

            if retrans_type == "RTO":
                timeline_class = "timeline-rto"
                type_label = "RTO Timeout"
            elif retrans_type == "Fast Retransmission":
                timeline_class = "timeline-fast"
                type_label = "Fast Retrans"
            else:
                timeline_class = "timeline-success"
                type_label = "Generic Retransmission" if retrans_type == "Retransmission" else retrans_type

            # Generate Wireshark commands
            ws_commands = self._generate_wireshark_commands(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flow_type="retransmission",
                seq_num=seq_num,
            )

            html += f"""
                <div class="timeline-event {timeline_class}">
                    <span class="timeline-marker"></span>
                    <div class="timeline-content">
                        <span class="timeline-time">{timestamp:.3f}s</span>
                        <span class="timeline-type">{type_label}</span>
                        <span class="timeline-detail">Seq: {seq_num}</span>
                        <div class="wireshark-section">
                            <details>
                                <summary><strong>🔍 Debug Commands</strong></summary>
                                <div style="margin-top: 10px;">
                                    <p style="margin: 5px 0;"><strong>Wireshark Display Filter:</strong></p>
                                    <code class="copy-code">{ws_commands['display_filter']}</code>
                                    <button class="copy-btn" onclick="copyToClipboard(this)">📋 Copy</button>

                                    <p style="margin: 15px 0 5px 0;"><strong>Tshark Extraction:</strong></p>
                                    <code class="copy-code">{ws_commands['tshark_extract']}</code>
                                    <button class="copy-btn" onclick="copyToClipboard(this)">📋 Copy</button>
                                </div>
                            </details>
                        </div>
                    </div>
                </div>
            """

        html += "          </div>"
        html += "        </div>"

        html += "      </div>"  # flow-details
        html += "    </div>"  # flow-details-collapsible
        html += "  </div>"  # flow-body
        html += "</div>"  # flow-detail-card

        return html

    def _generate_tcp_section(self, results: dict[str, Any]) -> str:
        """Generate TCP analysis section."""
        html = "<h2>🔌 TCP Analysis</h2>"

        # TCP Retransmissions
        retrans_data = results.get("retransmission", {})
        if retrans_data and retrans_data.get("total_retransmissions", 0) > 0:
            html += "<h3>📦 TCP Retransmissions</h3>"

            total_retrans = retrans_data.get("total_retransmissions", 0)
            rto_count = retrans_data.get("rto_count", 0)
            fast_retrans = retrans_data.get("fast_retrans_count", 0)

            # Calculate retransmission rate
            metadata = results.get("metadata", {})
            total_packets = metadata.get("total_packets", 0)
            retrans_rate = (total_retrans / total_packets * 100) if total_packets > 0 else 0

            # Enhanced metric cards with icons
            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card metric-danger">
                <div class="metric-icon">📦</div>
                <div class="metric-label">Total Retransmissions</div>
                <div class="metric-value">{total_retrans:,}</div>
                <div class="metric-subtext">{retrans_rate:.2f}% of total packets</div>
            </div>
            <div class="metric-card metric-warning">
                <div class="metric-icon">⏱️</div>
                <div class="metric-label">RTO (Timeout)</div>
                <div class="metric-value">{rto_count:,}</div>
                <div class="metric-subtext">{(rto_count/total_retrans*100) if total_retrans > 0 else 0:.1f}% of retransmissions</div>
            </div>
            <div class="metric-card metric-warning">
                <div class="metric-icon">⚡</div>
                <div class="metric-label">Fast Retransmissions</div>
                <div class="metric-value">{fast_retrans:,}</div>
                <div class="metric-subtext">{(fast_retrans/total_retrans*100) if total_retrans > 0 else 0:.1f}% of retransmissions</div>
            </div>
            """
            html += "</div>"

            # Add confidence overview
            html += self._generate_confidence_overview(retrans_data)

            # Top flows with retransmissions - Grouped by type
            retrans_list = retrans_data.get("retransmissions", [])
            if retrans_list:
                # Group by flow first
                flows = {}
                for r in retrans_list[:200]:  # Increased limit for better coverage
                    flow_key = f"{r.get('src_ip')}:{r.get('src_port')} → {r.get('dst_ip')}:{r.get('dst_port')}"
                    if flow_key not in flows:
                        flows[flow_key] = []
                    flows[flow_key].append(r)

                # Classify each flow by dominant retransmission type
                html += self._generate_grouped_retransmission_analysis(flows, total_packets)

        # TCP Handshakes
        handshake_data = results.get("tcp_handshake", {})
        if handshake_data:
            html += "<h3>🤝 TCP Handshakes</h3>"

            total_handshakes = handshake_data.get("total_handshakes", 0)
            slow_handshakes = handshake_data.get("slow_handshakes", 0)

            if total_handshakes > 0:
                html += '<div class="summary-grid">'
                html += f"""
                <div class="metric-card">
                    <div class="metric-label">Total Handshakes</div>
                    <div class="metric-value">{total_handshakes:,}</div>
                </div>
                <div class="metric-card" style="border-left-color: {'#ffc107' if slow_handshakes > 0 else '#28a745'};">
                    <div class="metric-label">Slow Handshakes</div>
                    <div class="metric-value">{slow_handshakes:,}</div>
                </div>
                """
                html += "</div>"

        # RTT Analysis
        rtt_data = results.get("rtt", {})
        if rtt_data and rtt_data.get("flows_with_high_rtt", 0) > 0:
            html += "<h3>⏲️ RTT (Round Trip Time) Analysis</h3>"

            global_stats = rtt_data.get("global_statistics", {})
            mean_rtt = global_stats.get("mean_rtt", 0) * 1000  # Convert to ms
            max_rtt = global_stats.get("max_rtt", 0) * 1000
            flows_with_high_rtt = rtt_data.get("flows_with_high_rtt", 0)

            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Mean RTT</div>
                <div class="metric-value">{mean_rtt:.2f} ms</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Max RTT</div>
                <div class="metric-value">{max_rtt:.2f} ms</div>
            </div>
            <div class="metric-card" style="border-left-color: #ffc107;">
                <div class="metric-label">Flows with High RTT</div>
                <div class="metric-value">{flows_with_high_rtt}</div>
            </div>
            """
            html += "</div>"

            # Add interpretation
            html += self._generate_rtt_interpretation(mean_rtt, max_rtt, flows_with_high_rtt)

            # Top flows with high RTT - Collapsible section
            flow_stats = rtt_data.get("flow_statistics", [])
            if flow_stats:
                # Limit to top 10
                sorted_flows = sorted(flow_stats, key=lambda x: x.get("max_rtt", 0), reverse=True)[:10]

                # Collapsible section for flows (Pure CSS with checkbox)
                html += '<div class="collapsible-section">'
                html += f"""
                    <input type="checkbox" id="collapsible-rtt-flows" class="collapsible-checkbox">
                    <label for="collapsible-rtt-flows" class="collapsible-header">
                        <span class="toggle-icon">▶</span>
                        <span class="header-title">Top Flows with High RTT ({len(sorted_flows)})</span>
                        <span class="header-info">Click to expand flow details</span>
                    </label>
                    <div class="collapsible-content">
                        <div class="content-inner">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Flow</th>
                                        <th>Mean RTT</th>
                                        <th>Max RTT</th>
                                        <th>
                                            Measurements
                                            <span class="tooltip-container">
                                                <span class="tooltip-icon">i</span>
                                                <span class="tooltip-text">
                                                    NUMBER OF RTT SAMPLES COLLECTED FOR THIS FLOW. MORE MEASUREMENTS PROVIDE A MORE RELIABLE AVERAGE RTT VALUE.
                                                </span>
                                            </span>
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                """

                for flow in sorted_flows:
                    flow_mean = flow.get("mean_rtt", 0) * 1000
                    flow_max = flow.get("max_rtt", 0) * 1000
                    html += f"""
                                    <tr>
                                        <td><code>{flow.get("flow_key", "N/A")}</code></td>
                                        <td>{flow_mean:.2f} ms</td>
                                        <td>{flow_max:.2f} ms</td>
                                        <td>{flow.get("measurements_count", 0)}</td>
                                    </tr>
                    """

                html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                """

        # TCP Window Analysis
        window_data = results.get("tcp_window", {})
        if window_data and window_data.get("flows_with_issues", 0) > 0:
            html += "<h3>🪟 TCP Window Analysis</h3>"

            # Calculate total zero windows and duration
            flow_stats = window_data.get("flow_statistics", [])
            total_zero_windows = sum(f.get("zero_window_count", 0) for f in flow_stats)
            # NOTE: This is the SUM of all flows' blocked time, which can exceed capture duration
            # if multiple flows are blocked simultaneously. This represents the cumulative impact.
            total_duration = sum(f.get("zero_window_total_duration", 0) for f in flow_stats)

            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card" style="border-left-color: #ffc107;">
                <div class="metric-label">Flows with Window Issues</div>
                <div class="metric-value">{window_data.get("flows_with_issues", 0)}</div>
            </div>
            <div class="metric-card" style="border-left-color: #dc3545;">
                <div class="metric-label">Total Zero Windows</div>
                <div class="metric-value">{total_zero_windows}</div>
            </div>
            <div class="metric-card" style="border-left-color: #dc3545;">
                <div class="metric-label">
                    Cumulative Blocked Time
                    <span class="tooltip-wrapper">
                        <span class="tooltip-icon">ℹ️</span>
                        <span class="tooltip-text">
                            Sum of blocked time across all flows. Each flow's zero-window duration is added together, so this metric can exceed capture duration if multiple flows are blocked simultaneously. For example, if 10 flows are each blocked for 1 hour in a 1-hour capture, the cumulative blocked time is 10 hours. This represents the total throughput impact across the network.
                        </span>
                    </span>
                </div>
                <div class="metric-value">{self._format_duration(total_duration)}</div>
            </div>
            """
            html += "</div>"

            # Add contextual explanation if cumulative time significantly exceeds capture duration
            metadata = results.get("metadata", {})
            capture_duration = metadata.get("capture_duration", 0)
            if capture_duration > 0 and total_duration > capture_duration:
                multiplier = total_duration / capture_duration
                flows_with_issues_count = window_data.get("flows_with_issues", 0)
                html += f"""
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0 0 10px 0; font-weight: bold; color: #856404;">
                        ℹ️ Understanding Cumulative Blocked Time
                    </p>
                    <p style="margin: 0; font-size: 0.95em; color: #856404;">
                        The cumulative blocked time ({self._format_duration(total_duration)}) exceeds the capture duration
                        ({self._format_duration(capture_duration)}) by {multiplier:.1f}x. This is normal when multiple flows
                        are blocked simultaneously. In this capture, <strong>{flows_with_issues_count} flow(s)</strong> experienced
                        zero-window conditions, and their blocked times are summed together to show the total throughput impact.
                    </p>
                    <p style="margin: 10px 0 0 0; font-size: 0.95em; color: #856404;">
                        <strong>Example:</strong> If 10 flows are each blocked for 1 hour during the same 1-hour capture window,
                        the cumulative blocked time is 10 hours, representing the aggregate impact across all affected connections.
                    </p>
                </div>
                """

            # Get total packets and capture duration for context
            metadata = results.get("metadata", {})
            total_packets = metadata.get("total_packets", 0)
            capture_duration = metadata.get("capture_duration", 0)

            # Generate grouped window analysis by bottleneck type
            html += self._generate_grouped_window_analysis(window_data, total_packets, capture_duration)

        return html

    def _generate_window_explanation_concise(self, type_key: str, flows: list) -> str:
        """Generate concise explanation for a TCP window issue type."""
        explanations = {
            "application": """
                <div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Application Bottleneck</strong> - Receiver application not consuming data fast enough<br>
                    <strong>Type:</strong> Receiver window filled, sender blocked from transmitting<br>
                    <strong>Impact:</strong> <span style='color: #dc3545;'>CRITICAL</span> - Throughput severely limited by slow consumer
                    </p>
                </div>
            """,
            "receiver": """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Receiver Constraint</strong> - Receiver advertised small window (network/buffer limits)<br>
                    <strong>Impact:</strong> <span style='color: #ffc107;'>HIGH</span> - Flow control limiting throughput<br>
                    <strong>Causes:</strong> Buffer constraints, receiver tuning, intentional throttling
                    </p>
                </div>
            """,
            "network": """
                <div style="background: #ffe5cc; border-left: 4px solid #fd7e14; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Network Bottleneck</strong> - Network congestion causing window reduction<br>
                    <strong>Impact:</strong> <span style='color: #fd7e14;'>MODERATE</span> - Congestion control reducing throughput<br>
                    <strong>Causes:</strong> Packet loss, high latency, congestion detected
                    </p>
                </div>
            """,
            "other": """
                <div style="background: #e2e3e5; border-left: 4px solid #6c757d; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Other Window Issues</strong> - Various window-related constraints<br>
                    <strong>Recommendation:</strong> Review flow details for specific patterns
                    </p>
                </div>
            """,
        }

        return explanations.get(type_key, "")

    def _generate_window_quick_actions(self, analysis: dict, type_key: str) -> str:
        """Generate quick actions box for window analysis."""
        html = '<div style="background: #e7f3ff; border: 1px solid #2196F3; border-radius: 6px; padding: 15px; margin-bottom: 15px;">'
        html += '<h5 style="margin: 0 0 10px 0; color: #1976D2;">💡 Suggested Actions</h5>'
        html += '<ul style="margin: 5px 0; padding-left: 20px; font-size: 0.9em;">'

        # Type-specific actions
        if type_key == "application":
            html += "<li><strong>Profile receiver application</strong> to identify slow processing</li>"
            html += '<li>Check CPU/memory usage: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">top -p &lt;pid&gt;</code> or <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">htop</code></li>'
            html += '<li>Monitor I/O bottlenecks: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">iostat -x 1</code></li>'
            html += "<li>Review application logs for errors or slow queries</li>"
            html += "<li>Consider increasing receive buffer size if application is optimized</li>"
        elif type_key == "receiver":
            html += "<li><strong>Tune TCP receive buffers</strong> on receiver side</li>"
            html += '<li>Check current settings: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">sysctl net.ipv4.tcp_rmem</code></li>'
            html += '<li>Increase buffer size: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"</code></li>'
            html += "<li>Enable window scaling if not already enabled</li>"
            html += "<li>Verify application socket options (SO_RCVBUF)</li>"
        elif type_key == "network":
            html += "<li><strong>Investigate network path</strong> for congestion or packet loss</li>"
            html += '<li>Check for retransmissions: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">netstat -s | grep retrans</code></li>'
            html += '<li>Monitor congestion window: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">ss -ti</code></li>'
            html += "<li>Review router/switch metrics for drops or congestion</li>"
            html += "<li>Consider QoS/traffic shaping if congestion persists</li>"
        else:
            html += "<li><strong>Analyze individual flows</strong> for specific bottleneck patterns</li>"
            html += "<li>Review tshark output for detailed window behavior</li>"
            html += "<li>Compare window sizes across different flows</li>"

        html += "</ul>"
        html += "</div>"

        return html

    def _generate_window_tshark_box(self, analysis: dict) -> str:
        """Generate tshark command box for window analysis with one-click copy."""
        # Build tshark filter for window analysis
        tshark_filter = "tcp.window_size_value == 0 || tcp.analysis.zero_window"

        html = '<div style="background: #263238; color: #aed581; padding: 15px; margin-bottom: 20px; border-radius: 6px; font-family: monospace; position: relative;">'
        html += '<div style="color: #81c784; margin-bottom: 8px; font-size: 0.85em;">📌 Tshark Command (click to select):</div>'
        html += f'<pre style="margin: 0; overflow-x: auto; cursor: text; user-select: all; background: #1e1e1e; padding: 10px; border-radius: 4px; font-size: 0.85em;" onclick="window.getSelection().selectAllChildren(this);">tshark -r &lt;file.pcap&gt; -Y \'{tshark_filter}\' -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.window_size_value -e tcp.window_size</pre>'
        html += '<div style="color: #90caf9; margin-top: 8px; font-size: 0.8em;">💡 Click command to select, then Ctrl+C (Cmd+C) to copy | Output: CSV with headers</div>'
        html += "</div>"

        return html

    def _generate_window_flow_table(self, flows: list, type_key: str) -> str:
        """Generate compact table of flows for window analysis."""
        from datetime import datetime

        # Limit to top 10 flows
        flows_to_show = flows[:10]

        html = '<div style="overflow-x: auto; margin-bottom: 20px;">'
        html += '<table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #dee2e6;">'
        html += '<thead style="background: #e9ecef;">'
        html += "<tr>"
        html += '<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Flow</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">First Zero Win</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Zero Windows</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Blocked Time</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Min Window</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Avg Window</th>'
        html += "</tr>"
        html += "</thead>"
        html += "<tbody>"

        for flow in flows_to_show:
            flow_key = flow.get("flow_key", "N/A")
            zero_window_count = flow.get("zero_window_count", 0)
            zero_window_duration = flow.get("zero_window_total_duration", 0)
            min_window = flow.get("min_window", 0)
            avg_window = flow.get("mean_window", 0)

            # Get first zero window timestamp
            first_zero_window_time = flow.get("first_zero_window_time", None)
            if first_zero_window_time:
                dt = datetime.fromtimestamp(first_zero_window_time)
                timestamp_iso = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                timestamp_iso = "N/A"

            html += '<tr style="border-bottom: 1px solid #dee2e6;">'
            html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{flow_key}</td>'
            html += f'<td style="padding: 10px; text-align: center; font-family: monospace; font-size: 0.85em; color: #555;">{timestamp_iso}</td>'
            html += f'<td style="padding: 10px; text-align: center;"><strong>{zero_window_count}</strong></td>'
            html += f'<td style="padding: 10px; text-align: center;">{self._format_duration(zero_window_duration)}</td>'
            html += f'<td style="padding: 10px; text-align: center;">{min_window:,} bytes</td>'
            html += f'<td style="padding: 10px; text-align: center;">{avg_window:,} bytes</td>'
            html += "</tr>"

        html += "</tbody>"
        html += "</table>"
        html += "</div>"

        if len(flows) > 10:
            html += f'<p style="color: #6c757d; font-size: 0.9em; font-style: italic; margin-top: 10px;">Showing top 10 of {len(flows)} flows. See JSON report for complete data.</p>'

        return html

    def _generate_window_type_section(self, type_key: str, title: str, flows: list, color: str, emoji: str, capture_duration: float = 0) -> str:
        """Generate a section for one window bottleneck type with explanation + flow table."""
        flow_count = len(flows)
        total_zero_windows = sum(f.get("zero_window_count", 0) for f in flows)
        total_duration = sum(f.get("zero_window_total_duration", 0.0) for f in flows)

        # Analyze root cause
        root_cause_analysis = self._analyze_window_root_cause(flows, type_key)

        html = f'<div class="window-type-section" style="margin: 20px 0; border: 2px solid {color}; border-radius: 8px; overflow: hidden;">'
        html += f'<div class="window-type-header" style="background: {color}; color: white; padding: 15px; font-weight: bold; font-size: 1.1em;">'
        html += f'{emoji} {title} — {flow_count} flow{"s" if flow_count != 1 else ""} ({total_zero_windows} zero windows, {self._format_duration(total_duration)} blocked)'
        html += "</div>"
        html += '<div class="window-type-body" style="padding: 20px; background: #f8f9fa;">'

        # Add root cause analysis (if found)
        if root_cause_analysis["root_cause"] or root_cause_analysis["pattern"]:
            html += self._generate_window_root_cause_box(root_cause_analysis, type_key, flows)

        # Add concise explanation
        html += self._generate_window_explanation_concise(type_key, flows)

        # FIX #4: Add warning for stuck flows (those with unclosed zero windows)
        if capture_duration > 0:
            stuck_flows = []
            for flow in flows:
                blocked_time = flow.get("zero_window_total_duration", 0)
                if blocked_time > capture_duration * 0.95:  # Within 95% of capture duration
                    stuck_flows.append(flow)

            if len(stuck_flows) > 0:
                html += f"""
                <div style="background: #fff3cd; border-left: 4px solid #dc3545; padding: 15px; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0 0 8px 0;"><strong>⚠️ Stuck Flows Detected</strong></p>
                    <p style="margin: 0; font-size: 0.95em; color: #856404;">
                        <strong>{len(stuck_flows)} flow(s)</strong> remained in zero-window state for the entire capture duration
                        (~{self._format_duration(capture_duration)}). These are likely <strong>zombie connections</strong> that
                        were established but immediately blocked and never recovered. Consider investigating why these connections
                        are stuck (application hung, receiver crashed, or network issue).
                    </p>
                </div>
                """

        # Add quick actions
        html += self._generate_window_quick_actions(root_cause_analysis, type_key)

        # Add tshark command (one-click copy)
        html += self._generate_window_tshark_box(root_cause_analysis)

        # Add compact flow table
        html += self._generate_window_flow_table(flows, type_key)

        html += "</div>"
        html += "</div>"

        return html

    def _generate_grouped_window_analysis(self, window_data: dict, total_packets: int, capture_duration: float = 0) -> str:
        """Generate window analysis grouped by bottleneck type (application, receiver, network, other)."""
        flow_stats = window_data.get("flow_statistics", [])

        # Filter to only flows with zero windows
        flows_with_zero_windows = [f for f in flow_stats if f.get("zero_window_count", 0) > 0]

        if not flows_with_zero_windows:
            return ""

        # Classify flows by bottleneck type
        flow_groups = {
            "application": [],  # Application bottleneck (critical)
            "receiver": [],     # Receiver constraint (high)
            "network": [],      # Network congestion (moderate)
            "other": [],        # Other/unknown (low)
        }

        for flow in flows_with_zero_windows:
            bottleneck = flow.get("suspected_bottleneck", "none")
            zero_count = flow.get("zero_window_count", 0)
            zero_duration = flow.get("zero_window_total_duration", 0.0)
            low_window_pct = flow.get("low_window_percentage", 0.0)

            # Classify by severity and characteristics
            # Application: High zero window count OR long duration (receiver not consuming)
            if bottleneck == "application" or (zero_count > 5 or zero_duration > 1.0):
                flow_groups["application"].append(flow)
            # Receiver: Low window percentage with zero windows (buffer constraints)
            elif bottleneck == "receiver" or (low_window_pct > 30 and zero_count > 0):
                flow_groups["receiver"].append(flow)
            # Network: Correlated with retransmissions (congestion)
            elif bottleneck == "network":
                flow_groups["network"].append(flow)
            # Other: Mild issues or unknown
            else:
                flow_groups["other"].append(flow)

        # Sort each group by severity (zero window count × duration)
        for group_type in flow_groups:
            flow_groups[group_type] = sorted(
                flow_groups[group_type],
                key=lambda f: f.get("zero_window_count", 0) * f.get("zero_window_total_duration", 0.0),
                reverse=True
            )

        html = ""

        # Generate section for each type (only if flows exist)
        if flow_groups["application"]:
            html += self._generate_window_type_section(
                "application",
                "Application Bottleneck (Critical)",
                flow_groups["application"],
                "#dc3545",
                "🔴",
                capture_duration
            )

        if flow_groups["receiver"]:
            html += self._generate_window_type_section(
                "receiver",
                "Receiver Buffer Constraint (High)",
                flow_groups["receiver"],
                "#ffc107",
                "🟡",
                capture_duration
            )

        if flow_groups["network"]:
            html += self._generate_window_type_section(
                "network",
                "Network Congestion (Moderate)",
                flow_groups["network"],
                "#fd7e14",
                "🟠",
                capture_duration
            )

        if flow_groups["other"]:
            html += self._generate_window_type_section(
                "other",
                "Other Window Issues (Low)",
                flow_groups["other"],
                "#6c757d",
                "⚪",
                capture_duration
            )

        return html

    def _analyze_jitter_root_cause(self, flows: list, severity_key: str) -> dict:
        """
        Analyze root cause and patterns for jitter issues.

        Args:
            flows: List of flow dicts with jitter statistics
            severity_key: Severity level (critical/high/medium/low)

        Returns:
            dict with root_cause, action, pattern, tshark_filter
        """
        result = {"root_cause": None, "action": None, "pattern": None, "tshark_filter": None}

        if not flows:
            return result

        # Extract destination IPs and services
        dest_ips = {}
        services = {}

        for flow in flows:
            flow_str = flow.get("flow", "")
            # Parse "src_ip:src_port -> dst_ip:dst_port (proto)"
            if " -> " in flow_str:
                dst_part = flow_str.split(" -> ")[1].split(" ")[0]
                if ":" in dst_part:
                    dst_ip = dst_part.rsplit(":", 1)[0]
                    dst_port = dst_part.rsplit(":", 1)[1]
                    dest_ips[dst_ip] = dest_ips.get(dst_ip, 0) + 1

                    # Identify service type
                    try:
                        port_int = int(dst_port)
                        service_name, _, _, _, _ = self._identify_service(port_int)
                        services[service_name] = services.get(service_name, 0) + 1
                    except (ValueError, TypeError):
                        pass

        # Pattern detection: Common destination
        if dest_ips:
            most_common_ip = max(dest_ips.items(), key=lambda x: x[1])

            if most_common_ip[1] == len(flows):
                result["pattern"] = f"All flows target {most_common_ip[0]}"

                # Check for reserved IPs
                ip_info = self._identify_ip_range(most_common_ip[0])
                if ip_info:
                    result["root_cause"] = f"{most_common_ip[0]} is {ip_info['name']} ({ip_info['rfc']})"
                    result["action"] = ip_info['action']
                else:
                    # Real network - suggest investigation
                    result["root_cause"] = f"High jitter to {most_common_ip[0]} across all flows"
                    result["action"] = f"Investigate network path to {most_common_ip[0]} for congestion or routing issues"

                # Generate tshark filter
                result["tshark_filter"] = f"ip.dst == {most_common_ip[0]}"

            elif most_common_ip[1] >= len(flows) * 0.5:
                result["pattern"] = f"{most_common_ip[1]} flows target {most_common_ip[0]} (dominant pattern)"
                result["action"] = f"Focus investigation on path to {most_common_ip[0]}"

        # Service-based root cause
        if services and not result["root_cause"]:
            most_common_service = max(services.items(), key=lambda x: x[1])
            if most_common_service[0] != "Unknown":
                result["root_cause"] = f"High jitter affecting {most_common_service[0]} traffic"
                result["action"] = f"Check QoS policies and network prioritization for {most_common_service[0]}"

        # Default actions by severity
        if not result["action"]:
            if severity_key == "critical":
                result["action"] = "Investigate network congestion, bandwidth saturation, or routing instability"
            elif severity_key == "high":
                result["action"] = "Check for packet reordering, multipath routing, or bursty traffic patterns"
            else:
                result["action"] = "Monitor for trends; may be acceptable for non-real-time services"

        # Default tshark filter
        if not result["tshark_filter"]:
            result["tshark_filter"] = "frame.time_delta_displayed > 0.1"  # Packets with >100ms gap

        return result

    def _generate_jitter_root_cause_box(self, analysis: dict, severity_key: str, flows: list) -> str:
        """Generate root cause analysis box for jitter issues (purple gradient)."""
        # Use consistent purple gradient
        bg_gradient = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"

        # Severity indicators
        severity_emojis = {"critical": "🔴", "high": "🟡", "medium": "🟢", "low": "⚪"}
        severity_texts = {"critical": "Critical Severity", "high": "High Severity", "medium": "Medium Severity", "low": "Low Severity"}

        severity_emoji = severity_emojis.get(severity_key, "⚪")
        severity_text = severity_texts.get(severity_key, "Low Severity")

        html = f'<div style="background: {bg_gradient}; color: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">'
        html += '<h4 style="margin: 0 0 10px 0; font-size: 1.1em;">🎯 Root Cause Analysis</h4>'

        # Severity indicator
        html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Severity:</strong> {severity_emoji} {severity_text}</p>'

        # Root cause
        if analysis["root_cause"]:
            html += f'<p style="margin: 5px 0; font-size: 1em;"><strong>Cause:</strong> {analysis["root_cause"]}</p>'

        # Pattern
        if analysis["pattern"]:
            html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Pattern:</strong> {analysis["pattern"]}</p>'

        # RFC 3393 note
        html += '<div style="background: rgba(255,255,255,0.15); padding: 10px; margin: 10px 0; border-radius: 5px; border-left: 3px solid rgba(255,255,255,0.5);">'
        html += '<p style="margin: 0; font-size: 0.9em;"><strong>📋 RFC 3393 Jitter:</strong></p>'
        html += '<p style="margin: 5px 0 0 0; font-size: 0.85em;">Inter-Packet Delay Variation (IPDV). Critical for real-time applications (VoIP, gaming, streaming).</p>'
        html += '</div>'

        # Recommended action
        if analysis["action"]:
            html += '<div style="background: rgba(255,255,255,0.2); padding: 10px; margin-top: 10px; border-radius: 5px;">'
            html += f'<p style="margin: 0; font-size: 0.9em;"><strong>💡 Recommended Action:</strong></p>'
            html += f'<p style="margin: 5px 0 0 0; font-size: 0.85em;">{analysis["action"]}</p>'
            html += '</div>'

        html += '</div>'
        return html

    def _generate_jitter_explanation_concise(self, severity_key: str, flows: list) -> str:
        """Generate concise explanation for jitter severity level."""
        explanations = {
            "critical": """
                <div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Critical Jitter</strong> - Severe delay variation (>100ms max or >30ms mean)<br>
                    <strong>Impact:</strong> <span style='color: #dc3545;'>SEVERE</span> - Unusable for real-time applications<br>
                    <strong>Causes:</strong> Network congestion, bandwidth saturation, routing instability
                    </p>
                </div>
            """,
            "high": """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>High Jitter</strong> - Noticeable delay variation (50-100ms)<br>
                    <strong>Impact:</strong> <span style='color: #ffc107;'>HIGH</span> - Degraded quality for video/audio<br>
                    <strong>Causes:</strong> Packet reordering, multipath routing, bursty traffic
                    </p>
                </div>
            """,
            "medium": """
                <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Medium Jitter</strong> - Moderate delay variation (30-50ms)<br>
                    <strong>Impact:</strong> <span style='color: #28a745;'>MODERATE</span> - Acceptable for most applications<br>
                    <strong>Note:</strong> May affect latency-sensitive services
                    </p>
                </div>
            """,
            "low": """
                <div style="background: #e2e3e5; border-left: 4px solid #6c757d; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Low Jitter</strong> - Minimal delay variation (<30ms)<br>
                    <strong>Impact:</strong> <span style='color: #6c757d;'>LOW</span> - Excellent network performance
                    </p>
                </div>
            """,
        }

        return explanations.get(severity_key, "")

    def _generate_jitter_quick_actions(self, analysis: dict, severity_key: str) -> str:
        """Generate quick actions box for jitter troubleshooting."""
        html = '<div style="background: #e7f3ff; border: 1px solid #2196F3; border-radius: 6px; padding: 15px; margin-bottom: 15px;">'
        html += '<h5 style="margin: 0 0 10px 0; color: #1976D2;">💡 Suggested Actions</h5>'
        html += '<ul style="margin: 5px 0; padding-left: 20px; font-size: 0.9em;">'

        # Severity-specific actions
        if severity_key == "critical":
            html += '<li><strong>Monitor link saturation:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">sar -n DEV 1</code> (Linux)</li>'
            html += '<li><strong>Check interface errors:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">netstat -i</code> or <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">ip -s link</code></li>'
            html += '<li>Investigate routing changes or BGP flaps</li>'
            html += '<li>Consider traffic shaping or QoS prioritization</li>'
        elif severity_key == "high":
            html += '<li><strong>Check for packet reordering:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">netstat -s | grep reordering</code></li>'
            html += '<li><strong>Monitor queue depths:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">tc -s qdisc show</code></li>'
            html += '<li>Review multipath routing configuration (ECMP)</li>'
            html += '<li>Analyze traffic patterns for bursts</li>'
        elif severity_key == "medium":
            html += '<li><strong>Monitor trends:</strong> Track jitter over time for degradation</li>'
            html += '<li>Review network topology for suboptimal paths</li>'
            html += '<li>Consider buffering strategies for applications</li>'
        else:
            html += '<li><strong>Baseline established:</strong> Document current jitter levels</li>'
            html += '<li>Continue monitoring for changes</li>'

        html += '</ul>'
        html += '</div>'

        return html

    def _generate_jitter_tshark_box(self, analysis: dict) -> str:
        """Generate tshark command box for jitter debugging."""
        tshark_filter = analysis.get("tshark_filter", "frame.time_delta_displayed > 0.1")

        html = '<div style="background: #263238; color: #aed581; padding: 15px; margin-bottom: 20px; border-radius: 6px; font-family: monospace; position: relative;">'
        html += '<div style="color: #81c784; margin-bottom: 8px; font-size: 0.85em;">📌 Tshark Command (click to select):</div>'
        html += f'<pre style="margin: 0; overflow-x: auto; cursor: text; user-select: all; background: #1e1e1e; padding: 10px; border-radius: 4px; font-size: 0.85em;" onclick="window.getSelection().selectAllChildren(this);">tshark -r &lt;file.pcap&gt; -Y \'{tshark_filter}\' -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_relative -e frame.time_delta_displayed -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport</pre>'
        html += '<div style="color: #90caf9; margin-top: 8px; font-size: 0.8em;">💡 Click command to select, then Ctrl+C (Cmd+C) to copy | Output: CSV with headers</div>'
        html += '</div>'

        return html

    def _generate_jitter_flow_table(self, flows: list, severity_key: str) -> str:
        """Generate compact table of flows for jitter analysis."""
        from datetime import datetime

        # Limit to top 10 flows
        flows_to_show = flows[:10]

        html = '<div style="overflow-x: auto; margin-bottom: 20px;">'
        html += '<table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #dee2e6;">'
        html += '<thead style="background: #e9ecef;">'
        html += '<tr>'
        html += '<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Flow</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">First Packet</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Mean Jitter</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Max Jitter</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">P95 Jitter</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Packets</th>'
        html += '</tr>'
        html += '</thead>'
        html += '<tbody>'

        for flow in flows_to_show:
            flow_str = flow.get("flow", "N/A")
            mean_jitter = flow.get("mean_jitter", 0) * 1000  # Convert to ms
            max_jitter = flow.get("max_jitter", 0) * 1000
            p95_jitter = flow.get("p95_jitter", 0) * 1000
            packets = flow.get("packets", 0)

            # Get first packet timestamp
            first_packet_time = flow.get("first_packet_time", None)
            if first_packet_time:
                dt = datetime.fromtimestamp(first_packet_time)
                timestamp_iso = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                timestamp_iso = "N/A"

            html += '<tr style="border-bottom: 1px solid #dee2e6;">'
            html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{flow_str}</td>'
            html += f'<td style="padding: 10px; text-align: center; font-family: monospace; font-size: 0.85em; color: #555;">{timestamp_iso}</td>'
            html += f'<td style="padding: 10px; text-align: center;"><strong>{mean_jitter:.2f} ms</strong></td>'
            html += f'<td style="padding: 10px; text-align: center;">{max_jitter:.2f} ms</td>'
            html += f'<td style="padding: 10px; text-align: center;">{p95_jitter:.2f} ms</td>'
            html += f'<td style="padding: 10px; text-align: center;">{packets}</td>'
            html += '</tr>'

        html += '</tbody>'
        html += '</table>'
        html += '</div>'

        if len(flows) > 10:
            html += f'<p style="color: #6c757d; font-size: 0.9em; font-style: italic; margin-top: 10px;">Showing top 10 of {len(flows)} flows. See JSON report for complete data.</p>'

        return html

    def _generate_jitter_severity_section(self, severity_key: str, title: str, flows: list, color: str, emoji: str) -> str:
        """Generate a section for one jitter severity level with RCA + flow table."""
        flow_count = len(flows)
        total_packets = sum(f.get("packets", 0) for f in flows)
        avg_mean_jitter = sum(f.get("mean_jitter", 0) for f in flows) / flow_count if flow_count > 0 else 0
        avg_mean_jitter_ms = avg_mean_jitter * 1000

        # Analyze root cause
        root_cause_analysis = self._analyze_jitter_root_cause(flows, severity_key)

        html = f'<div class="jitter-severity-section" style="margin: 20px 0; border: 2px solid {color}; border-radius: 8px; overflow: hidden;">'
        html += f'<div class="jitter-severity-header" style="background: {color}; color: white; padding: 15px; font-weight: bold; font-size: 1.1em;">'
        html += f'{emoji} {title} — {flow_count} flow{"s" if flow_count != 1 else ""} ({total_packets:,} packets, avg {avg_mean_jitter_ms:.2f}ms jitter)'
        html += '</div>'
        html += '<div class="jitter-severity-body" style="padding: 20px; background: #f8f9fa;">'

        # Add root cause analysis (if found)
        if root_cause_analysis["root_cause"] or root_cause_analysis["pattern"]:
            html += self._generate_jitter_root_cause_box(root_cause_analysis, severity_key, flows)

        # Add concise explanation
        html += self._generate_jitter_explanation_concise(severity_key, flows)

        # Add quick actions
        html += self._generate_jitter_quick_actions(root_cause_analysis, severity_key)

        # Add tshark command
        html += self._generate_jitter_tshark_box(root_cause_analysis)

        # Add compact flow table
        html += self._generate_jitter_flow_table(flows, severity_key)

        html += '</div>'
        html += '</div>'

        return html

    def _generate_grouped_jitter_analysis(self, jitter_data: dict) -> str:
        """Generate jitter analysis grouped by severity (critical, high, medium, low)."""
        high_jitter_flows = jitter_data.get("high_jitter_flows", [])

        if not high_jitter_flows:
            return ""

        # Classify flows by severity
        flow_groups = {
            "critical": [],  # Critical jitter (>100ms max or >30ms mean)
            "high": [],      # High jitter (50-100ms)
            "medium": [],    # Medium jitter (30-50ms)
            "low": [],       # Low jitter (<30ms)
        }

        for flow in high_jitter_flows:
            severity = flow.get("severity", "low")
            flow_groups[severity].append(flow)

        # Sort each group by mean jitter (descending)
        for group_type in flow_groups:
            flow_groups[group_type] = sorted(
                flow_groups[group_type],
                key=lambda f: f.get("mean_jitter", 0),
                reverse=True
            )

        html = ""

        # Generate section for each severity (only if flows exist)
        if flow_groups["critical"]:
            html += self._generate_jitter_severity_section(
                "critical",
                "Critical Jitter (Severe Delay Variation)",
                flow_groups["critical"],
                "#dc3545",
                "🔴"
            )

        if flow_groups["high"]:
            html += self._generate_jitter_severity_section(
                "high",
                "High Jitter (Noticeable Delays)",
                flow_groups["high"],
                "#ffc107",
                "🟡"
            )

        if flow_groups["medium"]:
            html += self._generate_jitter_severity_section(
                "medium",
                "Medium Jitter (Moderate Variation)",
                flow_groups["medium"],
                "#28a745",
                "🟢"
            )

        if flow_groups["low"]:
            html += self._generate_jitter_severity_section(
                "low",
                "Low Jitter (Excellent Performance)",
                flow_groups["low"],
                "#6c757d",
                "⚪"
            )

        return html

    def _analyze_dns_root_cause(self, transactions: list, issue_type: str) -> dict:
        """
        Analyze root cause and patterns for DNS issues.

        Args:
            transactions: List of DNS transaction dicts
            issue_type: Issue type (timeout/error/slow/k8s)

        Returns:
            dict with root_cause, action, pattern, tshark_filter
        """
        result = {"root_cause": None, "action": None, "pattern": None, "tshark_filter": None}

        if not transactions:
            return result

        # Extract domains and servers
        domains = {}
        servers = {}
        error_codes = {}

        for trans in transactions:
            query = trans.get("query", {})
            response = trans.get("response", {})

            domain = query.get("query_name", "")
            server_ip = query.get("dst_ip", "")
            error_code = response.get("response_code_name", "")

            if domain:
                domains[domain] = domains.get(domain, 0) + 1
            if server_ip:
                servers[server_ip] = servers.get(server_ip, 0) + 1
            if error_code and error_code != "NOERROR":
                error_codes[error_code] = error_codes.get(error_code, 0) + 1

        # Pattern detection: Common domain
        if domains:
            most_common_domain = max(domains.items(), key=lambda x: x[1])

            if most_common_domain[1] >= len(transactions) * 0.5:
                result["pattern"] = f"{most_common_domain[1]} queries for {most_common_domain[0]}"

                # Check for K8s domains
                if ".cluster.local" in most_common_domain[0] or ".svc." in most_common_domain[0]:
                    result["root_cause"] = f"Kubernetes DNS lookup for {most_common_domain[0]}"
                    result["action"] = "Normal K8s multi-level DNS resolution (expected behavior)"
                else:
                    result["root_cause"] = f"Repeated failures for domain {most_common_domain[0]}"
                    result["action"] = f"Verify DNS configuration or domain availability for {most_common_domain[0]}"

                result["tshark_filter"] = f'dns.qry.name contains "{most_common_domain[0]}"'

        # Pattern detection: Common server
        if servers and not result["root_cause"]:
            most_common_server = max(servers.items(), key=lambda x: x[1])

            if most_common_server[1] >= len(transactions) * 0.5:
                result["pattern"] = f"{most_common_server[1]} queries to DNS server {most_common_server[0]}"
                result["root_cause"] = f"DNS server {most_common_server[0]} experiencing issues"
                result["action"] = f"Check DNS server {most_common_server[0]} health and connectivity"
                result["tshark_filter"] = f"ip.dst == {most_common_server[0]} and dns"

        # Error code patterns
        if error_codes and not result["root_cause"]:
            most_common_error = max(error_codes.items(), key=lambda x: x[1])
            result["root_cause"] = f"{most_common_error[0]} errors ({most_common_error[1]} occurrences)"

            if most_common_error[0] == "NXDOMAIN":
                result["action"] = "Verify domain names are correct; check for typos or expired domains"
            elif most_common_error[0] == "SERVFAIL":
                result["action"] = "DNS server misconfiguration or upstream resolver failure"
            elif most_common_error[0] == "REFUSED":
                result["action"] = "DNS server refusing queries; check ACLs and firewall rules"

        # Default actions by issue type
        if not result["action"]:
            if issue_type == "timeout":
                result["action"] = "Investigate DNS server connectivity, firewall rules, or network congestion"
            elif issue_type == "error":
                result["action"] = "Review DNS server logs for configuration issues or upstream failures"
            elif issue_type == "slow":
                result["action"] = "Check DNS server load, network latency, or consider local caching"
            else:
                result["action"] = "Monitor DNS performance and error rates over time"

        # Default tshark filter
        if not result["tshark_filter"]:
            if issue_type == "timeout":
                result["tshark_filter"] = "dns and not dns.response.in"
            elif issue_type == "slow":
                result["tshark_filter"] = "dns and dns.time > 0.5"
            else:
                result["tshark_filter"] = "dns and dns.flags.rcode != 0"

        return result

    def _generate_dns_root_cause_box(self, analysis: dict, issue_type: str, transactions: list) -> str:
        """Generate root cause analysis box for DNS issues (purple gradient)."""
        bg_gradient = "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"

        # Severity indicators by issue type
        severity_emojis = {"timeout": "🔴", "error": "🟡", "slow": "🟠", "k8s": "🟢"}
        severity_texts = {
            "timeout": "Critical Severity",
            "error": "High Severity",
            "slow": "Medium Severity",
            "k8s": "Informational"
        }

        severity_emoji = severity_emojis.get(issue_type, "⚪")
        severity_text = severity_texts.get(issue_type, "Unknown")

        html = f'<div style="background: {bg_gradient}; color: white; padding: 15px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">'
        html += '<h4 style="margin: 0 0 10px 0; font-size: 1.1em;">🎯 Root Cause Analysis</h4>'

        # Severity indicator
        html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Severity:</strong> {severity_emoji} {severity_text}</p>'

        # Root cause
        if analysis["root_cause"]:
            html += f'<p style="margin: 5px 0; font-size: 1em;"><strong>Cause:</strong> {analysis["root_cause"]}</p>'

        # Pattern
        if analysis["pattern"]:
            html += f'<p style="margin: 5px 0; font-size: 0.95em;"><strong>Pattern:</strong> {analysis["pattern"]}</p>'

        # RFC note
        html += '<div style="background: rgba(255,255,255,0.15); padding: 10px; margin: 10px 0; border-radius: 5px; border-left: 3px solid rgba(255,255,255,0.5);">'
        html += '<p style="margin: 0; font-size: 0.9em;"><strong>📋 RFC 1035 DNS:</strong></p>'
        html += '<p style="margin: 5px 0 0 0; font-size: 0.85em;">Domain Name System resolution. Timeouts >5s, errors (NXDOMAIN/SERVFAIL), and slow responses impact application performance.</p>'
        html += '</div>'

        # Recommended action
        if analysis["action"]:
            html += '<div style="background: rgba(255,255,255,0.2); padding: 10px; margin-top: 10px; border-radius: 5px;">'
            html += f'<p style="margin: 0; font-size: 0.9em;"><strong>💡 Recommended Action:</strong></p>'
            html += f'<p style="margin: 5px 0 0 0; font-size: 0.85em;">{analysis["action"]}</p>'
            html += '</div>'

        html += '</div>'
        return html

    def _generate_dns_explanation_concise(self, issue_type: str, transactions: list) -> str:
        """Generate concise explanation for DNS issue type."""
        explanations = {
            "timeout": """
                <div style="background: #f8d7da; border-left: 4px solid #dc3545; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>DNS Timeouts</strong> - No response from DNS server<br>
                    <strong>Impact:</strong> <span style='color: #dc3545;'>CRITICAL</span> - Application cannot resolve domains, service unavailable<br>
                    <strong>Causes:</strong> DNS server down, firewall blocking port 53, network congestion
                    </p>
                </div>
            """,
            "error": """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>DNS Errors</strong> - NXDOMAIN, SERVFAIL, or REFUSED responses<br>
                    <strong>Impact:</strong> <span style='color: #ffc107;'>HIGH</span> - Domain resolution failures, connection errors<br>
                    <strong>Causes:</strong> Invalid domains, misconfigured DNS server, upstream resolver issues
                    </p>
                </div>
            """,
            "slow": """
                <div style="background: #ffe5cc; border-left: 4px solid #fd7e14; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Slow DNS Responses</strong> - Response time >500ms<br>
                    <strong>Impact:</strong> <span style='color: #fd7e14;'>MODERATE</span> - Delayed application startup, user experience degradation<br>
                    <strong>Causes:</strong> DNS server overload, network latency, missing local cache
                    </p>
                </div>
            """,
            "k8s": """
                <div style="background: #d4edda; border-left: 4px solid #28a745; padding: 12px; margin-bottom: 15px; border-radius: 4px;">
                    <p style="margin: 0; font-size: 0.95em;">
                    <strong>Kubernetes Expected Errors</strong> - Normal multi-level DNS resolution<br>
                    <strong>Impact:</strong> <span style='color: #28a745;'>NONE</span> - Expected behavior for *.cluster.local domains<br>
                    <strong>Note:</strong> K8s tries multiple DNS suffixes; NXDOMAIN responses are normal
                    </p>
                </div>
            """,
        }

        return explanations.get(issue_type, "")

    def _generate_dns_quick_actions(self, analysis: dict, issue_type: str) -> str:
        """Generate quick actions box for DNS troubleshooting."""
        html = '<div style="background: #e7f3ff; border: 1px solid #2196F3; border-radius: 6px; padding: 15px; margin-bottom: 15px;">'
        html += '<h5 style="margin: 0 0 10px 0; color: #1976D2;">💡 Suggested Actions</h5>'
        html += '<ul style="margin: 5px 0; padding-left: 20px; font-size: 0.9em;">'

        # Issue-specific actions
        if issue_type == "timeout":
            html += '<li><strong>Test DNS connectivity:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">dig @&lt;dns_server&gt; example.com</code></li>'
            html += '<li><strong>Check port 53:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">nc -vz &lt;dns_server&gt; 53</code> or <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">telnet &lt;dns_server&gt; 53</code></li>'
            html += '<li>Verify firewall rules allow UDP/TCP port 53</li>'
            html += '<li>Check DNS server status and logs</li>'
        elif issue_type == "error":
            html += '<li><strong>Query specific domain:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">nslookup &lt;domain&gt;</code> or <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">dig &lt;domain&gt;</code></li>'
            html += '<li><strong>Check DNS server logs:</strong> Review for SERVFAIL or configuration errors</li>'
            html += '<li>Verify upstream resolvers are reachable</li>'
            html += '<li>Test with alternative DNS servers (8.8.8.8, 1.1.1.1)</li>'
        elif issue_type == "slow":
            html += '<li><strong>Measure DNS latency:</strong> <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">time dig example.com</code></li>'
            html += '<li><strong>Enable local DNS caching:</strong> dnsmasq, systemd-resolved, or nscd</li>'
            html += '<li>Check network latency to DNS server: <code style="background: #fff; padding: 2px 6px; border-radius: 3px; font-size: 0.85em;">ping &lt;dns_server&gt;</code></li>'
            html += '<li>Consider using closer DNS servers or CDN-based resolvers</li>'
        else:  # k8s
            html += '<li><strong>Normal behavior:</strong> No action required</li>'
            html += '<li>K8s DNS tries multiple search domains (e.g., .svc.cluster.local, .cluster.local)</li>'
            html += '<li>NXDOMAIN responses are expected during multi-level resolution</li>'

        html += '</ul>'
        html += '</div>'

        return html

    def _generate_dns_tshark_box(self, analysis: dict) -> str:
        """Generate tshark command box for DNS debugging."""
        tshark_filter = analysis.get("tshark_filter", "dns and dns.flags.rcode != 0")

        html = '<div style="background: #263238; color: #aed581; padding: 15px; margin-bottom: 20px; border-radius: 6px; font-family: monospace; position: relative;">'
        html += '<div style="color: #81c784; margin-bottom: 8px; font-size: 0.85em;">📌 Tshark Command (click to select):</div>'
        html += f'<pre style="margin: 0; overflow-x: auto; cursor: text; user-select: all; background: #1e1e1e; padding: 10px; border-radius: 4px; font-size: 0.85em;" onclick="window.getSelection().selectAllChildren(this);">tshark -r &lt;file.pcap&gt; -Y \'{tshark_filter}\' -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type -e dns.flags.rcode -e dns.time</pre>'
        html += '<div style="color: #90caf9; margin-top: 8px; font-size: 0.8em;">💡 Click command to select, then Ctrl+C (Cmd+C) to copy | Output: CSV with headers</div>'
        html += '</div>'

        return html

    def _generate_dns_transaction_table(self, transactions: list, issue_type: str) -> str:
        """Generate compact table of DNS transactions."""
        from datetime import datetime

        # Limit to top 10 transactions
        transactions_to_show = transactions[:10]

        html = '<div style="overflow-x: auto; margin-bottom: 20px;">'
        html += '<table style="width: 100%; border-collapse: collapse; background: white; border: 1px solid #dee2e6;">'
        html += '<thead style="background: #e9ecef;">'
        html += '<tr>'
        html += '<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Domain</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Timestamp</th>'
        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Query Type</th>'

        if issue_type != "timeout":
            html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Response Time</th>'

        if issue_type == "error" or issue_type == "k8s":
            html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">Error Code</th>'

        html += '<th style="padding: 10px; text-align: center; border-bottom: 2px solid #dee2e6;">DNS Server</th>'
        html += '</tr>'
        html += '</thead>'
        html += '<tbody>'

        for trans in transactions_to_show:
            query = trans.get("query", {})
            response = trans.get("response", {})

            domain = query.get("query_name", "N/A")
            query_type = query.get("query_type", "N/A")
            server = query.get("dst_ip", "N/A")
            response_time = trans.get("response_time", 0) * 1000  # Convert to ms
            error_code = response.get("response_code_name", "NOERROR")

            # Get query timestamp
            query_time = query.get("timestamp", None)
            if query_time:
                dt = datetime.fromtimestamp(query_time)
                timestamp_iso = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                timestamp_iso = "N/A"

            html += '<tr style="border-bottom: 1px solid #dee2e6;">'
            html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{domain}</td>'
            html += f'<td style="padding: 10px; text-align: center; font-family: monospace; font-size: 0.85em; color: #555;">{timestamp_iso}</td>'
            html += f'<td style="padding: 10px; text-align: center;">{query_type}</td>'

            if issue_type != "timeout":
                html += f'<td style="padding: 10px; text-align: center;"><strong>{response_time:.2f} ms</strong></td>'

            if issue_type == "error" or issue_type == "k8s":
                html += f'<td style="padding: 10px; text-align: center;"><span style="color: #dc3545;">{error_code}</span></td>'

            html += f'<td style="padding: 10px; text-align: center;">{server}</td>'
            html += '</tr>'

        html += '</tbody>'
        html += '</table>'
        html += '</div>'

        if len(transactions) > 10:
            html += f'<p style="color: #6c757d; font-size: 0.9em; font-style: italic; margin-top: 10px;">Showing top 10 of {len(transactions)} transactions. See JSON report for complete data.</p>'

        return html

    def _generate_dns_issue_section(self, issue_type: str, title: str, transactions: list, color: str, emoji: str) -> str:
        """Generate a section for one DNS issue type with RCA + transaction table."""
        transaction_count = len(transactions)

        # Analyze root cause
        root_cause_analysis = self._analyze_dns_root_cause(transactions, issue_type)

        html = f'<div class="dns-issue-section" style="margin: 20px 0; border: 2px solid {color}; border-radius: 8px; overflow: hidden;">'
        html += f'<div class="dns-issue-header" style="background: {color}; color: white; padding: 15px; font-weight: bold; font-size: 1.1em;">'
        html += f'{emoji} {title} — {transaction_count} transaction{"s" if transaction_count != 1 else ""}'
        html += '</div>'
        html += '<div class="dns-issue-body" style="padding: 20px; background: #f8f9fa;">'

        # Add root cause analysis (if found)
        if root_cause_analysis["root_cause"] or root_cause_analysis["pattern"]:
            html += self._generate_dns_root_cause_box(root_cause_analysis, issue_type, transactions)

        # Add concise explanation
        html += self._generate_dns_explanation_concise(issue_type, transactions)

        # Add quick actions
        html += self._generate_dns_quick_actions(root_cause_analysis, issue_type)

        # Add tshark command
        html += self._generate_dns_tshark_box(root_cause_analysis)

        # Add compact transaction table
        html += self._generate_dns_transaction_table(transactions, issue_type)

        html += '</div>'
        html += '</div>'

        return html

    def _generate_grouped_dns_analysis(self, dns_data: dict) -> str:
        """Generate DNS analysis grouped by issue type (timeout, error, slow, k8s)."""
        # Get transaction details
        timeout_details = dns_data.get("timeout_details", [])
        slow_details = dns_data.get("slow_transactions_details", [])
        k8s_errors_details = dns_data.get("k8s_expected_errors_details", [])
        error_transactions = dns_data.get("error_transactions_details", [])

        html = ""

        # Generate section for each issue type (only if transactions exist)
        if timeout_details:
            html += self._generate_dns_issue_section(
                "timeout",
                "DNS Timeouts (Critical)",
                timeout_details,
                "#dc3545",
                "🔴"
            )

        if error_transactions:
            html += self._generate_dns_issue_section(
                "error",
                "DNS Errors (High)",
                error_transactions[:10],  # Limit to top 10
                "#ffc107",
                "🟡"
            )

        if slow_details:
            html += self._generate_dns_issue_section(
                "slow",
                "Slow DNS Responses (Moderate)",
                slow_details,
                "#fd7e14",
                "🟠"
            )

        if k8s_errors_details:
            html += self._generate_dns_issue_section(
                "k8s",
                "Kubernetes Expected Errors (Informational)",
                k8s_errors_details,
                "#28a745",
                "🟢"
            )

        return html

    def _generate_dns_section(self, results: dict[str, Any]) -> str:
        """Generate DNS analysis section."""
        html = "<h2>🌐 DNS Analysis</h2>"

        dns_data = results.get("dns", {})
        if not dns_data:
            html += '<div class="info-box"><p>No DNS data available.</p></div>'
            return html

        # DNS Overview
        html += "<h3>📊 DNS Overview</h3>"

        total_queries = dns_data.get("total_queries", 0)
        successful = dns_data.get("successful_transactions", 0)
        timeouts = dns_data.get("timeout_transactions", 0)
        errors = dns_data.get("error_transactions", 0)
        slow = dns_data.get("slow_transactions", 0)
        k8s_expected_errors = dns_data.get("k8s_expected_errors", 0)
        real_errors = dns_data.get("real_errors", 0)

        html += '<div class="summary-grid">'
        html += f"""
        <div class="metric-card">
            <div class="metric-label">Total Queries</div>
            <div class="metric-value">{total_queries:,}</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Successful</div>
            <div class="metric-value">{successful:,}</div>
        </div>
        <div class="metric-card" style="border-left-color: {'#ffc107' if slow > 0 else '#28a745'};">
            <div class="metric-label">Slow Responses</div>
            <div class="metric-value">{slow:,}</div>
        </div>
        <div class="metric-card" style="border-left-color: {'#dc3545' if timeouts > 0 else '#28a745'};">
            <div class="metric-label">Timeouts</div>
            <div class="metric-value">{timeouts:,}</div>
        </div>
        """

        # Errors metric - show breakdown if K8s errors detected
        if k8s_expected_errors > 0 and real_errors >= 0:
            error_color = "#dc3545" if real_errors > 0 else "#ffc107"
            html += f"""
        <div class="metric-card" style="border-left-color: {error_color};">
            <div class="metric-label">Errors</div>
            <div class="metric-value">{errors:,}</div>
            <div style="font-size: 0.75em; color: #666; margin-top: 0.5rem;">
                <div style="color: #28a745;">✓ Expected K8s: {k8s_expected_errors}</div>
                <div style="color: {'#dc3545' if real_errors > 0 else '#28a745'};">{'⚠️' if real_errors > 0 else '✓'} Real Issues: {real_errors}</div>
            </div>
        </div>
            """
        else:
            html += f"""
        <div class="metric-card" style="border-left-color: {'#dc3545' if errors > 0 else '#28a745'};">
            <div class="metric-label">Errors</div>
            <div class="metric-value">{errors:,}</div>
        </div>
            """

        html += "</div>"

        # Generate grouped DNS analysis by issue type
        html += self._generate_grouped_dns_analysis(dns_data)

        return html

    def _generate_security_section(self, results: dict[str, Any]) -> str:
        """Generate security analysis section."""
        html = "<h2>🔒 Security Analysis</h2>"

        # Check if we have any security data
        port_scan_data = results.get("port_scan_detection", {})
        brute_force_data = results.get("brute_force_detection", {})
        ddos_data = results.get("ddos_detection", {})
        dns_tunneling_data = results.get("dns_tunneling_detection", {})
        data_exfiltration_data = results.get("data_exfiltration_detection", {})
        c2_beaconing_data = results.get("c2_beaconing_detection", {})
        lateral_movement_data = results.get("lateral_movement_detection", {})

        has_port_scans = port_scan_data.get("total_scans_detected", 0) > 0
        has_brute_force = brute_force_data.get("total_attacks_detected", 0) > 0
        has_ddos = ddos_data.get("total_attacks_detected", 0) > 0
        has_dns_tunneling = dns_tunneling_data.get("total_tunneling_detected", 0) > 0
        has_data_exfiltration = data_exfiltration_data.get("total_exfiltration_detected", 0) > 0
        has_c2_beaconing = c2_beaconing_data.get("total_beaconing_detected", 0) > 0
        has_lateral_movement = lateral_movement_data.get("total_lateral_movement_detected", 0) > 0

        # If no security issues detected
        if not any(
            [
                has_port_scans,
                has_brute_force,
                has_ddos,
                has_dns_tunneling,
                has_data_exfiltration,
                has_c2_beaconing,
                has_lateral_movement,
            ]
        ):
            html += """
            <div class="no-issues">
                ✓ No security issues detected. The network traffic appears clean with no signs of port scanning, brute-force attacks, DDoS, or DNS tunneling.
            </div>
            """
            return html

        # Port Scan Detection Section
        if "port_scan_detection" in results:
            html += self._generate_port_scan_subsection(port_scan_data)

        # Brute-Force Detection Section
        if "brute_force_detection" in results:
            html += self._generate_brute_force_subsection(brute_force_data)

        # DDoS Detection Section
        if "ddos_detection" in results:
            html += self._generate_ddos_subsection(ddos_data)

        # DNS Tunneling Detection Section
        if "dns_tunneling_detection" in results:
            html += self._generate_dns_tunneling_subsection(dns_tunneling_data)

        # Data Exfiltration Detection Section
        if "data_exfiltration_detection" in results:
            html += self._generate_data_exfiltration_subsection(data_exfiltration_data)

        # C2 Beaconing Detection Section
        if "c2_beaconing_detection" in results:
            html += self._generate_c2_beaconing_subsection(c2_beaconing_data)

        # Lateral Movement Detection Section
        if "lateral_movement_detection" in results:
            html += self._generate_lateral_movement_subsection(lateral_movement_data)

        return html

    def _generate_port_scan_subsection(self, port_scan_data: dict[str, Any]) -> str:
        """Generate port scan detection subsection."""
        total_scans = port_scan_data.get("total_scans_detected", 0)

        if total_scans == 0:
            return """
            <h3>Port Scan Detection</h3>
            <div class="no-issues">
                ✓ No port scans detected.
            </div>
            """

        html = "<h3>⚠️ Port Scan Detection</h3>"

        # Severity breakdown and summary metrics
        severity_breakdown = port_scan_data.get("severity_breakdown", {})
        scan_type_breakdown = port_scan_data.get("scan_type_breakdown", {})
        top_scanners = port_scan_data.get("top_scanners", [])

        html += '<div class="summary-grid">'

        # Total scans
        html += f"""
        <div class="metric-card" style="border-left-color: #dc3545;">
            <div class="metric-label">Total Scans Detected</div>
            <div class="metric-value" style="color: #dc3545;">{total_scans}</div>
        </div>
        """

        # Severity counts
        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
        <div class="metric-card" style="border-left-color: #6c757d;">
            <div class="metric-label">Severity Breakdown</div>
            <div class="metric-value" style="font-size: 1.2em;">
                {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
            </div>
        </div>
        """

        # Scan types
        if scan_type_breakdown:
            scan_types_html = " | ".join([f"{st.title()}: {cnt}" for st, cnt in scan_type_breakdown.items()])
            html += f"""
            <div class="metric-card" style="border-left-color: #17a2b8;">
                <div class="metric-label">Scan Types</div>
                <div class="metric-value" style="font-size: 1em; color: #555;">{scan_types_html}</div>
            </div>
            """

        html += "</div>"

        # Top scanners table
        if top_scanners:
            html += "<h4>Top Scanners</h4>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Scan Count</th>
                    <th>Unique Ports</th>
                    <th>Total Attempts</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
            """

            for scanner in top_scanners[:10]:
                severity = scanner.get("max_severity", "low")
                badge_class = f"badge-{severity}"
                html += f"""
                <tr>
                    <td><strong>{scanner.get("source_ip", "N/A")}</strong></td>
                    <td>{scanner.get("scan_count", 0)}</td>
                    <td>{scanner.get("unique_ports", 0)}</td>
                    <td>{scanner.get("total_attempts", 0)}</td>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                </tr>
                """

            html += "</tbody></table>"

        # Detailed scan events
        scan_events = port_scan_data.get("scan_events", [])
        if scan_events:
            html += "<h4>Recent Scan Events (Top 10)</h4>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Type</th>
                    <th>Targets</th>
                    <th>Ports</th>
                    <th>Attempts</th>
                    <th>Rate</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
            """

            for event in scan_events[:10]:
                severity = event.get("severity", "low")
                badge_class = f"badge-{severity}"
                scan_rate = event.get("scan_rate", 0)
                html += f"""
                <tr>
                    <td><strong>{event.get("source_ip", "N/A")}</strong></td>
                    <td>{event.get("scan_type", "N/A").title()}</td>
                    <td>{event.get("unique_targets", 0)}</td>
                    <td>{event.get("unique_ports", 0)}</td>
                    <td>{event.get("total_attempts", 0)}</td>
                    <td>{scan_rate:.1f}/s</td>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                </tr>
                """

            html += "</tbody></table>"

        return html

    def _generate_brute_force_subsection(self, brute_force_data: dict[str, Any]) -> str:
        """Generate brute-force detection subsection."""
        total_attacks = brute_force_data.get("total_attacks_detected", 0)

        if total_attacks == 0:
            return """
            <h3>Brute-Force Detection</h3>
            <div class="no-issues">
                ✓ No brute-force attacks detected.
            </div>
            """

        html = "<h3>⚠️ Brute-Force Detection</h3>"

        # Severity breakdown and summary metrics
        severity_breakdown = brute_force_data.get("severity_breakdown", {})
        service_breakdown = brute_force_data.get("service_breakdown", {})
        top_attackers = brute_force_data.get("top_attackers", [])

        html += '<div class="summary-grid">'

        # Total attacks
        html += f"""
        <div class="metric-card" style="border-left-color: #dc3545;">
            <div class="metric-label">Total Attacks Detected</div>
            <div class="metric-value" style="color: #dc3545;">{total_attacks}</div>
        </div>
        """

        # Severity counts
        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
        <div class="metric-card" style="border-left-color: #6c757d;">
            <div class="metric-label">Severity Breakdown</div>
            <div class="metric-value" style="font-size: 1.2em;">
                {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
            </div>
        </div>
        """

        # Service breakdown
        if service_breakdown:
            services_html = " | ".join([f"{svc}: {cnt}" for svc, cnt in list(service_breakdown.items())[:5]])
            html += f"""
            <div class="metric-card" style="border-left-color: #17a2b8;">
                <div class="metric-label">Services Targeted</div>
                <div class="metric-value" style="font-size: 1em; color: #555;">{services_html}</div>
            </div>
            """

        html += "</div>"

        # Top attackers table
        if top_attackers:
            html += "<h4>Top Attackers</h4>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Attack Count</th>
                    <th>Services Targeted</th>
                    <th>Total Attempts</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
            """

            for attacker in top_attackers[:10]:
                severity = attacker.get("max_severity", "low")
                badge_class = f"badge-{severity}"
                services = ", ".join(attacker.get("services_targeted", []))
                html += f"""
                <tr>
                    <td><strong>{attacker.get("source_ip", "N/A")}</strong></td>
                    <td>{attacker.get("attack_count", 0)}</td>
                    <td>{services}</td>
                    <td>{attacker.get("total_attempts", 0)}</td>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                </tr>
                """

            html += "</tbody></table>"

        # Detailed attack events
        brute_force_events = brute_force_data.get("brute_force_events", [])
        if brute_force_events:
            html += "<h4>Recent Attack Events (Top 10)</h4>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Target IP</th>
                    <th>Service</th>
                    <th>Attempts</th>
                    <th>Failed</th>
                    <th>Rate</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
            """

            for event in brute_force_events[:10]:
                severity = event.get("severity", "low")
                badge_class = f"badge-{severity}"
                attempt_rate = event.get("attempt_rate", 0)
                html += f"""
                <tr>
                    <td><strong>{event.get("source_ip", "N/A")}</strong></td>
                    <td>{event.get("target_ip", "N/A")}</td>
                    <td>{event.get("service", "N/A")}</td>
                    <td>{event.get("total_attempts", 0)}</td>
                    <td>{event.get("failed_attempts", 0)}</td>
                    <td>{attempt_rate:.2f}/s</td>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                </tr>
                """

            html += "</tbody></table>"

        return html

    def _generate_ddos_subsection(self, ddos_data: dict[str, Any]) -> str:
        """Generate DDoS detection subsection."""
        total_attacks = ddos_data.get("total_attacks_detected", 0)

        if total_attacks == 0:
            return """
            <h3>DDoS Detection</h3>
            <div class="no-issues">
                ✓ No DDoS attacks detected.
            </div>
            """

        html = "<h3>⚠️ DDoS Detection</h3>"

        # Severity breakdown and summary metrics
        severity_breakdown = ddos_data.get("severity_breakdown", {})
        attack_type_breakdown = ddos_data.get("attack_type_breakdown", {})

        html += '<div class="summary-grid">'

        # Total attacks
        html += f"""
        <div class="metric-card" style="border-left-color: #dc3545;">
            <div class="metric-label">Total DDoS Attacks</div>
            <div class="metric-value" style="color: #dc3545;">{total_attacks}</div>
        </div>
        """

        # Severity counts
        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
        <div class="metric-card" style="border-left-color: #6c757d;">
            <div class="metric-label">Severity Breakdown</div>
            <div class="metric-value" style="font-size: 1.2em;">
                {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
            </div>
        </div>
        """

        # Attack types
        if attack_type_breakdown:
            attack_types_html = " | ".join(
                [f"{at.replace('_', ' ').title()}: {cnt}" for at, cnt in attack_type_breakdown.items()]
            )
            html += f"""
            <div class="metric-card" style="border-left-color: #17a2b8;">
                <div class="metric-label">Attack Types</div>
                <div class="metric-value" style="font-size: 1em; color: #555;">{attack_types_html}</div>
            </div>
            """

        html += "</div>"

        # Detailed attack events
        ddos_events = ddos_data.get("ddos_events", [])
        if ddos_events:
            html += "<h4>DDoS Attack Events (Top 10)</h4>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Target IP</th>
                    <th>Attack Type</th>
                    <th>Sources</th>
                    <th>Packets</th>
                    <th>Rate (pkt/s)</th>
                    <th>Volume</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
            """

            for event in ddos_events[:10]:
                severity = event.get("severity", "low")
                badge_class = f"badge-{severity}"
                pps = event.get("packets_per_second", 0)
                bytes_total = event.get("bytes_total", 0)

                # Format bytes
                if bytes_total > 1024 * 1024:
                    volume_str = f"{bytes_total / (1024 * 1024):.2f} MB"
                elif bytes_total > 1024:
                    volume_str = f"{bytes_total / 1024:.2f} KB"
                else:
                    volume_str = f"{bytes_total} B"

                attack_type = event.get("attack_type", "unknown").replace("_", " ").title()

                html += f"""
                <tr>
                    <td><strong>{event.get("target_ip", "N/A")}</strong></td>
                    <td>{attack_type}</td>
                    <td>{event.get("source_count", 0)}</td>
                    <td>{event.get("packet_count", 0):,}</td>
                    <td>{pps:,.1f}</td>
                    <td>{volume_str}</td>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                </tr>
                """

            html += "</tbody></table>"

            # Top attacking sources
            if ddos_events[0].get("top_sources"):
                html += "<h4>Top Attacking Sources</h4>"
                html += "<div style='margin: 10px 0;'>"
                top_sources = ddos_events[0].get("top_sources", [])[:10]
                for src in top_sources:
                    html += f"<span class='badge badge-low' style='margin: 3px;'>{src}</span>"
                html += "</div>"

        return html

    def _generate_dns_tunneling_subsection(self, dns_tunneling_data: dict[str, Any]) -> str:
        """Generate DNS tunneling detection subsection."""
        total_tunneling = dns_tunneling_data.get("total_tunneling_detected", 0)

        if total_tunneling == 0:
            return """
            <h3>DNS Tunneling Detection</h3>
            <div class="no-issues">
                ✓ No DNS tunneling detected.
            </div>
            """

        html = "<h3>⚠️ DNS Tunneling Detection</h3>"

        # Severity breakdown and summary metrics
        severity_breakdown = dns_tunneling_data.get("severity_breakdown", {})

        html += '<div class="summary-grid">'

        # Total tunneling
        html += f"""
        <div class="metric-card" style="border-left-color: #dc3545;">
            <div class="metric-label">Total Tunneling Detected</div>
            <div class="metric-value" style="color: #dc3545;">{total_tunneling}</div>
        </div>
        """

        # Severity counts
        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
        <div class="metric-card" style="border-left-color: #6c757d;">
            <div class="metric-label">Severity Breakdown</div>
            <div class="metric-value" style="font-size: 1.2em;">
                {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
            </div>
        </div>
        """

        html += "</div>"

        # Detailed tunneling events
        tunneling_events = dns_tunneling_data.get("tunneling_events", [])
        if tunneling_events:
            html += "<h4>DNS Tunneling Events (Top 10)</h4>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Source IP</th>
                    <th>Domain</th>
                    <th>Queries</th>
                    <th>Avg Length</th>
                    <th>Entropy</th>
                    <th>Example Queries</th>
                    <th>Indicators</th>
                    <th>Severity</th>
                </tr>
            </thead>
            <tbody>
            """

            for event in tunneling_events[:10]:
                severity = event.get("severity", "low")
                badge_class = f"badge-{severity}"
                avg_length = event.get("avg_query_length", 0)
                entropy = event.get("avg_entropy", 0)
                indicators = event.get("suspicious_patterns", [])

                # Truncate domain if too long
                domain = event.get("domain", "N/A")
                if len(domain) > 30:
                    domain = domain[:27] + "..."

                # Format example queries
                example_queries = event.get("example_queries", [])
                if example_queries:
                    # Show first 2 examples, truncate if too long
                    examples_list = []
                    for query in example_queries[:2]:
                        if len(query) > 35:
                            examples_list.append(query[:32] + "...")
                        else:
                            examples_list.append(query)
                    examples_str = "<br>".join(examples_list)
                else:
                    examples_str = "N/A"

                # Format indicators
                if len(indicators) > 2:
                    indicators_str = ", ".join(indicators[:2]) + f" +{len(indicators)-2}"
                else:
                    indicators_str = ", ".join(indicators) if indicators else "Various"

                html += f"""
                <tr>
                    <td><strong>{event.get("source_ip", "N/A")}</strong></td>
                    <td style="font-family: monospace; font-size: 0.85em;">{domain}</td>
                    <td>{event.get("query_count", 0)}</td>
                    <td>{avg_length:.0f} chars</td>
                    <td>{entropy:.2f} bits</td>
                    <td style="font-family: monospace; font-size: 0.75em; max-width: 200px;">{examples_str}</td>
                    <td style="font-size: 0.85em;">{indicators_str}</td>
                    <td><span class="badge {badge_class}">{severity.upper()}</span></td>
                </tr>
                """

            html += "</tbody></table>"

            # Explanation box
            html += """
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">
                <p style="margin: 0 0 8px 0;"><strong>ℹ️ About DNS Tunneling</strong></p>
                <p style="margin: 0; font-size: 0.9em; color: #555;">
                    DNS tunneling is a technique used to encode data of other programs or protocols in DNS queries and responses.
                    It's commonly used for <strong>command & control (C2) communication</strong>, <strong>data exfiltration</strong>,
                    and <strong>bypassing firewalls</strong>. Indicators include unusually long queries, high entropy subdomains
                    (base64/hex encoding), and excessive query rates to suspicious domains.
                </p>
            </div>
            """

        return html

    def _generate_data_exfiltration_subsection(self, data_exfiltration_data: dict[str, Any]) -> str:
        """Generate data exfiltration detection subsection."""
        total_exfiltration = data_exfiltration_data.get("total_exfiltration_detected", 0)

        if total_exfiltration == 0:
            return ""  # Don't show section if no detections

        html = """
        <div class="security-subsection">
            <h3>📤 Data Exfiltration Detection</h3>
        """

        # Summary
        severity_breakdown = data_exfiltration_data.get("severity_breakdown", {})
        _type_breakdown = data_exfiltration_data.get("type_breakdown", {})  # noqa: F841

        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
            <div class="alert alert-warning">
                <strong>⚠️  {total_exfiltration} potential data exfiltration event(s) detected</strong>
            </div>

            <div class="metric-card" style="border-left-color: #6c757d;">
                <div class="metric-label">Severity Breakdown</div>
                <div class="metric-value" style="font-size: 1.2em;">
                    {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                    {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                    {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                    {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
                </div>
            </div>
        """

        # Events table
        events = data_exfiltration_data.get("exfiltration_events", [])
        if events:
            html += """
            <h4>Detected Exfiltration Events:</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>Details</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
            """

            for event in events[:20]:  # Limit to 20 events
                event_type = event.get("type", "unknown")
                source_ip = event.get("source_ip", "N/A")
                severity = event.get("severity", "low")
                badge = self._get_severity_badge(severity)

                # Format details based on type
                if event_type == "large_upload":
                    upload_mb = event.get("upload_volume_mb", 0)
                    details = f"{upload_mb:.2f} MB uploaded"
                elif event_type == "suspicious_ratio":
                    ratio = event.get("ratio", 0)
                    details = f"Upload/Download ratio: {ratio}:1"
                elif event_type == "unusual_protocol":
                    ports = event.get("suspicious_ports", [])
                    details = f"Suspicious ports: {', '.join(map(str, ports))}"
                else:
                    details = event.get("description", "N/A")

                html += f"""
                <tr>
                    <td>{event_type}</td>
                    <td><code>{source_ip}</code></td>
                    <td>{details}</td>
                    <td>{badge}</td>
                </tr>
                """

            html += "</tbody></table>"

        # Educational info
        html += """
            <div class="info-box">
                <p style="margin: 0 0 8px 0;"><strong>ℹ️ About Data Exfiltration</strong></p>
                <p style="margin: 0; font-size: 0.9em; color: #555;">
                    Data exfiltration is the unauthorized transfer of data from a system.
                    Indicators include <strong>large upload volumes</strong>, <strong>suspicious upload/download ratios</strong>,
                    and <strong>data transfers over unusual protocols</strong>. Attackers may use non-standard ports or
                    encoding techniques to evade detection.
                </p>
            </div>
            """

        html += "</div>"
        return html

    def _generate_c2_beaconing_subsection(self, c2_beaconing_data: dict[str, Any]) -> str:
        """Generate C2 beaconing detection subsection."""
        total_beaconing = c2_beaconing_data.get("total_beaconing_detected", 0)

        if total_beaconing == 0:
            return ""  # Don't show section if no detections

        html = """
        <div class="security-subsection">
            <h3>📡 C2 Beaconing Detection</h3>
        """

        # Summary
        severity_breakdown = c2_beaconing_data.get("severity_breakdown", {})

        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
            <div class="alert alert-danger">
                <strong>🚨 {total_beaconing} potential C2 beaconing pattern(s) detected</strong>
            </div>

            <div class="metric-card" style="border-left-color: #6c757d;">
                <div class="metric-label">Severity Breakdown</div>
                <div class="metric-value" style="font-size: 1.2em;">
                    {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                    {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                    {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                    {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
                </div>
            </div>
        """

        # Events table
        events = c2_beaconing_data.get("beaconing_events", [])
        if events:
            html += """
            <h4>Detected Beaconing Patterns:</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Source IP</th>
                        <th>Destination</th>
                        <th>Beacon Count</th>
                        <th>Interval</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
            """

            for event in events[:20]:  # Limit to 20 events
                source_ip = event.get("source_ip", "N/A")
                dest_ip = event.get("destination_ip", "N/A")
                dest_port = event.get("destination_port", 0)
                beacon_count = event.get("beacon_count", 0)
                mean_interval = event.get("mean_interval_seconds", 0)
                severity = event.get("severity", "low")
                badge = self._get_severity_badge(severity)

                html += f"""
                <tr>
                    <td><code>{source_ip}</code></td>
                    <td><code>{dest_ip}:{dest_port}</code></td>
                    <td>{beacon_count} beacons</td>
                    <td>Every {mean_interval:.1f}s</td>
                    <td>{badge}</td>
                </tr>
                """

            html += "</tbody></table>"

        # Educational info
        html += """
            <div class="info-box">
                <p style="margin: 0 0 8px 0;"><strong>ℹ️ About C2 Beaconing</strong></p>
                <p style="margin: 0; font-size: 0.9em; color: #555;">
                    Command & Control (C2) beaconing is periodic communication between compromised hosts and attacker servers.
                    Characteristics include <strong>regular time intervals</strong>, <strong>consistent payload sizes</strong>,
                    and <strong>persistent connections</strong>. Beacons are used for remote control, data staging,
                    and maintaining persistent access.
                </p>
            </div>
            """

        html += "</div>"
        return html

    def _generate_lateral_movement_subsection(self, lateral_movement_data: dict[str, Any]) -> str:
        """Generate lateral movement detection subsection."""
        total_lateral_movement = lateral_movement_data.get("total_lateral_movement_detected", 0)

        if total_lateral_movement == 0:
            return ""  # Don't show section if no detections

        html = """
        <div class="security-subsection">
            <h3>🔀 Lateral Movement Detection</h3>
        """

        # Summary
        severity_breakdown = lateral_movement_data.get("severity_breakdown", {})
        _type_breakdown = lateral_movement_data.get("type_breakdown", {})  # noqa: F841

        critical = severity_breakdown.get("critical", 0)
        high = severity_breakdown.get("high", 0)
        medium = severity_breakdown.get("medium", 0)
        low = severity_breakdown.get("low", 0)

        html += f"""
            <div class="alert alert-danger">
                <strong>🚨 {total_lateral_movement} potential lateral movement event(s) detected</strong>
            </div>

            <div class="metric-card" style="border-left-color: #6c757d;">
                <div class="metric-label">Severity Breakdown</div>
                <div class="metric-value" style="font-size: 1.2em;">
                    {f'<span class="badge badge-critical">{critical} Critical</span> ' if critical > 0 else ''}
                    {f'<span class="badge badge-high">{high} High</span> ' if high > 0 else ''}
                    {f'<span class="badge badge-medium">{medium} Medium</span> ' if medium > 0 else ''}
                    {f'<span class="badge badge-low">{low} Low</span>' if low > 0 else ''}
                </div>
            </div>
        """

        # Events table
        events = lateral_movement_data.get("lateral_movement_events", [])
        if events:
            html += """
            <h4>Detected Lateral Movement:</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>Targets</th>
                        <th>Protocols</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
            """

            for event in events[:20]:  # Limit to 20 events
                event_type = event.get("type", "unknown")
                source_ip = event.get("source_ip", "N/A")
                target_count = event.get("target_count", 0)
                targets = event.get("targets", [])
                protocols = event.get("protocols_used", [])
                severity = event.get("severity", "low")
                badge = self._get_severity_badge(severity)

                targets_str = ", ".join(targets[:3])
                if len(targets) > 3:
                    targets_str += f", ... (+{len(targets) - 3} more)"

                protocols_str = ", ".join(protocols) if protocols else "N/A"

                html += f"""
                <tr>
                    <td>{event_type}</td>
                    <td><code>{source_ip}</code></td>
                    <td>{target_count} hosts<br><small>{targets_str}</small></td>
                    <td>{protocols_str}</td>
                    <td>{badge}</td>
                </tr>
                """

            html += "</tbody></table>"

        # Educational info
        html += """
            <div class="info-box">
                <p style="margin: 0 0 8px 0;"><strong>ℹ️ About Lateral Movement</strong></p>
                <p style="margin: 0; font-size: 0.9em; color: #555;">
                    Lateral movement is the technique attackers use to progressively move through a network,
                    searching for key assets and data. Common protocols include <strong>SMB/CIFS (ports 445, 139)</strong>,
                    <strong>RDP (port 3389)</strong>, <strong>WinRM (ports 5985, 5986)</strong>, and <strong>RPC (port 135)</strong>.
                    Multiple internal connections using administrative protocols are strong indicators.
                </p>
            </div>
            """

        html += "</div>"
        return html

    def _get_severity_badge(self, severity: str) -> str:
        """Generate HTML badge for severity level."""
        badge_class = f"badge-{severity}"
        return f'<span class="badge {badge_class}">{severity.upper()}</span>'
