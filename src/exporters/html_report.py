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

from typing import Any, Dict


class HTMLReportGenerator:
    """Generates HTML reports from analysis results."""

    def __init__(self):
        pass

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

        # Tabbed Navigation
        html_parts.append('<div class="tabs-container">')
        html_parts.append('  <div class="tabs-nav">')
        html_parts.append(
            '    <button class="tab-button active" onclick="switchTab(\'tab-overview\')">📊 Overview</button>'
        )
        html_parts.append('    <button class="tab-button" onclick="switchTab(\'tab-qos\')">🏥 QoS Analysis</button>')
        html_parts.append('    <button class="tab-button" onclick="switchTab(\'tab-tcp\')">🔌 TCP Analysis</button>')
        html_parts.append('    <button class="tab-button" onclick="switchTab(\'tab-dns\')">🌐 DNS Analysis</button>')
        html_parts.append('    <button class="tab-button" onclick="switchTab(\'tab-security\')">🔒 Security</button>')
        html_parts.append('    <button class="tab-button" onclick="switchTab(\'tab-network\')">📡 Network</button>')
        html_parts.append("  </div>")

        # Tab 1: Overview (Executive Summary + Health Score)
        html_parts.append('  <div id="tab-overview" class="tab-content active">')
        html_parts.append(self._generate_summary(results))
        if "health_score" in results:
            html_parts.append(self._generate_health_score_section(results))
        html_parts.append("  </div>")

        # Tab 2: QoS Analysis (Jitter, RTT, etc.)
        html_parts.append('  <div id="tab-qos" class="tab-content">')
        if "jitter" in results:
            html_parts.append(self._generate_jitter_section(results))
        else:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No QoS metrics available in this capture.</p>")
            html_parts.append("    </div>")
        html_parts.append("  </div>")

        # Tab 3: TCP Analysis (Retransmissions, RTT, Window, Handshakes)
        html_parts.append('  <div id="tab-tcp" class="tab-content">')
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
        html_parts.append('  <div id="tab-dns" class="tab-content">')
        if "dns" in results:
            html_parts.append(self._generate_dns_section(results))
        else:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No DNS analysis data available in this capture.</p>")
            html_parts.append("    </div>")
        html_parts.append("  </div>")

        # Tab 5: Security (Port Scans, Brute Force, DDoS, DNS Tunneling)
        html_parts.append('  <div id="tab-security" class="tab-content">')
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
        html_parts.append('  <div id="tab-network" class="tab-content">')
        if "protocol_distribution" in results:
            html_parts.append(self._generate_protocol_section(results))
        if "service_classification" in results:
            html_parts.append(self._generate_service_section(results))
        if "protocol_distribution" not in results and "service_classification" not in results:
            html_parts.append('    <div class="info-box">')
            html_parts.append("      <p>No network analysis data available.</p>")
            html_parts.append("    </div>")
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

        .severity-excellent { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .severity-good { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
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
            overflow: hidden;
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

        .tabs-nav {
            display: flex;
            border-bottom: 2px solid #e0e0e0;
            margin-bottom: 0;
            gap: 5px;
            flex-wrap: wrap;
        }

        .tab-button {
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
        }

        .tab-button:hover {
            background: #e8e8e8;
            color: #333;
        }

        .tab-button.active {
            background: white;
            color: #3498db;
            border-bottom-color: #3498db;
        }

        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .tab-icon {
            margin-right: 6px;
        }
    </style>
    <script>
        function switchTab(tabId) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });

            // Deactivate all tab buttons
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.remove('active');
            });

            // Show selected tab content
            const selectedTab = document.getElementById(tabId);
            if (selectedTab) {
                selectedTab.classList.add('active');
            }

            // Activate selected tab button
            const selectedButton = document.querySelector(`[onclick="switchTab('${tabId}')"]`);
            if (selectedButton) {
                selectedButton.classList.add('active');
            }

            // Save tab preference to localStorage
            localStorage.setItem('activeTab', tabId);
        }

        // Restore last active tab on page load
        document.addEventListener('DOMContentLoaded', function() {
            const savedTab = localStorage.getItem('activeTab') || 'tab-overview';
            switchTab(savedTab);
        });
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

        html = "<h2>💚 Network Health Score</h2>"

        # Main health score
        severity_class = f"severity-{severity}"
        html += f"""
        <div class="health-score {severity_class}">
            <div class="health-score-label">Overall Health Score</div>
            <div class="health-score-value">{score:.1f}</div>
            <div class="health-score-label">{severity.upper()}</div>
        """
        if summary:
            html += f'<p style="margin-top: 15px; opacity: 0.9;">{summary}</p>'
        html += "</div>"

        # Component scores
        if component_scores:
            html += "<h3>Component Scores</h3>"
            html += '<div class="component-scores">'

            for component, data in component_scores.items():
                comp_score = data.get("score", 0)
                html += f"""
                <div class="component-score-card">
                    <div class="component-name">{component.replace('_', ' ').title()}</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: {comp_score}%">{comp_score:.0f}%</div>
                    </div>
                </div>
                """

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
            for service, count in sorted(service_dist.items(), key=lambda x: x[1], reverse=True)[:10]:
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

            html += "</div></div>"

        return html

    def _generate_jitter_section(self, results: dict[str, Any]) -> str:
        """Generate jitter analysis section."""
        jitter_data = results.get("jitter", {})

        html = "<h2>📡 Jitter Analysis</h2>"

        # Add explanation box
        html += """
        <div style="background: #e8f4f8; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 4px;">
            <p style="margin: 0 0 10px 0;"><strong>ℹ️ What is Jitter (RFC 3393 IPDV)?</strong></p>
            <p style="margin: 0 0 8px 0; font-size: 0.95em;">
                Jitter measures the <strong>variation in packet delay</strong>. High jitter causes choppy audio/video in real-time applications.
            </p>
            <p style="margin: 0; font-size: 0.9em; color: #555;">
                <strong>Typical thresholds:</strong>
                VoIP: &lt;30ms (good), &lt;50ms (acceptable) |
                Video: &lt;100ms |
                Web/Data: &lt;200ms
            </p>
        </div>
        """

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

            # Add warning if jitter is extremely high
            mean_jitter_ms = global_stats.get("mean_jitter", 0) * 1000
            if mean_jitter_ms > 1000:  # > 1 second
                html += """
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">
                    <p style="margin: 0 0 8px 0;"><strong>⚠️ High Jitter Detected</strong></p>
                    <p style="margin: 0; font-size: 0.95em; color: #856404;">
                        The extremely high jitter values (> 1 second) typically indicate a <strong>long-duration capture with significant gaps</strong>
                        between packets, rather than continuous real-time traffic. This is normal for passive monitoring or captures
                        spanning hours/days. For real-time application analysis, use shorter capture windows (5-10 minutes).
                    </p>
                </div>
                """

        return html

    def _generate_service_section(self, results: dict[str, Any]) -> str:
        """Generate service classification section."""
        service_data = results.get("service_classification", {})

        html = "<h2>🧠 Service Classification</h2>"

        # Add explanation box
        html += """
        <div style="background: #e8f4f8; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 4px;">
            <p style="margin: 0 0 10px 0;"><strong>ℹ️ What is Service Classification?</strong></p>
            <p style="margin: 0 0 12px 0; font-size: 0.95em;">
                Intelligent traffic classification based on <strong>behavioral patterns</strong>, not just port numbers.
                Identifies application types by analyzing packet sizes, timing, and flow characteristics.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 0.9em;">
                <div>
                    <strong>📞 VoIP:</strong> Small packets (100-300B), constant rate (10-40ms intervals)
                </div>
                <div>
                    <strong>📹 Streaming:</strong> Large packets (>1000B), sustained throughput (>1Mbps)
                </div>
                <div>
                    <strong>💬 Interactive:</strong> Variable sizes, request/response pattern (web, SSH)
                </div>
                <div>
                    <strong>📦 Bulk:</strong> Large persistent flows (>1200B, >5s, file transfers)
                </div>
                <div>
                    <strong>🎛️ Control:</strong> Small sporadic packets (<512B, DNS, mDNS, NTP)
                </div>
            </div>
        </div>
        """

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
                    "Control": "This indicates primarily <strong>network management traffic</strong> (DNS, mDNS, NTP, DHCP). "
                    "Common in passive monitoring or captures with minimal user activity.",
                    "Streaming": "This indicates heavy <strong>multimedia usage</strong> (video/audio streaming). "
                    "May require bandwidth optimization or QoS prioritization.",
                    "Interactive": "This indicates primarily <strong>web browsing and interactive applications</strong> (HTTP, SSH). "
                    "Typical of normal user activity with request/response patterns.",
                    "Bulk": "This indicates significant <strong>file transfer activity</strong> (FTP, large downloads). "
                    "May impact available bandwidth for real-time applications.",
                    "VoIP": "This indicates heavy <strong>voice/video conferencing usage</strong>. "
                    "Requires consistent low latency and jitter for quality calls.",
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

            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card" style="border-left-color: #dc3545;">
                <div class="metric-label">Total Retransmissions</div>
                <div class="metric-value">{total_retrans:,}</div>
            </div>
            <div class="metric-card" style="border-left-color: #fd7e14;">
                <div class="metric-label">RTO (Timeout)</div>
                <div class="metric-value">{rto_count:,}</div>
            </div>
            <div class="metric-card" style="border-left-color: #ffc107;">
                <div class="metric-label">Fast Retransmissions</div>
                <div class="metric-value">{fast_retrans:,}</div>
            </div>
            """
            html += "</div>"

            # Top flows with retransmissions
            retrans_list = retrans_data.get("retransmissions", [])
            if retrans_list:
                # Group by flow
                flows = {}
                for r in retrans_list[:100]:  # Limit to first 100
                    flow_key = f"{r.get('src_ip')}:{r.get('src_port')} → {r.get('dst_ip')}:{r.get('dst_port')}"
                    if flow_key not in flows:
                        flows[flow_key] = []
                    flows[flow_key].append(r)

                html += "<h4>Top Flows with Retransmissions</h4>"
                html += '<table class="data-table">'
                html += """
                <thead>
                    <tr>
                        <th>Flow</th>
                        <th>Retransmissions</th>
                        <th>RTO Count</th>
                    </tr>
                </thead>
                <tbody>
                """

                # Sort flows by retransmission count
                sorted_flows = sorted(flows.items(), key=lambda x: len(x[1]), reverse=True)[:10]
                for flow_key, retrans in sorted_flows:
                    rto_in_flow = sum(1 for r in retrans if r.get("retrans_type") == "RTO")
                    html += f"""
                    <tr>
                        <td><code>{flow_key}</code></td>
                        <td>{len(retrans)}</td>
                        <td>{rto_in_flow}</td>
                    </tr>
                    """

                html += "</tbody></table>"

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
                <div class="metric-value">{rtt_data.get("flows_with_high_rtt", 0)}</div>
            </div>
            """
            html += "</div>"

            # Top flows with high RTT
            flow_stats = rtt_data.get("flow_statistics", [])
            if flow_stats:
                html += "<h4>Flows with High RTT</h4>"
                html += '<table class="data-table">'
                html += """
                <thead>
                    <tr>
                        <th>Flow</th>
                        <th>Mean RTT</th>
                        <th>Max RTT</th>
                        <th>Measurements</th>
                    </tr>
                </thead>
                <tbody>
                """

                for flow in flow_stats[:15]:
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

                html += "</tbody></table>"

        # TCP Window Analysis
        window_data = results.get("tcp_window", {})
        if window_data and window_data.get("flows_with_issues", 0) > 0:
            html += "<h3>🪟 TCP Window Analysis</h3>"

            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card" style="border-left-color: #ffc107;">
                <div class="metric-label">Flows with Window Issues</div>
                <div class="metric-value">{window_data.get("flows_with_issues", 0)}</div>
            </div>
            """
            html += "</div>"

            flow_stats = window_data.get("flow_statistics", [])
            if flow_stats:
                html += "<h4>Flows with Window Issues</h4>"
                html += '<table class="data-table">'
                html += """
                <thead>
                    <tr>
                        <th>Flow</th>
                        <th>Suspected Bottleneck</th>
                        <th>Zero Windows</th>
                        <th>Zero Window Duration</th>
                    </tr>
                </thead>
                <tbody>
                """

                for flow in flow_stats[:15]:
                    if flow.get("suspected_bottleneck") != "none":
                        bottleneck = flow.get("suspected_bottleneck", "unknown")
                        badge_class = "badge-danger" if bottleneck == "application" else "badge-warning"
                        html += f"""
                        <tr>
                            <td><code>{flow.get("flow_key", "N/A")}</code></td>
                            <td><span class="badge {badge_class}">{bottleneck.upper()}</span></td>
                            <td>{flow.get("zero_window_count", 0)}</td>
                            <td>{flow.get("zero_window_total_duration", 0):.3f}s</td>
                        </tr>
                        """

                html += "</tbody></table>"

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
        total_transactions = dns_data.get("total_transactions", 0)
        successful = dns_data.get("successful_transactions", 0)
        timeouts = dns_data.get("timeout_transactions", 0)
        errors = dns_data.get("error_transactions", 0)
        slow = dns_data.get("slow_transactions", 0)

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
        <div class="metric-card" style="border-left-color: {'#dc3545' if errors > 0 else '#28a745'};">
            <div class="metric-label">Errors</div>
            <div class="metric-value">{errors:,}</div>
        </div>
        """
        html += "</div>"

        # Response Time Statistics
        response_stats = dns_data.get("response_time_statistics", {})
        if response_stats:
            html += "<h3>⏱️ Response Time Statistics</h3>"

            mean_time = response_stats.get("mean_response_time", 0) * 1000
            min_time = response_stats.get("min_response_time", 0) * 1000
            max_time = response_stats.get("max_response_time", 0) * 1000

            html += '<div class="summary-grid">'
            html += f"""
            <div class="metric-card">
                <div class="metric-label">Mean Response Time</div>
                <div class="metric-value">{mean_time:.2f} ms</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Min Response Time</div>
                <div class="metric-value">{min_time:.2f} ms</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Max Response Time</div>
                <div class="metric-value">{max_time:.2f} ms</div>
            </div>
            """
            html += "</div>"

        # Problematic Domains
        top_problematic = dns_data.get("top_problematic_domains", [])
        if top_problematic:
            html += "<h3>⚠️ Problematic Domains</h3>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Issue Count</th>
                    <th>Main Error Type</th>
                </tr>
            </thead>
            <tbody>
            """

            for domain_info in top_problematic[:20]:
                domain = domain_info.get("domain", "N/A")
                count = domain_info.get("count", 0)
                main_error = domain_info.get("main_error", "Unknown")

                # Color code based on error type
                badge_class = "badge-danger"
                if main_error == "Slow Response":
                    badge_class = "badge-warning"
                elif main_error == "Timeout":
                    badge_class = "badge-critical"

                html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 0.9em;">{domain}</td>
                    <td>{count}</td>
                    <td><span class="badge {badge_class}">{main_error}</span></td>
                </tr>
                """

            html += "</tbody></table>"

        # Slow Transactions Details
        slow_details = dns_data.get("slow_transactions_details", [])
        if slow_details:
            html += "<h3>🐌 Slow DNS Transactions</h3>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Query Type</th>
                    <th>Response Time</th>
                    <th>Server</th>
                </tr>
            </thead>
            <tbody>
            """

            for trans in slow_details[:15]:
                query = trans.get("query", {})
                response_time = trans.get("response_time", 0) * 1000

                html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 0.9em;">{query.get("query_name", "N/A")}</td>
                    <td>{query.get("query_type", "N/A")}</td>
                    <td><strong>{response_time:.2f} ms</strong></td>
                    <td>{query.get("dst_ip", "N/A")}</td>
                </tr>
                """

            html += "</tbody></table>"

        # Timeout Details
        timeout_details = dns_data.get("timeout_details", [])
        if timeout_details:
            html += "<h3>⏰ DNS Timeouts</h3>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Query Type</th>
                    <th>Client IP</th>
                    <th>Server IP</th>
                </tr>
            </thead>
            <tbody>
            """

            for trans in timeout_details[:15]:
                query = trans.get("query", {})

                html += f"""
                <tr>
                    <td style="font-family: monospace; font-size: 0.9em;">{query.get("query_name", "N/A")}</td>
                    <td>{query.get("query_type", "N/A")}</td>
                    <td>{query.get("src_ip", "N/A")}</td>
                    <td>{query.get("dst_ip", "N/A")}</td>
                </tr>
                """

            html += "</tbody></table>"

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

                # Format indicators
                if len(indicators) > 2:
                    indicators_str = ", ".join(indicators[:2]) + f" +{len(indicators)-2} more"
                else:
                    indicators_str = ", ".join(indicators) if indicators else "Various"

                html += f"""
                <tr>
                    <td><strong>{event.get("source_ip", "N/A")}</strong></td>
                    <td style="font-family: monospace; font-size: 0.85em;">{domain}</td>
                    <td>{event.get("query_count", 0)}</td>
                    <td>{avg_length:.0f} chars</td>
                    <td>{entropy:.2f} bits</td>
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
        type_breakdown = data_exfiltration_data.get("type_breakdown", {})

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
        type_breakdown = lateral_movement_data.get("type_breakdown", {})

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
