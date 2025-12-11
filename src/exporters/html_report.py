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

    def _identify_service(self, port: int) -> tuple[str, str, str, bool]:
        """
        Identify service and whether high jitter is expected.

        Args:
            port: Port number to identify

        Returns:
            Tuple of (service_name, emoji, description, expect_high_jitter)
        """
        if port in self.KNOWN_ASYNC_SERVICES:
            name, emoji, description = self.KNOWN_ASYNC_SERVICES[port]
            return (name, emoji, description, True)  # High jitter expected
        return ("Unknown", "❓", "Unknown service", False)

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
        .mechanisms-reference-box {
            margin: 30px 0;
            background: #f8f9fa;
            padding: 25px;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
        }

        .mechanisms-reference-box h4 {
            margin-top: 0;
            margin-bottom: 20px;
            color: #2c3e50;
            font-size: 1.2em;
        }

        .mechanisms-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }

        .mechanism-card {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
            transition: all 0.2s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }

        .mechanism-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            transform: translateY(-2px);
        }

        .mechanism-header {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            background: #f8f9fa;
            border-bottom: 2px solid #e0e0e0;
        }

        .mechanism-icon {
            font-size: 1.5em;
        }

        .mechanism-name {
            font-weight: 600;
            color: #2c3e50;
            font-size: 1em;
        }

        .mechanism-body {
            padding: 16px;
        }

        .mechanism-description {
            margin: 0 0 12px 0;
            color: #555;
            font-size: 0.95em;
            line-height: 1.4;
        }

        .mechanism-details {
            margin-bottom: 12px;
        }

        .expand-btn {
            background: #f8f9fa;
            border: 1px solid #e0e0e0;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9em;
            color: #3498db;
            font-weight: 500;
            transition: all 0.2s ease;
            width: 100%;
            text-align: left;
        }

        .expand-btn:hover {
            background: #e8e8e8;
            border-color: #3498db;
            color: #2980b9;
        }

        .expand-btn:focus {
            outline: 2px solid #3498db;
            outline-offset: 2px;
        }

        .expand-btn.expanded {
            background: #e8f8f5;
            border-color: #1abc9c;
            color: #1abc9c;
        }

        .mechanism-details-expanded {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e0e0e0;
        }

        .mechanism-details-expanded p {
            margin: 10px 0;
            color: #333;
            font-size: 0.9em;
        }

        .mechanism-details-expanded ul {
            margin: 10px 0;
            padding-left: 20px;
            color: #333;
            font-size: 0.9em;
        }

        .mechanism-details-expanded li {
            margin: 6px 0;
        }

        /* Collapsible Section Enhancements (Pure CSS - No JavaScript) */
        .collapsible-section {
            margin: 30px 0;
            border-radius: 8px;
            overflow: hidden;
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
            overflow: hidden;
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

        /* Flow Details (Expanded Content) */
        .flow-details-collapsible {
            margin-top: 20px;
        }

        .flow-details {
            margin-top: 20px;
            padding-top: 20px;
            border-top: 2px solid #e0e0e0;
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

            .mechanisms-grid {
                grid-template-columns: 1fr;
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
            .mechanism-card,
            .expand-btn,
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

            .expand-btn {
                display: none;
            }

            .mechanism-details-expanded {
                display: block !important;
            }

            .flow-detail-card {
                page-break-inside: avoid;
            }
        }
    </style>
    <script>
        /* ==========================================
           RETRANSMISSION UI INTERACTIVITY
           ========================================== */

        // Toggle mechanism details (Learn More buttons)
        function toggleMechanismDetails(btn) {
            const targetId = btn.dataset.target;
            const details = document.getElementById(targetId);
            const isHidden = details.style.display === 'none';

            details.style.display = isHidden ? 'block' : 'none';
            btn.classList.toggle('expanded');

            // Update button text
            btn.textContent = isHidden ? 'Hide Details ↑' : 'Learn More ↓';
        }

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

        // Toggle flow details (individual flow expand buttons)
        function toggleFlowDetails(btn) {
            const flowId = btn.dataset.flowId;
            const details = document.getElementById(flowId);
            const isHidden = details.style.display === 'none';
            const expandIcon = btn.querySelector('.expand-icon');

            details.style.display = isHidden ? 'block' : 'none';
            btn.classList.toggle('expanded');

            // Update expand icon rotation via class
            if (isHidden) {
                setTimeout(() => {
                    btn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }, 100);
            }
        }

        // Expand all flows (utility function)
        function expandAllFlows() {
            const buttons = document.querySelectorAll('.flow-expand-btn');
            buttons.forEach(btn => {
                const flowId = btn.dataset.flowId;
                const details = document.getElementById(flowId);
                if (details && details.style.display === 'none') {
                    details.style.display = 'block';
                    btn.classList.add('expanded');
                }
            });
        }

        // Collapse all flows (utility function)
        function collapseAllFlows() {
            const buttons = document.querySelectorAll('.flow-expand-btn');
            buttons.forEach(btn => {
                const flowId = btn.dataset.flowId;
                const details = document.getElementById(flowId);
                if (details && details.style.display !== 'none') {
                    details.style.display = 'none';
                    btn.classList.remove('expanded');
                }
            });
        }

        // Keyboard support for accessibility (collapsible headers use Pure CSS with labels)
        document.addEventListener('keydown', function(e) {
            // Space key on buttons
            if (e.key === ' ' && (e.target.classList.contains('expand-btn') || e.target.classList.contains('flow-expand-btn'))) {
                e.preventDefault();
                if (e.target.classList.contains('expand-btn')) {
                    toggleMechanismDetails(e.target);
                } else if (e.target.classList.contains('flow-expand-btn')) {
                    toggleFlowDetails(e.target);
                }
            }
        });

        // Initialize event listeners for retransmission UI (collapsibles use Pure CSS now)
        function initializeEventListeners() {
            // Add click event listeners to expand buttons
            document.querySelectorAll('.expand-btn').forEach(btn => {
                if (!btn.hasAttribute('tabindex')) {
                    btn.setAttribute('tabindex', '0');
                }
                btn.addEventListener('click', function() {
                    toggleMechanismDetails(this);
                });
            });

            // Add click event listeners to flow expand buttons
            document.querySelectorAll('.flow-expand-btn').forEach(btn => {
                if (!btn.hasAttribute('tabindex')) {
                    btn.setAttribute('tabindex', '0');
                }
                btn.addEventListener('click', function() {
                    toggleFlowDetails(this);
                });
            });

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
                        <div class="progress-fill" style="width: {comp_score}%; background-color: {color};">{comp_score:.0f}%</div>  # noqa: E501
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
        else:
            # If no component scores available, provide guidance
            html += """
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
                <p style="margin: 0; font-size: 0.95em; color: #856404;">
                    <strong>ℹ️ Component Score Details Not Available</strong><br>
                    The health score is based on overall network metrics. Run analysis with more detailed options to see component breakdowns.  # noqa: E501
                </p>
            </div>
            """

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

        # Add explanation box
        html += """
        <div style="background: #e8f4f8; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
            <p style="margin: 0 0 10px 0;"><strong>ℹ️ What is Jitter (RFC 3393 IPDV)?</strong></p>
            <p style="margin: 0 0 8px 0; font-size: 0.95em;">
                Jitter measures the <strong>variation in packet delay</strong>. High jitter causes choppy audio/video in real-time applications.  # noqa: E501
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
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
                    <p style="margin: 0 0 8px 0;"><strong>⚠️ High Jitter Detected</strong></p>
                    <p style="margin: 0; font-size: 0.95em; color: #856404;">
                        The extremely high jitter values (> 1 second) typically indicate a <strong>long-duration capture with significant gaps</strong>  # noqa: E501
                        between packets, rather than continuous real-time traffic. This is normal for passive monitoring or captures  # noqa: E501
                        spanning hours/days. For real-time application analysis, use shorter capture windows (5-10 minutes).  # noqa: E501
                    </p>
                </div>
                """

        # High jitter flows - modern collapsible card design
        high_jitter_flows = jitter_data.get("high_jitter_flows", [])
        if high_jitter_flows:
            # Limit to top 10 flows sorted by severity/mean jitter
            top_flows = sorted(
                high_jitter_flows,
                key=lambda x: (
                    {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(x.get("severity", "low"), 0),
                    x.get("mean_jitter", 0),
                ),
                reverse=True,
            )[:10]

            # Collapsible section for jitter flows (Pure CSS with checkbox)
            html += '<div class="collapsible-section">'
            html += f"""
                <input type="checkbox" id="collapsible-jitter" class="collapsible-checkbox">
                <label for="collapsible-jitter" class="collapsible-header">
                    <span class="toggle-icon">▶</span>
                    <span class="header-title">Top Flows with High Jitter ({len(top_flows)})</span>
                    <span class="header-info">Click to expand flow details</span>
                </label>
                <div class="collapsible-content">
                    <div class="content-inner">
            """

            # Generate flow detail cards
            for idx, flow in enumerate(top_flows):
                flow_str = flow.get("flow", "N/A")
                severity = flow.get("severity", "low")
                mean_jitter = flow.get("mean_jitter", 0) * 1000  # Convert to ms
                max_jitter = flow.get("max_jitter", 0) * 1000
                p95_jitter = flow.get("p95_jitter", 0) * 1000
                packet_count = flow.get("packets", "N/A")

                # Parse flow string for IPs, ports, and Wireshark filter
                # Format: "src_ip:src_port -> dst_ip:dst_port (proto)"
                src_ip, src_port, dst_ip, dst_port = "0.0.0.0", "0", "0.0.0.0", "0"
                try:
                    if " -> " in flow_str:
                        parts = flow_str.replace(" -> ", ":").split(":")
                        if len(parts) >= 4:
                            src_ip = parts[0]
                            src_port = parts[1]
                            dst_ip = parts[2]
                            dst_port_str = parts[3].split(" ")[0]  # Remove "(TCP)" or "(UDP)"
                            dst_port = dst_port_str
                except (IndexError, ValueError):
                    pass  # Keep defaults if parsing fails

                # Parse port as integer for service detection
                dst_port_int = 0
                try:
                    dst_port_int = int(dst_port)
                except (ValueError, TypeError):
                    pass

                # Identify service and adjust severity
                service_name, service_emoji, service_desc, expect_high_jitter = self._identify_service(dst_port_int)  # noqa: E501

                # Adjust severity badge if high jitter is expected for this service
                adjusted_severity = severity
                severity_note = ""
                if expect_high_jitter and severity in ["critical", "high"]:
                    adjusted_severity = "medium"
                    severity_note = " (Expected)"

                # Determine badge class
                badge_class = f"badge-{adjusted_severity}"

                # Service badge display
                if service_name != "Unknown":
                    service_badge = f'<span class="service-badge">{service_emoji} {service_name}</span>'
                else:
                    service_badge = f'<span class="service-badge">🔌 Port {dst_port_int}</span>' if dst_port_int > 0 else '<span class="service-badge">🔌 Unknown</span>'  # noqa: E501

                # Generate Wireshark filter
                wireshark_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.srcport == {src_port} && tcp.dstport == {dst_port}"  # noqa: E501

                # Build flow card HTML
                html += f"""
                    <div class="flow-detail-card">
                        <div class="flow-header">
                            <div class="flow-title">
                                <span class="flow-label">Flow {idx + 1}</span>
                                <code class="flow-key">{flow_str}</code>
                            </div>
                            <div class="flow-badges">
                                {service_badge}
                                <span class="severity-badge {badge_class}">
                                    {adjusted_severity.upper()}{severity_note}
                                </span>
                            </div>
                        </div>
                        <div class="flow-body">
                            <div class="flow-stats-grid">
                                <div class="flow-stat">
                                    <span class="stat-label">Mean Jitter</span>
                                    <span class="stat-value">{mean_jitter:.2f} ms</span>
                                </div>
                                <div class="flow-stat">
                                    <span class="stat-label">Max Jitter</span>
                                    <span class="stat-value">{max_jitter:.2f} ms</span>
                                </div>
                                <div class="flow-stat">
                                    <span class="stat-label">P95 Jitter</span>
                                    <span class="stat-value">{p95_jitter:.2f} ms</span>
                                </div>
                                <div class="flow-stat">
                                    <span class="stat-label">Packets</span>
                                    <span class="stat-value">{packet_count}</span>
                                </div>
                            </div>
                """

                # Add service context tooltip for async services
                if expect_high_jitter:
                    html += f"""
                            <div class="service-context">
                                <span class="tooltip-wrapper">
                                    <span class="tooltip-icon">ℹ️</span>
                                    <span class="tooltip-text">
                                        High jitter is expected for {service_name} due to async batching and long-polling
                                    </span>
                                </span>
                                <span class="context-text">High jitter is normal for this service</span>
                            </div>
                    """

                # Add Wireshark debug section
                html += f"""
                            <div class="wireshark-section">
                                <strong>🔍 Debug this flow:</strong>
                                <code class="copy-code">{wireshark_filter}</code>
                                <button class="copy-btn" onclick="copyToClipboard(this)">📋 Copy</button>
                            </div>
                        </div>
                    </div>
                """

            html += "            </div>"  # content-inner
            html += "        </div>"  # collapsible-content
            html += "    </div>"  # collapsible-section

        return html

    def _generate_service_section(self, results: dict[str, Any]) -> str:
        """Generate service classification section."""
        service_data = results.get("service_classification", {})

        html = "<h2>🧠 Service Classification</h2>"

        # Add explanation box
        html += """
        <div style="background: #e8f4f8; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
            <p style="margin: 0 0 10px 0;"><strong>ℹ️ What is Service Classification?</strong></p>
            <p style="margin: 0 0 12px 0; font-size: 0.95em;">
                Intelligent traffic classification based on <strong>behavioral patterns</strong>, not just port numbers.
                Identifies application types by analyzing packet sizes, timing, and flow characteristics.
            </p>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; font-size: 0.9em;">  # noqa: E501
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
                    "Control": "This indicates primarily <strong>network management traffic</strong> (DNS, mDNS, NTP, DHCP). "  # noqa: E501
                    "Common in passive monitoring or captures with minimal user activity.",
                    "Streaming": "This indicates heavy <strong>multimedia usage</strong> (video/audio streaming). "
                    "May require bandwidth optimization or QoS prioritization.",
                    "Interactive": "This indicates primarily <strong>web browsing and interactive applications</strong> (HTTP, SSH). "  # noqa: E501
                    "Typical of normal user activity with request/response patterns.",
                    "Bulk": "This indicates significant <strong>file transfer activity</strong> (FTP, large downloads). "  # noqa: E501
                    "May impact available bandwidth for real-time applications.",
                    "VoIP": "This indicates heavy <strong>voice/video conferencing usage</strong>. "
                    "Requires consistent low latency and jitter for quality calls.",
                }

                message = context_messages.get(service_name, "")
                if message:
                    html += f"""
            <div style="background: #f0f8ff; border-left: 4px solid #2196F3; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
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
                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
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
        """Generate confidence overview box for retransmission analysis."""
        total_retrans = retrans_data.get("total_retransmissions", 0)
        retrans_list = retrans_data.get("retransmissions", [])

        # Determine overall confidence based on data quality
        high_confidence_count = sum(1 for r in retrans_list if r.get("confidence") == "high")
        medium_confidence_count = sum(1 for r in retrans_list if r.get("confidence") == "medium")
        _low_confidence_count = sum(1 for r in retrans_list if r.get("confidence") == "low")  # noqa: F841

        # Overall confidence is based on majority
        if high_confidence_count > len(retrans_list) * 0.6:
            _overall_confidence = "high"  # noqa: F841
            confidence_class = "confidence-high"
            confidence_emoji = "🟢"
            confidence_text = "High"
        elif high_confidence_count + medium_confidence_count > len(retrans_list) * 0.5:
            _overall_confidence = "medium"  # noqa: F841
            confidence_class = "confidence-medium"
            confidence_emoji = "🟡"
            confidence_text = "Medium"
        else:
            _overall_confidence = "low"  # noqa: F841
            confidence_class = "confidence-low"
            confidence_emoji = "🟠"
            confidence_text = "Low"

        html = '<div class="confidence-overview-box">'
        html += '  <div class="confidence-header">'
        html += "    <h4>Analysis Confidence</h4>"
        html += f"""
        <span class="confidence-badge {confidence_class}">
            <span class="badge-icon">{confidence_emoji}</span> {confidence_text}
        </span>
        """
        html += "  </div>"
        html += '  <div class="confidence-details">'
        html += (
            f'    <p class="confidence-reason">Detection confidence is <strong>{confidence_text}</strong> based on:</p>'
        )
        html += '    <ul class="confidence-factors">'

        # Add confidence factors
        if total_retrans > 100:
            html += (
                f'      <li><span class="factor-icon">✓</span> Sufficient sample size ({total_retrans:,} events)</li>'
            )
        elif total_retrans > 10:
            html += f'      <li><span class="factor-icon">✓</span> Adequate sample size ({total_retrans:,} events)</li>'
        else:
            html += f'      <li><span class="factor-icon">⚠</span> Limited sample size ({total_retrans:,} events)</li>'

        if high_confidence_count > 0:
            html += (
                f'      <li><span class="factor-icon">✓</span> {high_confidence_count} high-confidence detections</li>'
            )

        # Check for consistent patterns
        rto_count = retrans_data.get("rto_count", 0)
        fast_retrans = retrans_data.get("fast_retrans_count", 0)
        if rto_count > 0 or fast_retrans > 0:
            html += '      <li><span class="factor-icon">✓</span> Clear retransmission patterns identified</li>'

        html += "    </ul>"
        html += "  </div>"
        html += "</div>"

        return html

    def _generate_mechanism_cards(self) -> str:
        """Generate retransmission mechanism reference cards."""
        mechanisms = [
            {
                "icon": "⏱️",
                "name": "RTO Timeout",
                "description": "ACK not received within the Retransmission Timeout window.",
                "severity": "badge-danger",
                "severity_text": "High",
                "id": "rto-details",
                "details": [
                    "Packet loss on network path",
                    "Sustained high latency",
                    "Network congestion",
                    "Router buffer overflow",
                ],
                "impact": "Significant connection slowdown, reduced throughput",
                "action": "Check network stability, investigate packet loss",
            },
            {
                "icon": "⚡",
                "name": "Fast Retransmission",
                "description": "Three or more duplicate ACKs received (RFC 5681).",
                "severity": "badge-warning",
                "severity_text": "Medium",
                "id": "fast-retrans-details",
                "details": [
                    "Packet loss causing out-of-order delivery",
                    "TCP window reordering",
                    "Network reordering (normal in Internet paths)",
                    "Congestion window reduction",
                ],
                "impact": "Brief latency spike, usually recoverable quickly",
                "action": "Monitor patterns, usually not critical",
            },
            {
                "icon": "📋",
                "name": "Duplicate ACK",
                "description": "Same ACK number received multiple times.",
                "severity": "badge-info",
                "severity_text": "Low",
                "id": "dup-ack-details",
                "details": [
                    "Packet reordering on network",
                    "Receiver retransmitting ACKs",
                    "Common in WAN environments",
                    "Out-of-order segment arrival",
                ],
                "impact": "Usually minimal, normal TCP behavior",
                "action": "Not critical, monitor patterns over time",
            },
            {
                "icon": "💓",
                "name": "Keep-Alive",
                "description": "Connection maintenance packet to prevent NAT timeout.",
                "severity": "badge-success",
                "severity_text": "Low",
                "id": "keepalive-details",
                "details": [
                    "Idle connection state",
                    "NAT/Firewall timeout prevention",
                    "Session persistence",
                    "Connection health check",
                ],
                "impact": "None, normal TCP behavior",
                "action": "No action needed, expected behavior",
            },
        ]

        html = '<div class="mechanisms-reference-box">'
        html += "  <h4>Retransmission Mechanisms</h4>"
        html += '  <div class="mechanisms-grid">'

        for mech in mechanisms:
            html += f"""
            <div class="mechanism-card">
                <div class="mechanism-header">
                    <span class="mechanism-icon">{mech["icon"]}</span>
                    <span class="mechanism-name">{mech["name"]}</span>
                </div>
                <div class="mechanism-body">
                    <p class="mechanism-description">{mech["description"]}</p>
                    <div class="mechanism-details">
                        <strong>Severity:</strong>
                        <span class="badge {mech["severity"]}">{mech["severity_text"]}</span>
                    </div>
                    <button class="expand-btn" data-target="{mech["id"]}" onclick="toggleMechanismDetails(this)">
                        Learn More ↓
                    </button>
                    <div class="mechanism-details-expanded" id="{mech["id"]}" style="display: none;">
                        <p><strong>Why it occurs:</strong></p>
                        <ul>
            """
            for detail in mech["details"]:
                html += f"                            <li>{detail}</li>"
            html += f"""
                        </ul>
                        <p><strong>Impact:</strong> {mech["impact"]}</p>
                        <p><strong>User Action:</strong> {mech["action"]}</p>
                    </div>
                </div>
            </div>
            """

        html += "  </div>"
        html += "</div>"

        return html

    def _generate_handshake_mechanisms(self) -> str:
        """Generate TCP handshake mechanism reference cards."""
        mechanisms = [
            {
                "icon": "✅",
                "name": "Normal Handshake",
                "description": "Standard 3-way handshake completing within expected time.",
                "severity": "badge-success",
                "severity_text": "Normal",
                "id": "normal-handshake-details",
                "details": [
                    "Client sends SYN",
                    "Server responds with SYN-ACK",
                    "Client confirms with ACK",
                    "Typical completion time < 100ms for LAN",
                ],
                "impact": "None, normal TCP operation",
                "action": "No action needed",
                "timing": "< 100ms",
            },
            {
                "icon": "🐌",
                "name": "Slow Handshake",
                "description": "Handshake taking longer than expected (> 100ms).",
                "severity": "badge-warning",
                "severity_text": "Medium",
                "id": "slow-handshake-details",
                "details": [
                    "Network latency (WAN, satellite)",
                    "Server under heavy load",
                    "Firewall/IDS inspection delay",
                    "Geographic distance",
                ],
                "impact": "Increased connection establishment time, user-perceived delay",
                "action": "Check network path, server load, firewall rules",
                "timing": "> 100ms",
            },
            {
                "icon": "❌",
                "name": "Incomplete Handshake",
                "description": "Handshake not completed (missing SYN-ACK or ACK).",
                "severity": "badge-danger",
                "severity_text": "High",
                "id": "incomplete-handshake-details",
                "details": [
                    "Server not listening (port closed)",
                    "Firewall blocking connection",
                    "Packet loss on network",
                    "Server overloaded (SYN flood)",
                ],
                "impact": "Connection failure, application cannot communicate",
                "action": "Verify service availability, check firewall rules",
                "timing": "Never completes",
            },
            {
                "icon": "🔁",
                "name": "SYN Retransmission",
                "description": "Client retrying SYN packet (no SYN-ACK received).",
                "severity": "badge-warning",
                "severity_text": "Medium",
                "id": "syn-retrans-details",
                "details": [
                    "Original SYN packet lost",
                    "SYN-ACK response lost",
                    "Server slow to respond",
                    "Asymmetric routing issues",
                ],
                "impact": "Delayed connection, exponential backoff (1s, 2s, 4s...)",
                "action": "Investigate packet loss, check server responsiveness",
                "timing": "Retry delays",
            },
        ]

        html = '<div class="mechanisms-reference-box">'
        html += "  <h4>Handshake Types & Timing</h4>"
        html += '  <div class="mechanisms-grid">'

        for mech in mechanisms:
            html += f"""
            <div class="mechanism-card">
                <div class="mechanism-header">
                    <span class="mechanism-icon">{mech["icon"]}</span>
                    <span class="mechanism-name">{mech["name"]}</span>
                </div>
                <div class="mechanism-body">
                    <p class="mechanism-description">{mech["description"]}</p>
                    <div class="mechanism-details">
                        <strong>Timing:</strong>
                        <span class="badge {mech["severity"]}">{mech["timing"]}</span>
                    </div>
                    <button class="expand-btn" data-target="{mech["id"]}" onclick="toggleMechanismDetails(this)">
                        Learn More ↓
                    </button>
                    <div class="mechanism-details-expanded" id="{mech["id"]}" style="display: none;">
                        <p><strong>Why it occurs:</strong></p>
                        <ul>
            """
            for detail in mech["details"]:
                html += f"                            <li>{detail}</li>"
            html += f"""
                        </ul>
                        <p><strong>Impact:</strong> {mech["impact"]}</p>
                        <p><strong>User Action:</strong> {mech["action"]}</p>
                    </div>
                </div>
            </div>
            """

        html += "  </div>"
        html += "</div>"

        return html

    def _generate_window_mechanisms(self) -> str:
        """Generate TCP window mechanism reference cards."""
        mechanisms = [
            {
                "icon": "🚫",
                "name": "Zero Window",
                "description": "Receiver advertises window size of 0 (cannot accept more data).",
                "severity": "badge-danger",
                "severity_text": "High",
                "id": "zero-window-details",
                "details": [
                    "Receiver's buffer full (application not reading fast enough)",
                    "Slow application processing",
                    "Resource exhaustion (memory, CPU)",
                    "Flow control mechanism (intentional throttling)",
                ],
                "impact": "Sender pauses, throughput drops to zero, increased latency",
                "action": "Investigate receiver-side application, check buffer sizes",
                "reference": "RFC 793 (Section 3.7 - Flow Control)",
            },
            {
                "icon": "📈",
                "name": "Window Update",
                "description": "Receiver advertises increased window size (ready for more data).",
                "severity": "badge-success",
                "severity_text": "Low",
                "id": "window-update-details",
                "details": [
                    "Application consumed data from buffer",
                    "Recovery from zero window condition",
                    "Normal flow control operation",
                ],
                "impact": "Normal operation, allows sender to resume transmission",
                "action": "None (normal behavior)",
                "reference": "RFC 793",
            },
            {
                "icon": "🔍",
                "name": "Zero Window Probe",
                "description": "Sender probes receiver to check if window has opened.",
                "severity": "badge-warning",
                "severity_text": "Medium",
                "id": "window-probe-details",
                "details": [
                    "Sender received zero window advertisement",
                    "Periodic check (typically every 5-60 seconds)",
                    "Prevents indefinite stall",
                ],
                "impact": "Minimal (1 byte probes), ensures connection recovery",
                "action": "Monitor duration, investigate if prolonged",
                "reference": "RFC 1122 (Section 4.2.2.17)",
            },
            {
                "icon": "📉",
                "name": "Receiver Bottleneck",
                "description": "Receiver consistently advertises small window sizes.",
                "severity": "badge-warning",
                "severity_text": "Medium",
                "id": "receiver-bottleneck-details",
                "details": [
                    "Limited receiver buffer size",
                    "Slow application processing",
                    "CPU/memory constraints",
                    "Intentional rate limiting",
                ],
                "impact": "Reduced throughput, sender cannot fully utilize bandwidth",
                "action": "Tune receiver buffers (SO_RCVBUF), optimize application",
                "reference": "RFC 793",
            },
        ]

        html = '<div class="mechanisms-reference-box">'
        html += "  <h4>TCP Window Mechanisms</h4>"
        html += '  <div class="mechanisms-grid">'

        for mech in mechanisms:
            html += f"""
            <div class="mechanism-card">
                <div class="mechanism-header">
                    <span class="mechanism-icon">{mech["icon"]}</span>
                    <span class="mechanism-name">{mech["name"]}</span>
                </div>
                <div class="mechanism-body">
                    <p class="mechanism-description">{mech["description"]}</p>
                    <div class="mechanism-details">
                        <strong>Severity:</strong>
                        <span class="badge {mech["severity"]}">{mech["severity_text"]}</span>
                    </div>
                    <button class="expand-btn" data-target="{mech["id"]}" onclick="toggleMechanismDetails(this)">
                        Learn More ↓
                    </button>
                    <div class="mechanism-details-expanded" id="{mech["id"]}" style="display: none;">
                        <p><strong>Why it occurs:</strong></p>
                        <ul>
            """
            for detail in mech["details"]:
                html += f"                            <li>{detail}</li>"
            html += f"""
                        </ul>
                        <p><strong>Impact:</strong> {mech["impact"]}</p>
                        <p><strong>User Action:</strong> {mech["action"]}</p>
                        <p><strong>RFC Reference:</strong> {mech["reference"]}</p>
                    </div>
                </div>
            </div>
            """

        html += "  </div>"
        html += "</div>"

        return html

    def _generate_flow_detail_card(self, flow_key: str, retrans_list: list, index: int, flow_count: int) -> str:
        """Generate individual flow detail card with expandable analysis."""
        flow_label = f"Flow {index + 1}"
        total_retrans = len(retrans_list)

        # Count mechanisms
        rto_count = sum(1 for r in retrans_list if r.get("retrans_type") == "RTO")
        fast_retrans = sum(1 for r in retrans_list if r.get("retrans_type") == "Fast Retransmission")
        other_count = total_retrans - rto_count - fast_retrans

        # Determine overall confidence for this flow
        confidence_counts = {"high": 0, "medium": 0, "low": 0}
        for r in retrans_list:
            conf = r.get("confidence", "low")
            if conf in confidence_counts:
                confidence_counts[conf] += 1

        if confidence_counts["high"] > total_retrans * 0.5:
            flow_confidence = "confidence-high"
            flow_confidence_text = "High Confidence"
            flow_confidence_emoji = "🟢"
        elif confidence_counts["high"] + confidence_counts["medium"] > total_retrans * 0.5:
            flow_confidence = "confidence-medium"
            flow_confidence_text = "Medium Confidence"
            flow_confidence_emoji = "🟡"
        else:
            flow_confidence = "confidence-low"
            flow_confidence_text = "Low Confidence"
            flow_confidence_emoji = "🟠"

        # Determine severity
        retrans_rate = total_retrans / flow_count if flow_count > 0 else 0
        if retrans_rate > 0.05 or total_retrans > 50:
            severity_level = "warning"
            severity_text = "⚠️ High Retrans Rate"
        elif retrans_rate > 0.02 or total_retrans > 20:
            severity_level = "info"
            severity_text = "Moderate Retrans Rate"
        else:
            severity_level = "info"
            severity_text = "Low Retrans Rate"

        # Calculate duration
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

        html = '<div class="flow-detail-card">'
        html += '  <div class="flow-header">'
        html += '    <div class="flow-title">'
        html += f'      <span class="flow-label">{flow_label}</span>'
        html += f'      <code class="flow-key">{flow_key}</code>'
        html += "    </div>"
        html += '    <div class="flow-badges">'
        html += f"""
        <span class="confidence-badge {flow_confidence}">
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
              <span class="stat-label">Duration</span>
              <span class="stat-value">{self._format_duration(duration)}</span>
          </div>
        """
        html += "    </div>"

        # Collapsible detailed analysis
        html += '    <div class="flow-details-collapsible">'
        html += f"""
          <button class="flow-expand-btn" data-flow-id="flow-{index}" onclick="toggleFlowDetails(this)">
              <span class="expand-icon">+</span>
              View Detailed Analysis
          </button>
          <div class="flow-details" id="flow-{index}" style="display: none;">
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

            # Build Wireshark filter
            wireshark_filter = f"tcp.seq == {seq_num} && ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.srcport == {src_port} && tcp.dstport == {dst_port}"  # noqa: E501

            html += f"""
                <div class="timeline-event {timeline_class}">
                    <span class="timeline-marker"></span>
                    <div class="timeline-content">
                        <span class="timeline-time">{timestamp:.3f}s</span>
                        <span class="timeline-type">{type_label}</span>
                        <span class="timeline-detail">Seq: {seq_num}</span>
                        <div class="wireshark-section">
                            <strong>🔍 Debug this packet:</strong>
                            <code class="copy-code">{wireshark_filter}</code>
                            <button class="copy-btn" onclick="copyToClipboard(this)">📋 Copy</button>
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
                <div class="metric-subtext">{(rto_count/total_retrans*100) if total_retrans > 0 else 0:.1f}% of retransmissions</div>  # noqa: E501
            </div>
            <div class="metric-card metric-warning">
                <div class="metric-icon">⚡</div>
                <div class="metric-label">Fast Retransmissions</div>
                <div class="metric-value">{fast_retrans:,}</div>
                <div class="metric-subtext">{(fast_retrans/total_retrans*100) if total_retrans > 0 else 0:.1f}% of retransmissions</div>  # noqa: E501
            </div>
            """
            html += "</div>"

            # Add confidence overview
            html += self._generate_confidence_overview(retrans_data)

            # Add mechanism reference cards
            html += self._generate_mechanism_cards()

            # Top flows with retransmissions - Enhanced with collapsible cards
            retrans_list = retrans_data.get("retransmissions", [])
            if retrans_list:
                # Group by flow
                flows = {}
                for r in retrans_list[:200]:  # Increased limit for better coverage
                    flow_key = f"{r.get('src_ip')}:{r.get('src_port')} → {r.get('dst_ip')}:{r.get('dst_port')}"
                    if flow_key not in flows:
                        flows[flow_key] = []
                    flows[flow_key].append(r)

                # Sort flows by retransmission count
                sorted_flows = sorted(flows.items(), key=lambda x: len(x[1]), reverse=True)[:10]

                # Collapsible section for flows (Pure CSS with checkbox)
                html += '<div class="collapsible-section">'
                html += f"""
                    <input type="checkbox" id="collapsible-retransmissions" class="collapsible-checkbox">
                    <label for="collapsible-retransmissions" class="collapsible-header">
                        <span class="toggle-icon">▶</span>
                        <span class="header-title">Top Flows with Retransmissions ({len(sorted_flows)})</span>
                        <span class="header-info">Click to expand flow details</span>
                    </label>
                    <div class="collapsible-content">
                        <div class="content-inner">
                """

                # Generate flow detail cards
                for idx, (flow_key, retrans) in enumerate(sorted_flows):
                    html += self._generate_flow_detail_card(flow_key, retrans, idx, total_packets)

                html += "        </div>"
                html += "    </div>"
                html += "</div>"

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

                # Add handshake mechanism cards
                html += self._generate_handshake_mechanisms()

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

            # Calculate total zero windows and duration
            flow_stats = window_data.get("flow_statistics", [])
            total_zero_windows = sum(f.get("zero_window_count", 0) for f in flow_stats)
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
                    Total Duration
                    <span class="tooltip-wrapper">
                        <span class="tooltip-icon">ℹ️</span>
                        <span class="tooltip-text">
                            Cumulative time all flows spent in zero-window state (sender blocked, unable to transmit). Longer durations indicate more severe throughput impact.  # noqa: E501
                        </span>
                    </span>
                </div>
                <div class="metric-value">{self._format_duration(total_duration)}</div>
            </div>
            """
            html += "</div>"

            # Add window mechanism cards
            html += self._generate_window_mechanisms()

            flow_stats = window_data.get("flow_statistics", [])
            if flow_stats:
                # Filter to only show flows with actual zero windows
                flows_with_zero_windows = [f for f in flow_stats if f.get("zero_window_count", 0) > 0]

                if flows_with_zero_windows:
                    # Sort by zero window count (descending) to show worst first
                    sorted_flows = sorted(
                        flows_with_zero_windows, key=lambda f: f.get("zero_window_count", 0), reverse=True
                    )[:10]

                    # Collapsible section for top 10 flows (Pure CSS with checkbox)
                    html += '<div class="collapsible-section">'
                    html += f"""
                        <input type="checkbox" id="collapsible-window-issues" class="collapsible-checkbox">
                        <label for="collapsible-window-issues" class="collapsible-header">
                            <span class="toggle-icon">▶</span>
                            <span class="header-title">Top Flows with Window Issues ({len(sorted_flows)})</span>
                            <span class="header-info">Click to expand flow details</span>
                        </label>
                        <div class="collapsible-content">
                            <div class="content-inner">
                    """

                    for idx, flow in enumerate(sorted_flows):
                        bottleneck = flow.get("suspected_bottleneck", "none")
                        flow_key = flow.get("flow_key", "N/A")
                        zero_window_count = flow.get("zero_window_count", 0)
                        zero_window_duration = flow.get("zero_window_total_duration", 0)

                        # Determine severity badge
                        if bottleneck == "application":
                            badge_class = "badge-danger"
                            badge_text = "🚫 Critical Window Issue"
                        elif bottleneck == "network":
                            badge_class = "badge-warning"
                            badge_text = "⚠️ Network Bottleneck"
                        else:
                            badge_class = "badge-info"
                            badge_text = "Window Issue"

                        # Parse flow_key for Wireshark filter
                        # Window flow_key format: "src_ip:src_port->dst_ip:dst_port" (no spaces)
                        flow_parts = flow_key.replace("->", ":").split(":")
                        if len(flow_parts) == 4:
                            src_ip, src_port, dst_ip, dst_port = flow_parts
                        else:
                            src_ip, src_port, dst_ip, dst_port = "0.0.0.0", "0", "0.0.0.0", "0"

                        wireshark_filter = f"ip.src == {src_ip} && ip.dst == {dst_ip} && tcp.srcport == {src_port} && tcp.dstport == {dst_port} && tcp.window_size == 0"  # noqa: E501

                        html += f"""
                            <div class="flow-detail-card">
                                <div class="flow-header">
                                    <div class="flow-title">
                                        <span class="flow-label">Flow {idx + 1}</span>
                                        <code class="flow-key">{flow_key}</code>
                                    </div>
                                    <div class="flow-badges">
                                        <span class="severity-badge {badge_class}">
                                            {badge_text}
                                        </span>
                                    </div>
                                </div>
                                <div class="flow-body">
                                    <div class="flow-stats-grid">
                                        <div class="flow-stat">
                                            <span class="stat-label">Zero Windows</span>
                                            <span class="stat-value">{zero_window_count}</span>
                                        </div>
                                        <div class="flow-stat">
                                            <span class="stat-label">
                                                Total Duration
                                                <span class="tooltip-wrapper">
                                                    <span class="tooltip-icon">ℹ️</span>
                                                    <span class="tooltip-text">
                                                        Time this flow spent in zero-window state. During this period, the sender was blocked and could not transmit data.  # noqa: E501
                                                    </span>
                                                </span>
                                            </span>
                                            <span class="stat-value">{self._format_duration(zero_window_duration)}</span>  # noqa: E501
                                        </div>
                                        <div class="flow-stat">
                                            <span class="stat-label">Suspected Bottleneck</span>
                                            <span class="stat-value">{bottleneck.upper()}</span>
                                        </div>
                                        <div class="flow-stat">
                                            <span class="stat-label">Service</span>
                                            <span class="stat-value">Port {dst_port}</span>
                                        </div>
                                    </div>
                                    <div class="wireshark-section">
                                        <strong>🔍 Debug this flow:</strong>
                                        <code class="copy-code">{wireshark_filter}</code>
                                        <button class="copy-btn" onclick="copyToClipboard(this)">📋 Copy</button>
                                    </div>
                                </div>
                            </div>
                        """

                    html += "            </div>"
                    html += "        </div>"
                    html += "    </div>"

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
        _total_transactions = dns_data.get("total_transactions", 0)  # noqa: F841
        successful = dns_data.get("successful_transactions", 0)
        timeouts = dns_data.get("timeout_transactions", 0)
        errors = dns_data.get("error_transactions", 0)
        slow = dns_data.get("slow_transactions", 0)

        # Fix for Issue #10: Separate K8s expected errors from real errors
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
            # Show detailed breakdown: K8s expected vs real errors
            error_color = "#dc3545" if real_errors > 0 else "#ffc107"
            html += f"""
        <div class="metric-card" style="border-left-color: {error_color};">
            <div class="metric-label">Errors</div>
            <div class="metric-value">{errors:,}</div>
            <div style="font-size: 0.75em; color: #666; margin-top: 0.5rem;">
                <div style="color: #28a745;">✓ Expected K8s: {k8s_expected_errors}</div>
                <div style="color: {'#dc3545' if real_errors > 0 else '#28a745'};">{'⚠️' if real_errors > 0 else '✓'} Real Issues: {real_errors}</div>  # noqa: E501
            </div>
        </div>
            """
        else:
            # Standard error display (no K8s breakdown)
            html += f"""
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

        # DNS Error Types Breakdown
        error_types_breakdown = dns_data.get("error_types_breakdown", {})
        if error_types_breakdown:
            html += "<h3>🔍 DNS Error Types Breakdown</h3>"
            html += '<table class="data-table">'
            html += """
            <thead>
                <tr>
                    <th>Error Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
            """

            total_errors = sum(error_types_breakdown.values())
            for error_type, count in list(error_types_breakdown.items())[:10]:
                percentage = (count / total_errors * 100) if total_errors > 0 else 0

                # Color code based on error type severity
                badge_class = "badge-danger"
                if error_type == "Slow Response":
                    badge_class = "badge-warning"
                elif error_type == "Timeout":
                    badge_class = "badge-critical"
                elif error_type in ["NXDOMAIN", "SERVFAIL", "REFUSED"]:
                    badge_class = "badge-danger"

                html += f"""
                <tr>
                    <td><span class="badge {badge_class}">{error_type}</span></td>
                    <td>{count:,}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
                """

            html += "</tbody></table>"

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

        # Fix for Issue #10: Show K8s Expected Errors (informational)
        k8s_errors_details = dns_data.get("k8s_expected_errors_details", [])
        if k8s_errors_details:
            html += f"""
            <div style="margin-top: 1.5rem; padding: 1rem; background-color: #f8f9fa; border-left: 4px solid #28a745; border-radius: 4px;">  # noqa: E501
                <h4 style="margin: 0 0 0.5rem 0; color: #28a745;">
                    ℹ️ Kubernetes Expected DNS Errors ({k8s_expected_errors} total)
                </h4>
                <p style="margin: 0 0 1rem 0; font-size: 0.9em; color: #666;">
                    These NXDOMAIN responses for *.cluster.local domains are normal in Kubernetes multi-level DNS resolution.  # noqa: E501
                    They are excluded from problematic domains analysis.
                </p>
                <details style="cursor: pointer;">
                    <summary style="font-weight: 500; padding: 0.5rem; background: white; border-radius: 4px;">
                        Show Details ({len(k8s_errors_details)} samples)
                    </summary>
                    <table class="data-table" style="margin-top: 1rem;">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Error Code</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
            """
            for trans in k8s_errors_details[:15]:
                query = trans.get("query", {})
                response = trans.get("response", {})
                domain = query.get("query_name", "N/A")
                error_code = response.get("response_code_name", "N/A")
                timestamp = trans.get("timestamp", 0)

                html += f"""
                        <tr>
                            <td style="font-family: monospace; font-size: 0.85em;">{domain}</td>
                            <td><span class="badge badge-info">{error_code}</span></td>
                            <td style="font-size: 0.85em;">{timestamp:.3f}s</td>
                        </tr>
                """

            html += """
                        </tbody>
                    </table>
                </details>
            </div>
            """

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
                ✓ No security issues detected. The network traffic appears clean with no signs of port scanning, brute-force attacks, DDoS, or DNS tunneling.  # noqa: E501
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
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">  # noqa: E501
                <p style="margin: 0 0 8px 0;"><strong>ℹ️ About DNS Tunneling</strong></p>
                <p style="margin: 0; font-size: 0.9em; color: #555;">
                    DNS tunneling is a technique used to encode data of other programs or protocols in DNS queries and responses.  # noqa: E501
                    It's commonly used for <strong>command & control (C2) communication</strong>, <strong>data exfiltration</strong>,  # noqa: E501
                    and <strong>bypassing firewalls</strong>. Indicators include unusually long queries, high entropy subdomains  # noqa: E501
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
                    Indicators include <strong>large upload volumes</strong>, <strong>suspicious upload/download ratios</strong>,  # noqa: E501
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
                    Command & Control (C2) beaconing is periodic communication between compromised hosts and attacker servers.  # noqa: E501
                    Characteristics include <strong>regular time intervals</strong>, <strong>consistent payload sizes</strong>,  # noqa: E501
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
                    searching for key assets and data. Common protocols include <strong>SMB/CIFS (ports 445, 139)</strong>,  # noqa: E501
                    <strong>RDP (port 3389)</strong>, <strong>WinRM (ports 5985, 5986)</strong>, and <strong>RPC (port 135)</strong>.  # noqa: E501
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
