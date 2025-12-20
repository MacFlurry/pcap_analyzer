#!/usr/bin/env python3
"""
POC: Jitter Time-Series Visualization with Plotly.js

Demonstrates how to add interactive time-series graphs to pcap_analyzer
without modifying the existing codebase.
"""

from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import json

def analyze_jitter_timeseries(pcap_file):
    """
    Extract jitter time-series data from PCAP.

    Returns:
        dict: Flow-keyed jitter time-series data
    """
    packets = rdpcap(pcap_file)
    flow_packets = defaultdict(list)

    # Group packets by flow
    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            ip = pkt[IP]
            layer4 = pkt[TCP] if TCP in pkt else pkt[UDP]
            proto = "TCP" if TCP in pkt else "UDP"

            flow_key = f"{ip.src}:{layer4.sport} -> {ip.dst}:{layer4.dport} ({proto})"
            timestamp = float(pkt.time)

            flow_packets[flow_key].append(timestamp)

    # Calculate jitter time-series for each flow
    flow_jitter_timeseries = {}

    for flow_key, timestamps in flow_packets.items():
        if len(timestamps) < 3:
            continue

        timestamps.sort()

        # Calculate inter-packet delays
        delays = []
        delay_timestamps = []
        for i in range(1, len(timestamps)):
            delay = timestamps[i] - timestamps[i-1]
            delays.append(delay)
            delay_timestamps.append(timestamps[i])

        # Calculate jitter (IPDV) with timestamps
        jitter_values = []
        jitter_timestamps = []
        for i in range(1, len(delays)):
            jitter = abs(delays[i] - delays[i-1])
            jitter_values.append(jitter * 1000)  # Convert to ms
            jitter_timestamps.append(delay_timestamps[i])

        if len(jitter_values) > 0:
            # Make timestamps relative to first packet
            base_time = timestamps[0]
            relative_timestamps = [(t - base_time) for t in jitter_timestamps]

            flow_jitter_timeseries[flow_key] = {
                'timestamps': relative_timestamps,
                'jitter_values': jitter_values,
                'packet_count': len(timestamps),
                'jitter_samples': len(jitter_values)
            }

    return flow_jitter_timeseries


def generate_plotly_html(flow_data, output_file="jitter_poc.html"):
    """
    Generate HTML report with Plotly.js interactive graphs.

    Args:
        flow_data: Dictionary of flow jitter time-series
        output_file: Output HTML file path
    """

    # Select top 5 flows by number of jitter samples
    top_flows = sorted(flow_data.items(),
                      key=lambda x: x[1]['jitter_samples'],
                      reverse=True)[:5]

    html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POC: Jitter Time-Series Visualization</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .flow-header {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0 10px 0;
            font-family: monospace;
            font-size: 14px;
        }
        .stats {
            display: flex;
            gap: 20px;
            margin: 10px 0;
            font-size: 13px;
        }
        .stat-item {
            background: #e8f4f8;
            padding: 8px 15px;
            border-radius: 5px;
            border-left: 3px solid #3498db;
        }
        .graph-container {
            margin: 20px 0 40px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            background: #fafafa;
        }
        .note {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎨 POC: Interactive Jitter Time-Series Graphs</h1>

        <div class="success">
            <strong>✅ Proof of Concept Réussi!</strong><br>
            Cette page démontre comment ajouter des graphs interactifs Plotly.js
            à pcap_analyzer avec un effort minimal.
        </div>

        <div class="note">
            <strong>📊 Features interactives:</strong><br>
            • <strong>Hover</strong>: Survolez les points pour voir les valeurs exactes<br>
            • <strong>Zoom</strong>: Cliquez et glissez pour zoomer sur une zone<br>
            • <strong>Pan</strong>: Shift + glisser pour se déplacer<br>
            • <strong>Export</strong>: Bouton 📷 pour sauver en PNG<br>
            • <strong>Reset</strong>: Double-clic pour réinitialiser la vue
        </div>
"""

    # Generate graphs for top flows
    for idx, (flow_name, data) in enumerate(top_flows, 1):
        timestamps = data['timestamps']
        jitter_values = data['jitter_values']

        # Calculate stats
        mean_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else 0
        max_jitter = max(jitter_values) if jitter_values else 0
        min_jitter = min(jitter_values) if jitter_values else 0

        # Determine severity
        p95_jitter = sorted(jitter_values)[int(len(jitter_values) * 0.95)] if len(jitter_values) > 0 else 0
        severity = "🔴 CRITICAL" if p95_jitter > 50 else "🟠 WARNING" if p95_jitter > 30 else "🟢 OK"

        html_content += f"""
        <h2>Flow #{idx}</h2>
        <div class="flow-header">
            {flow_name}
        </div>
        <div class="stats">
            <div class="stat-item">
                <strong>Packets:</strong> {data['packet_count']}
            </div>
            <div class="stat-item">
                <strong>Jitter Samples:</strong> {data['jitter_samples']}
            </div>
            <div class="stat-item">
                <strong>Mean:</strong> {mean_jitter:.2f}ms
            </div>
            <div class="stat-item">
                <strong>P95:</strong> {p95_jitter:.2f}ms
            </div>
            <div class="stat-item">
                <strong>Max:</strong> {max_jitter:.2f}ms
            </div>
            <div class="stat-item">
                {severity}
            </div>
        </div>

        <div class="graph-container">
            <div id="graph-{idx}"></div>
        </div>

        <script>
        (function() {{
            var timestamps = {json.dumps(timestamps)};
            var jitter = {json.dumps(jitter_values)};

            var trace = {{
                x: timestamps,
                y: jitter,
                type: 'scatter',
                mode: 'lines+markers',
                name: 'Jitter',
                line: {{
                    color: '{('#e74c3c' if p95_jitter > 50 else '#f39c12' if p95_jitter > 30 else '#3498db')}',
                    width: 2
                }},
                marker: {{
                    size: 4,
                    color: '{('#e74c3c' if p95_jitter > 50 else '#f39c12' if p95_jitter > 30 else '#3498db')}'
                }},
                hovertemplate: '<b>Time:</b> %{{x:.3f}}s<br><b>Jitter:</b> %{{y:.2f}}ms<extra></extra>'
            }};

            // Add horizontal threshold lines
            var threshold_50ms = {{
                x: [timestamps[0], timestamps[timestamps.length-1]],
                y: [50, 50],
                type: 'scatter',
                mode: 'lines',
                name: 'Critical (50ms)',
                line: {{
                    color: '#e74c3c',
                    width: 1,
                    dash: 'dash'
                }},
                hoverinfo: 'skip'
            }};

            var threshold_30ms = {{
                x: [timestamps[0], timestamps[timestamps.length-1]],
                y: [30, 30],
                type: 'scatter',
                mode: 'lines',
                name: 'Warning (30ms)',
                line: {{
                    color: '#f39c12',
                    width: 1,
                    dash: 'dash'
                }},
                hoverinfo: 'skip'
            }};

            var data = [trace, threshold_50ms, threshold_30ms];

            var layout = {{
                title: {{
                    text: 'Jitter Over Time',
                    font: {{ size: 16, color: '#2c3e50' }}
                }},
                xaxis: {{
                    title: 'Time (seconds)',
                    gridcolor: '#e0e0e0',
                    showgrid: true
                }},
                yaxis: {{
                    title: 'Jitter (ms)',
                    gridcolor: '#e0e0e0',
                    showgrid: true
                }},
                hovermode: 'closest',
                showlegend: true,
                legend: {{
                    x: 1,
                    y: 1,
                    xanchor: 'right',
                    bgcolor: 'rgba(255, 255, 255, 0.8)',
                    bordercolor: '#ddd',
                    borderwidth: 1
                }},
                margin: {{ t: 50, r: 50, b: 50, l: 60 }},
                plot_bgcolor: '#fafafa',
                paper_bgcolor: '#fafafa'
            }};

            var config = {{
                responsive: true,
                displayModeBar: true,
                displaylogo: false,
                modeBarButtonsToRemove: ['select2d', 'lasso2d'],
                toImageButtonOptions: {{
                    format: 'png',
                    filename: 'jitter_flow_{idx}',
                    height: 600,
                    width: 1200,
                    scale: 2
                }}
            }};

            Plotly.newPlot('graph-{idx}', data, layout, config);
        }})();
        </script>
"""

    html_content += """
        <h2>💡 Implémentation dans pcap_analyzer</h2>

        <div class="note">
            <strong>Code requis:</strong><br><br>

            <strong>1. Modifier jitter_analyzer.py (lignes 136-142):</strong><br>
            <code>
            # Au lieu de:<br>
            self.flow_jitters[flow_key].append(jitter)<br><br>

            # Garder aussi le timestamp:<br>
            self.flow_jitters[flow_key].append((session[i][0], jitter))
            </code><br><br>

            <strong>2. Ajouter fonction generate_jitter_graph() dans report_generator.py:</strong><br>
            <code>
            def generate_jitter_graph(flow_data):<br>
            &nbsp;&nbsp;&nbsp;&nbsp;# Générer HTML Plotly.js comme ci-dessus<br>
            &nbsp;&nbsp;&nbsp;&nbsp;return html_snippet
            </code><br><br>

            <strong>3. Ajouter CDN Plotly dans le template HTML:</strong><br>
            <code>
            &lt;script src="https://cdn.plot.ly/plotly-2.27.0.min.js"&gt;&lt;/script&gt;
            </code><br><br>

            <strong>Effort total:</strong> 2-3 heures<br>
            <strong>Impact:</strong> Transformation de l'utilisabilité de l'outil! 🚀
        </div>

        <div class="success">
            <strong>✅ Avantages de cette approche:</strong><br>
            • Graphs interactifs (zoom, pan, export PNG)<br>
            • Pas d'installation supplémentaire (CDN)<br>
            • Responsive (mobile + desktop)<br>
            • Professio
nnel et moderne<br>
            • Détection visuelle immédiate des problèmes<br>
            • Export haute résolution pour rapports
        </div>

    </div>
</body>
</html>
"""

    with open(output_file, 'w') as f:
        f.write(html_content)

    return output_file


if __name__ == "__main__":
    print("="*80)
    print("🎨 POC: Jitter Time-Series Visualization")
    print("="*80)

    pcap_file = "test_comprehensive_v1.pcap"
    print(f"\n📂 Analyzing: {pcap_file}")

    # Extract jitter time-series
    flow_data = analyze_jitter_timeseries(pcap_file)
    print(f"✅ Found {len(flow_data)} flows with jitter data")

    # Generate HTML with Plotly graphs
    output_file = generate_plotly_html(flow_data)
    print(f"✅ Generated: {output_file}")

    print(f"\n🌐 Open in browser:")
    print(f"   open -a 'Google Chrome' {output_file}")
    print("\n" + "="*80)
