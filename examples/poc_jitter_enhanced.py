#!/usr/bin/env python3
"""
POC Enhanced: Jitter Time-Series with RTT Overlay + Retransmission Markers

Features:
- Jitter time-series graphs
- RTT overlay on secondary Y-axis
- Retransmission markers (red points)
- Multi-flow comparison graph
- Interactive Plotly.js visualization
"""

from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import json

def extract_comprehensive_data(pcap_file):
    """
    Extract jitter, RTT, and retransmission data from PCAP.

    Returns:
        dict: Comprehensive flow data with jitter, RTT, and retransmissions
    """
    packets = rdpcap(pcap_file)
    flow_packets = defaultdict(list)
    flow_data = {}

    # Group packets by flow with full TCP info
    for idx, pkt in enumerate(packets):
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]

            # Bidirectional flow key (canonical)
            if (ip.src, tcp.sport) < (ip.dst, tcp.dport):
                flow_key = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                direction = "forward"
            else:
                flow_key = f"{ip.dst}:{tcp.dport} -> {ip.src}:{tcp.sport}"
                direction = "reverse"

            timestamp = float(pkt.time)
            seq = tcp.seq
            ack = tcp.ack
            flags = tcp.flags

            flow_packets[flow_key].append({
                'idx': idx,
                'timestamp': timestamp,
                'direction': direction,
                'seq': seq,
                'ack': ack,
                'flags': flags,
                'src': ip.src,
                'dst': ip.dst,
                'sport': tcp.sport,
                'dport': tcp.dport,
                'len': len(tcp.payload) if hasattr(tcp, 'payload') else 0
            })

    # Process each flow
    for flow_key, pkts in flow_packets.items():
        if len(pkts) < 3:
            continue

        pkts.sort(key=lambda x: x['timestamp'])
        base_time = pkts[0]['timestamp']

        # Calculate jitter
        timestamps_rel = []
        jitter_values = []
        delays = []

        for i in range(1, len(pkts)):
            delay = pkts[i]['timestamp'] - pkts[i-1]['timestamp']
            delays.append(delay)

        for i in range(1, len(delays)):
            jitter = abs(delays[i] - delays[i-1])
            jitter_values.append(jitter * 1000)  # ms
            timestamps_rel.append(pkts[i+1]['timestamp'] - base_time)

        # Calculate RTT (simplified: time between data packet and ACK)
        rtt_values = []
        rtt_timestamps = []
        seen_seqs = {}

        for pkt in pkts:
            if pkt['direction'] == 'forward' and pkt['len'] > 0:
                # Data packet going forward
                seen_seqs[pkt['seq']] = pkt['timestamp']
            elif pkt['direction'] == 'reverse' and pkt['ack'] in seen_seqs:
                # ACK coming back
                rtt = (pkt['timestamp'] - seen_seqs[pkt['ack']]) * 1000  # ms
                if 0 < rtt < 10000:  # Sanity check (< 10s)
                    rtt_values.append(rtt)
                    rtt_timestamps.append(pkt['timestamp'] - base_time)

        # Detect retransmissions (simplified: same seq seen twice)
        retrans_markers = []
        seen_forward_seqs = {}

        for pkt in pkts:
            if pkt['direction'] == 'forward' and pkt['len'] > 0:
                seq_key = (pkt['seq'], pkt['len'])
                if seq_key in seen_forward_seqs:
                    # Retransmission detected
                    retrans_markers.append({
                        'timestamp': pkt['timestamp'] - base_time,
                        'seq': pkt['seq'],
                        'idx': pkt['idx']
                    })
                else:
                    seen_forward_seqs[seq_key] = pkt['timestamp']

        if len(jitter_values) > 0:
            flow_data[flow_key] = {
                'jitter': {
                    'timestamps': timestamps_rel,
                    'values': jitter_values
                },
                'rtt': {
                    'timestamps': rtt_timestamps,
                    'values': rtt_values
                },
                'retransmissions': retrans_markers,
                'packet_count': len(pkts)
            }

    return flow_data


def generate_enhanced_html(flow_data, output_file="jitter_enhanced_poc.html"):
    """
    Generate enhanced HTML with:
    - Individual flow graphs (jitter + RTT overlay + retrans markers)
    - Multi-flow comparison graph
    """

    # Select top 5 flows by jitter samples
    top_flows = sorted(flow_data.items(),
                      key=lambda x: len(x[1]['jitter']['values']),
                      reverse=True)[:5]

    html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POC Enhanced: Jitter + RTT + Retransmissions</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1600px;
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
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
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
            gap: 15px;
            margin: 10px 0;
            font-size: 13px;
            flex-wrap: wrap;
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
            padding: 15px;
            background: #fafafa;
        }
        .feature-badge {
            display: inline-block;
            background: #27ae60;
            color: white;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            margin-left: 10px;
        }
        .success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .info {
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 POC Enhanced: Jitter + RTT + Retransmissions</h1>

        <div class="success">
            <strong>✅ POC Enhanced avec 3 nouvelles features!</strong><br>
            <span class="feature-badge">NEW</span> RTT Overlay (double Y-axis)<br>
            <span class="feature-badge">NEW</span> Retransmission Markers (points rouges)<br>
            <span class="feature-badge">NEW</span> Multi-Flow Comparison
        </div>

        <div class="info">
            <strong>📊 Légende des graphes:</strong><br>
            • <strong style="color: #3498db;">Ligne bleue</strong>: Jitter (axe Y gauche)<br>
            • <strong style="color: #2ecc71;">Ligne verte</strong>: RTT (axe Y droit)<br>
            • <strong style="color: #e74c3c;">Points rouges</strong>: Retransmissions détectées<br>
            • <strong style="color: #f39c12;">Ligne orange pointillée</strong>: Threshold 30ms<br>
            • <strong style="color: #e74c3c;">Ligne rouge pointillée</strong>: Threshold 50ms
        </div>
"""

    # Multi-flow comparison graph first
    html_content += """
        <h2>📊 Multi-Flow Comparison</h2>
        <div class="info">
            Comparaison des 5 flux avec le plus de jitter sur un seul graphe.<br>
            Permet de voir immédiatement quel flux a le plus de problèmes.
        </div>
        <div class="graph-container">
            <div id="multi-flow-graph"></div>
        </div>

        <script>
        (function() {
"""

    # Generate multi-flow comparison data
    traces = []
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6']
    for idx, (flow_name, data) in enumerate(top_flows):
        jitter_data = data['jitter']
        color = colors[idx % len(colors)]

        traces.append({
            'x': jitter_data['timestamps'],
            'y': jitter_data['values'],
            'name': flow_name.split(' ')[0][:25] + '...',  # Shortened name
            'type': 'scatter',
            'mode': 'lines',
            'line': {'color': color, 'width': 2}
        })

    html_content += f"""
            var traces = {json.dumps(traces)};

            var layout = {{
                title: 'Jitter Comparison Across Top 5 Flows',
                xaxis: {{ title: 'Time (seconds)', gridcolor: '#e0e0e0' }},
                yaxis: {{ title: 'Jitter (ms)', gridcolor: '#e0e0e0' }},
                hovermode: 'closest',
                showlegend: true,
                legend: {{
                    x: 1.05,
                    y: 1,
                    bgcolor: 'rgba(255, 255, 255, 0.9)',
                    bordercolor: '#ddd',
                    borderwidth: 1
                }},
                margin: {{ t: 50, r: 200, b: 50, l: 60 }},
                plot_bgcolor: '#fafafa'
            }};

            var config = {{
                responsive: true,
                displayModeBar: true,
                displaylogo: false,
                toImageButtonOptions: {{
                    format: 'png',
                    filename: 'multi_flow_jitter_comparison',
                    height: 600,
                    width: 1400,
                    scale: 2
                }}
            }};

            Plotly.newPlot('multi-flow-graph', traces, layout, config);
        }})();
        </script>

        <h2>📈 Individual Flow Analysis (Jitter + RTT + Retransmissions)</h2>
"""

    # Individual flow graphs with RTT overlay and retrans markers
    for idx, (flow_name, data) in enumerate(top_flows, 1):
        jitter_data = data['jitter']
        rtt_data = data['rtt']
        retrans = data['retransmissions']

        # Calculate stats
        jitter_vals = jitter_data['values']
        mean_jitter = sum(jitter_vals) / len(jitter_vals) if jitter_vals else 0
        max_jitter = max(jitter_vals) if jitter_vals else 0
        p95_jitter = sorted(jitter_vals)[int(len(jitter_vals) * 0.95)] if len(jitter_vals) > 0 else 0

        mean_rtt = sum(rtt_data['values']) / len(rtt_data['values']) if rtt_data['values'] else 0
        max_rtt = max(rtt_data['values']) if rtt_data['values'] else 0

        severity = "🔴 CRITICAL" if p95_jitter > 50 else "🟠 WARNING" if p95_jitter > 30 else "🟢 OK"

        html_content += f"""
        <div class="flow-header">
            {flow_name}
        </div>
        <div class="stats">
            <div class="stat-item">
                <strong>Packets:</strong> {data['packet_count']}
            </div>
            <div class="stat-item">
                <strong>Jitter Samples:</strong> {len(jitter_vals)}
            </div>
            <div class="stat-item">
                <strong>Mean Jitter:</strong> {mean_jitter:.2f}ms
            </div>
            <div class="stat-item">
                <strong>P95 Jitter:</strong> {p95_jitter:.2f}ms
            </div>
            <div class="stat-item">
                <strong>Mean RTT:</strong> {mean_rtt:.2f}ms
            </div>
            <div class="stat-item">
                <strong>Max RTT:</strong> {max_rtt:.2f}ms
            </div>
            <div class="stat-item">
                <strong>Retransmissions:</strong> {len(retrans)}
            </div>
            <div class="stat-item">
                {severity}
            </div>
        </div>

        <div class="graph-container">
            <div id="flow-graph-{idx}"></div>
        </div>

        <script>
        (function() {{
            // Jitter trace (primary Y-axis)
            var jitterTrace = {{
                x: {json.dumps(jitter_data['timestamps'])},
                y: {json.dumps(jitter_data['values'])},
                type: 'scatter',
                mode: 'lines+markers',
                name: 'Jitter',
                yaxis: 'y',
                line: {{ color: '#3498db', width: 2 }},
                marker: {{ size: 4, color: '#3498db' }},
                hovertemplate: '<b>Time:</b> %{{x:.3f}}s<br><b>Jitter:</b> %{{y:.2f}}ms<extra></extra>'
            }};

            // RTT trace (secondary Y-axis)
            var rttTrace = {{
                x: {json.dumps(rtt_data['timestamps'])},
                y: {json.dumps(rtt_data['values'])},
                type: 'scatter',
                mode: 'lines+markers',
                name: 'RTT',
                yaxis: 'y2',
                line: {{ color: '#2ecc71', width: 2 }},
                marker: {{ size: 4, color: '#2ecc71' }},
                hovertemplate: '<b>Time:</b> %{{x:.3f}}s<br><b>RTT:</b> %{{y:.2f}}ms<extra></extra>'
            }};

            // Retransmission markers
            var retransTrace = {{
                x: {json.dumps([r['timestamp'] for r in retrans])},
                y: {json.dumps([p95_jitter * 1.2 for _ in retrans])},  // Place above jitter line
                type: 'scatter',
                mode: 'markers',
                name: 'Retransmissions',
                yaxis: 'y',
                marker: {{
                    size: 12,
                    color: '#e74c3c',
                    symbol: 'x',
                    line: {{ width: 2, color: '#c0392b' }}
                }},
                hovertemplate: '<b>Retransmission</b><br>Time: %{{x:.3f}}s<extra></extra>'
            }};

            // Threshold lines
            var threshold30 = {{
                x: [{jitter_data['timestamps'][0]}, {jitter_data['timestamps'][-1]}],
                y: [30, 30],
                type: 'scatter',
                mode: 'lines',
                name: 'Warning (30ms)',
                yaxis: 'y',
                line: {{ color: '#f39c12', width: 1, dash: 'dash' }},
                hoverinfo: 'skip'
            }};

            var threshold50 = {{
                x: [{jitter_data['timestamps'][0]}, {jitter_data['timestamps'][-1]}],
                y: [50, 50],
                type: 'scatter',
                mode: 'lines',
                name: 'Critical (50ms)',
                yaxis: 'y',
                line: {{ color: '#e74c3c', width: 1, dash: 'dash' }},
                hoverinfo: 'skip'
            }};

            var data = [jitterTrace, rttTrace, retransTrace, threshold30, threshold50];

            var layout = {{
                title: 'Jitter + RTT + Retransmissions Over Time',
                xaxis: {{
                    title: 'Time (seconds)',
                    gridcolor: '#e0e0e0',
                    domain: [0, 1]
                }},
                yaxis: {{
                    title: 'Jitter (ms)',
                    titlefont: {{ color: '#3498db' }},
                    tickfont: {{ color: '#3498db' }},
                    gridcolor: '#e0e0e0'
                }},
                yaxis2: {{
                    title: 'RTT (ms)',
                    titlefont: {{ color: '#2ecc71' }},
                    tickfont: {{ color: '#2ecc71' }},
                    overlaying: 'y',
                    side: 'right'
                }},
                hovermode: 'closest',
                showlegend: true,
                legend: {{
                    x: 1.15,
                    y: 1,
                    bgcolor: 'rgba(255, 255, 255, 0.9)',
                    bordercolor: '#ddd',
                    borderwidth: 1
                }},
                margin: {{ t: 50, r: 150, b: 50, l: 60 }},
                plot_bgcolor: '#fafafa'
            }};

            var config = {{
                responsive: true,
                displayModeBar: true,
                displaylogo: false,
                toImageButtonOptions: {{
                    format: 'png',
                    filename: 'flow_{idx}_jitter_rtt',
                    height: 600,
                    width: 1400,
                    scale: 2
                }}
            }};

            Plotly.newPlot('flow-graph-{idx}', data, layout, config);
        }})();
        </script>
"""

    html_content += """
        <h2>💡 Features Implémentées</h2>

        <div class="success">
            <strong>✅ RTT Overlay (Double Y-Axis):</strong><br>
            • Axe Y gauche: Jitter (bleu)<br>
            • Axe Y droit: RTT (vert)<br>
            • Permet de voir la corrélation jitter ↔ RTT<br>
            • Spike RTT = souvent spike jitter
        </div>

        <div class="success">
            <strong>✅ Retransmission Markers:</strong><br>
            • Points rouges (X) aux moments des retransmissions<br>
            • Hover pour voir le timestamp exact<br>
            • Corrélation visuelle retrans ↔ jitter/RTT
        </div>

        <div class="success">
            <strong>✅ Multi-Flow Comparison:</strong><br>
            • 5 flux sur un seul graphe<br>
            • Identification immédiate du pire flux<br>
            • Comparaison relative des performances
        </div>

        <h2>🚀 Prochaine Étape: Intégration</h2>

        <div class="info">
            <strong>Ready pour intégration dans pcap_analyzer!</strong><br><br>

            Ce POC démontre que toutes les features sont faciles à implémenter:<br>
            • RTT: Données déjà dans rtt_analyzer.py<br>
            • Retrans: Données déjà dans retransmission.py<br>
            • Multi-flow: Juste regrouper les données<br><br>

            <strong>Effort total:</strong> 3-4 heures pour intégrer tout ça<br>
            <strong>Impact:</strong> Transformation complète de l'outil! 🎯
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
    print("🚀 POC Enhanced: Jitter + RTT + Retransmissions")
    print("="*80)

    pcap_file = "test_comprehensive_v1.pcap"
    print(f"\n📂 Analyzing: {pcap_file}")

    # Extract comprehensive data
    flow_data = extract_comprehensive_data(pcap_file)
    print(f"✅ Found {len(flow_data)} flows with comprehensive data")

    # Generate enhanced HTML
    output_file = generate_enhanced_html(flow_data)
    print(f"✅ Generated: {output_file}")

    print(f"\n🌐 Open in browser:")
    print(f"   open -a 'Google Chrome' {output_file}")
    print("\n" + "="*80)
    print("\n📊 Features:")
    print("   ✅ RTT overlay (double Y-axis)")
    print("   ✅ Retransmission markers (red X)")
    print("   ✅ Multi-flow comparison graph")
    print("   ✅ Interactive zoom/pan/export")
    print("\n" + "="*80)
