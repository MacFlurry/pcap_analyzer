"""
Graph Generator for Interactive Plotly.js Visualizations

v4.18.0: Adds interactive time-series graphs to HTML reports.
"""

import json
from typing import Dict, List, Any, Optional


def generate_jitter_timeseries_graph(
    flow_name: str,
    flow_data: Dict[str, Any],
    rtt_data: Optional[Dict[str, List]] = None,
    retrans_timestamps: Optional[List[float]] = None,
    graph_id: str = "jitter-graph"
) -> str:
    """
    Generate Plotly.js interactive jitter time-series graph.

    Args:
        flow_name: Flow identifier string
        flow_data: Flow jitter data with 'timeseries' key
        rtt_data: Optional RTT data {'timestamps': [...], 'values': [...]}
        retrans_timestamps: Optional list of retransmission timestamps
        graph_id: HTML div ID for the graph

    Returns:
        HTML string with Plotly.js graph
    """
    if 'timeseries' not in flow_data:
        return ""

    timeseries = flow_data['timeseries']
    timestamps = timeseries['timestamps']
    jitter_values = [v * 1000 for v in timeseries['jitter_values']]  # Convert to ms

    if not timestamps or not jitter_values:
        return ""

    # Calculate stats for display
    mean_jitter = flow_data.get('mean_jitter', 0) * 1000
    p95_jitter = flow_data.get('p95_jitter', 0) * 1000
    max_jitter = flow_data.get('max_jitter', 0) * 1000

    # Determine color based on severity
    if p95_jitter > 50:
        jitter_color = '#e74c3c'  # Red - critical
    elif p95_jitter > 30:
        jitter_color = '#f39c12'  # Orange - warning
    else:
        jitter_color = '#3498db'  # Blue - OK

    html = f'<div id="{graph_id}" style="height: 400px;"></div>\n'
    html += '<script>\n(function() {\n'

    # Jitter trace
    html += f"""
    var jitterTrace = {{
        x: {json.dumps(timestamps)},
        y: {json.dumps(jitter_values)},
        type: 'scatter',
        mode: 'lines+markers',
        name: 'Jitter',
        yaxis: 'y',
        line: {{ color: '{jitter_color}', width: 2 }},
        marker: {{ size: 4, color: '{jitter_color}' }},
        hovertemplate: '<b>Time:</b> %{{x:.3f}}s<br><b>Jitter:</b> %{{y:.2f}}ms<extra></extra>'
    }};
    var data = [jitterTrace];
"""

    # Add RTT overlay if available
    if rtt_data and rtt_data.get('timestamps') and rtt_data.get('values'):
        rtt_timestamps = rtt_data['timestamps']
        rtt_values = [v * 1000 for v in rtt_data['values']]  # Convert to ms

        html += f"""
    var rttTrace = {{
        x: {json.dumps(rtt_timestamps)},
        y: {json.dumps(rtt_values)},
        type: 'scatter',
        mode: 'lines+markers',
        name: 'RTT',
        yaxis: 'y2',
        line: {{ color: '#2ecc71', width: 2 }},
        marker: {{ size: 4, color: '#2ecc71' }},
        hovertemplate: '<b>Time:</b> %{{x:.3f}}s<br><b>RTT:</b> %{{y:.2f}}ms<extra></extra>'
    }};
    data.push(rttTrace);
"""

    # Add retransmission markers if available
    if retrans_timestamps and len(retrans_timestamps) > 0:
        # Place markers above the jitter line
        marker_y = [p95_jitter * 1.2] * len(retrans_timestamps)

        html += f"""
    var retransTrace = {{
        x: {json.dumps(retrans_timestamps)},
        y: {json.dumps(marker_y)},
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
    data.push(retransTrace);
"""

    # Add threshold lines
    if timestamps:
        html += f"""
    var threshold30 = {{
        x: [{timestamps[0]}, {timestamps[-1]}],
        y: [30, 30],
        type: 'scatter',
        mode: 'lines',
        name: 'Warning (30ms)',
        yaxis: 'y',
        line: {{ color: '#f39c12', width: 1, dash: 'dash' }},
        hoverinfo: 'skip'
    }};
    var threshold50 = {{
        x: [{timestamps[0]}, {timestamps[-1]}],
        y: [50, 50],
        type: 'scatter',
        mode: 'lines',
        name: 'Critical (50ms)',
        yaxis: 'y',
        line: {{ color: '#e74c3c', width: 1, dash: 'dash' }},
        hoverinfo: 'skip'
    }};
    data.push(threshold30, threshold50);
"""

    # Layout configuration
    has_rtt = rtt_data and rtt_data.get('timestamps')

    html += f"""
    var layout = {{
        title: {{
            text: 'Jitter{' + RTT' if has_rtt else ''} Over Time',
            font: {{ size: 16, color: '#2c3e50' }}
        }},
        xaxis: {{
            title: 'Time (seconds)',
            gridcolor: '#e0e0e0',
            showgrid: true
        }},
        yaxis: {{
            title: 'Jitter (ms)',
            titlefont: {{ color: '#3498db' }},
            tickfont: {{ color: '#3498db' }},
            gridcolor: '#e0e0e0',
            showgrid: true
        }},
"""

    if has_rtt:
        html += """
        yaxis2: {
            title: 'RTT (ms)',
            titlefont: { color: '#2ecc71' },
            tickfont: { color: '#2ecc71' },
            overlaying: 'y',
            side: 'right'
        },
"""

    html += """
        hovermode: 'closest',
        showlegend: true,
        legend: {
            x: 1.15,
            y: 1,
            bgcolor: 'rgba(255, 255, 255, 0.9)',
            bordercolor: '#ddd',
            borderwidth: 1
        },
        margin: { t: 50, r: 150, b: 50, l: 60 },
        plot_bgcolor: '#fafafa',
        paper_bgcolor: '#ffffff'
    };

    var config = {
        responsive: true,
        displayModeBar: true,
        displaylogo: false,
        modeBarButtonsToRemove: ['select2d', 'lasso2d'],
        toImageButtonOptions: {
            format: 'png',
            filename: 'jitter_timeseries',
            height: 600,
            width: 1200,
            scale: 2
        }
    };

"""

    html += f"    Plotly.newPlot('{graph_id}', data, layout, config);\n"
    html += '})();\n</script>\n'

    return html


def generate_multi_flow_comparison_graph(
    flows_data: List[Dict[str, Any]],
    graph_id: str = "multi-flow-comparison"
) -> str:
    """
    Generate multi-flow comparison graph.

    Args:
        flows_data: List of dicts with 'name', 'timeseries' keys
        graph_id: HTML div ID

    Returns:
        HTML string with Plotly.js graph
    """
    if not flows_data:
        return ""

    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6',
              '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#d35400']

    html = f'<div id="{graph_id}" style="height: 500px;"></div>\n'
    html += '<script>\n(function() {\n'
    html += '    var data = [];\n'

    for idx, flow in enumerate(flows_data[:10]):  # Max 10 flows
        if 'timeseries' not in flow:
            continue

        timeseries = flow['timeseries']
        timestamps = timeseries['timestamps']
        jitter_values = [v * 1000 for v in timeseries['jitter_values']]
        flow_name = flow.get('name', f'Flow {idx+1}')
        color = colors[idx % len(colors)]

        # Shorten flow name for legend
        if len(flow_name) > 40:
            flow_name = flow_name[:37] + '...'

        html += f"""
    data.push({{
        x: {json.dumps(timestamps)},
        y: {json.dumps(jitter_values)},
        type: 'scatter',
        mode: 'lines',
        name: '{flow_name}',
        line: {{ color: '{color}', width: 2 }},
        hovertemplate: '<b>{flow_name}</b><br>Time: %{{x:.3f}}s<br>Jitter: %{{y:.2f}}ms<extra></extra>'
    }});
"""

    html += """
    var layout = {
        title: {
            text: 'Multi-Flow Jitter Comparison',
            font: { size: 18, color: '#2c3e50' }
        },
        xaxis: {
            title: 'Time (seconds)',
            gridcolor: '#e0e0e0',
            showgrid: true
        },
        yaxis: {
            title: 'Jitter (ms)',
            gridcolor: '#e0e0e0',
            showgrid: true
        },
        hovermode: 'closest',
        showlegend: true,
        legend: {
            x: 1.05,
            y: 1,
            bgcolor: 'rgba(255, 255, 255, 0.9)',
            bordercolor: '#ddd',
            borderwidth: 1
        },
        margin: { t: 60, r: 200, b: 50, l: 60 },
        plot_bgcolor: '#fafafa',
        paper_bgcolor: '#ffffff'
    };

    var config = {
        responsive: true,
        displayModeBar: true,
        displaylogo: false,
        toImageButtonOptions: {
            format: 'png',
            filename: 'multi_flow_jitter',
            height: 700,
            width: 1400,
            scale: 2
        }
    };

"""

    html += f"    Plotly.newPlot('{graph_id}', data, layout, config);\n"
    html += '})();\n</script>\n'

    return html


def get_plotly_cdn() -> str:
    """Return Plotly.js CDN script tag."""
    return '<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>'
