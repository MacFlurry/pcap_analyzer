"""
Générateur de rapports JSON et HTML
"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from jinja2 import Template


class ReportGenerator:
    """Générateur de rapports pour l'analyse PCAP"""

    HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'analyse PCAP - {{ analysis_info.pcap_file }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        header {
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        h1 {
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .meta-info {
            color: #7f8c8d;
            font-size: 0.9em;
        }

        h2 {
            color: #34495e;
            font-size: 1.8em;
            margin: 30px 0 15px 0;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }

        h3 {
            color: #2c3e50;
            font-size: 1.3em;
            margin: 20px 0 10px 0;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }

        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .summary-card.success {
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }

        .summary-card.warning {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .summary-card.danger {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }

        .summary-card h3 {
            color: white;
            margin: 0 0 10px 0;
            font-size: 1em;
            opacity: 0.9;
        }

        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
        }

        .section {
            background: #f8f9fa;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }

        .section.warning {
            border-left-color: #f39c12;
            background: #fef5e7;
        }

        .section.danger {
            border-left-color: #e74c3c;
            background: #fadbd8;
        }

        .section.success {
            border-left-color: #27ae60;
            background: #d5f4e6;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
        }

        th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }

        .badge.success {
            background: #27ae60;
            color: white;
        }

        .badge.warning {
            background: #f39c12;
            color: white;
        }

        .badge.danger {
            background: #e74c3c;
            color: white;
        }

        .badge.info {
            background: #3498db;
            color: white;
        }

        .suggestions {
            background: #e8f8f5;
            border-left: 4px solid #1abc9c;
            padding: 15px;
            margin: 15px 0;
        }

        .suggestions ul {
            margin-left: 20px;
        }

        .suggestions li {
            margin: 8px 0;
        }

        code {
            background: #ecf0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }

        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }

        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 Rapport d'analyse de latence réseau</h1>
            <div class="meta-info">
                <strong>Fichier PCAP:</strong> {{ analysis_info.pcap_file }}<br>
                <strong>Date d'analyse:</strong> {{ analysis_info.analysis_date }}<br>
                <strong>Durée de capture:</strong> {{ "%.2f"|format(analysis_info.capture_duration) }} secondes<br>
                <strong>Total de paquets:</strong> {{ analysis_info.total_packets }}
            </div>
        </header>

        <!-- Vue d'ensemble -->
        <h2>Vue d'ensemble</h2>
        <div class="summary-grid">
            <div class="summary-card {% if timestamps.gaps_detected > 0 %}warning{% else %}success{% endif %}">
                <h3>Gaps temporels</h3>
                <div class="value">{{ timestamps.gaps_detected }}</div>
            </div>

            <div class="summary-card {% if tcp_handshake.slow_handshakes > 0 %}warning{% else %}success{% endif %}">
                <h3>Handshakes lents</h3>
                <div class="value">{{ tcp_handshake.slow_handshakes }}</div>
            </div>

            <div class="summary-card {% if retransmission.total_retransmissions > 20 %}danger{% elif retransmission.total_retransmissions > 5 %}warning{% else %}success{% endif %}">
                <h3>Retransmissions</h3>
                <div class="value">{{ retransmission.total_retransmissions }}</div>
            </div>

            <div class="summary-card {% if tcp_window.flows_with_issues > 0 %}warning{% else %}success{% endif %}">
                <h3>Problèmes fenêtre TCP</h3>
                <div class="value">{{ tcp_window.flows_with_issues }}</div>
            </div>

            <div class="summary-card {% if icmp.pmtu_issues_count > 0 %}danger{% elif icmp.dest_unreachable_count > 0 %}warning{% else %}success{% endif %}">
                <h3>Problèmes ICMP</h3>
                <div class="value">{{ icmp.pmtu_issues_count + icmp.dest_unreachable_count }}</div>
            </div>

            <div class="summary-card {% if dns.timeout_transactions > 0 or dns.slow_transactions > 0 %}warning{% else %}success{% endif %}">
                <h3>Problèmes DNS</h3>
                <div class="value">{{ dns.timeout_transactions + dns.slow_transactions }}</div>
            </div>
        </div>

        <!-- Analyse des timestamps -->
        {% if timestamps.gaps_detected > 0 %}
        <h2>⏱️ Analyse des timestamps</h2>
        <div class="section warning">
            <h3>{{ timestamps.gaps_detected }} gap(s) temporel(s) détecté(s)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Paquets</th>
                        <th>Durée du gap</th>
                        <th>Direction</th>
                        <th>Protocole</th>
                    </tr>
                </thead>
                <tbody>
                    {% for gap in timestamps.gaps[:20] %}
                    <tr>
                        <td>#{{ gap.packet_num_before }} → #{{ gap.packet_num_after }}</td>
                        <td><strong>{{ "%.3f"|format(gap.gap_duration) }}s</strong></td>
                        <td><code>{{ gap.src_ip }} → {{ gap.dst_ip }}</code></td>
                        <td><span class="badge info">{{ gap.protocol }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Handshakes TCP -->
        {% if tcp_handshake.slow_handshakes > 0 %}
        <h2>🤝 Analyse des handshakes TCP</h2>
        <div class="section warning">
            <h3>{{ tcp_handshake.slow_handshakes }} handshake(s) lent(s)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Flux</th>
                        <th>Durée totale</th>
                        <th>SYN→SYN/ACK</th>
                        <th>SYN/ACK→ACK</th>
                        <th>Côté suspect</th>
                    </tr>
                </thead>
                <tbody>
                    {% for hs in tcp_handshake.slow_handshake_details %}
                    <tr>
                        <td><code>{{ hs.src_ip }}:{{ hs.src_port }} → {{ hs.dst_ip }}:{{ hs.dst_port }}</code></td>
                        <td><strong>{{ "%.3f"|format(hs.total_handshake_time or 0) }}s</strong></td>
                        <td>{{ "%.3f"|format(hs.syn_to_synack_delay or 0) }}s</td>
                        <td>{{ "%.3f"|format(hs.synack_to_ack_delay or 0) }}s</td>
                        <td>
                            {% if hs.suspected_side == 'server' %}
                            <span class="badge danger">Serveur</span>
                            {% elif hs.suspected_side == 'client' %}
                            <span class="badge warning">Client</span>
                            {% elif hs.suspected_side == 'network' %}
                            <span class="badge info">Réseau</span>
                            {% else %}
                            <span class="badge">{{ hs.suspected_side }}</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- Retransmissions -->
        {% if retransmission.flows_with_issues > 0 %}
        <h2>🔄 Retransmissions et anomalies TCP</h2>
        <div class="section {% if retransmission.total_retransmissions > 50 %}danger{% else %}warning{% endif %}">
            <h3>{{ retransmission.flows_with_issues }} flux avec problèmes</h3>
            <p><strong>Retransmissions totales:</strong> {{ retransmission.total_retransmissions }}</p>
            <p><strong>Anomalies totales:</strong> {{ retransmission.total_anomalies }}</p>

            <h4>Flux les plus problématiques:</h4>
            <table>
                <thead>
                    <tr>
                        <th>Flux</th>
                        <th>Sévérité</th>
                        <th>Retransmissions</th>
                        <th>DUP ACK</th>
                        <th>Out-of-Order</th>
                        <th>Zero Window</th>
                    </tr>
                </thead>
                <tbody>
                    {% for flow in retransmission.flow_statistics[:15] %}
                    {% if flow.severity != 'none' %}
                    <tr>
                        <td><code>{{ flow.flow_key }}</code></td>
                        <td>
                            {% if flow.severity == 'critical' %}
                            <span class="badge danger">CRITIQUE</span>
                            {% elif flow.severity == 'medium' %}
                            <span class="badge warning">MOYEN</span>
                            {% else %}
                            <span class="badge info">BAS</span>
                            {% endif %}
                        </td>
                        <td>{{ flow.retransmissions }}</td>
                        <td>{{ flow.dup_acks }}</td>
                        <td>{{ flow.out_of_order }}</td>
                        <td>{{ flow.zero_windows }}</td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- SYN Retransmissions -->
        {% if syn_retransmissions.total_syn_retransmissions and syn_retransmissions.total_syn_retransmissions > 0 %}
        <h2>🔴 Retransmissions SYN - Problèmes de Handshake</h2>
        <div class="section danger">
            <h3>{{ syn_retransmissions.total_syn_retransmissions }} handshake(s) avec retransmissions SYN excessives</h3>
            <p><strong>Seuil de détection:</strong> {{ syn_retransmissions.threshold_seconds }}s</p>
            <p>Ces connexions ont dû retransmettre le paquet SYN initial plusieurs fois avant de recevoir un SYN/ACK du serveur.</p>

            <h4>Handshakes problématiques (Top 10):</h4>
            <table>
                <thead>
                    <tr>
                        <th>Connexion</th>
                        <th>Tentatives SYN</th>
                        <th>Délai total</th>
                        <th>Problème suspecté</th>
                    </tr>
                </thead>
                <tbody>
                    {% for hs in syn_retransmissions.top_problematic_connections[:10] %}
                    <tr>
                        <td><code>{{ hs.src_ip }}:{{ hs.src_port }} → {{ hs.dst_ip }}:{{ hs.dst_port }}</code></td>
                        <td>{{ hs.retransmission_count + 1 }}</td>
                        <td>{{ "%.3f"|format(hs.total_delay or 0) }}s</td>
                        <td>{{ hs.suspected_issue }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            <h4>Détails des retransmissions:</h4>
            {% for hs in syn_retransmissions.top_problematic_connections[:5] %}
            <div class="detail-box">
                <h5>{{ hs.src_ip }}:{{ hs.src_port }} → {{ hs.dst_ip }}:{{ hs.dst_port }}</h5>
                <p><strong>Timeline:</strong></p>
                <ul>
                    {% for t in hs.syn_attempts_iso %}
                    <li>SYN #{{ loop.index }} à {{ t }}</li>
                    {% endfor %}
                    {% if hs.synack_time_iso %}
                    <li><strong>SYN/ACK reçu à {{ hs.synack_time_iso }}</strong> ({{ "%.3f"|format(hs.total_delay or 0) }}s après le 1er SYN)</li>
                    {% endif %}
                </ul>
                <p><strong>Diagnostic:</strong> {{ hs.suspected_issue }}</p>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <!-- RTT -->
        {% if rtt.flows_with_high_rtt > 0 %}
        <h2>⏲️ Analyse RTT (Round Trip Time)</h2>
        <div class="section warning">
            <h3>{{ rtt.flows_with_high_rtt }} flux avec RTT élevé</h3>
            <p><strong>RTT moyen global:</strong> {{ "%.2f"|format((rtt.global_statistics.mean_rtt or 0) * 1000) }} ms</p>
            <p><strong>RTT max global:</strong> {{ "%.2f"|format((rtt.global_statistics.max_rtt or 0) * 1000) }} ms</p>

            <table>
                <thead>
                    <tr>
                        <th>Flux</th>
                        <th>RTT moyen</th>
                        <th>RTT min/max</th>
                        <th>Pics RTT</th>
                        <th>Mesures</th>
                    </tr>
                </thead>
                <tbody>
                    {% for flow in rtt.flow_statistics[:15] %}
                    {% if flow.mean_rtt > rtt.thresholds.warning_seconds %}
                    <tr>
                        <td><code>{{ flow.flow_key }}</code></td>
                        <td><strong>{{ "%.2f"|format(flow.mean_rtt * 1000) }} ms</strong></td>
                        <td>{{ "%.2f"|format(flow.min_rtt * 1000) }} / {{ "%.2f"|format(flow.max_rtt * 1000) }} ms</td>
                        <td>{{ flow.rtt_spikes }}</td>
                        <td>{{ flow.measurements_count }}</td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- TCP Window -->
        {% if tcp_window.flows_with_issues > 0 %}
        <h2>🪟 Analyse des fenêtres TCP</h2>
        <div class="section warning">
            <h3>{{ tcp_window.flows_with_issues }} flux avec problèmes de fenêtre</h3>
            <table>
                <thead>
                    <tr>
                        <th>Flux</th>
                        <th>Goulot suspecté</th>
                        <th>Zero Windows</th>
                        <th>Durée ZW totale</th>
                        <th>Fenêtre min/moy/max</th>
                    </tr>
                </thead>
                <tbody>
                    {% for flow in tcp_window.flow_statistics[:15] %}
                    {% if flow.suspected_bottleneck != 'none' %}
                    <tr>
                        <td><code>{{ flow.flow_key }}</code></td>
                        <td>
                            {% if flow.suspected_bottleneck == 'application' %}
                            <span class="badge danger">Application</span>
                            {% elif flow.suspected_bottleneck == 'receiver' %}
                            <span class="badge warning">Récepteur</span>
                            {% else %}
                            <span class="badge info">{{ flow.suspected_bottleneck }}</span>
                            {% endif %}
                        </td>
                        <td>{{ flow.zero_window_count }}</td>
                        <td>{{ "%.3f"|format(flow.zero_window_total_duration) }}s</td>
                        <td>{{ flow.min_window }} / {{ "%.0f"|format(flow.mean_window) }} / {{ flow.max_window }} bytes</td>
                    </tr>
                    {% endif %}
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <!-- ICMP / PMTU -->
        {% if icmp.pmtu_issues_count > 0 or icmp.dest_unreachable_count > 0 %}
        <h2>📡 Analyse ICMP et PMTU</h2>

        {% if icmp.pmtu_issues_count > 0 %}
        <div class="section danger">
            <h3>🔴 {{ icmp.pmtu_issues_count }} problème(s) PMTU détecté(s)</h3>
            <table>
                <thead>
                    <tr>
                        <th>Paquet</th>
                        <th>Message</th>
                        <th>MTU suggéré</th>
                        <th>Flux affecté</th>
                    </tr>
                </thead>
                <tbody>
                    {% for msg in icmp.pmtu_issues %}
                    <tr>
                        <td>#{{ msg.packet_num }}</td>
                        <td>{{ msg.message }}</td>
                        <td>{% if msg.mtu > 0 %}<strong>{{ msg.mtu }} bytes</strong>{% else %}N/A{% endif %}</td>
                        <td><code>{{ msg.original_src }} → {{ msg.original_dst }}</code></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            {% if icmp.pmtu_suggestions %}
            <div class="suggestions">
                <h4>💡 Suggestions:</h4>
                <ul>
                    {% for suggestion in icmp.pmtu_suggestions %}
                    <li>{{ suggestion }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        {% endif %}

        {% if icmp.dest_unreachable_count > 0 %}
        <div class="section warning">
            <h3>{{ icmp.dest_unreachable_count }} message(s) Destination Unreachable</h3>
            <p>Des destinations sont injoignables. Vérifiez la configuration réseau et les pare-feu.</p>
        </div>
        {% endif %}
        {% endif %}

        <!-- DNS -->
        {% if dns.timeout_transactions > 0 or dns.slow_transactions > 0 %}
        <h2>🌐 Analyse DNS</h2>
        <div class="section {% if dns.timeout_transactions > 5 %}danger{% else %}warning{% endif %}">
            <h3>Problèmes DNS détectés</h3>
            <p><strong>Requêtes totales:</strong> {{ dns.total_queries }}</p>
            <p><strong>Timeouts:</strong> {{ dns.timeout_transactions }}</p>
            <p><strong>Réponses lentes:</strong> {{ dns.slow_transactions }}</p>
            <p><strong>Erreurs:</strong> {{ dns.error_transactions }}</p>

            {% if dns.top_problematic_domains %}
            <h4>Domaines problématiques:</h4>
            <table>
                <thead>
                    <tr>
                        <th>Domaine</th>
                        <th>Nombre de problèmes</th>
                    </tr>
                </thead>
                <tbody>
                    {% for domain, count in dns.top_problematic_domains %}
                    <tr>
                        <td><code>{{ domain }}</code></td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endif %}

        <div class="footer">
            <p>Rapport généré par <strong>PCAP Analyzer</strong> - {{ analysis_info.analysis_date }}</p>
        </div>
    </div>
</body>
</html>
    """

    def __init__(self, output_dir: str = "reports"):
        """
        Initialise le générateur de rapports

        Args:
            output_dir: Répertoire de sortie des rapports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, analysis_results: Dict[str, Any],
                       pcap_file: str, output_name: str = None) -> Dict[str, str]:
        """
        Génère les rapports JSON et HTML

        Args:
            analysis_results: Résultats de l'analyse
            pcap_file: Nom du fichier PCAP analysé
            output_name: Nom de base pour les fichiers de sortie

        Returns:
            Dictionnaire avec les chemins des fichiers générés
        """
        if output_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"pcap_analysis_{timestamp}"

        # Ajoute des métadonnées
        analysis_results['analysis_info'] = {
            'pcap_file': pcap_file,
            'analysis_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_packets': analysis_results.get('timestamps', {}).get('total_packets', 0),
            'capture_duration': analysis_results.get('timestamps', {}).get('capture_duration_seconds', 0)
        }

        # Génère le rapport JSON
        json_path = self.output_dir / f"{output_name}.json"
        self._generate_json(analysis_results, json_path)

        # Génère le rapport HTML
        html_path = self.output_dir / f"{output_name}.html"
        self._generate_html(analysis_results, html_path)

        return {
            'json': str(json_path),
            'html': str(html_path)
        }

    def _generate_json(self, data: Dict[str, Any], output_path: Path) -> None:
        """Génère le rapport JSON"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def _generate_html(self, data: Dict[str, Any], output_path: Path) -> None:
        """Génère le rapport HTML"""
        template = Template(self.HTML_TEMPLATE)
        html_content = template.render(
            analysis_info=data.get('analysis_info', {}),
            timestamps=data.get('timestamps', {}),
            tcp_handshake=data.get('tcp_handshake', {}),
            retransmission=data.get('retransmission', {}),
            rtt=data.get('rtt', {}),
            tcp_window=data.get('tcp_window', {}),
            icmp=data.get('icmp', {}),
            dns=data.get('dns', {}),
            syn_retransmissions=data.get('syn_retransmissions', {})
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
