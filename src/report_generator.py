"""
Générateur de rapports JSON et HTML
"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


class ReportGenerator:
    """Générateur de rapports pour l'analyse PCAP"""

    COMMON_PORTS = {
        80: "HTTP",
        443: "HTTPS",
        20: "FTP-Data",
        21: "FTP-Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP-Server",
        68: "DHCP-Client",
        69: "TFTP",
        110: "POP3",
        137: "NetBIOS-NS",
        138: "NetBIOS-DGM",
        139: "NetBIOS-SSN",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        3389: "RDP",
        5353: "mDNS",
        1900: "SSDP",
        8080: "HTTP-Alt"
    }

    def __init__(self, output_dir: str = "reports", template_dir: str = "templates"):
        """
        Initialise le générateur de rapports

        Args:
            output_dir: Répertoire de sortie des rapports
            template_dir: Répertoire contenant les templates Jinja2
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Enable autoescape for security (prevent XSS attacks)
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )


    def generate_report(self, analysis_results: Dict[str, Any],
                       pcap_file: str, output_name: str = None) -> Dict[str, str]:
        """
        Génère les rapports JSON et HTML

        Args:
            analysis_results: Résultats de l'analyse
            pcap_file: Nom du fichier PCAP analysé
            output_name: Nom de base pour les fichiers de sortie (peut être un chemin)

        Returns:
            Dictionnaire avec les chemins des fichiers générés
        """
        if output_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_name = f"pcap_analysis_{timestamp}"

        # Si output_name contient un chemin, l'utiliser directement
        output_path = Path(output_name)
        if output_path.suffix:  # Si c'est un chemin avec extension
            base_path = output_path.with_suffix('')
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:  # Sinon utiliser output_dir
            base_path = self.output_dir / output_name

        # Ajoute des métadonnées
        total_packets = analysis_results.get('timestamps', {}).get('total_packets', 0)
        analysis_results['analysis_info'] = {
            'pcap_file': Path(pcap_file).name,  # Show only filename, not full path
            'analysis_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_packets': total_packets,
            'capture_duration': analysis_results.get('timestamps', {}).get('capture_duration_seconds', 0),
            # Pre-calculated flags for template logic (moved from template to Python)
            'is_very_small_capture': total_packets < 100,
            'is_small_capture': total_packets < 1000
        }

        # Calculate RTO rate (moved from template to Python)
        retrans_data = analysis_results.get('retransmission', {})
        rto_count = retrans_data.get('rto_count', 0)
        analysis_results['analysis_info']['rto_rate'] = (rto_count / total_packets * 100) if total_packets > 0 else 0

        # Génère le rapport JSON
        json_path = Path(f"{base_path}.json")
        self._generate_json(analysis_results, json_path)

        # Génère le rapport HTML
        html_path = Path(f"{base_path}.html")
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
        # Load CSS file for embedding (self-contained HTML reports)
        css_path = Path(__file__).parent.parent / "templates" / "static" / "css" / "report.css"
        try:
            with open(css_path, 'r', encoding='utf-8') as f:
                embedded_css = f.read()
        except FileNotFoundError:
            # Fallback: use minimal CSS if file not found
            embedded_css = "/* CSS file not found */"

        # Regrouper les retransmissions par flux pour l'affichage collapsible
        retrans_data = data.get('retransmission', {})
        retrans_by_flow = {}
        
        if 'retransmissions' in retrans_data and retrans_data['retransmissions']:
            for r in retrans_data['retransmissions']:
                flow_key = f"{r['src_ip']}:{r['src_port']} → {r['dst_ip']}:{r['dst_port']}"
                if flow_key not in retrans_by_flow:
                    retrans_by_flow[flow_key] = {
                        'flow_key': flow_key,
                        'details': [],
                        'total_retransmissions_in_flow': 0 # Added for convenience in template
                    }
                retrans_by_flow[flow_key]['details'].append(r)
                retrans_by_flow[flow_key]['total_retransmissions_in_flow'] += 1
        
        # Sort flows by number of retransmissions for consistent display
        sorted_retrans_flows = sorted(retrans_by_flow.values(), 
                                      key=lambda x: x['total_retransmissions_in_flow'], reverse=True)
        retrans_data['retrans_by_flow'] = sorted_retrans_flows
        
        # Pré-calcul du max pour les barres de volume (Top Talkers)
        if data.get('top_talkers', {}).get('top_ips'):
            max_bytes = 0
            for ip in data['top_talkers']['top_ips']:
                if ip['total_bytes'] > max_bytes:
                    max_bytes = ip['total_bytes']
            data['top_talkers']['max_total_bytes'] = max_bytes
        
        template = self.env.get_template("report_template.html")
        html_content = template.render(
            embedded_css=embedded_css,
            analysis_info=data.get('analysis_info', {}),
            timestamps=data.get('timestamps', {}),
            tcp_handshake=data.get('tcp_handshake', {}),
            retransmission=retrans_data,
            rtt=data.get('rtt', {}),
            tcp_window=data.get('tcp_window', {}),
            icmp=data.get('icmp', {}),
            dns=data.get('dns', {}),
            syn_retransmissions=data.get('syn_retransmissions', {}),
            tcp_reset=data.get('tcp_reset', {}),
            ip_fragmentation=data.get('ip_fragmentation', {}),
            top_talkers=data.get('top_talkers', {}),
            throughput=data.get('throughput', {}),
            tcp_timeout=data.get('tcp_timeout', {}),
            asymmetric_traffic=data.get('asymmetric_traffic', {}),
            burst=data.get('burst', {}),
            temporal=data.get('temporal', {}),
            sack=data.get('sack', {}),
            common_ports=self.COMMON_PORTS
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)