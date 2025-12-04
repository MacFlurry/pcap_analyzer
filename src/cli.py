#!/usr/bin/env python3
"""
Interface en ligne de commande pour l'analyseur PCAP
"""

import click
import sys
from pathlib import Path
from scapy.all import PcapReader
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.table import Table

from .config import get_config
from .ssh_capture import capture_from_config
from .analyzers import (
    TimestampAnalyzer,
    TCPHandshakeAnalyzer,
    RetransmissionAnalyzer,
    RTTAnalyzer,
    TCPWindowAnalyzer,
    ICMPAnalyzer,
    DNSAnalyzer,
    SYNRetransmissionAnalyzer,
    TCPResetAnalyzer,
    IPFragmentationAnalyzer,
    TopTalkersAnalyzer,
    ThroughputAnalyzer,
    TCPTimeoutAnalyzer,
    AsymmetricTrafficAnalyzer,
    BurstAnalyzer,
    TemporalPatternAnalyzer
)
from .report_generator import ReportGenerator

console = Console()


def load_pcap_streaming(pcap_file: str, analyzers: list) -> int:
    """
    Charge et analyse un fichier PCAP en mode streaming
    
    Args:
        pcap_file: Chemin vers le fichier PCAP
        analyzers: Liste des analyseurs à appliquer
        
    Returns:
        Nombre de paquets traités
    """
    try:
        packet_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Analyse du fichier PCAP: {pcap_file}[/cyan]".format(pcap_file=pcap_file)),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Chargement et analyse...", total=None)
            
            with PcapReader(pcap_file) as reader:
                for packet in reader:
                    packet_count += 1
                    
                    # Passe le paquet à chaque analyseur
                    for analyzer in analyzers:
                        if hasattr(analyzer, 'process_packet'):
                            analyzer.process_packet(packet, packet_count - 1)
                    
                    # Mise à jour périodique
                    if packet_count % 10000 == 0:
                        progress.update(task, description=f"[cyan]Traité {packet_count} paquets...")
        
        console.print(f"[green]✓ {packet_count} paquets analysés[/green]")
        
        # Finalise tous les analyseurs avec spinner
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Finalisation des analyses..."),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Calcul des statistiques...", total=None)
            for analyzer in analyzers:
                if hasattr(analyzer, 'finalize'):
                    analyzer.finalize()
        
        return packet_count
        
    except FileNotFoundError:
        console.print(f"[red]❌ Fichier non trouvé: {pcap_file}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Erreur lors du chargement: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def analyze_pcap_streaming(pcap_file: str, config, latency_filter: float = None, show_details: bool = False, details_limit: int = 20):
    """Analyse un fichier PCAP en mode streaming optimisé"""
    thresholds = config.thresholds

    results = {}
    
    # Initialisation des analyseurs
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Initialisation des analyseurs...", total=1)
        
        # 1. Timestamps
        gap_threshold = latency_filter if latency_filter else thresholds.get('packet_gap', 1.0)
        timestamp_analyzer = TimestampAnalyzer(gap_threshold=gap_threshold)

        # 2. TCP Handshake
        handshake_analyzer = TCPHandshakeAnalyzer(
            syn_synack_threshold=thresholds.get('syn_synack_delay', 0.1),
            total_threshold=thresholds.get('handshake_total', 0.3),
            latency_filter=latency_filter
        )

        # 3. Retransmissions
        retrans_analyzer = RetransmissionAnalyzer(
            retrans_low=thresholds.get('retransmission_low', 10),
            retrans_medium=thresholds.get('retransmission_medium', 50),
            retrans_critical=thresholds.get('retransmission_critical', 100),
            retrans_rate_low=thresholds.get('retransmission_rate_low', 1.0),
            retrans_rate_medium=thresholds.get('retransmission_rate_medium', 3.0),
            retrans_rate_critical=thresholds.get('retransmission_rate_critical', 5.0)
        )

        # 4. RTT
        rtt_analyzer = RTTAnalyzer(
            rtt_warning=thresholds.get('rtt_warning', 0.1),
            rtt_critical=thresholds.get('rtt_critical', 0.5),
            latency_filter=latency_filter
        )

        # 5. TCP Window
        window_analyzer = TCPWindowAnalyzer(
            low_window_threshold=thresholds.get('low_window_threshold', 8192),
            zero_window_duration=thresholds.get('zero_window_duration', 0.1)
        )

        # 6. ICMP / PMTU
        icmp_analyzer = ICMPAnalyzer()

        # 7. DNS
        dns_analyzer = DNSAnalyzer(
            response_warning=thresholds.get('dns_response_warning', 0.1),
            response_critical=thresholds.get('dns_response_critical', 1.0),
            timeout=thresholds.get('dns_timeout', 5.0),
            latency_filter=latency_filter
        )

        # 8. Retransmissions SYN détaillées
        syn_threshold = latency_filter if latency_filter else thresholds.get('syn_retrans_threshold', 2.0)
        syn_retrans_analyzer = SYNRetransmissionAnalyzer(threshold=syn_threshold)
        
        # 9. TCP Reset
        tcp_reset_analyzer = TCPResetAnalyzer()
        
        # 10. Fragmentation IP
        ip_fragmentation_analyzer = IPFragmentationAnalyzer()
        
        # 11. Top Talkers
        top_talkers_analyzer = TopTalkersAnalyzer()
        
        # 12. Throughput
        throughput_analyzer = ThroughputAnalyzer()
        
        # 13. TCP Timeout
        tcp_timeout_analyzer = TCPTimeoutAnalyzer(
            idle_threshold=thresholds.get('tcp_idle_threshold', 30.0),
            zombie_threshold=thresholds.get('tcp_zombie_threshold', 60.0)
        )
        
        # 14. Asymmetric Traffic
        asymmetric_analyzer = AsymmetricTrafficAnalyzer(
            asymmetry_threshold=thresholds.get('asymmetry_threshold', 0.3),
            min_bytes_threshold=thresholds.get('asymmetry_min_bytes', 10000)
        )
        
        # 15. Burst Analyzer
        burst_analyzer = BurstAnalyzer(
            interval_ms=thresholds.get('burst_interval_ms', 100),
            burst_threshold_multiplier=thresholds.get('burst_threshold_multiplier', 3.0),
            min_packets_for_burst=thresholds.get('burst_min_packets', 50)
        )
        
        # 16. Temporal Pattern Analyzer
        temporal_analyzer = TemporalPatternAnalyzer(
            slot_duration_seconds=thresholds.get('temporal_slot_duration', 60)
        )
        
        progress.update(task, advance=1)

    # Traitement streaming
    analyzers = [
        timestamp_analyzer,
        handshake_analyzer,
        retrans_analyzer,
        rtt_analyzer,
        window_analyzer,
        icmp_analyzer,
        dns_analyzer,
        syn_retrans_analyzer,
        tcp_reset_analyzer,
        ip_fragmentation_analyzer,
        top_talkers_analyzer,
        throughput_analyzer,
        tcp_timeout_analyzer,
        asymmetric_analyzer,
        burst_analyzer,
        temporal_analyzer
    ]
    
    load_pcap_streaming(pcap_file, analyzers)
    
    # Récupération des résultats
    results['timestamps'] = timestamp_analyzer._generate_report() if hasattr(timestamp_analyzer, '_generate_report') else {}
    results['tcp_handshake'] = handshake_analyzer._generate_report() if hasattr(handshake_analyzer, '_generate_report') else {}
    results['retransmission'] = retrans_analyzer._generate_report() if hasattr(retrans_analyzer, '_generate_report') else {}
    results['rtt'] = rtt_analyzer._generate_report() if hasattr(rtt_analyzer, '_generate_report') else {}
    results['tcp_window'] = window_analyzer._generate_report() if hasattr(window_analyzer, '_generate_report') else {}
    results['icmp'] = icmp_analyzer._generate_report() if hasattr(icmp_analyzer, '_generate_report') else {}
    results['dns'] = dns_analyzer._generate_report() if hasattr(dns_analyzer, '_generate_report') else {}
    results['syn_retransmissions'] = syn_retrans_analyzer._generate_report() if hasattr(syn_retrans_analyzer, '_generate_report') else {}
    results['tcp_reset'] = tcp_reset_analyzer.get_results()
    results['ip_fragmentation'] = ip_fragmentation_analyzer.get_results()
    results['top_talkers'] = top_talkers_analyzer.get_results()
    results['throughput'] = throughput_analyzer.get_results()
    results['tcp_timeout'] = tcp_timeout_analyzer.get_results()
    results['asymmetric_traffic'] = asymmetric_analyzer.get_results()
    results['burst'] = burst_analyzer.get_results()
    results['temporal'] = temporal_analyzer.get_results()

    # Affichage des résumés
    console.print("\n")
    console.print(Panel.fit("📊 Résultats de l'analyse", style="bold blue"))

    console.print("\n" + timestamp_analyzer.get_gaps_summary())
    console.print("\n" + handshake_analyzer.get_summary())
    console.print("\n" + retrans_analyzer.get_summary())
    
    # Affichage des détails des retransmissions si demandé
    if show_details and retrans_analyzer:
        details = retrans_analyzer.get_details(limit=details_limit)
        if details:
            console.print("\n" + details)
    
    console.print("\n" + rtt_analyzer.get_summary())
    console.print("\n" + window_analyzer.get_summary())
    console.print("\n" + icmp_analyzer.get_summary())
    console.print("\n" + dns_analyzer.get_summary())
    console.print("\n" + syn_retrans_analyzer.get_summary())
    
    # Résumé TCP Reset
    reset_results = results['tcp_reset']
    console.print("\n[bold cyan]🔴 Analyse des TCP Reset (RST)[/bold cyan]")
    console.print(f"Total RST détectés: {reset_results['total_resets']}")
    console.print(f"RST prématurés (avant échange de données): {reset_results['premature_resets']}")
    console.print(f"RST post-données: {reset_results['post_data_resets']}")
    console.print(f"Flux impactés: {reset_results['flows_with_resets']}")
    
    # Résumé Fragmentation IP
    frag_results = results['ip_fragmentation']
    console.print("\n[bold cyan]📦 Analyse de la fragmentation IP[/bold cyan]")
    console.print(f"Total fragments détectés: {frag_results['total_fragments']}")
    if frag_results['has_fragmentation']:
        console.print(f"Groupes de fragments: {frag_results['total_fragment_groups']}")
        console.print(f"Réassemblages complets: {frag_results['complete_reassemblies']}")
        console.print(f"Réassemblages incomplets: {frag_results['incomplete_reassemblies']}")
        console.print(f"PMTU estimé: {frag_results['estimated_pmtu']} bytes")
    else:
        console.print("[green]✓ Aucune fragmentation IP détectée[/green]")
    
    # Résumé Top Talkers
    talkers = results['top_talkers']
    console.print("\n[bold cyan]📊 Top Talkers[/bold cyan]")
    if talkers['top_ips']:
        console.print("Top 5 IPs par volume:")
        for i, ip_stat in enumerate(talkers['top_ips'][:5], 1):
            total_mb = ip_stat['total_bytes'] / (1024 * 1024)
            console.print(f"  {i}. {ip_stat['ip']}: {total_mb:.2f} MB ({ip_stat['packets_sent'] + ip_stat['packets_received']} paquets)")
    
    # Protocoles
    if talkers['protocol_stats']:
        console.print("Répartition par protocole:")
        for proto, stats in talkers['protocol_stats'].items():
            mb = stats['bytes'] / (1024 * 1024)
            console.print(f"  - {proto}: {mb:.2f} MB ({stats['packets']} paquets)")
    
    # Résumé Throughput
    tp = results['throughput']
    console.print("\n[bold cyan]📈 Analyse du débit (Throughput)[/bold cyan]")
    console.print(f"Débit global: {tp['global_throughput']['throughput_mbps']:.2f} Mbps")
    console.print(f"Durée totale: {tp['global_throughput']['duration_seconds']:.2f}s")
    console.print(f"Flux analysés: {tp['total_flows']}")
    if tp['slow_flows']:
        console.print(f"[yellow]Flux lents détectés: {len(tp['slow_flows'])}[/yellow]")
    
    # Résumé TCP Timeout
    timeout = results['tcp_timeout']
    cats = timeout['categories']
    console.print("\n[bold cyan]⏱️ Analyse des Timeouts TCP[/bold cyan]")
    console.print(f"Connexions totales: {timeout['total_connections']}")
    console.print(f"Connexions problématiques: {timeout['problematic_count']}")
    if timeout['problematic_count'] > 0:
        console.print(f"  - SYN timeout: {cats['syn_timeout_count']}")
        console.print(f"  - Half-open: {cats['half_open_count']}")
        console.print(f"  - Zombie: {cats['zombie_count']}")
        console.print(f"  - Idle: {cats['idle_count']}")
        console.print(f"  - Établies sans données: {cats['established_idle_count']}")
    
    # Résumé Trafic Asymétrique
    asym = results['asymmetric_traffic']
    asym_summary = asym['summary']
    console.print("\n[bold cyan]⚖️ Analyse du Trafic Asymétrique[/bold cyan]")
    console.print(f"Flux analysés: {asym_summary['total_flows']}")
    console.print(f"Flux asymétriques (ratio < {asym_summary['asymmetry_threshold']}): {asym_summary['asymmetric_flows']} ({asym_summary['asymmetric_percentage']:.1f}%)")
    console.print(f"Flux quasi-unidirectionnels: {asym_summary['unidirectional_flows']}")
    if asym['asymmetric_flows']:
        console.print("Top 3 flux les plus asymétriques:")
        for i, f in enumerate(asym['asymmetric_flows'][:3], 1):
            console.print(f"  {i}. {f['src_ip']}:{f['src_port']} → {f['dst_ip']}:{f['dst_port']} ({f['protocol']}): {f['asymmetry_percent']:.1f}% asymétrique")
    
    # Résumé Bursts
    burst = results['burst']
    burst_summary = burst['summary']
    burst_interval = burst['interval_stats']
    console.print("\n[bold cyan]💥 Analyse des Bursts de Paquets[/bold cyan]")
    console.print(f"Intervalles analysés: {burst_summary['total_intervals']} (intervalle: {burst_summary['interval_ms']}ms)")
    console.print(f"Régularité du trafic: {burst_interval['traffic_regularity']} (CV: {burst_interval['coefficient_of_variation']}%)")
    console.print(f"Bursts détectés: {burst_summary['bursts_detected']}")
    if burst['worst_burst']:
        wb = burst['worst_burst']
        console.print(f"[yellow]Pire burst: {wb['start_iso']} - {wb['packet_count']} paquets ({wb['packets_per_second']:.0f} pkt/s, {wb['peak_ratio']:.1f}x la moyenne)[/yellow]")
    
    # Résumé Patterns Temporels
    temporal = results['temporal']
    temp_summary = temporal['summary']
    temp_slots = temporal['slot_stats']
    console.print("\n[bold cyan]📅 Analyse des Patterns Temporels[/bold cyan]")
    console.print(f"Période: {temp_summary['capture_start']} → {temp_summary['capture_end']}")
    console.print(f"Créneaux analysés: {temp_summary['total_slots']} (durée: {temp_summary['slot_duration_seconds']}s)")
    console.print(f"Paquets/créneau: moy={temp_slots['avg_packets_per_slot']:.0f}, max={temp_slots['max_packets_per_slot']} ({temp_slots['peak_to_avg_ratio']}x)")
    console.print(f"Pics détectés: {temp_summary['peaks_detected']}, Creux: {temp_summary['valleys_detected']}")
    if temporal['periodic_patterns']:
        console.print(f"[yellow]Patterns périodiques: {temp_summary['periodic_patterns_detected']}[/yellow]")
        for p in temporal['periodic_patterns'][:2]:
            console.print(f"  - {p['source_ip']}: toutes les {p['description']} ({p['confidence']}% confiance)")

    return results


@click.group()
def cli():
    """Analyseur automatisé des causes de latence réseau"""
    pass


@cli.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('-l', '--latency', type=float, help='Seuil de latence en secondes pour le filtrage')
@click.option('-c', '--config', type=click.Path(exists=True), help='Fichier de configuration personnalisé')
@click.option('-o', '--output', help='Nom de base pour les rapports de sortie')
@click.option('--no-report', is_flag=True, help='Ne pas générer de rapports HTML/JSON')
@click.option('-d', '--details', is_flag=True, help='Afficher les détails des retransmissions')
@click.option('--details-limit', type=int, default=20, help='Nombre max de retransmissions à afficher (défaut: 20)')
def analyze(pcap_file, latency, config, output, no_report, details, details_limit):
    """
    Analyse un fichier PCAP pour détecter les causes de latence

    Exemple:
        pcap_analyzer analyze capture.pcap
        pcap_analyzer analyze capture.pcap -l 2.0
        pcap_analyzer analyze capture.pcap -d          # Afficher détails retransmissions
        pcap_analyzer analyze capture.pcap -d --details-limit 50
    """
    # Charge la configuration
    cfg = get_config(config)

    # Mode filtrage
    if latency:
        console.print(f"[yellow]Mode filtrage: analyse des paquets avec latence >= {latency}s[/yellow]")

    results = analyze_pcap_streaming(pcap_file, cfg, latency_filter=latency, show_details=details, details_limit=details_limit)

    # Génération des rapports
    if not no_report:
        console.print("\n[cyan]Génération des rapports...[/cyan]")
        report_gen = ReportGenerator(output_dir=cfg.get('reports.output_dir', 'reports'))
        report_files = report_gen.generate_report(results, pcap_file, output)

        console.print(f"[green]✓ Rapport JSON: {report_files['json']}[/green]")
        console.print(f"[green]✓ Rapport HTML: {report_files['html']}[/green]")


@cli.command()
@click.option('-d', '--duration', type=int, default=60, help='Durée de capture en secondes (défaut: 60)')
@click.option('-f', '--filter', help='Filtre BPF personnalisé (remplace celui de la config)')
@click.option('-o', '--output', help='Nom du fichier PCAP local de sortie')
@click.option('-c', '--config', type=click.Path(exists=True), help='Fichier de configuration personnalisé')
@click.option('--analyze/--no-analyze', default=True, help='Analyser automatiquement après capture')
@click.option('-l', '--latency', type=float, help='Seuil de latence pour l\'analyse')
def capture(duration, filter, output, config, analyze, latency):
    """
    Capture des paquets via SSH depuis un serveur distant

    Exemple:
        pcap_analyzer capture -d 120
        pcap_analyzer capture -d 60 -f "host 192.168.1.100"
    """
    # Charge la configuration
    cfg = get_config(config)

    # Nom du fichier de sortie
    if output is None:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"capture_{timestamp}.pcap"

    try:
        # Lance la capture
        local_pcap = capture_from_config(
            config=cfg.config,
            local_path=output,
            duration=duration,
            filter_override=filter
        )

        console.print(f"\n[green]✓ Capture terminée: {local_pcap}[/green]")

        # Analyse automatique si demandé
        if analyze:
            console.print("\n[cyan]Lancement de l'analyse automatique...[/cyan]")
            results = analyze_pcap_streaming(local_pcap, cfg, latency_filter=latency)

            # Génération des rapports
            console.print("\n[cyan]Génération des rapports...[/cyan]")
            report_gen = ReportGenerator(output_dir=cfg.get('reports.output_dir', 'reports'))
            report_files = report_gen.generate_report(results, local_pcap, None)

            console.print(f"[green]✓ Rapport JSON: {report_files['json']}[/green]")
            console.print(f"[green]✓ Rapport HTML: {report_files['html']}[/green]")

    except Exception as e:
        console.print(f"[red]❌ Erreur lors de la capture: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option('-c', '--config', type=click.Path(exists=True), help='Fichier de configuration à afficher')
def show_config(config):
    """Affiche la configuration actuelle"""
    cfg = get_config(config)

    table = Table(title="Configuration actuelle")
    table.add_column("Paramètre", style="cyan")
    table.add_column("Valeur", style="green")

    # Thresholds
    table.add_section()
    table.add_row("[bold]SEUILS[/bold]", "")
    for key, value in cfg.thresholds.items():
        table.add_row(f"  {key}", str(value))

    # SSH Config
    table.add_section()
    table.add_row("[bold]SSH[/bold]", "")
    ssh_config = cfg.ssh_config
    table.add_row("  host", ssh_config.get('host', 'N/A'))
    table.add_row("  username", ssh_config.get('username', 'N/A'))
    table.add_row("  port", str(ssh_config.get('port', 22)))

    # Reports
    table.add_section()
    table.add_row("[bold]RAPPORTS[/bold]", "")
    report_config = cfg.report_config
    table.add_row("  output_dir", report_config.get('output_dir', 'N/A'))
    table.add_row("  formats", ', '.join(report_config.get('formats', [])))

    console.print(table)


def main():
    """Point d'entrée principal"""
    cli()


if __name__ == '__main__':
    main()
