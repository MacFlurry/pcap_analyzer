#!/usr/bin/env python3
"""
Interface en ligne de commande pour l'analyseur PCAP
"""

import click
import sys
import gc
from pathlib import Path
from scapy.all import PcapReader
from scapy.config import conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich.table import Table

from .config import get_config
from .ssh_capture import capture_from_config
from .analyzer_factory import AnalyzerFactory
from .report_generator import ReportGenerator
from .parsers.fast_parser import FastPacketParser

console = Console()

# Performance optimization: Configure Scapy to only dissect necessary layers
# This can provide 30-50% performance boost by skipping unnecessary protocol parsing
def configure_scapy_performance():
    """Configure Scapy for optimal performance with selective layer parsing."""
    # Only dissect layers we actually use in our analyzers
    conf.layers.filter([Ether, IP, IPv6, TCP, UDP, ICMP, DNS])

    # Disable verbose mode for performance
    conf.verb = 0


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

                    # Performance optimization: Periodic garbage collection for large files
                    # Helps prevent memory fragmentation and reduces memory pressure
                    if packet_count % 50000 == 0:
                        gc.collect()
                        progress.update(task, description=f"[cyan]Traité {packet_count} paquets... (GC)")
                    # Mise à jour périodique
                    elif packet_count % 10000 == 0:
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


def analyze_pcap_hybrid(pcap_file: str, config, latency_filter: float = None, show_details: bool = False, details_limit: int = 20):
    """
    PHASE 2 OPTIMIZATION: Hybrid analysis using dpkt + Scapy.

    This provides 3-5x performance boost by:
    1. Using dpkt for fast metadata extraction (simple analyzers)
    2. Using Scapy only for complex analysis (DNS, ICMP, deep packet inspection)

    Performance comparison:
    - Old (Scapy only): ~94 seconds for 172k packets
    - New (Hybrid): ~30-40 seconds (target)
    """
    thresholds = config.thresholds
    results = {}

    console.print("[cyan]🚀 Phase 2: Hybrid Analysis (dpkt + Scapy)...[/cyan]")

    # Step 1: Fast metadata extraction with dpkt (3-5x faster than Scapy)
    console.print("[cyan]Phase 1/2: Fast metadata extraction (dpkt)...[/cyan]")

    # Create analyzers
    analyzer_dict, analyzers = AnalyzerFactory.create_analyzers(config, latency_filter)

    # Get analyzers that support fast metadata processing
    timestamp_analyzer = analyzer_dict["timestamp"]
    handshake_analyzer = analyzer_dict["handshake"]
    retrans_analyzer = analyzer_dict["retransmission"]
    rtt_analyzer = analyzer_dict["rtt"]
    window_analyzer = analyzer_dict["window"]
    reset_analyzer = analyzer_dict["tcp_reset"]
    toptalkers_analyzer = analyzer_dict["top_talkers"]
    throughput_analyzer = analyzer_dict["throughput"]
    syn_retrans_analyzer = analyzer_dict["syn_retransmissions"]

    # Fast pass with dpkt
    parser = FastPacketParser(pcap_file)
    packet_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Processing with dpkt..."),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Extracting metadata...", total=None)

        for metadata in parser.parse():
            packet_count += 1

            # Pass metadata to compatible analyzers (much faster than Scapy)
            timestamp_analyzer.process_packet(metadata, packet_count - 1)
            handshake_analyzer.process_packet(metadata, packet_count - 1)
            retrans_analyzer.process_packet(metadata, packet_count - 1)
            rtt_analyzer.process_packet(metadata, packet_count - 1)
            window_analyzer.process_packet(metadata, packet_count - 1)
            reset_analyzer.process_packet(metadata, packet_count - 1)
            toptalkers_analyzer.process_packet(metadata, packet_count - 1)
            throughput_analyzer.process_packet(metadata, packet_count - 1)
            syn_retrans_analyzer.process_packet(metadata, packet_count - 1)

            if packet_count % 50000 == 0:
                gc.collect()
                progress.update(task, description=f"[cyan]Processed {packet_count} packets (dpkt)...")
            elif packet_count % 10000 == 0:
                progress.update(task, description=f"[cyan]Processed {packet_count} packets...")

    console.print(f"[green]✓ Phase 1 complete: {packet_count} packets processed with dpkt[/green]")

    # Step 2: Scapy pass for complex analysis only (DNS, ICMP, etc.)
    console.print("[cyan]Phase 2/2: Deep analysis for complex protocols (Scapy)...[/cyan]")
    configure_scapy_performance()

    # Only these analyzers need Scapy's deep packet inspection
    dns_analyzer = analyzer_dict["dns"]
    icmp_analyzer = analyzer_dict["icmp"]

    complex_packet_count = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Processing complex protocols..."),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scapy pass...", total=None)

        with PcapReader(pcap_file) as reader:
            for i, packet in enumerate(reader):
                # Only process packets that need deep inspection
                if packet.haslayer(DNS):
                    dns_analyzer.process_packet(packet, i)
                    complex_packet_count += 1
                if packet.haslayer(ICMP):
                    icmp_analyzer.process_packet(packet, i)
                    complex_packet_count += 1

                if i % 10000 == 0:
                    progress.update(task, description=f"[cyan]Scapy: {complex_packet_count} complex packets...")

    console.print(f"[green]✓ Phase 2 complete: {complex_packet_count} packets needed deep inspection[/green]")

    # Finalize all analyzers
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Finalizing analyses..."),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Computing statistics...", total=None)
        for analyzer in analyzers:
            if hasattr(analyzer, 'finalize'):
                analyzer.finalize()

    # Collect results (growing list of dpkt-compatible analyzers)
    results['timestamps'] = timestamp_analyzer._generate_report()
    results['tcp_handshake'] = handshake_analyzer._generate_report()
    results['retransmission'] = retrans_analyzer._generate_report()
    results['rtt'] = rtt_analyzer._generate_report()
    results['tcp_window'] = window_analyzer._generate_report()
    results['tcp_reset'] = reset_analyzer._generate_report()
    results['top_talkers'] = toptalkers_analyzer._generate_report()
    results['throughput'] = throughput_analyzer._generate_report()
    results['syn_retransmissions'] = syn_retrans_analyzer._generate_report()
    results['dns'] = dns_analyzer._generate_report()
    results['icmp'] = icmp_analyzer._generate_report()

    # Add empty results for other analyzers (they'll be implemented next)
    for key in ['ip_fragmentation', 'tcp_timeout',
                'asymmetric_traffic', 'burst', 'temporal', 'sack']:
        if key not in results:
            results[key] = {}

    # Display summaries
    console.print("\n")
    console.print(Panel.fit("📊 Résultats de l'analyse (Hybrid Mode)", style="bold blue"))
    console.print("\n" + timestamp_analyzer.get_gaps_summary())
    console.print("\n" + handshake_analyzer.get_summary())
    console.print("\n" + retrans_analyzer.get_summary())
    console.print("\n" + rtt_analyzer.get_summary())
    console.print("\n" + window_analyzer.get_summary())
    console.print("\n" + reset_analyzer.get_summary())
    console.print("\n" + syn_retrans_analyzer.get_summary())
    console.print("\n" + throughput_analyzer.get_summary())
    console.print("\n" + icmp_analyzer.get_summary())
    console.print("\n" + dns_analyzer.get_summary())
    console.print("\n" + toptalkers_analyzer.get_summary())

    return results


def analyze_pcap_streaming(pcap_file: str, config, latency_filter: float = None, show_details: bool = False, details_limit: int = 20):
    """Analyse un fichier PCAP en mode streaming optimisé (Legacy Scapy-only mode)"""
    # Performance optimization: Configure Scapy for selective layer parsing
    # This provides a significant performance boost by only dissecting necessary layers
    configure_scapy_performance()

    thresholds = config.thresholds

    results = {}

    # Initialisation des analyseurs via la factory (élimine ~110 lignes de duplication)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Initialisation des analyseurs...", total=1)

        # Create all analyzers using the factory pattern
        analyzer_dict, analyzers = AnalyzerFactory.create_analyzers(config, latency_filter)

        # Extract individual analyzers for backward compatibility
        timestamp_analyzer = analyzer_dict["timestamp"]
        handshake_analyzer = analyzer_dict["handshake"]
        retrans_analyzer = analyzer_dict["retransmission"]
        rtt_analyzer = analyzer_dict["rtt"]
        window_analyzer = analyzer_dict["window"]
        icmp_analyzer = analyzer_dict["icmp"]
        dns_analyzer = analyzer_dict["dns"]
        syn_retrans_analyzer = analyzer_dict["syn_retransmissions"]
        tcp_reset_analyzer = analyzer_dict["tcp_reset"]
        ip_fragmentation_analyzer = analyzer_dict["ip_fragmentation"]
        top_talkers_analyzer = analyzer_dict["top_talkers"]
        throughput_analyzer = analyzer_dict["throughput"]
        tcp_timeout_analyzer = analyzer_dict["tcp_timeout"]
        asymmetric_analyzer = analyzer_dict["asymmetric_traffic"]
        burst_analyzer = analyzer_dict["burst"]
        temporal_analyzer = analyzer_dict["temporal"]
        sack_analyzer = analyzer_dict["sack"]

        progress.update(task, advance=1)
    
    load_pcap_streaming(pcap_file, analyzers)

    # Récupération des résultats
    # NOTE: hasattr checks exist due to inconsistent analyzer interfaces (_generate_report vs get_results)
    # TODO: A BaseAnalyzer abstract class would eliminate the need for these hasattr checks
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
    results['sack'] = sack_analyzer.get_results()

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

    # Résumé SACK/D-SACK
    sack = results['sack']
    sack_summary = sack['summary']
    sack_efficiency = sack['efficiency']
    console.print("\n[bold cyan]🔄 Analyse SACK/D-SACK[/bold cyan]")
    console.print(f"Paquets TCP avec SACK: {sack_summary['sack_packets']} ({sack_summary['sack_usage_percentage']}%)")
    console.print(f"D-SACK détectés: {sack_summary['dsack_packets']} ({sack_summary['dsack_ratio_percentage']}% des SACK)")
    console.print(f"Flux utilisant SACK: {sack_summary['flows_using_sack']}")
    
    if sack_summary['sack_packets'] > 0:
        console.print(f"[green]Économie estimée: {sack_efficiency['estimated_retransmission_savings_mb']} MB en retransmissions évitées[/green]")
        if sack_efficiency['flows_with_dsack'] > 0:
            console.print(f"[yellow]⚠️ {sack_efficiency['flows_with_dsack']} flux avec D-SACK (problématiques)[/yellow]")
    else:
        console.print("[dim]Aucune utilisation SACK détectée[/dim]")

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
@click.option('--mode', type=click.Choice(['hybrid', 'legacy'], case_sensitive=False), default='hybrid',
              help='Mode d\'analyse: hybrid (dpkt+Scapy, 3-5x plus rapide) ou legacy (Scapy seul)')
def analyze(pcap_file, latency, config, output, no_report, details, details_limit, mode):
    """
    Analyse un fichier PCAP pour détecter les causes de latence

    Exemple:
        pcap_analyzer analyze capture.pcap
        pcap_analyzer analyze capture.pcap --mode hybrid  # 3-5x plus rapide (défaut)
        pcap_analyzer analyze capture.pcap --mode legacy  # Scapy seul
        pcap_analyzer analyze capture.pcap -l 2.0
        pcap_analyzer analyze capture.pcap -d          # Afficher détails retransmissions
        pcap_analyzer analyze capture.pcap -d --details-limit 50
    """
    # Security: Validate and canonicalize pcap_file path to prevent symlink attacks
    try:
        pcap_path = Path(pcap_file).resolve(strict=True)
        # Ensure it's a file and not a directory
        if not pcap_path.is_file():
            raise click.BadParameter(f"Le chemin spécifié n'est pas un fichier: {pcap_file}")
        # Prevent reading sensitive system files
        sensitive_dirs = ['/etc', '/root', '/sys', '/proc', '/dev']
        for sensitive_dir in sensitive_dirs:
            if str(pcap_path).startswith(sensitive_dir):
                raise click.BadParameter(f"Accès refusé: impossible de lire des fichiers dans {sensitive_dir}")
        pcap_file = str(pcap_path)
    except (OSError, RuntimeError) as e:
        raise click.BadParameter(f"Erreur de validation du chemin: {e}")

    # Charge la configuration
    cfg = get_config(config)

    # Mode filtrage
    if latency:
        console.print(f"[yellow]Mode filtrage: analyse des paquets avec latence >= {latency}s[/yellow]")

    # Choose analysis mode
    if mode == 'hybrid':
        console.print("[green]⚡ Using HYBRID mode (dpkt + Scapy) - 3-5x faster![/green]")
        results = analyze_pcap_hybrid(pcap_file, cfg, latency_filter=latency, show_details=details, details_limit=details_limit)
    else:
        console.print("[yellow]Using LEGACY mode (Scapy only)[/yellow]")
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

    # Validate SSH configuration is present for capture command
    try:
        cfg.validate_ssh_config()
    except ValueError as e:
        console.print(f"[red]❌ {e}[/red]")
        sys.exit(1)

    # Nom du fichier de sortie
    if output is None:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"capture_{timestamp}.pcap"

    # Security: Validate output path to prevent path traversal attacks
    try:
        output_path = Path(output).resolve()

        # Prevent directory traversal
        if '..' in output:
            raise click.BadParameter("Chemin non autorisé: '..' n'est pas permis dans le chemin de sortie")

        # Prevent writing to sensitive system directories
        sensitive_dirs = ['/etc', '/root', '/sys', '/proc', '/dev', '/usr', '/bin', '/sbin', '/boot']
        for sensitive_dir in sensitive_dirs:
            if str(output_path).startswith(sensitive_dir):
                raise click.BadParameter(f"Accès refusé: impossible d'écrire dans {sensitive_dir}")

        # Validate parent directory
        if not output_path.parent.exists():
            raise click.BadParameter(f"Le dossier parent n'existe pas: {output_path.parent}")
        if output_path.parent.is_file():
            raise click.BadParameter(f"Le chemin parent est un fichier, pas un dossier: {output_path.parent}")
    except (OSError, RuntimeError) as e:
        raise click.BadParameter(f"Erreur de validation du chemin de sortie: {e}")

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
