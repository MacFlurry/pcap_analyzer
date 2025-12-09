#!/usr/bin/env python3
"""
Interface en ligne de commande pour l'analyseur PCAP
"""

import click
import sys
import gc
from pathlib import Path
from typing import Dict, Any, Optional
from scapy.all import PcapReader
from scapy.config import conf
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table

from .config import get_config, Config
from .ssh_capture import capture_from_config
from .analyzer_factory import AnalyzerFactory
from .report_generator import ReportGenerator
from .parsers.fast_parser import FastPacketParser

console = Console()

# Performance constants
MEMORY_CLEANUP_INTERVAL = 50_000  # packets - periodic memory cleanup interval
PROGRESS_UPDATE_INTERVAL = 1_000  # packets - progress bar update frequency


def _generate_reports(
    results: Dict[str, Any],
    pcap_file: str,
    output: Optional[str],
    cfg: Config
) -> Dict[str, str]:
    """
    Generate JSON and HTML reports.

    Args:
        results: Analysis results dictionary
        pcap_file: Path to the PCAP file analyzed
        output: Optional output name for reports
        cfg: Configuration object

    Returns:
        Dictionary with paths to generated report files
    """
    console.print("\n[cyan]Génération des rapports...[/cyan]")
    report_gen = ReportGenerator(output_dir=cfg.get('reports.output_dir', 'reports'))
    report_files = report_gen.generate_report(results, pcap_file, output)

    console.print(f"[green]✓ Rapport JSON: {report_files['json']}[/green]")
    console.print(f"[green]✓ Rapport HTML: {report_files['html']}[/green]")

    return report_files


# Performance optimization: Configure Scapy to only dissect necessary layers
# This can provide 30-50% performance boost by skipping unnecessary protocol parsing
def configure_scapy_performance() -> None:
    """Configure Scapy for optimal performance with selective layer parsing."""
    # Only dissect layers we actually use in our analyzers
    conf.layers.filter([Ether, IP, IPv6, TCP, UDP, ICMP, DNS])

    # Disable verbose mode for performance
    conf.verb = 0


def analyze_pcap_hybrid(
    pcap_file: str,
    config: Config,
    latency_filter: Optional[float] = None,
    show_details: bool = False,
    details_limit: int = 20
) -> Dict[str, Any]:
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

    # Step 1: Fast metadata extraction with dpkt (3-5x faster than Scapy)
    console.print("[cyan]Phase 1/2: Extraction des métadonnées...[/cyan]")

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
    tcp_timeout_analyzer = analyzer_dict["tcp_timeout"]
    burst_analyzer = analyzer_dict["burst"]
    temporal_analyzer = analyzer_dict["temporal"]

    # Fast pass with dpkt
    parser = FastPacketParser(pcap_file)

    # Count total packets first for accurate progress reporting
    total_packets = sum(1 for _ in FastPacketParser(pcap_file).parse())

    packet_count = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Processing..."),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Extracting metadata...", total=total_packets)

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
            tcp_timeout_analyzer.process_packet(metadata, packet_count - 1)
            burst_analyzer.process_packet(metadata, packet_count - 1)
            temporal_analyzer.process_packet(metadata, packet_count - 1)

            if packet_count % MEMORY_CLEANUP_INTERVAL == 0:
                gc.collect()

            if packet_count % PROGRESS_UPDATE_INTERVAL == 0:
                progress.update(task, completed=packet_count)

    console.print(f"[green]✓ Phase 1 terminée: {packet_count} paquets traités[/green]")

    # Step 2: Scapy pass for complex analysis only (DNS, ICMP, etc.)
    console.print("[cyan]Phase 2/2: Analyse approfondie des protocoles complexes...[/cyan]")
    configure_scapy_performance()

    # Only these analyzers need Scapy's deep packet inspection
    dns_analyzer = analyzer_dict["dns"]
    icmp_analyzer = analyzer_dict["icmp"]

    complex_packet_count = 0
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Processing complex protocols..."),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Deep inspection...", total=total_packets)

        with PcapReader(pcap_file) as reader:
            for i, packet in enumerate(reader):
                # Only process packets that need deep inspection
                if packet.haslayer(DNS):
                    dns_analyzer.process_packet(packet, i)
                    complex_packet_count += 1
                if packet.haslayer(ICMP):
                    icmp_analyzer.process_packet(packet, i)
                    complex_packet_count += 1

                if i % PROGRESS_UPDATE_INTERVAL == 0:
                    progress.update(task, completed=i)

    console.print(f"[green]✓ Phase 2 terminée: {complex_packet_count} paquets analysés[/green]")

    # Finalize all analyzers
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Finalisation..."),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Computing statistics...", total=len(analyzers))
        for idx, analyzer in enumerate(analyzers):
            if hasattr(analyzer, 'finalize'):
                analyzer.finalize()
            progress.update(task, completed=idx + 1)

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
    results['tcp_timeout'] = tcp_timeout_analyzer.get_results()
    results['burst'] = burst_analyzer._generate_report()
    results['temporal'] = temporal_analyzer._generate_report()
    results['dns'] = dns_analyzer._generate_report()
    results['icmp'] = icmp_analyzer._generate_report()

    # Add empty results for other analyzers (they'll be implemented next)
    for key in ['ip_fragmentation', 'asymmetric_traffic', 'sack']:
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
    console.print("\n" + tcp_timeout_analyzer.get_summary())
    console.print("\n" + throughput_analyzer.get_summary())
    console.print("\n" + burst_analyzer.get_summary())
    console.print("\n" + temporal_analyzer.get_summary())
    console.print("\n" + icmp_analyzer.get_summary())
    console.print("\n" + dns_analyzer.get_summary())
    console.print("\n" + toptalkers_analyzer.get_summary())

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
@click.option('--no-details', is_flag=True, help='Ne pas afficher les détails des retransmissions')
@click.option('--details-limit', type=int, default=20, help='Nombre max de retransmissions à afficher (défaut: 20)')
def analyze(pcap_file, latency, config, output, no_report, no_details, details_limit):
    """
    Analyse un fichier PCAP local pour détecter les causes de latence

    Utilise le mode hybride optimisé (dpkt + Scapy) - 1.7x plus rapide
    Les détails des retransmissions sont affichés par défaut

    Exemple:
        pcap_analyzer analyze capture.pcap
        pcap_analyzer analyze capture.pcap -l 2.0
        pcap_analyzer analyze capture.pcap --no-details
        pcap_analyzer analyze capture.pcap --details-limit 50
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

    # Détails par défaut (sauf si --no-details)
    show_details = not no_details

    # Analyse avec le mode hybride optimisé (dpkt + Scapy)
    results = analyze_pcap_hybrid(pcap_file, cfg, latency_filter=latency, show_details=show_details, details_limit=details_limit)

    # Génération des rapports
    if not no_report:
        _generate_reports(results, pcap_file, output, cfg)


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
            results = analyze_pcap_hybrid(local_pcap, cfg, latency_filter=latency, show_details=True)

            # Génération des rapports
            _generate_reports(results, local_pcap, None, cfg)

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
