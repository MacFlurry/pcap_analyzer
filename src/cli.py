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
    SYNRetransmissionAnalyzer
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
        console.print(f"[cyan]Analyse du fichier PCAP: {pcap_file}[/cyan]")
        packet_count = 0
        
        with PcapReader(pcap_file) as reader:
            for packet in reader:
                packet_count += 1
                
                # Passe le paquet à chaque analyseur
                for analyzer in analyzers:
                    if hasattr(analyzer, 'process_packet'):
                        analyzer.process_packet(packet, packet_count - 1)
                
                # Affichage périodique
                if packet_count % 100000 == 0:
                    console.print(f"[dim]Traité {packet_count} paquets...[/dim]")
        
        console.print(f"[green]✓ {packet_count} paquets analysés[/green]")
        
        # Finalise tous les analyseurs
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
        syn_retrans_analyzer
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
