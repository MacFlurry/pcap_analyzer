#!/usr/bin/env python3
"""
Interface en ligne de commande pour l'analyseur PCAP
"""

import gc
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from scapy.all import PcapReader
from scapy.config import conf
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from .analyzer_factory import AnalyzerFactory
from .analyzers.brute_force_detector import BruteForceDetector
from .analyzers.c2_beaconing_detector import C2BeaconingDetector
from .analyzers.data_exfiltration_detector import DataExfiltrationDetector
from .analyzers.ddos_detector import DDoSDetector
from .analyzers.dns_tunneling_detector import DNSTunnelingDetector
from .analyzers.health_score import HealthScoreCalculator
from .analyzers.jitter_analyzer import JitterAnalyzer
from .analyzers.lateral_movement_detector import LateralMovementDetector
from .analyzers.port_scan_detector import PortScanDetector
from .analyzers.protocol_distribution import ProtocolDistributionAnalyzer
from .analyzers.service_classifier import ServiceClassifier
from .config import Config, get_config
from .exporters.csv_export import CSVExporter
from .exporters.html_report import HTMLReportGenerator
from .parsers.fast_parser import FastPacketParser
from .performance.memory_optimizer import MemoryMonitor, MemoryOptimizer
from .performance.parallel_executor import ParallelAnalyzerExecutor
from .performance.streaming_processor import StreamingProcessor
from .report_generator import ReportGenerator
from .ssh_capture import capture_from_config
from .utils.result_sanitizer import get_empty_analyzer_result, sanitize_results

console = Console()

# Performance constants
MEMORY_CLEANUP_INTERVAL = 50_000  # packets - periodic memory cleanup interval
PROGRESS_UPDATE_INTERVAL = 1_000  # packets - progress bar update frequency


def _generate_reports(results: dict[str, Any], pcap_file: str, output: Optional[str], cfg: Config) -> dict[str, str]:
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

    # Use the old generator for JSON only
    report_gen = ReportGenerator(output_dir=cfg.get("reports.output_dir", "reports"))

    # Prepare output paths
    output_dir = Path(cfg.get("reports.output_dir", "reports"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if output is None:
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"pcap_analysis_{timestamp}"

    # Add metadata if not present (fix for Issue #3 - Total Packets = 0)
    if "metadata" not in results:
        results["metadata"] = {}
    results["metadata"]["pcap_file"] = Path(pcap_file).name

    # Extract total packets from protocol_distribution if available
    if "protocol_distribution" in results:
        results["metadata"]["total_packets"] = results["protocol_distribution"].get("total_packets", 0)

    # Extract capture duration from timestamps if available
    if "timestamps" in results:
        results["metadata"]["capture_duration"] = results["timestamps"].get("capture_duration", 0)

    # Generate JSON with old generator
    json_path = output_dir / f"{output}.json"
    report_gen._generate_json(results, json_path)

    # Generate HTML with NEW generator (Sprint 9 - with tabs)
    html_generator = HTMLReportGenerator()
    html_path = output_dir / f"{output}.html"
    html_generator.save(results, str(html_path))

    console.print(f"[green]✓ Rapport JSON: {json_path}[/green]")
    console.print(f"[green]✓ Rapport HTML: {html_path}[/green]")

    return {"json": str(json_path), "html": str(html_path)}


def _handle_exports(
    results: dict[str, Any],
    pcap_file: str,
    export_html: Optional[str],
    export_csv: Optional[str],
    export_dir: Optional[str],
) -> None:
    """
    Handle Sprint 4 export formats (HTML report and CSV export).

    Args:
        results: Analysis results dictionary
        pcap_file: Path to the PCAP file analyzed
        export_html: Optional path for HTML report export
        export_csv: Optional directory for CSV export
        export_dir: Optional directory for all exports
    """
    if not (export_html or export_csv or export_dir):
        return

    console.print("\n[cyan]📤 Exporting analysis results...[/cyan]")

    # Add metadata if not present
    if "metadata" not in results:
        results["metadata"] = {}
    results["metadata"]["pcap_file"] = Path(pcap_file).name

    # Extract total packets from protocol_distribution if available
    if "protocol_distribution" in results:
        results["metadata"]["total_packets"] = results["protocol_distribution"].get("total_packets", 0)

    # Extract capture duration from timestamps if available
    if "timestamps" in results:
        results["metadata"]["capture_duration"] = results["timestamps"].get("capture_duration", 0)

    # Export to directory (all formats)
    if export_dir:
        import os

        os.makedirs(export_dir, exist_ok=True)

        # Export HTML
        html_path = os.path.join(export_dir, "report.html")
        html_gen = HTMLReportGenerator()
        html_gen.save(results, html_path)
        console.print(f"[green]✓ HTML Report: {html_path}[/green]")

        # Export CSV
        csv_dir = os.path.join(export_dir, "csv")
        csv_exporter = CSVExporter()
        csv_exporter.export_all(results, csv_dir)
        console.print(f"[green]✓ CSV Files: {csv_dir}/[/green]")

    else:
        # Export HTML to specific path
        if export_html:
            html_gen = HTMLReportGenerator()
            html_gen.save(results, export_html)
            console.print(f"[green]✓ HTML Report: {export_html}[/green]")

        # Export CSV to directory
        if export_csv:
            csv_exporter = CSVExporter()
            csv_exporter.export_all(results, export_csv)
            console.print(f"[green]✓ CSV Files: {export_csv}/[/green]")


# Performance optimization: Configure Scapy to only dissect necessary layers
# This can provide 30-50% performance boost by skipping unnecessary protocol parsing
def configure_scapy_performance() -> None:
    """Configure Scapy for optimal performance with selective layer parsing."""
    # Only dissect layers we actually use in our analyzers
    # Check if already filtered (important for persistent workers)
    try:
        conf.layers.filter([Ether, IP, IPv6, TCP, UDP, ICMP, DNS])
    except ValueError:
        # Already filtered, skip (happens in persistent worker environments)
        pass

    # Disable verbose mode for performance
    conf.verb = 0


def analyze_pcap_hybrid(
    pcap_file: str,
    config: Config,
    latency_filter: Optional[float] = None,
    show_details: bool = False,
    details_limit: int = 20,
    include_localhost: bool = False,
    enable_streaming: bool = True,
    enable_parallel: bool = False,
    memory_limit_mb: Optional[float] = None,
) -> dict[str, Any]:
    """
    PHASE 2 OPTIMIZATION: Hybrid analysis using dpkt + Scapy.

    This provides 3-5x performance boost by:
    1. Using dpkt for fast metadata extraction (simple analyzers)
    2. Using Scapy only for complex analysis (DNS, ICMP, deep packet inspection)
    3. (Sprint 10) Automatic streaming mode for large files (>100MB)
    4. (Sprint 10) Optional parallel execution for multi-core CPUs

    Performance comparison:
    - Old (Scapy only): ~94 seconds for 172k packets
    - New (Hybrid): ~30-40 seconds (target)
    - New (Hybrid + Streaming): memory-efficient for files >100MB
    """
    thresholds = config.thresholds
    results = {}

    # Sprint 10: Initialize performance optimization tools
    memory_optimizer = MemoryOptimizer(memory_limit_mb=memory_limit_mb)
    streaming_processor = StreamingProcessor(pcap_file)

    # Show performance mode info
    perf_stats = streaming_processor.get_stats()
    console.print(f"\n[cyan]📊 Performance Mode:[/cyan]")
    console.print(f"  File size: {perf_stats['file_size_mb']:.2f} MB")
    console.print(f"  Mode: {perf_stats['processing_mode']}")
    console.print(f"  Description: {perf_stats['recommended_mode']}")
    if perf_stats["chunk_size"]:
        console.print(f"  Chunk size: {perf_stats['chunk_size']} packets")

    # Show memory status
    mem_stats = memory_optimizer.get_memory_stats()
    console.print(f"  System memory: {mem_stats.available_mb:.0f} MB available ({mem_stats.percent:.0f}% used)")
    console.print()

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
        SpinnerColumn(), TextColumn("[cyan]Processing..."), BarColumn(), TaskProgressColumn(), console=console
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

    # PCAP-NG Compatibility Fix: Scapy's PcapReader cannot handle PCAP-NG properly
    # Detect format and convert to standard PCAP if needed
    pcap_for_scapy = pcap_file
    temp_pcap_path = None

    try:
        import subprocess

        # Check file format using tcpdump
        result = subprocess.run(
            ["tcpdump", "-r", pcap_file, "-c", "1"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        # If file is PCAP-NG, convert to standard PCAP for Scapy compatibility
        if "pcap-ng" in result.stderr.lower() or "pcapng" in result.stderr.lower():
            console.print("[yellow]⚠ PCAP-NG détecté - Conversion en PCAP standard pour Scapy...[/yellow]")

            # Create temporary PCAP file
            import tempfile

            temp_fd, temp_pcap_path = tempfile.mkstemp(suffix=".pcap", prefix="scapy_")
            os.close(temp_fd)  # Close file descriptor, we'll use the path

            # Convert using tcpdump (faster and more reliable than editcap)
            subprocess.run(
                ["tcpdump", "-r", pcap_file, "-w", temp_pcap_path],
                capture_output=True,
                check=True,
                timeout=60,
            )

            pcap_for_scapy = temp_pcap_path
            console.print(f"[green]✓ Conversion réussie: {temp_pcap_path}[/green]")

    except subprocess.TimeoutExpired:
        console.print("[yellow]⚠ Conversion timeout - Utilisation du fichier original[/yellow]")
    except subprocess.CalledProcessError as e:
        console.print(f"[yellow]⚠ Conversion échouée: {e} - Utilisation du fichier original[/yellow]")
    except Exception as e:
        console.print(f"[yellow]⚠ Erreur détection format: {e} - Utilisation du fichier original[/yellow]")

    # Only these analyzers need Scapy's deep packet inspection
    dns_analyzer = analyzer_dict["dns"]
    icmp_analyzer = analyzer_dict["icmp"]

    # Sprint 2 & 3: New analyzers for protocol, jitter, and service classification
    protocol_analyzer = ProtocolDistributionAnalyzer()
    jitter_analyzer = JitterAnalyzer()
    service_classifier = ServiceClassifier()

    # Sprint 5-7: Security analyzers
    port_scan_detector = PortScanDetector(include_localhost=include_localhost)
    brute_force_detector = BruteForceDetector(include_localhost=include_localhost)
    ddos_detector = DDoSDetector(include_localhost=include_localhost)
    dns_tunneling_detector = DNSTunnelingDetector(include_localhost=include_localhost)

    # Sprint 11: Advanced Threat Detection
    data_exfiltration_detector = DataExfiltrationDetector(include_localhost=include_localhost)
    c2_beaconing_detector = C2BeaconingDetector(include_localhost=include_localhost)
    lateral_movement_detector = LateralMovementDetector(include_localhost=include_localhost)

    # Sprint 10: Use streaming processor for memory efficiency
    # If PCAP-NG was converted, reinitialize streaming processor with converted file
    if temp_pcap_path is not None:
        streaming_processor = StreamingProcessor(pcap_for_scapy)
        perf_stats = streaming_processor.get_stats()

    processing_mode = perf_stats["processing_mode"]
    scapy_packets = []
    complex_packet_count = 0

    # Wrap packet loading with memory monitoring
    with MemoryMonitor("Packet Loading", memory_optimizer) as monitor:
        if processing_mode == "memory" and enable_streaming:
            # Small files: Load all packets into memory (original behavior)
            console.print("[cyan]Loading packets into memory (small file mode)...[/cyan]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Processing complex protocols..."),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Deep inspection...", total=total_packets)

                with PcapReader(pcap_for_scapy) as reader:
                    for i, packet in enumerate(reader):
                        # Collect all packets for protocol/jitter analysis
                        scapy_packets.append(packet)

                        # Only process packets that need deep inspection
                        if packet.haslayer(DNS):
                            dns_analyzer.process_packet(packet, i)
                            complex_packet_count += 1
                        if packet.haslayer(ICMP):
                            icmp_analyzer.process_packet(packet, i)
                            complex_packet_count += 1

                        if i % PROGRESS_UPDATE_INTERVAL == 0:
                            progress.update(task, completed=i)

        else:
            # Large files: Use streaming/chunked processing
            console.print(f"[cyan]Using streaming mode for large file ({processing_mode})...[/cyan]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Processing complex protocols..."),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Deep inspection...", total=total_packets)
                packet_idx = 0

                for chunk in streaming_processor.stream_chunks():
                    # Extend scapy_packets with chunk
                    scapy_packets.extend(chunk)

                    # Process chunk for deep inspection
                    for packet in chunk:
                        if packet.haslayer(DNS):
                            dns_analyzer.process_packet(packet, packet_idx)
                            complex_packet_count += 1
                        if packet.haslayer(ICMP):
                            icmp_analyzer.process_packet(packet, packet_idx)
                            complex_packet_count += 1

                        packet_idx += 1

                        if packet_idx % PROGRESS_UPDATE_INTERVAL == 0:
                            progress.update(task, completed=packet_idx)

                    # Trigger GC after each chunk if under memory pressure (Fix for Issue #4)
                    if memory_optimizer.check_memory_pressure():
                        collected = memory_optimizer.trigger_gc(force=False)  # Use cooldown logic
                        # Rate-limit logging to reduce spam
                        if collected > 0:
                            console.print(f"[green]  GC collected {collected} objects[/green]")
                        elif memory_optimizer.consecutive_empty_gcs == 1:
                            # Only log once when GC starts being ineffective
                            console.print(f"[dim]  GC triggered but collected 0 objects (will reduce frequency)[/dim]")

                    # Explicit cleanup after chunk processing
                    memory_optimizer.release_chunk_memory(chunk)

    # Show memory usage
    mem_summary = monitor.get_summary()
    console.print(f"[cyan]Memory used for packet loading: {mem_summary['used_mb']:.2f} MB[/cyan]")

    # Reset GC tracking before Phase 2 (Fix for Issue #4)
    # This allows GC to retry if needed during analysis phase
    memory_optimizer.reset_gc_tracking()

    # Analyze protocol distribution and jitter
    console.print("[cyan]Analyzing protocol distribution...[/cyan]")
    protocol_results = protocol_analyzer.analyze(scapy_packets)

    console.print("[cyan]Analyzing jitter (RFC 3393 IPDV)...[/cyan]")
    jitter_results = jitter_analyzer.analyze(scapy_packets)

    console.print("[cyan]Classifying traffic patterns (ML-like heuristics)...[/cyan]")
    service_results = service_classifier.analyze(scapy_packets)

    # Sprint 5-7: Security analysis
    console.print("[cyan]Detecting port scans...[/cyan]")
    port_scan_results = port_scan_detector.analyze(scapy_packets)

    console.print("[cyan]Detecting brute-force attacks...[/cyan]")
    brute_force_results = brute_force_detector.analyze(scapy_packets)

    console.print("[cyan]Detecting DDoS attacks...[/cyan]")
    ddos_results = ddos_detector.analyze(scapy_packets)

    console.print("[cyan]Detecting DNS tunneling...[/cyan]")
    dns_tunneling_results = dns_tunneling_detector.analyze(scapy_packets)

    console.print("[cyan]Detecting data exfiltration...[/cyan]")
    data_exfiltration_results = data_exfiltration_detector.analyze(scapy_packets)

    console.print("[cyan]Detecting C2 beaconing...[/cyan]")
    c2_beaconing_results = c2_beaconing_detector.analyze(scapy_packets)

    console.print("[cyan]Detecting lateral movement...[/cyan]")
    lateral_movement_results = lateral_movement_detector.analyze(scapy_packets)

    console.print(f"[green]✓ Phase 2 terminée: {complex_packet_count} paquets analysés[/green]")

    # Finalize all analyzers
    with Progress(
        SpinnerColumn(), TextColumn("[cyan]Finalisation..."), BarColumn(), TaskProgressColumn(), console=console
    ) as progress:
        task = progress.add_task("[cyan]Computing statistics...", total=len(analyzers))
        for idx, analyzer in enumerate(analyzers):
            if hasattr(analyzer, "finalize"):
                analyzer.finalize()
            progress.update(task, completed=idx + 1)

    # Collect results (growing list of dpkt-compatible analyzers)
    results["timestamps"] = timestamp_analyzer._generate_report()
    results["tcp_handshake"] = handshake_analyzer._generate_report()
    results["retransmission"] = retrans_analyzer._generate_report()
    results["rtt"] = rtt_analyzer._generate_report()
    results["tcp_window"] = window_analyzer._generate_report()
    results["tcp_reset"] = reset_analyzer._generate_report()
    results["top_talkers"] = toptalkers_analyzer._generate_report()
    results["throughput"] = throughput_analyzer._generate_report()
    results["syn_retransmissions"] = syn_retrans_analyzer._generate_report()
    results["tcp_timeout"] = tcp_timeout_analyzer.get_results()
    results["burst"] = burst_analyzer._generate_report()
    results["temporal"] = temporal_analyzer._generate_report()
    results["dns"] = dns_analyzer._generate_report()
    results["icmp"] = icmp_analyzer._generate_report()

    # Sprint 2 & 3: New analyzer results
    results["protocol_distribution"] = protocol_results
    results["jitter"] = jitter_results
    results["service_classification"] = service_results

    # Sprint 5-7: Security analyzer results
    results["port_scan_detection"] = port_scan_results
    results["brute_force_detection"] = brute_force_results
    results["ddos_detection"] = ddos_results
    results["dns_tunneling_detection"] = dns_tunneling_results

    # Sprint 11: Advanced Threat Detection results
    results["data_exfiltration_detection"] = data_exfiltration_results
    results["c2_beaconing_detection"] = c2_beaconing_results
    results["lateral_movement_detection"] = lateral_movement_results

    # Add empty results for unimplemented analyzers with proper structure
    for key in ["ip_fragmentation", "asymmetric_traffic", "sack"]:
        if key not in results:
            results[key] = get_empty_analyzer_result(key)

    # Sanitize all results to replace null values with sensible defaults
    results = sanitize_results(results)

    # Calculate Health Score (RFC-compliant overall assessment)
    console.print("\n[cyan]Calcul du Health Score...[/cyan]")
    health_calculator = HealthScoreCalculator()
    health_result = health_calculator.calculate(results)
    results["health_score"] = {
        "overall_score": health_result.overall_score,
        "qos_class": health_result.qos_class,
        "severity": health_result.severity,
        "severity_badge": health_result.severity_badge,
        "metric_scores": [
            {
                "metric_name": m.metric_name,
                "raw_value": m.raw_value,
                "penalty": m.penalty,
                "weight": m.weight,
                "weighted_penalty": m.weighted_penalty,
                "threshold_status": m.threshold_status,
                "rfc_reference": m.rfc_reference,
            }
            for m in health_result.metric_scores
        ],
        "total_penalty": health_result.total_penalty,
        "recommendations": health_result.recommendations,
    }

    # Display summaries
    console.print("\n")
    console.print(Panel.fit("📊 Résultats de l'analyse (Hybrid Mode)", style="bold blue"))

    # Display Health Score first (Executive Summary)
    console.print("\n")
    console.print(
        Panel.fit(
            f"🏥 Health Score: {health_result.overall_score:.1f}/100 {health_result.severity_badge}", style="bold cyan"
        )
    )
    console.print(f"[bold]Severity:[/bold] {health_result.severity.upper()}")
    console.print(f"[bold]QoS Class:[/bold] {health_result.qos_class} (ITU-T Y.1541)")

    if health_result.recommendations:
        console.print("\n[bold yellow]📋 Top Recommendations:[/bold yellow]")
        for i, rec in enumerate(health_result.recommendations[:3], 1):
            console.print(f"  {i}. {rec}")

    console.print("")  # Separator
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

    # Sprint 2: Display protocol distribution summary
    console.print("\n📊 Protocol Distribution:")
    if protocol_results["total_packets"] > 0:
        console.print(f"  Total Packets: {protocol_results['total_packets']}")
        for proto, count in protocol_results.get("layer4_distribution", {}).items():
            pct = protocol_results.get("layer4_percentages", {}).get(proto, 0)
            console.print(f"  - {proto}: {count} ({pct:.1f}%)")
        if protocol_results.get("top_tcp_ports"):
            top_ports = protocol_results["top_tcp_ports"][:3]
            ports_str = ", ".join(f"{p['port']} ({p['service']})" for p in top_ports)
            console.print(f"  Top TCP Ports: {ports_str}")

    # Sprint 2: Display jitter summary
    console.print("\n📡 Jitter Analysis (RFC 3393):")
    if jitter_results["total_flows"] > 0:
        console.print(f"  Total Flows Analyzed: {jitter_results['total_flows']}")
        if jitter_results.get("global_statistics"):
            stats = jitter_results["global_statistics"]
            console.print(f"  Mean Jitter: {stats.get('mean_jitter', 0)*1000:.2f}ms")
            console.print(f"  Max Jitter: {stats.get('max_jitter', 0)*1000:.2f}ms")
        if jitter_results.get("high_jitter_flows"):
            console.print(f"  [yellow]High Jitter Flows: {len(jitter_results['high_jitter_flows'])}[/yellow]")

    # Sprint 3: Display service classification summary
    console.print("\n🧠 Intelligent Service Classification:")
    if service_results["total_flows"] > 0:
        summary = service_results["classification_summary"]
        console.print(f"  Total Flows: {summary['total_flows']}")
        console.print(f"  Classified: {summary['classified_count']} ({summary['classification_rate']:.1f}%)")

        # Display service distribution
        if service_results.get("service_classifications"):
            console.print("  Service Distribution:")
            for service, count in sorted(
                service_results["service_classifications"].items(), key=lambda x: x[1], reverse=True
            ):
                console.print(f"    - {service}: {count} flows")

    # Sprint 5: Display security analysis summary
    console.print("\n🔒 Security Analysis:")

    # Port scan detection
    if port_scan_results.get("total_scans_detected", 0) > 0:
        console.print(f"  🔴 Port Scans Detected: {port_scan_results['total_scans_detected']}")
        severity = port_scan_results.get("severity_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
    else:
        console.print("  ✓ No port scans detected")

    # Brute-force detection
    if brute_force_results.get("total_attacks_detected", 0) > 0:
        console.print(f"  🔴 Brute-Force Attacks: {brute_force_results['total_attacks_detected']}")
        severity = brute_force_results.get("severity_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
    else:
        console.print("  ✓ No brute-force attacks detected")

    # DDoS detection
    if ddos_results.get("total_attacks_detected", 0) > 0:
        console.print(f"  🔴 DDoS Attacks: {ddos_results['total_attacks_detected']}")
        severity = ddos_results.get("severity_breakdown", {})
        attack_types = ddos_results.get("attack_type_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
        if attack_types:
            types_str = ", ".join([f"{count} {atype}" for atype, count in attack_types.items()])
            console.print(f"     Types: {types_str}")
    else:
        console.print("  ✓ No DDoS attacks detected")

    # DNS tunneling detection
    if dns_tunneling_results.get("total_tunneling_detected", 0) > 0:
        console.print(f"  🔴 DNS Tunneling: {dns_tunneling_results['total_tunneling_detected']}")
        severity = dns_tunneling_results.get("severity_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
    else:
        console.print("  ✓ No DNS tunneling detected")

    # Data exfiltration detection
    if data_exfiltration_results.get("total_exfiltration_detected", 0) > 0:
        console.print(f"  🔴 Data Exfiltration: {data_exfiltration_results['total_exfiltration_detected']}")
        severity = data_exfiltration_results.get("severity_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
    else:
        console.print("  ✓ No data exfiltration detected")

    # C2 beaconing detection
    if c2_beaconing_results.get("total_beaconing_detected", 0) > 0:
        console.print(f"  🔴 C2 Beaconing: {c2_beaconing_results['total_beaconing_detected']}")
        severity = c2_beaconing_results.get("severity_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
    else:
        console.print("  ✓ No C2 beaconing detected")

    # Lateral movement detection
    if lateral_movement_results.get("total_lateral_movement_detected", 0) > 0:
        console.print(f"  🔴 Lateral Movement: {lateral_movement_results['total_lateral_movement_detected']}")
        severity = lateral_movement_results.get("severity_breakdown", {})
        if severity:
            console.print(
                f"     Critical: {severity.get('critical', 0)}, "
                f"High: {severity.get('high', 0)}, "
                f"Medium: {severity.get('medium', 0)}, "
                f"Low: {severity.get('low', 0)}"
            )
    else:
        console.print("  ✓ No lateral movement detected")

    # Sprint 10: Display final memory report
    console.print("\n[cyan]📊 Memory Report:[/cyan]")
    mem_report = memory_optimizer.get_memory_report()
    console.print(f"  Current usage: {mem_report['current_mb']:.2f} MB")
    console.print(f"  Peak usage: {mem_report['peak_mb']:.2f} MB")
    console.print(f"  GC triggered: {mem_report['gc_triggered_count']} times")
    console.print(f"  Recommendation: {mem_report['recommendation']}")

    # Cleanup temporary PCAP file if it was created for PCAP-NG conversion
    if temp_pcap_path is not None and os.path.exists(temp_pcap_path):
        try:
            os.unlink(temp_pcap_path)
            console.print(f"[cyan]✓ Fichier temporaire supprimé: {temp_pcap_path}[/cyan]")
        except Exception as e:
            console.print(f"[yellow]⚠ Erreur lors de la suppression du fichier temporaire: {e}[/yellow]")

    return results


@click.group()
def cli():
    """Analyseur automatisé des causes de latence réseau"""
    pass


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("-l", "--latency", type=float, help="Seuil de latence en secondes pour le filtrage")
@click.option("-c", "--config", type=click.Path(exists=True), help="Fichier de configuration personnalisé")
@click.option("-o", "--output", help="Nom de base pour les rapports de sortie")
@click.option("--no-report", is_flag=True, help="Ne pas générer de rapports HTML/JSON")
@click.option("--no-details", is_flag=True, help="Ne pas afficher les détails des retransmissions")
@click.option("--details-limit", type=int, default=20, help="Nombre max de retransmissions à afficher (défaut: 20)")
@click.option("--export-html", type=click.Path(), help="Export HTML report to specific file")
@click.option("--export-csv", type=click.Path(), help="Export CSV files to directory")
@click.option("--export-dir", type=click.Path(), help="Export all formats (HTML + CSV) to directory")
@click.option(
    "--include-localhost", is_flag=True, help="Include localhost traffic in security analysis (default: excluded)"
)
@click.option("--no-streaming", is_flag=True, help="Disable automatic streaming mode for large files (Sprint 10)")
@click.option(
    "--parallel",
    is_flag=True,
    help="Enable parallel analyzer execution using multiple CPU cores (Sprint 10 - experimental)",
)
@click.option("--memory-limit", type=float, help="Set memory limit in MB (default: 80% of available memory)")
def analyze(
    pcap_file,
    latency,
    config,
    output,
    no_report,
    no_details,
    details_limit,
    export_html,
    export_csv,
    export_dir,
    include_localhost,
    no_streaming,
    parallel,
    memory_limit,
):
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
        sensitive_dirs = ["/etc", "/root", "/sys", "/proc", "/dev"]
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
    # Sprint 10: Add performance optimizations
    results = analyze_pcap_hybrid(
        pcap_file,
        cfg,
        latency_filter=latency,
        show_details=show_details,
        details_limit=details_limit,
        include_localhost=include_localhost,
        enable_streaming=not no_streaming,
        enable_parallel=parallel,
        memory_limit_mb=memory_limit,
    )

    # Génération des rapports
    if not no_report:
        _generate_reports(results, pcap_file, output, cfg)

    # Sprint 4: Export formats
    _handle_exports(results, pcap_file, export_html, export_csv, export_dir)


@cli.command()
@click.option("-d", "--duration", type=int, default=60, help="Durée de capture en secondes (défaut: 60)")
@click.option("-f", "--filter", help="Filtre BPF personnalisé (remplace celui de la config)")
@click.option("-o", "--output", help="Nom du fichier PCAP local de sortie")
@click.option("-c", "--config", type=click.Path(exists=True), help="Fichier de configuration personnalisé")
@click.option("--analyze/--no-analyze", default=True, help="Analyser automatiquement après capture")
@click.option("-l", "--latency", type=float, help="Seuil de latence pour l'analyse")
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
        if ".." in output:
            raise click.BadParameter("Chemin non autorisé: '..' n'est pas permis dans le chemin de sortie")

        # Prevent writing to sensitive system directories
        sensitive_dirs = ["/etc", "/root", "/sys", "/proc", "/dev", "/usr", "/bin", "/sbin", "/boot"]
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
            config=cfg.config, local_path=output, duration=duration, filter_override=filter
        )

        console.print(f"\n[green]✓ Capture terminée: {local_pcap}[/green]")

        # Analyse automatique si demandé
        if analyze:
            console.print("\n[cyan]Lancement de l'analyse automatique...[/cyan]")
            results = analyze_pcap_hybrid(
                local_pcap, cfg, latency_filter=latency, show_details=True, include_localhost=False
            )

            # Génération des rapports
            _generate_reports(results, local_pcap, None, cfg)

    except Exception as e:
        console.print(f"[red]❌ Erreur lors de la capture: {e}[/red]")
        sys.exit(1)


@cli.command()
@click.option("-c", "--config", type=click.Path(exists=True), help="Fichier de configuration à afficher")
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
    table.add_row("  host", ssh_config.get("host", "N/A"))
    table.add_row("  username", ssh_config.get("username", "N/A"))
    table.add_row("  port", str(ssh_config.get("port", 22)))

    # Reports
    table.add_section()
    table.add_row("[bold]RAPPORTS[/bold]", "")
    report_config = cfg.report_config
    table.add_row("  output_dir", report_config.get("output_dir", "N/A"))
    table.add_row("  formats", ", ".join(report_config.get("formats", [])))

    console.print(table)


@cli.command()
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("-o", "--output", type=click.Path(), help="Save benchmark report to file")
def benchmark(pcap_file, output):
    """
    Benchmark PCAP analyzer performance (Sprint 10)

    Measures performance with different optimization modes:
    - Memory vs Streaming mode comparison
    - Throughput calculation (packets/second)
    - Memory usage profiling
    - Consistency testing with multiple iterations

    Example:
        pcap_analyzer benchmark capture.pcap
        pcap_analyzer benchmark large_file.pcap -o benchmark_report.txt
    """
    from .performance.benchmark import run_benchmark

    console.print("\n[cyan]🏃 Running Performance Benchmark...[/cyan]")
    console.print(f"[cyan]File: {pcap_file}[/cyan]\n")

    try:
        # Run benchmark
        report = run_benchmark(pcap_file)

        # Display report
        console.print("\n" + report)

        # Save to file if requested
        if output:
            output_path = Path(output)
            output_path.write_text(report)
            console.print(f"\n[green]✓ Benchmark report saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]❌ Benchmark failed: {e}[/red]")
        import traceback

        traceback.print_exc()
        sys.exit(1)


def main():
    """Point d'entrée principal"""
    cli()


if __name__ == "__main__":
    main()
