#!/usr/bin/env python3
"""
CPU Profiling for PCAP Analysis

Profiles CPU usage during PCAP analysis to identify bottlenecks and
optimization opportunities.

Usage:
    python scripts/profile_analysis.py <pcap_file>
    python scripts/profile_analysis.py <pcap_file> --top 30
    python scripts/profile_analysis.py <pcap_file> --output profile.prof
    python scripts/profile_analysis.py <pcap_file> --flamegraph

Requirements:
    pip install snakeviz  # For visualization

Visualization:
    snakeviz profile.prof  # Opens in browser

Output:
    ========================================
    CPU PROFILING
    ========================================
    File: sample.pcap (26.00 MB)
    Packets: 131,000

    Total Time: 55.23s
    Total Calls: 1,234,567

    Top 20 Functions (Cumulative Time):
    ------------------------------------------------
      ncalls  tottime  percall  cumtime  percall filename:lineno(function)
      131000    2.345    0.000   15.234    0.000 fast_parser.py:45(parse_packet)
       50000    1.234    0.000   10.123    0.000 protocol_analyzer.py:78(analyze)
      ...

    Bottlenecks Detected:
      ⚠️  fast_parser.py:45 - 27.6% of total time
      ⚠️  protocol_analyzer.py:78 - 18.3% of total time
"""

import argparse
import cProfile
import io
import pstats
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.cli import analyze_pcap_hybrid
from src.config import get_config


def format_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"


def profile_pcap(pcap_file: str, top_n: int = 20) -> dict:
    """
    Profile PCAP analysis with cProfile.

    Args:
        pcap_file: Path to PCAP file
        top_n: Number of top functions to display

    Returns:
        Dictionary with profiling results
    """
    pcap_path = Path(pcap_file)

    print("=" * 60)
    print("CPU PROFILING")
    print("=" * 60)
    print(f"File: {pcap_path.name}")

    # Get packet count
    try:
        from scapy.all import PcapReader

        packet_count = 0
        print("Counting packets...")
        with PcapReader(str(pcap_path)) as reader:
            for _ in reader:
                packet_count += 1
        print(f"Packets: {packet_count:,}")
    except Exception as e:
        print(f"Could not count packets: {e}")
        packet_count = None

    print()
    print("Starting CPU profiling...")
    print()

    # Profile analysis
    profiler = cProfile.Profile()
    profiler.enable()

    try:
        config = get_config()
        results = analyze_pcap_hybrid(pcap_file, config)
    except Exception as e:
        print(f"Analysis failed: {e}")
        import traceback

        traceback.print_exc()
        profiler.disable()
        return {"error": str(e)}

    profiler.disable()

    # Extract stats
    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream)

    # Sort by cumulative time (most impactful)
    stats.sort_stats("cumulative")

    # Get total stats
    total_time = sum(stat[2] for stat in stats.stats.values())  # tottime
    total_calls = sum(stat[0] for stat in stats.stats.values())  # ncalls

    print("=" * 60)
    print("PROFILING STATISTICS")
    print("=" * 60)
    print(f"Total Time:     {format_duration(total_time)}")
    print(f"Total Calls:    {total_calls:,}")
    if packet_count:
        print(f"Time/Packet:    {(total_time / packet_count) * 1000:.2f}ms")
    print()

    # Print top functions
    print(f"Top {top_n} Functions (Cumulative Time):")
    print("-" * 120)
    stats.print_stats(top_n)

    # Analyze bottlenecks
    print()
    print("=" * 60)
    print("BOTTLENECK ANALYSIS")
    print("=" * 60)

    bottlenecks = []
    for func_key, (cc, nc, tt, ct, callers) in list(stats.stats.items())[:top_n]:
        filename, line, func_name = func_key
        pct = (ct / total_time * 100) if total_time > 0 else 0

        # Flag if >15% of total time
        if pct > 15:
            bottlenecks.append(
                {
                    "function": f"{Path(filename).name}:{line}({func_name})",
                    "cumtime": ct,
                    "percentage": pct,
                    "calls": nc,
                }
            )

    if bottlenecks:
        print("⚠️  Bottlenecks detected (>15% of total time):")
        print()
        for bottleneck in bottlenecks:
            print(f"  - {bottleneck['function']}")
            print(f"    Time: {format_duration(bottleneck['cumtime'])} ({bottleneck['percentage']:.1f}%)")
            print(f"    Calls: {bottleneck['calls']:,}")
            print()

        print("RECOMMENDATIONS:")
        print("  - Consider optimizing functions with high cumtime")
        print("  - Check if functions are called too frequently (ncalls)")
        print("  - Profile with py-spy for production profiling")
        print("  - Use snakeviz for interactive visualization")
    else:
        print("✅ No major bottlenecks detected (<15% per function)")

    print()

    return {
        "file": pcap_path.name,
        "packet_count": packet_count,
        "total_time": total_time,
        "total_calls": total_calls,
        "bottlenecks": bottlenecks,
        "stats": stats,
    }


def main():
    parser = argparse.ArgumentParser(description="CPU profiling for PCAP analysis")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--top", type=int, default=20, help="Number of top functions to show (default: 20)")
    parser.add_argument("--output", type=Path, help="Save profiling data to file (.prof)")
    parser.add_argument("--flamegraph", action="store_true", help="Generate flamegraph (requires py-spy)")

    args = parser.parse_args()

    # Validate PCAP file
    if not args.pcap_file.exists():
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    # Profile
    try:
        results = profile_pcap(str(args.pcap_file), top_n=args.top)
    except Exception as e:
        print(f"Profiling failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Check for errors
    if "error" in results:
        sys.exit(1)

    # Save profiling data
    if args.output:
        results["stats"].dump_stats(str(args.output))
        print(f"Profiling data saved to: {args.output}")
        print()
        print("Visualize with: snakeviz", args.output)
        print()

    # Generate flamegraph (if py-spy available)
    if args.flamegraph:
        try:
            import subprocess

            print("Generating flamegraph with py-spy...")
            output_svg = args.pcap_file.stem + "_flamegraph.svg"

            subprocess.run(
                [
                    "py-spy",
                    "record",
                    "--output",
                    output_svg,
                    "--",
                    "python",
                    "-m",
                    "src.cli",
                    "analyze",
                    str(args.pcap_file),
                    "--no-report",
                ],
                check=True,
            )

            print(f"Flamegraph saved to: {output_svg}")
            print()
        except FileNotFoundError:
            print("Error: py-spy not found. Install with: pip install py-spy")
        except Exception as e:
            print(f"Flamegraph generation failed: {e}")

    sys.exit(0)


if __name__ == "__main__":
    main()
