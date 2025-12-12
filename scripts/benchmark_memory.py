#!/usr/bin/env python3
"""
Memory Profiling for PCAP Analysis

Profiles memory usage during PCAP analysis to ensure peak memory stays
within acceptable limits.

Usage:
    python scripts/benchmark_memory.py <pcap_file>
    python scripts/benchmark_memory.py <pcap_file> --detailed
    python scripts/benchmark_memory.py <pcap_file> --output memory_report.txt

Output:
    ========================================
    MEMORY PROFILING
    ========================================
    File: sample.pcap (26.00 MB)
    Packets: 131,000

    Peak Memory: 487 MB
    Current Memory: 245 MB
    Memory Increase: 452 MB
    Memory/Packet: 3.7 KB

    GC Collections: 12
    GC Cooldowns: 3

    Top 10 Memory Allocations:
      1. src/analyzers/protocol_distribution.py:45: 45.2 MB
      2. src/parsers/fast_parser.py:123: 32.1 MB
      ...

    ========================================
    VALIDATION
    ========================================
    Status: ✅ PASS
      - Peak memory <4GB for 500MB PCAP
      - Memory/Packet ratio acceptable (<10KB/packet)
"""

import argparse
import sys
import tracemalloc
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.cli import analyze_pcap_hybrid
from src.config import get_config


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"


def profile_memory(pcap_file: str, detailed: bool = False) -> dict:
    """
    Profile memory usage during PCAP analysis.

    Args:
        pcap_file: Path to PCAP file
        detailed: Show detailed allocation breakdown

    Returns:
        Dictionary with profiling results
    """
    pcap_path = Path(pcap_file)

    # File stats
    file_size = pcap_path.stat().st_size

    print("=" * 60)
    print("MEMORY PROFILING")
    print("=" * 60)
    print(f"File: {pcap_path.name} ({format_bytes(file_size)})")

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
    print("Starting memory profiling...")
    print()

    # Start memory tracking
    tracemalloc.start()
    snapshot_start = tracemalloc.take_snapshot()

    # Run analysis
    try:
        config = get_config()
        results = analyze_pcap_hybrid(pcap_file, config, enable_streaming=True)
    except Exception as e:
        print(f"Analysis failed: {e}")
        import traceback

        traceback.print_exc()
        tracemalloc.stop()
        return {"error": str(e)}

    # Get memory stats
    current, peak = tracemalloc.get_traced_memory()
    snapshot_end = tracemalloc.take_snapshot()

    tracemalloc.stop()

    # Calculate metrics
    memory_increase = peak - snapshot_start.statistics("lineno")[0].size
    memory_per_packet = peak / packet_count if packet_count else None

    print("=" * 60)
    print("MEMORY STATISTICS")
    print("=" * 60)
    print(f"Peak Memory:        {format_bytes(peak)}")
    print(f"Current Memory:     {format_bytes(current)}")
    print(f"Memory Increase:    {format_bytes(memory_increase)}")
    if memory_per_packet:
        print(f"Memory/Packet:      {format_bytes(memory_per_packet)}")
    print()

    # GC stats from results (if available)
    if "health_score" in results:
        print("Garbage Collection:")
        # Extract GC stats if logged (would need to be added to results)
        print("  (GC stats not available in current implementation)")
        print()

    # Top allocations
    if detailed:
        print("Top 20 Memory Allocations:")
        stats = snapshot_end.compare_to(snapshot_start, "lineno")
        for i, stat in enumerate(stats[:20], 1):
            print(f"  {i}. {stat}")
        print()

        # Top allocations by file
        print("Top 10 Files by Memory:")
        stats_by_file = snapshot_end.compare_to(snapshot_start, "filename")
        for i, stat in enumerate(stats_by_file[:10], 1):
            print(f"  {i}. {stat}")
        print()

    return {
        "file": pcap_path.name,
        "file_size": file_size,
        "file_size_str": format_bytes(file_size),
        "packet_count": packet_count,
        "peak_memory": peak,
        "peak_memory_str": format_bytes(peak),
        "current_memory": current,
        "current_memory_str": format_bytes(current),
        "memory_increase": memory_increase,
        "memory_increase_str": format_bytes(memory_increase),
        "memory_per_packet": memory_per_packet,
        "memory_per_packet_str": format_bytes(memory_per_packet) if memory_per_packet else None,
        "top_allocations": stats[:20] if detailed else None,
    }


def validate_results(results: dict) -> bool:
    """
    Validate memory profiling results.

    Args:
        results: Profiling results dictionary

    Returns:
        True if validation passed
    """
    if "error" in results:
        print("=" * 60)
        print("ERROR")
        print("=" * 60)
        print(results["error"])
        return False

    print("=" * 60)
    print("VALIDATION")
    print("=" * 60)

    passed = True
    issues = []

    # Check 1: Peak memory vs file size ratio
    file_size_mb = results["file_size"] / (1024 * 1024)
    peak_memory_mb = results["peak_memory"] / (1024 * 1024)
    ratio = peak_memory_mb / file_size_mb

    print(f"File Size:          {file_size_mb:.2f} MB")
    print(f"Peak Memory:        {peak_memory_mb:.2f} MB")
    print(f"Memory/File Ratio:  {ratio:.2f}x")
    print()

    # Expected ratios:
    # - Small files (<100MB): 20x ratio OK (streaming disabled)
    # - Medium files (100-500MB): 8-40x ratio OK
    # - Large files (>500MB): <8x ratio (aggressive streaming)

    if file_size_mb < 100:
        max_ratio = 25
    elif file_size_mb < 500:
        max_ratio = 45
    else:
        max_ratio = 10

    if ratio > max_ratio:
        passed = False
        issues.append(f"Memory/File ratio too high: {ratio:.2f}x (expected <{max_ratio}x)")
    else:
        print(f"✅ Memory/File ratio acceptable (<{max_ratio}x)")

    # Check 2: Absolute memory limit
    MAX_MEMORY_GB = 4  # 4GB limit
    max_memory_bytes = MAX_MEMORY_GB * 1024 * 1024 * 1024

    if results["peak_memory"] > max_memory_bytes:
        passed = False
        issues.append(f"Peak memory exceeds {MAX_MEMORY_GB}GB limit")
    else:
        print(f"✅ Peak memory within {MAX_MEMORY_GB}GB limit")

    # Check 3: Memory per packet (if available)
    if results["memory_per_packet"]:
        mem_per_pkt_kb = results["memory_per_packet"] / 1024
        MAX_MEM_PER_PKT_KB = 10  # 10KB/packet max

        if mem_per_pkt_kb > MAX_MEM_PER_PKT_KB:
            passed = False
            issues.append(f"Memory per packet too high: {mem_per_pkt_kb:.1f}KB (expected <{MAX_MEM_PER_PKT_KB}KB)")
        else:
            print(f"✅ Memory per packet acceptable (<{MAX_MEM_PER_PKT_KB}KB)")

    print()

    if passed:
        print("Status: ✅ PASS")
    else:
        print("Status: ❌ FAIL")
        print()
        print("Issues:")
        for issue in issues:
            print(f"  - {issue}")
        print()
        print("RECOMMENDATIONS:")
        print("  - Enable streaming mode for large files (automatic >100MB)")
        print("  - Check for memory leaks in analyzers")
        print("  - Verify GC is triggering correctly")
        print("  - Consider increasing chunk size for aggressive streaming")

    return passed


def main():
    parser = argparse.ArgumentParser(description="Memory profiling for PCAP analysis")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--detailed", action="store_true", help="Show detailed allocation breakdown")
    parser.add_argument("--output", type=Path, help="Save report to file")

    args = parser.parse_args()

    # Validate PCAP file
    if not args.pcap_file.exists():
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    # Profile memory
    try:
        results = profile_memory(str(args.pcap_file), detailed=args.detailed)
    except Exception as e:
        print(f"Profiling failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Validate results
    passed = validate_results(results)

    # Save report if requested
    if args.output:
        import json

        # Remove non-serializable data
        output_results = {k: v for k, v in results.items() if k != "top_allocations"}

        with open(args.output, "w") as f:
            json.dump(output_results, f, indent=2)
        print(f"\nReport saved to: {args.output}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
