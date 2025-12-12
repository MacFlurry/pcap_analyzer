#!/usr/bin/env python3
"""
Benchmark CLI vs Web Overhead

Compares performance between CLI mode (baseline) and Web mode to ensure
overhead stays below 10%.

Usage:
    python scripts/benchmark_cli_vs_web.py <pcap_file>
    python scripts/benchmark_cli_vs_web.py <pcap_file> --web-url http://localhost:8000

Output:
    ========================================
    BENCHMARK: CLI vs Web Overhead
    ========================================
    PCAP: sample.pcap
    Size: 26.00 MB
    Packets: 131,000

    === CLI Benchmark (3 iterations) ===
    Run 1: 54.23s
    Run 2: 55.67s
    Run 3: 54.89s
    Average: 54.93s

    === Web Benchmark (3 iterations) ===
    Run 1: 57.12s
    Run 2: 58.34s
    Run 3: 57.89s
    Average: 57.78s

    ========================================
    RESULTS
    ========================================
    CLI Time:    54.93s
    Web Time:    57.78s
    Overhead:    2.85s (5.2%)

    Status: ✅ PASS (<10% overhead)
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import List

import requests


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


def benchmark_cli(pcap_file: str) -> float:
    """
    Benchmark CLI mode.

    Args:
        pcap_file: Path to PCAP file

    Returns:
        Execution time in seconds
    """
    start = time.perf_counter()

    result = subprocess.run(
        ["python", "-m", "src.cli", "analyze", pcap_file, "--no-report"],
        check=True,
        capture_output=True,
        text=True,
    )

    duration = time.perf_counter() - start

    # Check for errors
    if result.returncode != 0:
        raise Exception(f"CLI failed: {result.stderr}")

    return duration


def benchmark_web(pcap_file: str, api_url: str = "http://localhost:8000") -> float:
    """
    Benchmark Web mode (upload + analysis).

    Args:
        pcap_file: Path to PCAP file
        api_url: Base URL of API

    Returns:
        Total execution time in seconds (upload + analysis)
    """
    start = time.perf_counter()

    # Upload PCAP
    with open(pcap_file, "rb") as f:
        response = requests.post(f"{api_url}/upload", files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")})

    if response.status_code != 200:
        raise Exception(f"Upload failed: {response.status_code} - {response.text}")

    task_id = response.json()["task_id"]

    # Poll status until completion (max 10 minutes)
    timeout = 600  # 10 minutes
    poll_start = time.time()

    while time.time() - poll_start < timeout:
        status_resp = requests.get(f"{api_url}/status/{task_id}")

        if status_resp.status_code != 200:
            raise Exception(f"Status check failed: {status_resp.status_code}")

        status_data = status_resp.json()
        status = status_data["status"]

        if status == "completed":
            # Success - get report to verify
            report_resp = requests.get(f"{api_url}/report/{task_id}")
            if report_resp.status_code != 200:
                raise Exception(f"Report retrieval failed: {report_resp.status_code}")
            break
        elif status == "failed":
            error = status_data.get("error", "Unknown error")
            raise Exception(f"Analysis failed: {error}")
        elif status in ["pending", "processing"]:
            # Still running - wait and retry
            time.sleep(2)
        else:
            raise Exception(f"Unknown status: {status}")
    else:
        raise Exception(f"Analysis timeout (>{timeout}s)")

    return time.perf_counter() - start


def run_benchmarks(pcap_file: str, iterations: int = 3, web_url: str = "http://localhost:8000") -> dict:
    """
    Run CLI and Web benchmarks.

    Args:
        pcap_file: Path to PCAP file
        iterations: Number of iterations per test
        web_url: Base URL of Web API

    Returns:
        Dictionary with benchmark results
    """
    pcap_path = Path(pcap_file)

    # File stats
    file_size_mb = pcap_path.stat().st_size / (1024 * 1024)

    # Get packet count (quick estimate using scapy)
    try:
        from scapy.all import PcapReader

        packet_count = 0
        with PcapReader(str(pcap_path)) as reader:
            for _ in reader:
                packet_count += 1
    except Exception:
        packet_count = None

    print("=" * 60)
    print("BENCHMARK: CLI vs Web Overhead")
    print("=" * 60)
    print(f"PCAP: {pcap_path.name}")
    print(f"Size: {file_size_mb:.2f} MB")
    if packet_count:
        print(f"Packets: {packet_count:,}")
    print()

    # CLI Benchmark
    print(f"=== CLI Benchmark ({iterations} iterations) ===")
    cli_times = []
    for i in range(iterations):
        try:
            duration = benchmark_cli(str(pcap_path))
            cli_times.append(duration)
            print(f"Run {i+1}: {format_duration(duration)}")
        except Exception as e:
            print(f"Run {i+1}: FAILED - {e}")
            return {"error": f"CLI benchmark failed: {e}"}

    cli_avg = sum(cli_times) / len(cli_times)
    print(f"Average: {format_duration(cli_avg)}")
    print()

    # Web Benchmark
    print(f"=== Web Benchmark ({iterations} iterations) ===")
    web_times = []
    for i in range(iterations):
        try:
            duration = benchmark_web(str(pcap_path), web_url)
            web_times.append(duration)
            print(f"Run {i+1}: {format_duration(duration)}")
        except Exception as e:
            print(f"Run {i+1}: FAILED - {e}")
            return {"error": f"Web benchmark failed: {e}"}

    web_avg = sum(web_times) / len(web_times)
    print(f"Average: {format_duration(web_avg)}")
    print()

    # Calculate overhead
    overhead = web_avg - cli_avg
    overhead_pct = (overhead / cli_avg) * 100

    # Throughput
    cli_throughput = packet_count / cli_avg if packet_count else None
    web_throughput = packet_count / web_avg if packet_count else None

    return {
        "file": pcap_path.name,
        "file_size_mb": file_size_mb,
        "packet_count": packet_count,
        "cli_times": cli_times,
        "cli_avg": cli_avg,
        "web_times": web_times,
        "web_avg": web_avg,
        "overhead": overhead,
        "overhead_pct": overhead_pct,
        "cli_throughput": cli_throughput,
        "web_throughput": web_throughput,
    }


def print_results(results: dict) -> bool:
    """
    Print benchmark results.

    Args:
        results: Benchmark results dictionary

    Returns:
        True if test passed, False otherwise
    """
    if "error" in results:
        print("=" * 60)
        print("ERROR")
        print("=" * 60)
        print(results["error"])
        return False

    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"CLI Time:    {format_duration(results['cli_avg'])}")
    print(f"Web Time:    {format_duration(results['web_avg'])}")
    print(f"Overhead:    {format_duration(results['overhead'])} ({results['overhead_pct']:.1f}%)")
    print()

    if results["cli_throughput"]:
        print(f"CLI Throughput: {results['cli_throughput']:,.0f} packets/sec")
        print(f"Web Throughput: {results['web_throughput']:,.0f} packets/sec")
        print()

    # Validation
    OVERHEAD_THRESHOLD = 10.0  # 10%
    passed = results["overhead_pct"] < OVERHEAD_THRESHOLD

    if passed:
        print(f"✅ PASS: Overhead <{OVERHEAD_THRESHOLD}%")
    else:
        print(f"❌ FAIL: Overhead >={OVERHEAD_THRESHOLD}%")
        print()
        print("RECOMMENDATIONS:")
        print("  - Check Docker resource limits (CPU/Memory)")
        print("  - Verify no other processes consuming resources")
        print("  - Profile web endpoint for bottlenecks")
        print("  - Check network latency (if API not local)")

    return passed


def main():
    parser = argparse.ArgumentParser(description="Benchmark CLI vs Web overhead")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--iterations", type=int, default=3, help="Number of iterations per test (default: 3)")
    parser.add_argument(
        "--web-url", type=str, default="http://localhost:8000", help="Web API base URL (default: http://localhost:8000)"
    )
    parser.add_argument("--output", type=Path, help="Save results to JSON file")

    args = parser.parse_args()

    # Validate PCAP file
    if not args.pcap_file.exists():
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    # Run benchmarks
    try:
        results = run_benchmarks(str(args.pcap_file), iterations=args.iterations, web_url=args.web_url)
    except Exception as e:
        print(f"Benchmark failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Print results
    passed = print_results(results)

    # Save to file if requested
    if args.output:
        import json

        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
