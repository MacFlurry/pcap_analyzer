#!/usr/bin/env python3
"""
Memory Profiling Script for v4.15.0 Packet Timeline Feature

Profiles memory usage with different PCAP sizes and flow counts:
- Baseline (no timeline feature)
- v4.15.0 with 0 problematic flows
- v4.15.0 with 50 problematic flows
- v4.15.0 with 100 problematic flows

Target: <10% memory overhead
"""

import gc
import os
import sys
import time
import tracemalloc
from collections import deque
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class MemoryProfiler:
    """Memory profiler for packet timeline feature."""

    def __init__(self):
        self.results = {}

    def profile_baseline(self, num_packets=10000):
        """Profile baseline memory (no timeline feature)."""
        print(f"\n=== Baseline Memory Profile ({num_packets:,} packets) ===")

        gc.collect()
        tracemalloc.start()

        # Simulate packet processing WITHOUT timeline
        packets_processed = 0
        flow_data = {}

        for i in range(num_packets):
            # Basic flow tracking (no timeline)
            flow_key = f"192.168.1.{i % 100}:1234 → 192.168.1.{(i % 100) + 1}:80"

            if flow_key not in flow_data:
                flow_data[flow_key] = {
                    "packet_count": 0,
                    "retransmissions": []
                }

            flow_data[flow_key]["packet_count"] += 1
            packets_processed += 1

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"Packets processed: {packets_processed:,}")
        print(f"Flows tracked: {len(flow_data):,}")
        print(f"Current memory: {current / 1024 / 1024:.2f} MB")
        print(f"Peak memory: {peak / 1024 / 1024:.2f} MB")

        self.results["baseline"] = {
            "packets": packets_processed,
            "flows": len(flow_data),
            "current_mb": current / 1024 / 1024,
            "peak_mb": peak / 1024 / 1024
        }

        return peak

    def profile_timeline_no_flows(self, num_packets=10000):
        """Profile with timeline feature but 0 problematic flows."""
        print(f"\n=== Timeline Feature - 0 Problematic Flows ({num_packets:,} packets) ===")

        gc.collect()
        tracemalloc.start()

        # Timeline buffers (but none created)
        timeline_buffers = {}
        packets_processed = 0
        flow_data = {}

        for i in range(num_packets):
            flow_key = f"192.168.1.{i % 100}:1234 → 192.168.1.{(i % 100) + 1}:80"

            if flow_key not in flow_data:
                flow_data[flow_key] = {
                    "packet_count": 0,
                    "retransmissions": []
                }

            flow_data[flow_key]["packet_count"] += 1
            packets_processed += 1

            # No timeline buffers created (no problematic flows)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"Packets processed: {packets_processed:,}")
        print(f"Flows tracked: {len(flow_data):,}")
        print(f"Timeline buffers: {len(timeline_buffers):,}")
        print(f"Current memory: {current / 1024 / 1024:.2f} MB")
        print(f"Peak memory: {peak / 1024 / 1024:.2f} MB")

        self.results["timeline_0_flows"] = {
            "packets": packets_processed,
            "flows": len(flow_data),
            "timeline_buffers": len(timeline_buffers),
            "current_mb": current / 1024 / 1024,
            "peak_mb": peak / 1024 / 1024
        }

        return peak

    def profile_timeline_with_flows(self, num_packets=10000, num_problematic_flows=50):
        """Profile with timeline feature and N problematic flows."""
        print(f"\n=== Timeline Feature - {num_problematic_flows} Problematic Flows ({num_packets:,} packets) ===")

        gc.collect()
        tracemalloc.start()

        # Timeline buffers for problematic flows
        timeline_buffers = {}
        packets_processed = 0
        flow_data = {}

        for i in range(num_packets):
            flow_key = f"192.168.1.{i % 100}:1234 → 192.168.1.{(i % 100) + 1}:80"

            if flow_key not in flow_data:
                flow_data[flow_key] = {
                    "packet_count": 0,
                    "retransmissions": []
                }

            flow_data[flow_key]["packet_count"] += 1

            # Simulate problematic flows (first N flows)
            if (i % 100) < num_problematic_flows:
                # Create timeline buffer if needed
                if flow_key not in timeline_buffers:
                    timeline_buffers[flow_key] = deque(maxlen=10)

                # Add packet to timeline
                timeline_buffers[flow_key].append({
                    "seq": 1000 + i,
                    "ack": 2000 + i,
                    "flags": "A",
                    "len": 1500,
                    "time": float(i) * 0.001
                })

            packets_processed += 1

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"Packets processed: {packets_processed:,}")
        print(f"Flows tracked: {len(flow_data):,}")
        print(f"Timeline buffers: {len(timeline_buffers):,}")
        print(f"Current memory: {current / 1024 / 1024:.2f} MB")
        print(f"Peak memory: {peak / 1024 / 1024:.2f} MB")

        # Calculate per-flow memory
        if len(timeline_buffers) > 0:
            per_flow_kb = (current / 1024) / len(timeline_buffers)
            print(f"Memory per timeline buffer: {per_flow_kb:.2f} KB")

        self.results[f"timeline_{num_problematic_flows}_flows"] = {
            "packets": packets_processed,
            "flows": len(flow_data),
            "timeline_buffers": len(timeline_buffers),
            "current_mb": current / 1024 / 1024,
            "peak_mb": peak / 1024 / 1024
        }

        return peak

    def compare_results(self):
        """Compare memory usage across scenarios."""
        print("\n" + "=" * 80)
        print("MEMORY USAGE COMPARISON")
        print("=" * 80)

        baseline_peak = self.results["baseline"]["peak_mb"]

        print(f"\n{'Scenario':<40} {'Peak MB':>12} {'Overhead':>12}")
        print("-" * 80)

        for scenario, data in self.results.items():
            peak_mb = data["peak_mb"]
            overhead_pct = ((peak_mb - baseline_peak) / baseline_peak) * 100

            print(f"{scenario:<40} {peak_mb:>12.2f} {overhead_pct:>11.1f}%")

        # Check if <10% overhead target met
        print("\n" + "=" * 80)
        print("TARGET VERIFICATION")
        print("=" * 80)

        for scenario, data in self.results.items():
            if scenario == "baseline":
                continue

            peak_mb = data["peak_mb"]
            overhead_pct = ((peak_mb - baseline_peak) / baseline_peak) * 100

            status = "✅ PASS" if overhead_pct < 10.0 else "❌ FAIL"
            print(f"{scenario}: {overhead_pct:.1f}% overhead - {status}")

    def profile_large_scale(self):
        """Profile large-scale scenarios."""
        print("\n" + "=" * 80)
        print("LARGE-SCALE MEMORY PROFILING")
        print("=" * 80)

        # Test with 1M packets
        print(f"\n=== 1M Packets, 100 Problematic Flows ===")

        gc.collect()
        tracemalloc.start()

        timeline_buffers = {}

        for i in range(1000000):
            flow_key = f"192.168.1.{i % 1000}:1234 → 192.168.1.{(i % 1000) + 1}:80"

            # First 100 flows are problematic
            if (i % 1000) < 100:
                if flow_key not in timeline_buffers:
                    timeline_buffers[flow_key] = deque(maxlen=10)

                timeline_buffers[flow_key].append({
                    "seq": 1000 + i,
                    "time": float(i) * 0.0001
                })

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        print(f"Packets processed: 1,000,000")
        print(f"Timeline buffers: {len(timeline_buffers):,}")
        print(f"Current memory: {current / 1024 / 1024:.2f} MB")
        print(f"Peak memory: {peak / 1024 / 1024:.2f} MB")

        if len(timeline_buffers) > 0:
            per_flow_kb = (current / 1024) / len(timeline_buffers)
            print(f"Memory per timeline buffer: {per_flow_kb:.2f} KB")


def main():
    """Run memory profiling."""
    print("=" * 80)
    print("PACKET TIMELINE FEATURE - MEMORY PROFILING")
    print("Version: v4.15.0")
    print("=" * 80)

    profiler = MemoryProfiler()

    # Profile different scenarios
    profiler.profile_baseline(num_packets=10000)
    profiler.profile_timeline_no_flows(num_packets=10000)
    profiler.profile_timeline_with_flows(num_packets=10000, num_problematic_flows=50)
    profiler.profile_timeline_with_flows(num_packets=10000, num_problematic_flows=100)

    # Compare results
    profiler.compare_results()

    # Large-scale test
    profiler.profile_large_scale()

    print("\n" + "=" * 80)
    print("PROFILING COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
