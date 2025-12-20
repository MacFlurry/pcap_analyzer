#!/usr/bin/env python3
"""
Resource Limits Demonstration

This script demonstrates the OS-level resource limits functionality
implemented for DoS protection (CWE-770, NIST SC-5).

Run this to see how resource limits work in practice.
"""

import logging
import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging to see all messages
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)-8s: %(message)s'
)

from src.utils.resource_limits import (
    get_current_resource_usage,
    set_resource_limits,
)

def demo_basic_usage():
    """Demonstrate basic resource limit usage."""
    print("=" * 70)
    print("DEMO 1: Basic Resource Limits")
    print("=" * 70)
    print()

    print("Setting resource limits with defaults:")
    print("  - Memory: 4 GB")
    print("  - CPU time: 3600 seconds (1 hour)")
    print("  - File size: 10 GB")
    print("  - File descriptors: 1024")
    print()

    set_resource_limits()

    print()
    print("Limits have been set. Check the INFO messages above.")
    print()


def demo_custom_limits():
    """Demonstrate setting custom resource limits."""
    print("=" * 70)
    print("DEMO 2: Custom Resource Limits")
    print("=" * 70)
    print()

    print("Setting custom limits:")
    print("  - Memory: 2 GB (lower for resource-constrained systems)")
    print("  - CPU time: 1800 seconds (30 minutes)")
    print("  - File size: 5 GB")
    print("  - File descriptors: 512")
    print()

    set_resource_limits(
        memory_gb=2.0,
        cpu_seconds=1800,
        max_file_size_gb=5.0,
        max_open_files=512
    )

    print()
    print("Custom limits have been set.")
    print()


def demo_resource_usage():
    """Demonstrate getting current resource usage."""
    print("=" * 70)
    print("DEMO 3: Current Resource Usage")
    print("=" * 70)
    print()

    usage = get_current_resource_usage()

    print(f"Platform: {usage['platform']}")
    print(f"Resource module available: {usage['resource_module_available']}")
    print()

    if usage.get('resource_module_available'):
        print("Current Resource Usage:")
        print(f"  Memory: {usage.get('memory_mb', 0):.2f} MB")
        print(f"  CPU time: {usage.get('cpu_time_seconds', 0):.2f} seconds")
        print()

        print("Current Limits:")
        mem_limit = usage.get('memory_limit_gb')
        cpu_limit = usage.get('cpu_limit_seconds')

        if mem_limit:
            print(f"  Memory limit: {mem_limit} GB")
        else:
            print("  Memory limit: Not enforced (macOS limitation)")

        if cpu_limit:
            print(f"  CPU limit: {cpu_limit} seconds")
        else:
            print("  CPU limit: Unlimited")
    else:
        print("Resource module not available on this platform (Windows).")
        print("Resource limits cannot be enforced.")

    print()


def demo_security_protection():
    """Demonstrate security protection concept."""
    print("=" * 70)
    print("DEMO 4: Security Protection (Conceptual)")
    print("=" * 70)
    print()

    print("How Resource Limits Protect Against Attacks:")
    print()

    print("1. ZIP BOMB PROTECTION (Memory Limit)")
    print("   Without limits: 10 MB zip → 10 GB RAM → System crash")
    print("   With limits:    Process killed when exceeding 4 GB")
    print()

    print("2. INFINITE LOOP PROTECTION (CPU Limit)")
    print("   Without limits: Malicious PCAP → Infinite loop → Process hangs forever")
    print("   With limits:    Process receives SIGXCPU after 1 hour → Graceful exit")
    print()

    print("3. DISK EXHAUSTION PROTECTION (File Size Limit)")
    print("   Without limits: Runaway log → 100 GB log file → Disk full")
    print("   With limits:    File write fails at 10 GB → Disk protected")
    print()

    print("4. FD EXHAUSTION PROTECTION (File Descriptor Limit)")
    print("   Without limits: Malicious file → 10,000 temp files → FDs exhausted")
    print("   With limits:    File open fails at 1024 FDs → System protected")
    print()

    print("Security Standards:")
    print("  ✓ CWE-770: Allocation of Resources Without Limits")
    print("  ✓ NIST SP 800-53 SC-5: Denial of Service Protection")
    print()


def demo_cli_usage():
    """Demonstrate CLI usage examples."""
    print("=" * 70)
    print("DEMO 5: CLI Usage Examples")
    print("=" * 70)
    print()

    print("Command Line Interface:")
    print()

    print("# Analyze with default limits (4GB RAM, 1 hour CPU)")
    print("pcap_analyzer analyze capture.pcap")
    print()

    print("# Increase memory limit for large files")
    print("pcap_analyzer analyze large_file.pcap --max-memory 8.0")
    print()

    print("# Increase CPU time for complex analysis")
    print("pcap_analyzer analyze complex.pcap --max-cpu-time 7200")
    print()

    print("# Combine both for very large files")
    print("pcap_analyzer analyze huge.pcap --max-memory 16.0 --max-cpu-time 10800")
    print()

    print("# Capture with resource limits")
    print("pcap_analyzer capture -d 300 --max-memory 8.0")
    print()


def demo_error_handling():
    """Demonstrate error handling."""
    print("=" * 70)
    print("DEMO 6: Error Handling")
    print("=" * 70)
    print()

    print("What happens when limits are exceeded:")
    print()

    print("1. MEMORY LIMIT EXCEEDED")
    print("   Exception: MemoryError")
    print("   Message: 'CRITICAL: Memory limit exceeded!'")
    print("   Suggestions:")
    print("     - Increase memory limit: --max-memory 8.0")
    print("     - Enable streaming mode (automatic for files >100MB)")
    print("     - Split PCAP file into smaller chunks")
    print()

    print("2. CPU LIMIT EXCEEDED")
    print("   Signal: SIGXCPU")
    print("   Message: 'CPU time limit exceeded! Terminating gracefully.'")
    print("   Action: Process exits with code 1")
    print()

    print("3. INVALID INPUT")
    print("   Try setting negative memory limit...")
    try:
        set_resource_limits(memory_gb=-1)
    except ValueError as e:
        print(f"   ✓ Caught ValueError: {e}")
    print()


def main():
    """Run all demonstrations."""
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║         RESOURCE LIMITS DEMONSTRATION                            ║")
    print("║         DoS Protection (CWE-770, NIST SC-5)                      ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()

    demos = [
        ("Basic Usage", demo_basic_usage),
        ("Custom Limits", demo_custom_limits),
        ("Resource Usage", demo_resource_usage),
        ("Security Protection", demo_security_protection),
        ("CLI Usage", demo_cli_usage),
        ("Error Handling", demo_error_handling),
    ]

    for i, (name, demo_func) in enumerate(demos, 1):
        demo_func()
        if i < len(demos):
            input("Press Enter to continue to next demo...")
            print("\n")

    print("=" * 70)
    print("DEMONSTRATION COMPLETE")
    print("=" * 70)
    print()
    print("For more information, see:")
    print("  - docs/RESOURCE_LIMITS.md")
    print("  - RESOURCE_LIMITS_IMPLEMENTATION.md")
    print()


if __name__ == "__main__":
    main()
