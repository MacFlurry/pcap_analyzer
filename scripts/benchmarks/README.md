# Performance Benchmarking Tools

This directory contains performance profiling and benchmarking tools for the PCAP Analyzer.

**Note**: These are not automated tests. They are manual profiling tools for performance analysis.

## Tools

### benchmark_performance.py

Measures execution time, memory usage, and analyzer performance for PCAP analysis.

**Usage**:
```bash
python scripts/benchmarks/benchmark_performance.py <pcap_file>
python scripts/benchmarks/benchmark_performance.py <pcap_file> --profile
python scripts/benchmarks/benchmark_performance.py <pcap_file> --memory
```

**Output**:
- Execution time
- Peak memory usage
- Packets/second
- Analyzer breakdown by time

### compare_performance.py

Compares performance between different git branches or versions.

**Usage**:
```bash
# Compare current branch with main
python scripts/benchmarks/compare_performance.py <pcap_file> --baseline main

# Compare two branches
python scripts/benchmarks/compare_performance.py <pcap_file> --baseline v4.0.0 --current v4.2.1

# Quick comparison (execution time only)
python scripts/benchmarks/compare_performance.py <pcap_file> --quick
```

**Output**:
- Side-by-side performance comparison
- Percentage improvements/regressions
- Per-analyzer breakdown

## Requirements

```bash
pip install memory_profiler
```

## Notes

These tools were moved from `tests/` as they are not part of the automated test suite.
They are useful for:
- Performance profiling during development
- Regression testing for performance
- Identifying bottlenecks
