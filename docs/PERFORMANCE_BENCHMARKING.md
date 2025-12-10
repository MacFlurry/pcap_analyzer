# Performance Benchmarking Guide

This guide explains how to benchmark and compare the performance of PCAP Analyzer.

## Tools

### 1. `benchmark_performance.py` - Single Benchmark

Measures performance metrics for a single PCAP file analysis.

**Usage:**
```bash
# Basic benchmark (execution time only)
python tests/benchmark_performance.py sample.pcap

# With memory profiling
python tests/benchmark_performance.py sample.pcap --memory

# With analyzer profiling
python tests/benchmark_performance.py sample.pcap --profile

# Full benchmark (all metrics)
python tests/benchmark_performance.py sample.pcap --all
```

**Metrics Collected:**
- **Execution Time**: Total time to analyze PCAP
- **Throughput**: Packets processed per second
- **Memory Usage**: Peak memory consumption (with `--memory`)
- **Analyzer Breakdown**: Time spent in each analyzer (with `--profile`)
- **Health Score Results**: Overall score and component scores

**Example Output:**
```
============================================================
PCAP Analyzer - Performance Benchmark
============================================================
PCAP File: large_capture.pcap

Analyzing file statistics...
  File Size: 125.3 MB
  Total Packets: 50,000

Measuring execution time...
  Execution Time: 12.34s
  Throughput: 4,050 packets/sec

Measuring memory usage...
  Peak Memory: 245.6 MB
  Memory Increase: 180.2 MB

Profiling analyzer performance...
  Analyzer Breakdown:
    - analyze_rtt: 3.5s (28%)
    - analyze_tcp_handshake: 2.1s (17%)
    - analyze_timestamps: 1.8s (15%)
    - calculate_health_score: 0.5s (4%)

Health Score Results:
  Overall Score: 85.5/100
  Packet Loss: 95.0/100
  Retransmissions: 88.0/100
  RTT: 78.5/100

============================================================
Benchmark Complete
============================================================
```

### 2. `compare_performance.py` - Before/After Comparison

Compares performance between two git branches to measure the impact of changes.

**Usage:**
```bash
# Compare current branch with main
python tests/compare_performance.py sample.pcap --baseline main

# Compare two specific branches
python tests/compare_performance.py sample.pcap --baseline v1.0 --current feature-branch

# Quick comparison (execution time only)
python tests/compare_performance.py sample.pcap --baseline main --quick
```

**Example Output:**
```
Comparing branches:
  Baseline: main
  Current:  feature/health-score

Running baseline benchmark (main)...
Running current benchmark (feature/health-score)...

======================================================================
Performance Comparison Results
======================================================================
PCAP File: large_capture.pcap
File Size: 125.3 MB
Packets:   50,000

Execution Time:
  Baseline: 15.20s
  Current:  12.34s
  Change:   -18.8% ↓

Throughput (packets/sec):
  Baseline: 3,289
  Current:  4,065
  Change:   +23.6% ↑

Peak Memory:
  Baseline: 280.0 MB
  Current:  245.6 MB
  Change:   -12.3% ↓

Analyzer Performance:
  analyze_tcp_handshake: 2.50s → 2.10s (-16.0% ↓)
  analyze_rtt: 4.20s → 3.50s (-16.7% ↓)
  analyze_timestamps: 2.00s → 1.80s (-10.0% ↓)
  calculate_health_score: NEW → 0.50s

======================================================================
✓ Performance IMPROVED
======================================================================
```

## Benchmarking Best Practices

### 1. Choose Representative PCAP Files

Use PCAP files that represent typical workloads:

- **Small** (< 1 MB, < 1,000 packets): Unit test level
- **Medium** (1-50 MB, 1K-50K packets): Typical analysis
- **Large** (50-500 MB, 50K-500K packets): Stress test
- **Very Large** (> 500 MB, > 500K packets): Performance limit

### 2. Consistent Test Environment

- Close other applications
- Run multiple iterations and average results
- Use the same hardware for comparisons
- Ensure network interfaces are idle (for live capture benchmarks)

### 3. Interpreting Results

**Execution Time:**
- < 1s per 10K packets: Excellent
- 1-5s per 10K packets: Good
- 5-10s per 10K packets: Acceptable
- \> 10s per 10K packets: Needs optimization

**Memory Usage:**
- Should scale linearly with PCAP size
- Peak memory should be < 3x file size
- Memory leaks: watch for increasing usage across runs

**Throughput:**
- \> 10K packets/sec: Excellent
- 5-10K packets/sec: Good
- 1-5K packets/sec: Acceptable
- < 1K packets/sec: Needs optimization

### 4. Performance Targets

Based on Sprint 1 improvements:

| Metric | Before | Target | Achieved |
|--------|--------|--------|----------|
| Execution Time | Baseline | -15% | TBD |
| Memory Usage | Baseline | No regression | TBD |
| Throughput | Baseline | +15% | TBD |

## Optimization Tips

### General
- Profile before optimizing (use `--profile`)
- Focus on hot paths (top 20% of time)
- Optimize algorithms before code

### Memory
- Use generators for large datasets
- Clear packet lists after processing
- Consider streaming for very large files

### Execution Time
- Minimize packet iteration passes
- Cache computed values
- Use efficient data structures (sets > lists for lookups)

### Analyzers
- Skip unnecessary analysis when possible
- Early exit when thresholds not met
- Batch operations where possible

## Continuous Benchmarking

### Pre-commit Benchmark
Before committing performance-sensitive changes:

```bash
# Benchmark current implementation
python tests/benchmark_performance.py sample.pcap --all > before.txt

# Make changes...

# Compare with baseline
python tests/compare_performance.py sample.pcap --baseline HEAD
```

### CI/CD Integration
Add performance regression tests to CI:

```yaml
- name: Performance Benchmark
  run: |
    python tests/compare_performance.py test_data/sample.pcap --baseline main
    # Fail if performance regressed by > 20%
```

## Troubleshooting

### Issue: Benchmark script fails with import error
**Solution:** Ensure virtual environment is activated and dependencies installed:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: Memory profiling not working
**Solution:** Install memory_profiler:
```bash
pip install memory_profiler
```

### Issue: Git checkout fails during comparison
**Solution:** Ensure working directory is clean:
```bash
git status  # Check for uncommitted changes
git stash   # Stash changes if needed
```

### Issue: Inconsistent results between runs
**Solution:**
- Close other applications
- Run multiple times and average
- Use larger PCAP files (> 10 MB)
- Disable CPU frequency scaling

## Advanced Usage

### Custom Metrics
Extend `PerformanceBenchmark` class to add custom metrics:

```python
from benchmark_performance import PerformanceBenchmark

class CustomBenchmark(PerformanceBenchmark):
    def measure_custom_metric(self):
        # Your custom measurement logic
        pass
```

### Automated Regression Detection
Use comparison tool in scripts:

```python
import subprocess
import sys

result = subprocess.run([
    "python", "tests/compare_performance.py",
    "sample.pcap", "--baseline", "main"
], capture_output=True)

# Parse output and check for regression
if "REGRESSED" in result.stdout.decode():
    print("Performance regression detected!")
    sys.exit(1)
```

## References

- [Python Performance Tips](https://wiki.python.org/moin/PythonSpeed/PerformanceTips)
- [Profiling Python Programs](https://docs.python.org/3/library/profile.html)
- [Memory Profiler Documentation](https://pypi.org/project/memory-profiler/)
