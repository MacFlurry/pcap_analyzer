# Resource Limits for DoS Protection

## Overview

The PCAP Analyzer implements OS-level resource limits to prevent resource exhaustion attacks (Denial of Service). This is implemented according to industry best practices and security standards.

## Security Standards Compliance

- **CWE-770**: Allocation of Resources Without Limits or Throttling (Rank 25 in 2025 CWE Top 25)
- **NIST SP 800-53 SC-5**: Denial of Service Protection
- **OWASP ASVS 5.2**: File and Resource Validation

## Implementation

### Module Location

`src/utils/resource_limits.py`

### Resource Limits Enforced

| Resource | Limit Type | Default | Purpose |
|----------|-----------|---------|---------|
| Memory (RLIMIT_AS) | Virtual Memory | 4 GB | Prevents zip bombs and memory exhaustion |
| CPU Time (RLIMIT_CPU) | Cumulative CPU | 3600s (1 hour) | Prevents infinite loops and algorithmic DoS |
| File Size (RLIMIT_FSIZE) | Max file write | 10 GB | Prevents disk exhaustion from log files |
| File Descriptors (RLIMIT_NOFILE) | Max open files | 1024 | Prevents file descriptor exhaustion |

### How It Works

1. **Initialization**: Resource limits are set at the start of `analyze` and `capture` commands
2. **Hard Limits**: These are HARD limits - the OS will kill the process if exceeded
3. **Graceful Handling**: The application catches violations and provides user-friendly error messages

### Signal Handling

- **SIGXCPU**: Sent when CPU time limit is exceeded
  - Handler logs the violation and exits gracefully
  - Prevents the process from hanging indefinitely

- **MemoryError**: Raised when memory allocation fails due to RLIMIT_AS
  - Caught in CLI commands
  - Provides suggestions to user (increase limit, use streaming mode, split file)

## Usage

### CLI Options

Both `analyze` and `capture` commands support resource limit configuration:

```bash
# Use default limits (4GB RAM, 1 hour CPU time)
pcap_analyzer analyze capture.pcap

# Increase memory limit for large files
pcap_analyzer analyze capture.pcap --max-memory 8.0

# Increase CPU time limit for complex analysis
pcap_analyzer analyze capture.pcap --max-cpu-time 7200

# Combine both
pcap_analyzer analyze capture.pcap --max-memory 16.0 --max-cpu-time 10800
```

### Programmatic Usage

```python
from src.utils.resource_limits import set_resource_limits

# Set custom limits
set_resource_limits(
    memory_gb=8.0,          # 8 GB RAM limit
    cpu_seconds=7200,       # 2 hours CPU time
    max_file_size_gb=20.0,  # 20 GB file size limit
    max_open_files=2048     # 2048 file descriptors
)
```

### Error Handling

```python
from src.utils.resource_limits import handle_memory_error

try:
    # Memory-intensive operation
    data = load_large_pcap()
except MemoryError:
    handle_memory_error()  # Logs and exits gracefully
```

## Platform Support

| Platform | RLIMIT_AS | RLIMIT_CPU | RLIMIT_FSIZE | RLIMIT_NOFILE |
|----------|-----------|------------|--------------|---------------|
| Linux | ✓ Full | ✓ Full | ✓ Full | ✓ Full |
| macOS | ✗ Not supported* | ✓ Full | ✓ Full | ✓ Full |
| Windows | ✗ No resource module | ✗ No resource module | ✗ No resource module | ✗ No resource module |

*Note: macOS does not fully support RLIMIT_AS. The module will log a warning and continue with other limits.

### Platform-Specific Behavior

#### Linux (Recommended for Production)
- **Full support** for all resource limits
- Memory limits are strictly enforced
- Ideal for production deployments

#### macOS (Development)
- **Partial support**: CPU, file size, and file descriptor limits work
- **Memory limits (RLIMIT_AS) not supported**: Known macOS limitation
- Warning logged when memory limits cannot be set
- Still provides protection against CPU and file resource exhaustion

#### Windows
- **Not supported**: Windows does not have the `resource` module
- Module gracefully skips limit setting with a warning
- Consider using WSL2 or Linux VM for production use

## Security Benefits

### 1. Zip Bomb Protection

Without memory limits, a malicious PCAP file compressed as a zip bomb could:
- Expand from 10 MB to 10 GB in memory
- Crash the system by consuming all RAM
- Cause swap thrashing and system freeze

**With memory limits**: Process is killed when attempting to allocate excessive memory.

### 2. Algorithmic DoS Prevention

Without CPU limits, a malicious PCAP file could:
- Trigger O(n²) or worse algorithmic complexity
- Cause infinite loops in parsing logic
- Hang the analysis indefinitely

**With CPU limits**: Process receives SIGXCPU and exits gracefully after 1 hour.

### 3. Disk Exhaustion Prevention

Without file size limits, a runaway process could:
- Generate multi-GB log files
- Fill up disk space
- Cause system instability

**With file size limits**: File writes fail when exceeding 10 GB.

### 4. File Descriptor Exhaustion Prevention

Without FD limits, a malicious file could:
- Trigger creation of thousands of temporary files
- Exhaust file descriptors
- Prevent other processes from opening files

**With FD limits**: File opens fail when exceeding 1024 open files.

## Monitoring and Logging

### Get Current Resource Usage

```python
from src.utils.resource_limits import get_current_resource_usage

usage = get_current_resource_usage()
print(f"Memory usage: {usage['memory_mb']:.2f} MB")
print(f"CPU time: {usage['cpu_time_seconds']:.2f}s")
print(f"Memory limit: {usage['memory_limit_gb']} GB")
print(f"CPU limit: {usage['cpu_limit_seconds']}s")
```

### Logs

All resource limit operations are logged:

```
INFO: Setting OS-level resource limits for DoS protection (CWE-770, NIST SC-5)
INFO: Memory limit (RLIMIT_AS): 4.0 GB (prevents zip bombs and memory exhaustion)
INFO: CPU time limit (RLIMIT_CPU): 3600 seconds (prevents infinite loops)
INFO: File size limit (RLIMIT_FSIZE): 10.0 GB (prevents disk exhaustion)
INFO: File descriptor limit (RLIMIT_NOFILE): 1024 (prevents fd exhaustion)
INFO: Installed SIGXCPU handler for graceful CPU limit violation handling
INFO: Resource limits successfully applied.
```

## Best Practices

1. **Production Deployments**: Use Linux for full resource limit support
2. **Large Files**: Increase `--max-memory` as needed, but always set a limit
3. **Long Analysis**: Increase `--max-cpu-time` for complex PCAPs, but always set a limit
4. **Automated Systems**: Always set resource limits to prevent runaway processes
5. **Monitoring**: Log resource usage and violations for security auditing

## Troubleshooting

### Memory Limit Exceeded

**Symptom**: Process exits with "CRITICAL: Memory limit exceeded!"

**Solutions**:
1. Increase memory limit: `--max-memory 8.0`
2. Ensure streaming mode is enabled (default for files >100MB)
3. Split PCAP file into smaller chunks
4. Check for actual memory leaks

### CPU Limit Exceeded

**Symptom**: Process receives SIGXCPU and exits

**Solutions**:
1. Increase CPU limit: `--max-cpu-time 7200`
2. Profile code to identify performance bottlenecks
3. Enable parallel processing: `--parallel`
4. Check for infinite loops in custom analyzers

### Limits Not Applied (macOS)

**Symptom**: Warning about RLIMIT_AS not supported

**Expected Behavior**: This is normal on macOS. Other limits still apply.

**Solutions**:
1. Continue with other limits (CPU, file size, FDs)
2. Use Linux for production deployments requiring memory limits

### Limits Not Applied (Windows)

**Symptom**: Warning about resource module not available

**Expected Behavior**: Windows doesn't support resource limits.

**Solutions**:
1. Use WSL2 (Windows Subsystem for Linux)
2. Use Docker container with Linux base image
3. Deploy on Linux server for production

## Testing

Run the test suite to verify resource limits work on your platform:

```bash
python3 -c "
from src.utils.resource_limits import set_resource_limits, get_current_resource_usage
import logging

logging.basicConfig(level=logging.INFO)

# Test setting limits
set_resource_limits(memory_gb=4.0, cpu_seconds=3600)

# Verify
usage = get_current_resource_usage()
print(f'Platform: {usage[\"platform\"]}')
print(f'Resource module available: {usage[\"resource_module_available\"]}')
if usage.get('cpu_limit_seconds'):
    print(f'CPU limit: {usage[\"cpu_limit_seconds\"]}s')
"
```

## References

- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [NIST SP 800-53 SC-5: Denial of Service Protection](https://nvd.nist.gov/800-53/Rev4/control/SC-5)
- [Python resource module documentation](https://docs.python.org/3/library/resource.html)
- [OWASP ASVS 5.2: File and Resource Validation](https://owasp.org/www-project-application-security-verification-standard/)

## Version History

- **v1.0.0** (2025-12-20): Initial implementation
  - RLIMIT_AS (memory) support with macOS compatibility
  - RLIMIT_CPU (CPU time) support
  - RLIMIT_FSIZE (file size) support
  - RLIMIT_NOFILE (file descriptors) support
  - Signal handlers for graceful violations
  - CLI integration with --max-memory and --max-cpu-time options
  - Comprehensive error handling and logging
