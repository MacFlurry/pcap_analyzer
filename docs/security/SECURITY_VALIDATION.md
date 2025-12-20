# PCAP File Validation - OWASP ASVS 5.2 Implementation

## Overview

This document describes the PCAP file validation implementation that complies with OWASP Application Security Verification Standard (ASVS) 5.2 and addresses critical security vulnerabilities.

## Security Standards Implemented

### OWASP ASVS 5.2.2 - File Type and Content Validation
- **Standard**: Verify that the application validates file type by checking magic bytes rather than file extension
- **Implementation**: `validate_pcap_magic_number()` reads and validates the first 4 bytes of the file
- **Supported Formats**:
  - Standard PCAP (big-endian): `0xa1b2c3d4`
  - Standard PCAP (little-endian): `0xd4c3b2a1`
  - PCAP with nanosecond precision (big-endian): `0xa1b23c4d`
  - PCAP with nanosecond precision (little-endian): `0x4d3cb2a1`
  - PCAP-NG (next generation): `0x0a0d0d0a`

### OWASP ASVS 5.2.1 - File Size Validation
- **Standard**: Verify that the application validates file size to prevent resource exhaustion
- **Implementation**: `validate_pcap_file_size()` checks file size before processing
- **Limits**:
  - Minimum: 24 bytes (PCAP header size)
  - Maximum: 20 GB (configurable, default)
  - Empty files: Rejected (0 bytes)

### CWE-434: Unrestricted Upload of File with Dangerous Type
- **Rank**: #12 in 2025 CWE Top 25 Most Dangerous Software Weaknesses
- **Mitigation**: Magic byte validation prevents malicious files disguised as PCAP files
- **Examples Blocked**:
  - Executables (ELF: `0x7f454c46`, PE: `0x4d5a9000`)
  - Archives (ZIP: `0x504b0304`)
  - Documents (PDF: `0x25504446`)
  - Images (JPEG: `0xffd8ffe0`, PNG: `0x89504e47`)
  - Scripts (text files with .pcap extension)

### CWE-770: Allocation of Resources Without Limits or Throttling
- **Mitigation**: File size validation prevents memory exhaustion attacks
- **Protection**: Rejects files exceeding configurable size limit before processing
- **NIST SP 800-53 SC-5**: Denial of Service Protection compliance

## Implementation Details

### Module Structure

```
src/utils/file_validator.py
├── validate_pcap_magic_number()  # Magic byte validation
├── validate_pcap_file_size()     # File size validation
└── validate_pcap_file()          # Combined validation (recommended)
```

### Validation Flow

1. **File Size Validation** (fast, fail-fast)
   - Check file exists and is a regular file
   - Reject empty files (0 bytes)
   - Reject files below minimum size (24 bytes)
   - Reject files above maximum size (20 GB default)

2. **Magic Number Validation** (requires file I/O)
   - Read first 4 bytes of file
   - Compare against known PCAP magic numbers
   - Return PCAP type if valid
   - Raise descriptive error if invalid

### Integration in CLI

The validation is integrated in `src/cli.py` in the `analyze()` function:

```python
# OWASP ASVS 5.2: File Validation (CWE-434, CWE-770)
console.print("[cyan]Validating PCAP file...[/cyan]")
try:
    pcap_type, file_size = validate_pcap_file(pcap_file, max_size_gb=20)
    file_size_mb = file_size / (1024 * 1024)
    console.print(f"[green]✓ Valid {pcap_type.upper()} file ({file_size_mb:.2f} MB)[/green]")
except FileNotFoundError as e:
    console.print(f"[red]✗ File validation failed: {e}[/red]")
    raise click.Abort()
except PermissionError as e:
    console.print(f"[red]✗ File validation failed: {e}[/red]")
    raise click.Abort()
except ValueError as e:
    console.print(f"[red]✗ File validation failed: {e}[/red]")
    console.print("[yellow]Hint: Ensure the file is a valid PCAP capture...[/yellow]")
    raise click.Abort()
```

## Security Features

### Information Disclosure Prevention (CWE-209)
- File paths are **NEVER** included in error messages
- Error messages are sanitized for user display
- Detailed errors are logged to application logs only
- Stack traces are not shown to users

### Fail-Fast Validation
- File size checked before opening file (efficient)
- Invalid files rejected immediately
- No processing of untrusted content before validation

### Defense in Depth
- Multiple validation layers (size + magic bytes)
- Path canonicalization (prevent symlink attacks)
- Sensitive directory protection
- Resource limit enforcement

## Testing

### Test Script
Run the comprehensive test suite:

```bash
python test_file_validator.py
```

### Test Coverage

1. **Valid PCAP Files**
   - Standard PCAP (both endianness)
   - PCAP with nanosecond precision
   - PCAP-NG format
   - Real PCAP files from project

2. **Invalid Magic Numbers**
   - Text files
   - Executables (ELF, PE)
   - Archives (ZIP)
   - Documents (PDF)
   - Images (JPEG, PNG)

3. **File Size Validation**
   - Empty files (0 bytes)
   - Too small files (< 24 bytes)
   - Valid size files
   - Too large files (> limit)

4. **Error Handling**
   - Non-existent files
   - Permission denied
   - Path sanitization

### Example Test Results

```
=== Testing Valid PCAP Files ===
✓ Magic number validation passed: pcap
✓ Size validation passed: 7.95 KB
✓ Combined validation passed: pcap, 7.95 KB

=== Testing Invalid Magic Numbers ===
Testing: Executable (ELF)
✓ Correctly rejected: Invalid PCAP file: magic number 0x7f454c46 not recognized

Testing: Text file (.txt)
✓ Correctly rejected: Invalid PCAP file: magic number 0x54686973 not recognized

=== Testing File Size Validation ===
Test 1: Empty file
✓ Correctly rejected empty file

Test 4: File too large (exceeds limit)
✓ Correctly rejected too-large file
```

## Usage Examples

### CLI Usage

```bash
# Analyze valid PCAP file
pcap_analyzer analyze capture.pcap

# Output:
# Validating PCAP file...
# ✓ Valid PCAP file (2.50 MB)
# [Analysis continues...]

# Attempt to analyze invalid file
pcap_analyzer analyze malware.exe

# Output:
# Validating PCAP file...
# ✗ File validation failed: Invalid PCAP file: magic number 0x4d5a9000 not recognized
# Hint: Ensure the file is a valid PCAP capture (not a text file, executable, or corrupted file)
# Aborted!
```

### Programmatic Usage

```python
from src.utils.file_validator import validate_pcap_file

# Validate PCAP file before processing
try:
    pcap_type, file_size = validate_pcap_file('/path/to/capture.pcap')
    print(f"Valid {pcap_type} file ({file_size} bytes)")
    # Safe to proceed with processing
except ValueError as e:
    print(f"Validation failed: {e}")
    # Abort processing
except FileNotFoundError:
    print("File not found")
except PermissionError:
    print("Permission denied")
```

## Error Messages

### User-Friendly Errors

All error messages are designed to be:
- **Informative**: Explain what went wrong
- **Actionable**: Suggest how to fix the issue
- **Secure**: Do not leak sensitive information

Examples:

```
Invalid PCAP file: magic number 0x54686973 not recognized.
Expected one of: standard PCAP (0xa1b2c3d4), PCAP-NS (0xa1b23c4d),
or PCAP-NG (0x0a0d0d0a). Please ensure the file is a valid PCAP capture.

Invalid PCAP file: file is empty (0 bytes)

PCAP file too large: 25.3 GB exceeds maximum of 20 GB.
Consider processing the file in chunks or increasing the size limit.

Invalid PCAP file: file too small (12 bytes).
Minimum valid PCAP file is 24 bytes (header size).
```

## Audit Logging

All validation failures are logged with:
- Timestamp
- File path (internal logs only)
- Magic number detected (if applicable)
- Validation error type
- User action (abort)

Example log entries:

```
2025-01-15 14:23:45 - WARNING - Invalid magic number detected: 0x7f454c46
2025-01-15 14:24:12 - WARNING - Empty file detected during validation
2025-01-15 14:25:03 - WARNING - File too large: 25.3 GB > 20 GB
2025-01-15 14:26:34 - ERROR - File not found during validation
```

## Performance Impact

- **File Size Validation**: ~0.1ms (stat syscall only)
- **Magic Number Validation**: ~0.5ms (read 4 bytes)
- **Total Overhead**: < 1ms per file
- **Memory Usage**: Minimal (only 4 bytes read)

The validation overhead is negligible compared to PCAP processing time.

## Configuration

### Maximum File Size

The maximum file size can be configured:

```python
# Default: 20 GB
validate_pcap_file(pcap_file, max_size_gb=20)

# Custom limit: 50 GB for large captures
validate_pcap_file(pcap_file, max_size_gb=50)

# Strict limit: 1 GB for testing
validate_pcap_file(pcap_file, max_size_gb=1)
```

### Minimum File Size

The minimum file size is fixed at 24 bytes (PCAP header size) and cannot be changed.

## References

### Standards
- [OWASP ASVS 5.2](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [NIST SP 800-53 SC-5](https://nvd.nist.gov/800-53/Rev4/control/SC-5)

### Vulnerabilities
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

### File Formats
- [PCAP File Format](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [PCAP-NG Specification](https://github.com/pcapng/pcapng)

## Compliance Summary

| Standard | Requirement | Status | Implementation |
|----------|-------------|--------|----------------|
| OWASP ASVS 5.2.2 | File type validation via magic bytes | ✅ Compliant | `validate_pcap_magic_number()` |
| OWASP ASVS 5.2.1 | File size validation | ✅ Compliant | `validate_pcap_file_size()` |
| CWE-434 | Prevent dangerous file uploads | ✅ Mitigated | Magic byte validation |
| CWE-770 | Resource allocation limits | ✅ Mitigated | File size limits |
| CWE-209 | No sensitive info in errors | ✅ Mitigated | Error sanitization |
| NIST SC-5 | DoS Protection | ✅ Compliant | Size + resource limits |

## Future Enhancements

### Planned
1. Content-based validation (verify PCAP header fields)
2. Configurable size limits via config file
3. Metrics collection (validation failures by type)
4. Integration with malware scanning APIs

### Under Consideration
1. YARA rules for PCAP validation
2. Hash-based allowlisting/blocklisting
3. Signature verification for trusted sources
4. Rate limiting for validation attempts

## Support

For questions or issues related to file validation:
1. Check this documentation first
2. Review test suite for examples
3. Check application logs for detailed errors
4. Contact security team for vulnerability reports
