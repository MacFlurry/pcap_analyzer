# Track Specification: Test Coverage Improvement

## Overview
Improve the reliability and security of the PCAP Analyzer by increasing test coverage to 60%+ globally and 70%+ for critical modules (`upload.py`, `reports.py`, `analyzer.py`). This track focuses on closing gaps in unit tests, implementing robust integration tests for the analysis lifecycle, and ensuring strict multi-tenant isolation.

## Objectives
- **Identify Gaps:** Use `coverage.py` to pinpoint untested logic in core service modules.
- **Infrastructure:** Develop reusable fixtures for PCAP file simulation and mock external dependencies like `tshark`.
- **Integration Testing:** Validate the full "Upload -> Analyze -> Report" lifecycle, including error handling and resource constraints.
- **Security Validation:** Verify multi-tenant isolation and report sanitization (PII redaction).

## Scope

### Targeted Modules
- `app/services/analyzer.py`: Packet analysis logic, `tshark` interactions.
- `app/services/reports.py`: HTML/JSON report generation and access control.
- `app/api/routes/`: Specifically upload and report retrieval endpoints.

### Key Requirements
1. **PCAP Simulation:**
   - Create valid minimal PCAPs.
   - Create malformed/corrupted PCAP files for error handling tests.
2. **Mocking Strategy:**
   - Mock `tshark` subprocess calls to ensure tests are deterministic and don't require the binary in all environments.
   - Mock filesystem operations for cleanup tests.
3. **Multi-Tenancy:**
   - Ensure User A cannot access User B's reports.
   - Verify Admin access to all reports.
4. **Resource Limits:**
   - Test behavior when file sizes exceed limits or memory/CPU constraints are hit.

## Acceptance Criteria
- [ ] Global test coverage reaches 60%+.
- [ ] Coverage for `analyzer.py`, `reports.py`, and `upload` logic reaches 70%+.
- [ ] All integration tests in `tests/integration/test_upload_lifecycle.py` pass.
- [ ] Multi-tenant isolation is verified by automated tests.
- [ ] `TESTING_GUIDE.md` is updated with new integration testing procedures.

## Technical Details
- **Test Framework:** `pytest`
- **Mocking:** `unittest.mock`
- **Coverage Tool:** `coverage.py` (via `pytest-cov`)
- **Data Generation:** `Hypothesis` for edge-case packet data (optional but recommended).
