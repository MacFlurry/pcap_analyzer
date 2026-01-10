# Track: HTML Report Timestamp Discrepancy Fix (v5.4.5)

## Context
A discrepancy was identified between the CLI output and the HTML report regarding SYN retransmission timestamps.
- CLI showed "Premier SYN" (correct start of connection attempt).
- HTML report showed "First Retransmission" (timestamp of the second packet in the sequence).

## Objectives
- [x] Identify root cause in `src/exporters/html_report.py`.
- [x] Synchronize HTML report with CLI output by using `SYNRetransmissionAnalyzer` data.
- [x] Update column headers dynamically for SYN flows ("First SYN" instead of "First Retrans").
- [x] Bump version to v5.4.5 (PATCH).
- [x] Update project metadata (src/__version__.py, Chart.yaml, CHANGELOG.md).
- [x] Tag and push to repository.

## Root Cause Analysis
The HTML generator was relying solely on `RetransmissionAnalyzer` (generic), which captures retransmission packets but doesn't necessarily track the initial "parent" packet's timestamp if it wasn't a retransmission itself. `SYNRetransmissionAnalyzer` is stateful and tracks the `first_syn_time`.

## Implementation Details
- Modified `_generate_flow_table` in `src/exporters/html_report.py`.
- Added a `syn_lookup` mechanism to retrieve specialized SYN analysis data.
- Overrode the displayed timestamp and duration when a matching SYN flow is found.
- Updated the table header to display "First SYN" for SYN flows.

## Verification Results
- **CLI Output:** `Premier SYN: 11:32:48.746`
- **HTML Report (After Fix):** `First SYN: 2026-01-06 11:32:48.746`
- Results are now 100% consistent across interfaces.

## Release Info
- Version: `5.4.5`
- Date: 2026-01-10
- Branch: `main`
- Tag: `v5.4.5`
