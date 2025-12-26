# Specification: Version Synchronization v5.0.0-rc2

**Track ID:** `version_sync_v5_0_0_rc2`
**Type:** Release Engineering

## Overview
This track addresses version inconsistencies between the application code, Helm chart, and deployment configurations. It establishes `v5.0.0-rc2` as the new unified version, incorporating recent security hardening and Let's Encrypt features.

## Target Version
**Version:** `5.0.0-rc2`

## Affected Files

### 1. Application Code
- **File:** `src/__version__.py`
- **Value:** `__version__ = "5.0.0-rc2"`

### 2. Helm Chart Definition
- **File:** `helm-chart/pcap-analyzer/Chart.yaml`
- **Field `appVersion`:** `5.0.0-rc2` (Application version)
- **Field `version`:** `1.2.0-rc2` (Chart version)
    - *Rationale:* Previous was 1.1.3 (implied from logs/context). Bumping minor for significant feature additions (cert-manager). Using -rc2 suffix to match app lifecycle.

### 3. Helm Chart Defaults
- **File:** `helm-chart/pcap-analyzer/values.yaml`
- **Field `image.tag`:** `v5.0.0-rc2`

## Changelog Updates
The `CHANGELOG.md` must be updated to include a new section `[5.0.0-rc2]` summarizing:
- **Feature:** Automated TLS with Let's Encrypt and cert-manager.
- **Security:** Server-side route protection for HTML pages.
- **Security:** Hybrid Authentication (Header + Cookie) with HttpOnly cookies.
- **Security:** Enhanced logout functionality.
