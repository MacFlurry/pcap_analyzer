# Track: Version Synchronization & v5.0.0-rc2 Release

**Goal:** Synchronize project versions across all files and bump to `v5.0.0-rc2` to include recent security and infrastructure features.

**Status:** Proposed

## Objectives
1.  Bump application version to `v5.0.0-rc2`.
2.  Synchronize Helm Chart version (`appVersion` and `version`).
3.  Synchronize Helm Chart default image tag.
4.  Update `CHANGELOG.md` to reflect `v5.0.0-rc2` and document recent changes.

## Implementation Plan

### Phase 1: Version Updates
- [x] **Update Application Version**: Update `src/__version__.py` to `5.0.0-rc2`.
- [ ] **Update Helm Chart**: Update `helm-chart/pcap-analyzer/Chart.yaml`:
    - `appVersion` -> `5.0.0-rc2`
    - `version` -> `1.2.0` (Bump chart version as well, was `1.1.3`)
- [ ] **Update Helm Values**: Update `helm-chart/pcap-analyzer/values.yaml`:
    - `image.tag` -> `v5.0.0-rc2`

### Phase 2: Changelog
- [x] **Update Changelog**: Add entry for `[5.0.0-rc2]` in `CHANGELOG.md` covering:
    - Automated TLS with Let's Encrypt (cert-manager)
    - Server-side route protection (HTML Auth Hardening)
    - HttpOnly Cookies for session management

### Phase 3: Verification
- [x] **Verify consistency**: Check all files match.
