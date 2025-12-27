# Track: Deploy to VPS & Promote to v5.0.0 Stable

**Goal:** Deploy the application to a production VPS with a public IP, enable Let's Encrypt for `pcaplab.com`, and promote the release to `v5.0.0`.

**Status:** Pending (Blocked by Infrastructure)

## Context
The project is currently at `v5.0.0-rc2`. The code is feature-complete for v5.0.0, including automated TLS support via cert-manager. However, actual TLS certificate issuance requires a public IP and DNS configuration, which are not available in the current local environment.

**Current Version:** `v5.0.0-rc2`
**Target Version:** `v5.0.0`

## Prerequisites
- [ ] **VPS Provisioning**: A Linux VPS (Ubuntu/Debian) with public IP.
- [ ] **DNS Configuration**:
  - `pcaplab.com` A record pointing to the VPS IP
  - `www.pcaplab.com` A record pointing to the VPS IP (for www redirect)
- [ ] **Port Access**: Ports 80 and 443 open.

## Implementation Plan

### Phase 1: Infrastructure Setup
- [ ] **Provision VPS**: Install Docker, K3s/MicroK8s/Kind, Helm.
- [ ] **Clone Repository**: Clone `pcap_analyzer` repo.
- [ ] **Configure DNS**: Point domain to VPS.

### Phase 2: Deployment & TLS
- [ ] **Configure WWW Redirect**: Update Helm chart per `www-redirect-config.md`.
- [ ] **Run Setup Script**: Execute `scripts/setup-letsencrypt.sh`.
- [ ] **Deploy App**: Helm install with production issuer enabled (both domains).
- [ ] **Verify HTTPS**: Confirm valid Let's Encrypt certificate covers both domains.
- [ ] **Test Redirects**: Verify `www.pcaplab.com` → `pcaplab.com` (HTTP 301).

### Phase 3: Release Promotion
- [ ] **Version Bump**: Update `src/__version__.py` to `5.0.0`.
- [ ] **Chart Update**: Update `Chart.yaml` appVersion to `5.0.0`.
- [ ] **Changelog**: Finalize `CHANGELOG.md` for `v5.0.0`.
- [ ] **Tag**: Git tag `v5.0.0`.
