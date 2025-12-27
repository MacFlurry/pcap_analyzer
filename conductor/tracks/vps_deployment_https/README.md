# Track: Production VPS Deployment with HTTPS

## Overview
This track manages the deployment of PCAP Analyzer to a production VPS with public IP, enabling Let's Encrypt HTTPS.

## Status
**Blocked**: Waiting for VPS provisioning with public IP

## Files in This Track

### `plan.md`
Main implementation plan with phases and checklists.

### `www-redirect-config.md`
Detailed configuration guide for www.pcaplab.com → pcaplab.com redirect:
- DNS configuration (both A records)
- Helm chart updates
- NGINX Ingress redirect annotation
- Testing procedures
- Troubleshooting guide

## Current Blockers

1. **Infrastructure**: No VPS with public IP available yet
2. **DNS**: Cannot configure `pcaplab.com` DNS until VPS IP is known
3. **Let's Encrypt**: Requires publicly accessible IP for HTTP-01 challenge

## What's Ready

✅ **cert-manager**: Scripts and manifests ready
✅ **Helm Chart**: TLS support configured
✅ **Documentation**: Complete setup guides
✅ **WWW Redirect**: Configuration documented

## What's Needed

⏳ **VPS**: Linux server with public IP
⏳ **DNS Access**: Ability to configure pcaplab.com DNS records
⏳ **Deployment**: Run setup scripts on VPS

## Quick Start (When VPS Available)

```bash
# 1. Configure DNS
# pcaplab.com A → <VPS_IP>
# www.pcaplab.com A → <VPS_IP>

# 2. On VPS: Clone repo
git clone <repo_url>
cd pcap_analyzer

# 3. Install cert-manager
./scripts/setup-letsencrypt.sh

# 4. Update Helm values with www redirect
# (See www-redirect-config.md)

# 5. Deploy application
helm upgrade --install pcap-analyzer ./helm-chart/pcap-analyzer \
  --namespace pcap-analyzer \
  --create-namespace \
  --set ingress.tls.enabled=true \
  --set ingress.tls.issuer=letsencrypt-production

# 6. Verify HTTPS and redirects
curl -I https://pcaplab.com
curl -I https://www.pcaplab.com  # Should redirect to pcaplab.com
```

## Key Features Being Deployed

1. **Automated TLS**: Let's Encrypt certificates via cert-manager
2. **WWW Redirect**: www.pcaplab.com → pcaplab.com (SEO-friendly)
3. **Production Security**: TLS 1.2/1.3, HTTPS enforcement
4. **Zero-Touch Certs**: Automatic renewal every 60 days

## Success Criteria

- [ ] VPS provisioned and accessible
- [ ] DNS configured for both domains
- [ ] cert-manager installed and running
- [ ] Application deployed with TLS enabled
- [ ] HTTPS working on both domains
- [ ] WWW redirect working (HTTP 301)
- [ ] Certificate valid and covers both domains

## Notes

- Production deployment unlocks final release promotion
- Let's Encrypt staging issuer available for testing