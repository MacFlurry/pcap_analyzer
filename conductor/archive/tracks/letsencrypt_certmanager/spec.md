# Track Specification: Let's Encrypt with cert-manager

## Overview
Implement automated TLS certificate management using Let's Encrypt and cert-manager for the official domain `pcaplab.com` on Kubernetes.

## Goals
1. Install and configure cert-manager on Kubernetes cluster
2. Configure Let's Encrypt ClusterIssuer (staging + production)
3. Update Helm chart to support automatic certificate issuance
4. Implement automated certificate renewal (90-day lifecycle)
5. Support cluster recreation with automatic certificate re-issuance

## Scope

### In Scope
- cert-manager installation via Helm
- Let's Encrypt ACME HTTP-01 challenge configuration
- ClusterIssuer for staging (testing) and production
- Ingress annotations for automatic certificate issuance
- DNS configuration validation for pcaplab.com
- Certificate monitoring and renewal automation
- Documentation for cluster recreation scenarios

### Out of Scope
- DNS-01 challenge (only HTTP-01)
- Wildcard certificates (*.pcaplab.com)
- Custom CA certificates
- Certificate backup/restore (not needed - auto-reissue)

## Success Criteria
- [ ] cert-manager installed and operational
- [ ] HTTPS working on https://pcaplab.com with valid Let's Encrypt certificate
- [ ] Certificate automatically renews before expiration (30 days before)
- [ ] New cluster deployments automatically request certificates
- [ ] No manual intervention required for certificate lifecycle
- [ ] Browser shows valid/trusted certificate (not self-signed)

## Technical Requirements

### Prerequisites
1. **DNS Configuration**: pcaplab.com must point to cluster LoadBalancer/Ingress IP
2. **Ingress Controller**: NGINX ingress controller installed
3. **Port 80 accessible**: Required for ACME HTTP-01 challenge
4. **Email**: Valid email for Let's Encrypt notifications

### Architecture
```
Internet (port 80/443)
    ↓
LoadBalancer/Ingress (external IP)
    ↓
NGINX Ingress Controller
    ↓
cert-manager (watches Ingress resources)
    ↓
Let's Encrypt ACME (HTTP-01 challenge)
    ↓
Certificate issued → Kubernetes Secret
    ↓
Ingress uses Secret for TLS
```

### cert-manager Components
1. **ClusterIssuer**: Cluster-wide certificate issuer configuration
2. **Certificate**: Custom resource defining certificate requirements
3. **CertificateRequest**: Automatic resource created by cert-manager
4. **Order**: ACME order tracking
5. **Challenge**: ACME challenge resolution (HTTP-01)

### Let's Encrypt Environments
1. **Staging**: For testing (lenient rate limits, fake certificates)
   - URL: https://acme-staging-v02.api.letsencrypt.org/directory
   - Rate limit: Very high
   - Use for: Testing configuration

2. **Production**: For real certificates (strict rate limits)
   - URL: https://acme-v02.api.letsencrypt.org/directory
   - Rate limit: 50 certificates/domain/week
   - Use for: Production deployment

## Implementation Phases

### Phase 1: cert-manager Installation
- Install cert-manager CRDs
- Deploy cert-manager via Helm
- Verify cert-manager pods running

### Phase 2: ClusterIssuer Configuration
- Create staging ClusterIssuer (testing)
- Create production ClusterIssuer (real certs)
- Configure email for Let's Encrypt notifications

### Phase 3: Helm Chart Updates
- Add cert-manager annotations to Ingress
- Add TLS configuration to Ingress
- Make issuer configurable (staging/production)
- Update values.yaml with TLS options

### Phase 4: DNS Configuration
- Verify pcaplab.com DNS points to cluster IP
- Test DNS resolution
- Document DNS configuration

### Phase 5: Certificate Issuance
- Deploy with staging issuer (test)
- Verify staging certificate issued
- Switch to production issuer
- Verify production certificate issued

### Phase 6: Testing & Validation
- Test HTTPS access: https://pcaplab.com
- Verify certificate details (issuer, expiry, SAN)
- Test HTTP→HTTPS redirect
- Simulate cluster recreation

### Phase 7: Documentation
- Document installation steps
- Document DNS requirements
- Document troubleshooting
- Document cluster recreation workflow

## Cluster Recreation Workflow

When you delete and recreate the cluster:
1. Reinstall cert-manager (automated via Helm)
2. Redeploy ClusterIssuers (automated via Helm)
3. Deploy application with Ingress (automated)
4. cert-manager detects missing certificate
5. **Automatic**: cert-manager requests new certificate from Let's Encrypt
6. **Automatic**: ACME HTTP-01 challenge completed
7. **Automatic**: New certificate issued and stored in Secret
8. **Automatic**: Ingress uses new certificate for TLS

**Key Point**: No manual intervention needed. cert-manager handles everything.

## Security Considerations
- Store Let's Encrypt email in Helm values (not hardcoded)
- Use production issuer only after testing staging
- Monitor rate limits (50 certs/week/domain)
- Certificate private keys stored in Kubernetes Secrets
- Automatic renewal 30 days before expiry

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Hit Let's Encrypt rate limit | No new certificates for 7 days | Test with staging issuer first |
| DNS not pointing to cluster | Certificate issuance fails | Validate DNS before production issuer |
| Port 80 blocked | HTTP-01 challenge fails | Ensure LoadBalancer exposes port 80 |
| cert-manager misconfigured | No automatic renewal | Test renewal in staging environment |

## References
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [ACME HTTP-01 Challenge](https://letsencrypt.org/docs/challenge-types/)
- [cert-manager Helm Chart](https://artifacthub.io/packages/helm/cert-manager/cert-manager)

## Timeline Estimate
- Phase 1-2: 30 minutes (cert-manager installation)
- Phase 3: 1 hour (Helm chart updates)
- Phase 4: Variable (depends on DNS provider)
- Phase 5-6: 1 hour (certificate issuance + testing)
- Phase 7: 1 hour (documentation)

**Total**: ~3-4 hours (excluding DNS propagation time)

## Deliverables
1. cert-manager deployed on Kubernetes
2. ClusterIssuers configured (staging + production)
3. Updated Helm chart with TLS support
4. Documentation: `docs/LETSENCRYPT.md`
5. Working HTTPS on pcaplab.com
6. Certificate lifecycle automation verified
