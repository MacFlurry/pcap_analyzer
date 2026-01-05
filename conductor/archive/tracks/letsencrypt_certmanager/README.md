# Let's Encrypt + cert-manager Track

## Overview
This track implements automated TLS certificate management for the PCAP Analyzer application using Let's Encrypt and cert-manager on Kubernetes.

## Quick Start

### For Conductor (AI Agent)
1. Read `spec.md` for requirements and architecture
2. Follow `plan.md` step-by-step for implementation
3. Update `product.md` and `tech-stack.md` as needed

### For Humans
```bash
# 1. Install cert-manager
./scripts/setup-letsencrypt.sh

# 2. Deploy application with TLS
helm upgrade --install pcap-analyzer ./helm-chart/pcap-analyzer \
  --namespace pcap-analyzer \
  --create-namespace \
  --set image.tag=v5.0.0-rc1 \
  --set ingress.tls.enabled=true \
  --set ingress.tls.issuer=letsencrypt-production

# 3. Verify certificate
kubectl get certificate -n pcap-analyzer
curl -v https://pcaplab.com
```

## Important Answers to Your Questions

### "Does deleting the cluster mean I get a new certificate?"
**YES!** This is the beauty of cert-manager:

1. **You delete cluster** → Certificate and all data gone
2. **You recreate cluster** → Fresh Kubernetes cluster
3. **You run setup script** → cert-manager installed
4. **You deploy app** → Ingress created with cert-manager annotations
5. **cert-manager detects missing cert** → Automatically requests new certificate from Let's Encrypt
6. **ACME challenge completes** → New certificate issued (30 seconds to 5 minutes)
7. **HTTPS works** → No manual intervention needed!

**Key Point**: You NEVER need to manually request, renew, or manage certificates. cert-manager does everything automatically.

### Certificate Lifecycle
```
Day 0:   Certificate issued (90-day validity)
Day 60:  cert-manager starts watching for renewal
Day 90:  Certificate expires (but cert-manager renews at Day 60)
```

cert-manager automatically renews certificates **30 days before expiry**.

### Cluster Recreation Example
```bash
# Original cluster
kind create cluster --name pcap-analyzer
# ... setup cert-manager, deploy app ...
# Certificate issued: pcaplab-com-tls (expires 2025-03-26)

# DELETE CLUSTER (simulating disaster/migration)
kind delete cluster --name pcap-analyzer
# Certificate gone! 💀

# RECREATE CLUSTER
kind create cluster --name pcap-analyzer
./scripts/setup-letsencrypt.sh  # Reinstall cert-manager
helm install pcap-analyzer ...  # Deploy app

# cert-manager sees: "Missing certificate for pcaplab.com"
# cert-manager action: Request new certificate from Let's Encrypt
# Result: NEW certificate issued (expires 2025-03-27) ✅
```

## Prerequisites

### DNS Configuration (REQUIRED)
Your domain `pcaplab.com` **must** point to your cluster's external IP:

```bash
# 1. Get cluster external IP
kubectl get svc -n ingress-nginx ingress-nginx-controller

# 2. Configure DNS A record
# Provider: Cloudflare, Route53, etc.
Type:  A
Name:  @ (or pcaplab.com)
Value: <EXTERNAL_IP>
TTL:   300

# 3. Verify DNS
dig pcaplab.com +short
# Should return: <EXTERNAL_IP>
```

**Without DNS pointing to your cluster, certificate issuance will FAIL** (Let's Encrypt can't reach your cluster for ACME challenge).

### Port 80 Accessibility (REQUIRED)
Let's Encrypt uses HTTP-01 challenge on port 80:

```bash
# Verify port 80 is accessible
curl -I http://pcaplab.com/.well-known/acme-challenge/test
```

If blocked by firewall → Certificate issuance will fail.

## Testing Strategy

### 1. Always Test with Staging First
```bash
# Use staging issuer (high rate limits, fake certs)
--set ingress.tls.issuer=letsencrypt-staging
```

Why? Production has strict rate limits:
- **50 certificates per week per domain**
- If you hit the limit → **7-day lockout**

### 2. Verify Staging Certificate
```bash
kubectl get certificate -n pcap-analyzer
# Should show: Ready=True

curl -v https://pcaplab.com 2>&1 | grep issuer
# Should show: issuer=Fake LE Intermediate X1
```

Browser will show warning (expected - it's a test cert).

### 3. Switch to Production
```bash
# Use production issuer (strict rate limits, real certs)
--set ingress.tls.issuer=letsencrypt-production
```

### 4. Verify Production Certificate
```bash
curl -v https://pcaplab.com 2>&1 | grep issuer
# Should show: issuer=Let's Encrypt Authority X3

# Browser should show: 🔒 Connection is secure
```

## Files Created by This Track

```
k8s/cert-manager/
├── clusterissuer-staging.yaml      # Staging issuer (testing)
└── clusterissuer-production.yaml   # Production issuer (real certs)

scripts/
└── setup-letsencrypt.sh            # Automated setup script

docs/
└── LETSENCRYPT.md                  # User documentation

helm-chart/pcap-analyzer/
├── values.yaml                     # Updated with TLS config
└── templates/ingress.yaml          # Updated with cert-manager annotations
```

## Troubleshooting

### Certificate stuck in "Pending"
```bash
# Check why
kubectl describe certificate pcaplab-com-tls -n pcap-analyzer
kubectl describe order -n pcap-analyzer
kubectl describe challenge -n pcap-analyzer

# Common causes:
# - DNS not pointing to cluster
# - Port 80 blocked
# - NGINX ingress not running
```

### HTTP-01 Challenge Fails
```bash
# Test manual HTTP access
curl http://pcaplab.com/.well-known/acme-challenge/test

# If fails:
# 1. Check DNS: dig pcaplab.com
# 2. Check firewall: Allow port 80
# 3. Check ingress: kubectl get ing -n pcap-analyzer
```

### Rate Limit Hit
```bash
# Check issued certificates
# https://crt.sh/?q=pcaplab.com

# If hit limit:
# - Wait 7 days
# - Use staging for testing
```

## Monitoring

### Check Certificate Expiry
```bash
kubectl get certificate -n pcap-analyzer -o yaml | grep notAfter
```

### Monitor Renewal
cert-manager automatically renews at 30 days before expiry. No action needed.

### Health Check
```bash
kubectl get pods -n cert-manager
# All should be Running

kubectl logs -n cert-manager deployment/cert-manager --tail=50
# Should show no errors
```

## Security

- ✅ Private keys stored in Kubernetes Secrets (encrypted at rest)
- ✅ TLS 1.2 and TLS 1.3 only (no SSLv3, TLS 1.0, TLS 1.1)
- ✅ Force HTTPS redirect (HTTP → HTTPS)
- ✅ HSTS header (optional, can be added)
- ✅ Certificate auto-renewal (no expired certs)

## Cost

**FREE** 🎉
- Let's Encrypt: Free certificates
- cert-manager: Open-source software
- Renewal: Automated (no manual work)

## Next Steps

1. Review `spec.md` for detailed requirements
2. Follow `plan.md` for step-by-step implementation
3. Run `./scripts/setup-letsencrypt.sh` to install cert-manager
4. Deploy app with TLS enabled
5. Verify HTTPS working on https://pcaplab.com
6. Test cluster recreation to verify auto-reissuance

## Support

- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Troubleshooting Guide](https://cert-manager.io/docs/troubleshooting/)
