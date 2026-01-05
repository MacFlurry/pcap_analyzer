# Automated TLS Certificates with Let's Encrypt & cert-manager

This guide describes how to set up, manage, and troubleshoot automated TLS certificates for `pcaplab.com` using [cert-manager](https://cert-manager.io/) and [Let's Encrypt](https://letsencrypt.org/).

## Overview

The setup uses:
- **cert-manager**: Kubernetes controller for certificate management.
- **Let's Encrypt**: Free, automated, and open certificate authority.
- **ACME HTTP-01 Challenge**: Domain validation method (requires port 80).
- **ClusterIssuer**: Cluster-wide configuration for Let's Encrypt (Staging & Production).

## 🚀 Quick Start

### 1. Prerequisite: DNS
Ensure `pcaplab.com` points to your Kubernetes Cluster's LoadBalancer IP (External IP).

```bash
# Verify DNS resolution
dig pcaplab.com +short
```

### 2. Install cert-manager
Run the automated setup script to install cert-manager and configure ClusterIssuers:

```bash
./scripts/setup-letsencrypt.sh
```

### 3. Deploy Application
Deploy the PCAP Analyzer with TLS enabled.

**Staging (Test first!):**
```bash
helm upgrade --install pcap-analyzer ./helm-chart/pcap-analyzer \
  --namespace pcap-analyzer \
  --create-namespace \
  --set ingress.tls.enabled=true \
  --set ingress.tls.issuer=letsencrypt-staging \
  --set ingress.tls.secretName=pcaplab-com-tls-staging
```

**Production (Real certificate):**
```bash
helm upgrade --install pcap-analyzer ./helm-chart/pcap-analyzer \
  --namespace pcap-analyzer \
  --create-namespace \
  --set ingress.tls.enabled=true \
  --set ingress.tls.issuer=letsencrypt-production \
  --set ingress.tls.secretName=pcaplab-com-tls
```

---

## 🔄 Cluster Recreation (Zero Touch)

When you delete and recreate the Kubernetes cluster, certificates are automatically re-issued without manual intervention.

1. **Delete Cluster**: `kind delete cluster` (or cloud equivalent)
2. **Recreate Cluster**: `kind create cluster`
3. **Run Setup**: `./scripts/setup-letsencrypt.sh`
4. **Deploy App**: `helm upgrade --install ...` (as above)

**What happens automatically:**
1. cert-manager starts up.
2. Ingress is created with `cert-manager.io/cluster-issuer` annotation.
3. cert-manager detects missing Secret `pcaplab-com-tls`.
4. cert-manager creates an `Order` with Let's Encrypt.
5. Let's Encrypt verifies domain ownership via HTTP-01 (NGINX intercepts path).
6. Certificate is issued and stored in the Secret.
7. HTTPS is live!

---

## 🛠️ Configuration

### ClusterIssuers
Located in `k8s/cert-manager/`:
- `clusterissuer-staging.yaml`: Uses Let's Encrypt Staging API (Fake certs, high rate limits).
- `clusterissuer-production.yaml`: Uses Let's Encrypt Production API (Real certs, strict rate limits).

### Helm Values
In `helm-chart/pcap-analyzer/values.yaml`:
```yaml
ingress:
  tls:
    enabled: true
    issuer: letsencrypt-production
    secretName: pcaplab-com-tls
```

---

## 🔍 Troubleshooting

### Check Certificate Status
```bash
kubectl get certificate -n pcap-analyzer
kubectl describe certificate pcaplab-com-tls -n pcap-analyzer
```

### Debugging Issuance Flow
If certificate is not `Ready: True`:

1. **Check Order/Challenge**:
   ```bash
   kubectl get order -n pcap-analyzer
   kubectl get challenge -n pcap-analyzer
   ```

2. **Check cert-manager Logs**:
   ```bash
   kubectl logs -n cert-manager -l app=cert-manager
   ```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| **Challenge Pending** | DNS not pointing to cluster | Verify A record for `pcaplab.com`. Check LoadBalancer IP. |
| **404 on Challenge** | NGINX not routing correctly | Ensure Ingress controller is running and `ingressClassName` matches. |
| **Rate Limited** | Too many requests to Prod | Use `letsencrypt-staging` for testing. |
| **Self-Signed Cert** | Deployment not updated | Ensure Helm upgrade used `tls.enabled=true`. |

---

## 🔐 Security Notes

- **Private Keys**: Stored in Kubernetes Secrets (`pcaplab-com-tls`). Backup is not required as they are auto-generated.
- **Renewal**: Automatic 30 days before expiration.
- **Rate Limits**: Production limit is ~50 certs/week/domain. Always test with Staging.
