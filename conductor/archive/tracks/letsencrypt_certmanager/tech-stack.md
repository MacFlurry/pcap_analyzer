# Technical Stack: Let's Encrypt + cert-manager

## Core Technologies

### cert-manager v1.14.0
**Role**: Kubernetes certificate controller

**What it does**:
- Watches Ingress resources for TLS annotations
- Automatically requests certificates from Let's Encrypt
- Manages certificate lifecycle (issuance, renewal, expiry)
- Stores certificates as Kubernetes Secrets
- Renews certificates 30 days before expiry

**Why we use it**:
- ✅ Industry standard for Kubernetes certificate management
- ✅ Fully automated (zero manual intervention)
- ✅ Supports multiple certificate authorities
- ✅ Active development and community support
- ✅ CNCF graduated project

**Architecture**:
```
cert-manager components:
├── cert-manager-controller  (main controller)
├── cert-manager-webhook     (validation webhook)
└── cert-manager-cainjector  (CA injection)
```

**Documentation**: https://cert-manager.io/

---

### Let's Encrypt
**Role**: Free, automated, open Certificate Authority

**What it does**:
- Issues trusted X.509 certificates for HTTPS
- Validates domain ownership via ACME challenges
- Trusted by 99.9% of browsers worldwide
- Rate limits: 50 certificates/domain/week

**Why we use it**:
- ✅ FREE (vs. paid CAs: $50-200/year)
- ✅ Trusted by all major browsers
- ✅ Automated via ACME protocol
- ✅ Short-lived certificates (90 days) = better security
- ✅ Industry standard for automated TLS

**Environments**:
- **Staging**: https://acme-staging-v02.api.letsencrypt.org/directory
  - High rate limits (testing)
  - Issues fake certificates (not trusted)

- **Production**: https://acme-v02.api.letsencrypt.org/directory
  - Strict rate limits (50/week)
  - Issues real certificates (trusted)

**Documentation**: https://letsencrypt.org/docs/

---

### ACME Protocol (RFC 8555)
**Role**: Automated Certificate Management Environment

**What it does**:
- Standard protocol for automated certificate issuance
- Validates domain ownership via challenges
- Supports HTTP-01, DNS-01, TLS-ALPN-01 challenges

**We use**: HTTP-01 challenge
```
1. cert-manager requests certificate from Let's Encrypt
2. Let's Encrypt responds with challenge token
3. cert-manager creates Ingress route: /.well-known/acme-challenge/<token>
4. Let's Encrypt fetches http://pcaplab.com/.well-known/acme-challenge/<token>
5. If token matches → domain validated
6. Let's Encrypt issues certificate
7. cert-manager stores certificate in Kubernetes Secret
```

**Why HTTP-01**:
- ✅ Simple (requires only port 80)
- ✅ Works with any Ingress controller
- ❌ Requires domain accessible from internet
- ❌ Cannot issue wildcard certificates (use DNS-01 for that)

**Documentation**: https://datatracker.ietf.org/doc/html/rfc8555

---

### Kubernetes Ingress
**Role**: HTTP/HTTPS routing and load balancing

**What it does**:
- Exposes HTTP/HTTPS routes to services
- Terminates TLS (HTTPS decryption)
- Uses certificates from Kubernetes Secrets

**Our configuration**:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-production
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - pcaplab.com
    secretName: pcaplab-com-tls  # cert-manager creates this
  rules:
  - host: pcaplab.com
    http:
      paths:
      - path: /
        backend:
          service:
            name: pcap-analyzer
            port: 8000
```

**Key annotations**:
- `cert-manager.io/cluster-issuer`: Tells cert-manager which issuer to use
- `nginx.ingress.kubernetes.io/force-ssl-redirect`: Redirect HTTP→HTTPS
- `nginx.ingress.kubernetes.io/ssl-protocols`: TLS version enforcement

---

### NGINX Ingress Controller
**Role**: Ingress implementation using NGINX

**What it does**:
- Implements Kubernetes Ingress API
- Load balancing
- TLS termination
- HTTP→HTTPS redirect

**Why we use it**:
- ✅ Most popular Ingress controller
- ✅ Production-proven (Netflix, Spotify, etc.)
- ✅ Works seamlessly with cert-manager
- ✅ Rich feature set (rate limiting, auth, etc.)

**Installation**:
```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
```

---

### Helm
**Role**: Kubernetes package manager

**What it does**:
- Manages Kubernetes application deployments
- Templating for Kubernetes manifests
- Version management

**Our usage**:
```bash
# Install cert-manager
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --version v1.14.0

# Install PCAP Analyzer with TLS
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --set ingress.tls.enabled=true \
  --set ingress.tls.issuer=letsencrypt-production
```

---

## Kubernetes Resources

### ClusterIssuer
**Custom Resource**: cert-manager.io/v1

**Purpose**: Cluster-wide certificate issuer configuration

**Example**:
```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-production
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: contact@pcaplab.com
    privateKeySecretRef:
      name: letsencrypt-production-account-key
    solvers:
    - http01:
        ingress:
          class: nginx
```

**Why ClusterIssuer vs Issuer**:
- ✅ ClusterIssuer: Cluster-wide (can be used by any namespace)
- ❌ Issuer: Namespace-scoped (only one namespace)

We use **ClusterIssuer** for flexibility.

---

### Certificate
**Custom Resource**: cert-manager.io/v1

**Purpose**: Represents a certificate request

**Lifecycle**:
1. Ingress with `cert-manager.io/cluster-issuer` annotation created
2. cert-manager automatically creates Certificate resource
3. Certificate resource triggers CertificateRequest
4. CertificateRequest triggers ACME Order
5. Order triggers ACME Challenge
6. Challenge passes → Certificate issued
7. Certificate stored in Secret specified by Ingress

**Automatic creation**: We don't manually create Certificate resources. cert-manager creates them automatically based on Ingress annotations.

---

### Secret
**Kubernetes Resource**: v1

**Purpose**: Stores certificate and private key

**Structure**:
```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/tls
metadata:
  name: pcaplab-com-tls
data:
  tls.crt: <base64-encoded certificate>
  tls.key: <base64-encoded private key>
```

**Security**:
- ✅ Encrypted at rest (Kubernetes encryption)
- ✅ RBAC-protected (only authorized pods can read)
- ✅ Never logged or displayed
- ✅ Automatically rotated on renewal

---

## Certificate Lifecycle

### Issuance (Day 0)
```
1. Ingress created with cert-manager annotation
2. cert-manager detects missing certificate
3. Creates Certificate resource
4. Sends ACME order to Let's Encrypt
5. Let's Encrypt responds with HTTP-01 challenge
6. cert-manager creates temporary Ingress route
7. Let's Encrypt validates challenge
8. Certificate issued (90-day validity)
9. Stored in Kubernetes Secret
10. Ingress uses Secret for TLS
```

**Time**: 30 seconds to 5 minutes

---

### Renewal (Day 60)
```
1. cert-manager monitors certificate expiry
2. At 30 days before expiry, starts renewal
3. Sends ACME order to Let's Encrypt
4. Completes HTTP-01 challenge
5. New certificate issued (90-day validity)
6. Updates Kubernetes Secret
7. NGINX automatically reloads new certificate
8. Zero downtime
```

**Time**: 30 seconds to 5 minutes
**Downtime**: ZERO (hot reload)

---

### Expiry (Day 90)
**Normal case**: Never reaches expiry (renewed at Day 60)

**Failure case**: If renewal fails for 30 days:
- Day 60: Renewal attempt 1 (fails)
- Day 61-89: Retry attempts (exponential backoff)
- Day 90: Certificate expires
- User sees: "Certificate expired" warning

**Mitigation**: Monitor certificate expiry with alerts

---

## Security Architecture

### TLS Configuration
```yaml
# Ingress annotations
nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256:..."
nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
```

**Protocols**:
- ✅ TLS 1.3 (preferred)
- ✅ TLS 1.2 (fallback)
- ❌ TLS 1.1 (disabled)
- ❌ TLS 1.0 (disabled)
- ❌ SSLv3 (disabled)

**Ciphers**: Modern, secure cipher suites only

---

### Certificate Validation
```
Certificate Chain:
├── Root CA: ISRG Root X1 (Internet Security Research Group)
├── Intermediate: Let's Encrypt Authority X3
└── Leaf: pcaplab.com (our certificate)
```

**Trust Chain**:
1. Browser trusts ISRG Root X1 (pre-installed)
2. ISRG Root X1 signs Let's Encrypt Authority X3
3. Let's Encrypt Authority X3 signs pcaplab.com
4. Browser validates chain → Trusted

---

### Private Key Security
- 🔐 **Storage**: Kubernetes Secret (encrypted at rest)
- 🔐 **Access**: RBAC-controlled (only cert-manager and Ingress)
- 🔐 **Rotation**: New key on every renewal (every 60 days)
- 🔐 **Backup**: Not needed (auto-reissue on cluster recreation)
- 🔐 **Algorithm**: RSA 2048-bit or ECDSA P-256

---

## Observability

### Monitoring
```bash
# Certificate status
kubectl get certificate -n pcap-analyzer

# Order status (ACME)
kubectl get order -n pcap-analyzer

# Challenge status (HTTP-01)
kubectl get challenge -n pcap-analyzer

# cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager -f
```

### Metrics (Prometheus)
cert-manager exposes Prometheus metrics:
- `certmanager_certificate_expiration_timestamp_seconds`
- `certmanager_certificate_renewal_timestamp_seconds`
- `certmanager_http_acme_client_request_count`

**Alert example**:
```yaml
- alert: CertificateExpiringSoon
  expr: certmanager_certificate_expiration_timestamp_seconds - time() < 604800
  annotations:
    summary: "Certificate expires in <7 days"
```

---

## Comparison: Alternatives

### Manual Certificates
**Pros**: Full control
**Cons**: Manual renewal, downtime, human error, cost
**Verdict**: ❌ Not recommended

### AWS Certificate Manager (ACM)
**Pros**: Free, automated
**Cons**: AWS-only, vendor lock-in
**Verdict**: ⚠️ Good for AWS, but we use Kubernetes

### HashiCorp Vault
**Pros**: Enterprise features, PKI
**Cons**: Complex, overkill for simple TLS
**Verdict**: ⚠️ Use if you already have Vault

### cert-manager + Let's Encrypt
**Pros**: Free, automated, cloud-agnostic, industry standard
**Cons**: Public CA (not private)
**Verdict**: ✅ Best choice for Kubernetes

---

## Dependencies

### External Dependencies
- **Let's Encrypt API**: https://acme-v02.api.letsencrypt.org
- **DNS**: Domain must point to cluster IP
- **Internet**: Port 80 must be accessible

### Kubernetes Dependencies
- **Ingress Controller**: NGINX Ingress Controller
- **CustomResourceDefinitions**: cert-manager CRDs
- **RBAC**: cert-manager service accounts and roles

### Helm Dependencies
```bash
# cert-manager Helm repository
helm repo add jetstack https://charts.jetstack.io
```

---

## Performance

### Certificate Issuance
- **Time**: 30 seconds to 5 minutes
- **Factors**: DNS propagation, Let's Encrypt API response
- **Retry**: Exponential backoff on failure

### Certificate Renewal
- **Time**: 30 seconds to 5 minutes
- **Frequency**: Every 60 days (30 days before expiry)
- **Downtime**: ZERO (hot reload)

### Resource Usage
```yaml
cert-manager:
  CPU: 10m (request) → 100m (limit)
  Memory: 32Mi (request) → 128Mi (limit)
```

**Impact**: Negligible (<0.1% of cluster resources)

---

## Limitations

### Let's Encrypt Rate Limits
- **50 certificates per domain per week**
- **5 duplicate certificates per week** (same SAN)
- **300 pending authorizations per account**

**Mitigation**: Use staging issuer for testing

### HTTP-01 Challenge Limitations
- ❌ Cannot issue wildcard certificates (use DNS-01)
- ❌ Requires port 80 accessible from internet
- ❌ Requires domain to resolve to cluster IP

---

## Best Practices

### Development
- ✅ Use staging issuer for testing
- ✅ Verify DNS before certificate issuance
- ✅ Test cluster recreation workflow

### Production
- ✅ Use production issuer only after staging works
- ✅ Monitor certificate expiry
- ✅ Set up alerts for certificate issues
- ✅ Document DNS configuration

### Security
- ✅ Use TLS 1.2+ only
- ✅ Force HTTPS redirect
- ✅ Rotate certificates regularly (auto-renewal)
- ✅ Monitor cert-manager logs for suspicious activity

---

## References

### Official Documentation
- [cert-manager](https://cert-manager.io/docs/)
- [Let's Encrypt](https://letsencrypt.org/docs/)
- [ACME RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)
- [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)

### Community Resources
- [cert-manager GitHub](https://github.com/cert-manager/cert-manager)
- [Let's Encrypt Community](https://community.letsencrypt.org/)
- [CNCF cert-manager](https://www.cncf.io/projects/cert-manager/)

### Tools
- [SSL Labs Test](https://www.ssllabs.com/ssltest/) - Test TLS configuration
- [crt.sh](https://crt.sh/) - Certificate transparency logs
- [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/) - Check rate limits
