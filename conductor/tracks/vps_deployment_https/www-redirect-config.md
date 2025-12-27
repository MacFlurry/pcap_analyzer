# WWW Redirect Configuration (www.pcaplab.com → pcaplab.com)

## Goal
Configure automatic HTTP 301 permanent redirect from `www.pcaplab.com` to `pcaplab.com` for SEO optimization and consistent user experience.

## Architecture Decision

**Chosen Solution**: Single Ingress with NGINX redirect annotation

**Why:**
- ✅ Simple configuration (one Ingress resource)
- ✅ One Let's Encrypt certificate covers both domains (SAN)
- ✅ HTTP 301 permanent redirect (SEO-friendly)
- ✅ Preserves URL path: `www.pcaplab.com/history` → `pcaplab.com/history`
- ✅ No additional backend service needed

---

## DNS Configuration

Configure on your DNS provider (Cloudflare, Route53, etc.):

```dns
# Principal domain
Type: A
Name: @ (or pcaplab.com)
Value: <VPS_PUBLIC_IP>
TTL: 300

# WWW subdomain (same IP)
Type: A
Name: www
Value: <VPS_PUBLIC_IP>
TTL: 300
```

**Alternative (CNAME):**
```dns
Type: CNAME
Name: www
Value: pcaplab.com
TTL: 300
```

---

## Helm Chart Updates

### Update: `helm-chart/pcap-analyzer/values.yaml`

Add www host to ingress configuration:

```yaml
ingress:
  enabled: true
  className: "nginx"

  tls:
    enabled: true
    issuer: letsencrypt-production
    secretName: pcaplab-com-tls

  annotations:
    # Force HTTPS redirect
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    # SSL protocols
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    # Proxy body size
    nginx.ingress.kubernetes.io/proxy-body-size: "500m"
    # WWW to non-WWW redirect
    nginx.ingress.kubernetes.io/configuration-snippet: |
      if ($host = 'www.pcaplab.com') {
        return 301 https://pcaplab.com$request_uri;
      }

  hosts:
    # Principal domain (application)
    - host: pcaplab.com
      paths:
        - path: /
          pathType: Prefix

    # WWW domain (will be redirected)
    - host: www.pcaplab.com
      paths:
        - path: /
          pathType: Prefix
```

### Update: `helm-chart/pcap-analyzer/templates/ingress.yaml`

Ensure template supports multiple hosts and TLS configuration:

```yaml
{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "pcap-analyzer.fullname" . }}
  labels:
    {{- include "pcap-analyzer.labels" . | nindent 4 }}
  annotations:
    {{- if .Values.ingress.tls.enabled }}
    # cert-manager annotation for automatic certificate issuance
    cert-manager.io/cluster-issuer: {{ .Values.ingress.tls.issuer }}
    {{- end }}
    {{- with .Values.ingress.annotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  ingressClassName: {{ .Values.ingress.className }}

  {{- if .Values.ingress.tls.enabled }}
  tls:
  - hosts:
    {{- range .Values.ingress.hosts }}
    - {{ .host }}
    {{- end }}
    secretName: {{ .Values.ingress.tls.secretName }}
  {{- end }}

  rules:
  {{- range .Values.ingress.hosts }}
  - host: {{ .host }}
    http:
      paths:
      {{- range .paths }}
      - path: {{ .path }}
        pathType: {{ .pathType }}
        backend:
          service:
            name: {{ include "pcap-analyzer.fullname" $ }}
            port:
              number: 8000
      {{- end }}
  {{- end }}
{{- end }}
```

---

## Let's Encrypt Certificate with SAN

When deployed, cert-manager will automatically request a certificate covering both domains:

```
Certificate:
  Subject: CN=pcaplab.com
  Subject Alternative Names:
    - DNS:pcaplab.com
    - DNS:www.pcaplab.com
  Issuer: Let's Encrypt Authority X3
  Valid: 90 days
```

**Important**: Both domains must be in the `tls.hosts` list for the certificate to cover them.

---

## Deployment Steps (On VPS)

### 1. Update Helm values.yaml

```bash
# Edit values.yaml to add www host
vim helm-chart/pcap-analyzer/values.yaml
```

Add the configuration shown above.

### 2. Deploy with Helm

```bash
helm upgrade --install pcap-analyzer ./helm-chart/pcap-analyzer \
  --namespace pcap-analyzer \
  --create-namespace \
  --set image.tag=v5.0.0 \
  --set ingress.tls.enabled=true \
  --set ingress.tls.issuer=letsencrypt-production
```

### 3. Monitor certificate issuance

```bash
# Watch certificate status
kubectl get certificate -n pcap-analyzer -w

# Check certificate includes both domains
kubectl get certificate pcaplab-com-tls -n pcap-analyzer -o yaml
```

Expected output:
```yaml
spec:
  dnsNames:
  - pcaplab.com
  - www.pcaplab.com
```

---

## Testing & Validation

### Test 1: DNS Resolution

```bash
# Both should resolve to VPS IP
dig pcaplab.com +short
dig www.pcaplab.com +short
```

Expected: Same IP address

### Test 2: HTTP Redirect (www → non-www)

```bash
curl -I http://www.pcaplab.com
```

Expected:
```
HTTP/1.1 301 Moved Permanently
Location: https://pcaplab.com/
```

### Test 3: HTTPS Redirect (www → non-www)

```bash
curl -I https://www.pcaplab.com
```

Expected:
```
HTTP/1.1 301 Moved Permanently
Location: https://pcaplab.com/
```

### Test 4: Path Preservation

```bash
curl -I https://www.pcaplab.com/history
```

Expected:
```
HTTP/1.1 301 Moved Permanently
Location: https://pcaplab.com/history
```

### Test 5: Certificate Validity

```bash
# Check certificate covers both domains
echo | openssl s_client -connect www.pcaplab.com:443 -servername www.pcaplab.com 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

Expected:
```
X509v3 Subject Alternative Name:
    DNS:pcaplab.com, DNS:www.pcaplab.com
```

### Test 6: Browser Test

1. Open browser
2. Navigate to: `http://www.pcaplab.com`
3. Should automatically redirect to: `https://pcaplab.com`
4. Check address bar: Shows `pcaplab.com` (no www)
5. Check certificate: Valid, covers both domains

---

## SEO Considerations

### Canonical URL

The redirect ensures `pcaplab.com` is the canonical URL:

- ✅ All traffic goes to `pcaplab.com`
- ✅ Search engines index `pcaplab.com` (not `www.`)
- ✅ No duplicate content penalty
- ✅ Link juice preserved (301 redirect)

### Additional Meta Tag (Optional)

Add to HTML templates if needed:

```html
<link rel="canonical" href="https://pcaplab.com/" />
```

---

## Alternative Solutions (Not Chosen)

### Option 1: Separate Ingress for Redirect

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pcap-analyzer-www-redirect
  annotations:
    nginx.ingress.kubernetes.io/permanent-redirect: https://pcaplab.com
spec:
  ingressClassName: nginx
  rules:
  - host: www.pcaplab.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: pcap-analyzer
            port:
              number: 8000
```

**Why not chosen:** More complex (2 Ingress resources vs 1)

### Option 2: Cloudflare Page Rule

If using Cloudflare as DNS provider:

```
Page Rule: www.pcaplab.com/*
Action: Forwarding URL (301)
Destination: https://pcaplab.com/$1
```

**Why not chosen:** Vendor lock-in, prefer Kubernetes-native solution

---

## Troubleshooting

### Issue 1: Certificate only covers pcaplab.com

**Symptom**: Browser warning on `www.pcaplab.com`

**Cause**: `www.pcaplab.com` not in Ingress `tls.hosts`

**Fix**:
```bash
kubectl get ingress pcap-analyzer -n pcap-analyzer -o yaml
# Verify both hosts are in tls.hosts list
```

### Issue 2: Redirect not working

**Symptom**: `www.pcaplab.com` serves content instead of redirecting

**Cause**: Missing NGINX configuration snippet

**Fix**:
```bash
kubectl get ingress pcap-analyzer -n pcap-analyzer -o yaml | grep -A5 configuration-snippet
# Should show the redirect rule
```

### Issue 3: DNS not resolving

**Symptom**: `dig www.pcaplab.com` fails

**Cause**: Missing DNS A/CNAME record

**Fix**: Add DNS record on provider

---

## Monitoring

### Check Redirect Rate

Monitor redirect logs in NGINX:

```bash
kubectl logs -n ingress-nginx deployment/ingress-nginx-controller | grep "301.*www.pcaplab.com"
```

### Analytics Integration

If using Google Analytics:

- Redirects are transparent (301 preserves referrer)
- All traffic appears as `pcaplab.com`
- No configuration needed

---

## Success Criteria

- [x] DNS configured for both domains
- [x] Helm chart updated with www host
- [x] NGINX redirect annotation added
- [ ] Certificate covers both domains (verify on VPS)
- [ ] HTTP redirect working (verify on VPS)
- [ ] HTTPS redirect working (verify on VPS)
- [ ] Path preservation working (verify on VPS)
- [ ] Browser shows canonical URL (verify on VPS)

---

## References

- [NGINX Ingress Annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)
- [cert-manager SAN Certificates](https://cert-manager.io/docs/usage/certificate/#creating-certificate-resources)
- [Google SEO: 301 Redirects](https://developers.google.com/search/docs/crawling-indexing/301-redirects)
- [HTTP 301 Specification](https://datatracker.ietf.org/doc/html/rfc7231#section-6.4.2)
