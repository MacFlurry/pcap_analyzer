# Implementation Plan: Let's Encrypt with cert-manager

## Phase 1: cert-manager Installation (Script Implemented)

### Step 1.1: Install cert-manager CRDs
- [x] Script created: `scripts/setup-letsencrypt.sh`

### Step 1.2: Add cert-manager Helm repository
- [x] Script created: `scripts/setup-letsencrypt.sh`

### Step 1.3: Install cert-manager via Helm
- [x] Script created: `scripts/setup-letsencrypt.sh`

### Step 1.4: Verify installation
- [ ] Run verification commands after deployment

---

## Phase 2: ClusterIssuer Configuration (Files Created)

### Step 2.1: Create staging ClusterIssuer
- [x] File created: `k8s/cert-manager/clusterissuer-staging.yaml`

### Step 2.2: Create production ClusterIssuer
- [x] File created: `k8s/cert-manager/clusterissuer-production.yaml`

### Step 2.3: Apply ClusterIssuers
- [x] Script created: `scripts/setup-letsencrypt.sh`

### Step 2.4: Verify ClusterIssuers
- [ ] Run verification commands after deployment

---

## Phase 3: Helm Chart Updates (Completed)

### Step 3.1: Update `helm-chart/pcap-analyzer/values.yaml`
- [x] Updated TLS configuration structure
- [x] Added Ingress annotations

### Step 3.2: Update `helm-chart/pcap-analyzer/templates/ingress.yaml`
- [x] Updated Ingress template for cert-manager support

### Step 3.3: Test Helm template rendering
- [x] Verified with `helm template`

---

## Phase 4: DNS Configuration (Pending Deployment)

### Step 4.1: Get cluster external IP
- [ ] Pending deployment

### Step 4.2: Configure DNS A record
- [ ] Pending user action (DNS Provider)

### Step 4.3: Verify DNS propagation
- [ ] Pending DNS update

---

## Phase 5: Certificate Issuance (Staging) (Pending Deployment)

### Step 5.1: Deploy with staging issuer
- [ ] Run Helm upgrade command

### Step 5.2: Monitor certificate issuance
- [ ] Verify status

### Step 5.3: Verify staging certificate issued
- [ ] Check secret and curl

---

## Phase 6: Certificate Issuance (Production) (Pending Deployment)

### Step 6.1: Switch to production issuer
- [ ] Run Helm upgrade command

### Step 6.2: Monitor production certificate
- [ ] Verify status

### Step 6.3: Verify production certificate
- [ ] Check browser access

---

## Phase 7: Testing & Validation (Pending Deployment)

### Test 7.1: HTTPS Access
- [ ] Verify

### Test 7.2: Certificate Details
- [ ] Verify

### Test 7.3: Browser Validation
- [ ] Verify

### Test 7.4: Certificate Renewal Simulation
- [ ] Verify

---

## Phase 8: Cluster Recreation Test (Pending Deployment)

### Test 8.1: Delete cluster
- [ ] Run command

### Test 8.2: Recreate cluster
- [ ] Run command

### Test 8.3: Reinstall everything
- [ ] Run setup script

### Test 8.4: Verify automatic certificate issuance
- [ ] Verify

---

## Troubleshooting

See `docs/LETSENCRYPT.md` for troubleshooting steps.

---

## Monitoring & Maintenance

See `docs/LETSENCRYPT.md` for monitoring instructions.

---

## Automation Script

- [x] Created `scripts/setup-letsencrypt.sh`

---

## Files to Create

1. [x] `k8s/cert-manager/clusterissuer-staging.yaml`
2. [x] `k8s/cert-manager/clusterissuer-production.yaml`
3. [x] `scripts/setup-letsencrypt.sh`
4. [x] `docs/LETSENCRYPT.md` (documentation)
5. [x] Updated `helm-chart/pcap-analyzer/values.yaml`
6. [x] Updated `helm-chart/pcap-analyzer/templates/ingress.yaml`

---

## Success Checklist

- [ ] cert-manager installed and running
- [ ] ClusterIssuers created (staging + production)
- [x] Helm chart updated with TLS support
- [ ] DNS configured (pcaplab.com → cluster IP)
- [ ] Staging certificate tested
- [ ] Production certificate issued
- [ ] HTTPS working on https://pcaplab.com
- [ ] HTTP→HTTPS redirect working
- [ ] Browser shows valid certificate
- [ ] Cluster recreation tested
- [x] Documentation completed