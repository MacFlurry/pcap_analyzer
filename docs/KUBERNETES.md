# Architecture Kubernetes - PCAP Analyzer

## Vue d'ensemble

PCAP Analyzer peut être déployé sur Kubernetes via un **Helm chart** pour bénéficier des fonctionnalités de production : health probes, resource management, persistent storage, et monitoring.

**Version actuelle :** v4.21.0 (Production Ready - Score de sécurité 91.5%)

> 🔒 **Sécurité :** Cette application bénéficie d'un score de sécurité de **91.5%** avec conformité 100% aux standards OWASP ASVS 5.0, NIST SP 800-53 Rev. 5, CWE Top 25 (2025), et GDPR. Voir [SECURITY.md](../SECURITY.md) pour les détails complets de l'architecture de sécurité.

**⚠️ Limitation actuelle :** 1 replica seulement (architecture monoposte avec SQLite + stockage local)

## Architecture Kubernetes

### Composants déployés

```
┌─────────────────────────────────────────────────┐
│            Kubernetes Cluster                    │
│                                                  │
│  ┌────────────────────────────────────────────┐ │
│  │         Namespace: pcap-analyzer           │ │
│  │                                            │ │
│  │  ┌──────────────────────────────────┐     │ │
│  │  │  Service (NodePort)              │     │ │
│  │  │  • Type: NodePort                │     │ │
│  │  │  • Port: 8000                    │     │ │
│  │  │  • NodePort: 30080               │     │ │
│  │  └───────────┬──────────────────────┘     │ │
│  │              │                             │ │
│  │              ▼                             │ │
│  │  ┌──────────────────────────────────┐     │ │
│  │  │  Deployment (1 replica)          │     │ │
│  │  │  ┌────────────────────────────┐  │     │ │
│  │  │  │  Pod: pcap-analyzer        │  │     │ │
│  │  │  │  • Image: pcap-analyzer    │  │     │ │
│  │  │  │  • Resources: 1-4 CPU      │  │     │ │
│  │  │  │  •           1-4 Gi RAM    │  │     │ │
│  │  │  │  • Liveness probe          │  │     │ │
│  │  │  │  • Readiness probe         │  │     │ │
│  │  │  └────────┬───────────────────┘  │     │ │
│  │  └───────────┼──────────────────────┘     │ │
│  │              │                             │ │
│  │              ▼                             │ │
│  │  ┌──────────────────────────────────┐     │ │
│  │  │  PersistentVolumeClaim           │     │ │
│  │  │  • Size: 10Gi                    │     │ │
│  │  │  • AccessMode: ReadWriteOnce     │     │ │
│  │  │  • StorageClass: standard        │     │ │
│  │  │  • Mounted: /data                │     │ │
│  │  └──────────────────────────────────┘     │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

## Helm Chart - Structure

### Templates Kubernetes

```
helm-chart/pcap-analyzer/
├── Chart.yaml              # Métadonnées (nom, version, description)
├── values.yaml             # Configuration par défaut
├── templates/
│   ├── deployment.yaml     # Deployment avec 1 replica
│   ├── service.yaml        # Service NodePort
│   ├── pvc.yaml           # PersistentVolumeClaim
│   ├── _helpers.tpl       # Fonctions helpers Helm
│   └── NOTES.txt          # Instructions post-install
└── README.md              # Documentation Helm
```

### Chart.yaml

```yaml
apiVersion: v2
name: pcap-analyzer
description: Network packet capture analysis tool
type: application
version: 1.0.2
appVersion: "4.21.0"
```

**Justification :**
- `apiVersion: v2` : Helm 3 (pas de Tiller, plus sécurisé)
- `type: application` : Chart d'application (vs library)
- `version` : Version du chart (SemVer)
- `appVersion` : Version de l'app packagée

## Deployment - Configuration détaillée

### Replica count

```yaml
# values.yaml
replicaCount: 1  # ⚠️ Ne pas augmenter
```

**Pourquoi 1 replica seulement ?**

1. **SQLite** : Base de données fichier local
   - Pas de locking distribué
   - Corruptions si accès concurrent depuis plusieurs pods

2. **PVC ReadWriteOnce** : Montage sur 1 seul node
   - 2 pods sur nodes différents → conflit
   - ReadWriteMany coûteux (NFS, CephFS)

3. **APScheduler** : Queue en mémoire
   - Pas de partage entre pods
   - 2 pods = 2 queues indépendantes = doublons

**Migration vers multi-replicas :** Voir section "Migration" plus bas

### Health Probes

```yaml
# templates/deployment.yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: http
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /api/health
    port: http
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

**Différence liveness vs readiness :**

| Probe | Rôle | Échec → Action |
|-------|------|----------------|
| **Liveness** | Application vivante ? | Restart pod |
| **Readiness** | Prêt pour trafic ? | Retirer du service |

**Timeline démarrage :**

```
T+0s   : Pod créé
T+10s  : Readiness check commence
T+15s  : Readiness OK → Pod ajouté au Service
T+30s  : Liveness check commence
T+30s+ : Checks périodiques (liveness: 10s, readiness: 5s)
```

**Endpoint /api/health :**

```python
@router.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "4.21.0",
        "uptime_seconds": time.time() - start_time,
        "active_analyses": worker.get_active_count(),
        "queue_size": worker.get_queue_size(),
        "disk_space_gb": shutil.disk_usage("/data").free / (1024**3)
    }
```

**Scénarios :**
- **Startup lent** : Readiness fail → pod pas de trafic → app démarre tranquillement
- **OOM imminent** : Liveness fail → restart avant crash
- **Analyse lourde** : Readiness fail temporaire → trafic redirigé

### Resource Management

```yaml
# values.yaml
resources:
  limits:
    memory: 4Gi
    cpu: "2"
  requests:
    memory: 1Gi
    cpu: "1"
```

**Justification :**

| Resource | Request | Limit | Raison |
|----------|---------|-------|--------|
| Memory | 1Gi | 4Gi | Baseline 1G, pics 4G pour gros PCAP |
| CPU | 1 core | 2 cores | Analyse utilise 1-2 cores max |

**QoS Class :** `Burstable` (requests < limits)
- Permet bursts pour analyses ponctuelles
- Évite OOM sur pics de charge

**Monitoring :**
```bash
# Utilisation réelle
kubectl top pod -n pcap-analyzer

# Résultat typique
NAME                             CPU   MEMORY
pcap-analyzer-7d5d644f84-69wrl  150m  256Mi
```

**Tuning :**
```bash
# Augmenter pour gros fichiers (>500 MB)
helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer \
  --set resources.limits.memory=8Gi \
  --namespace pcap-analyzer
```

### Environment Variables

```yaml
env:
  - name: MAX_UPLOAD_SIZE_MB
    value: "500"
  - name: REPORT_TTL_HOURS
    value: "24"
  - name: DATA_DIR
    value: "/data"
  - name: LOG_LEVEL
    value: "INFO"
  - name: MAX_QUEUE_SIZE
    value: "5"
```

**Templating Helm :**
```yaml
# templates/deployment.yaml
env:
  - name: MAX_UPLOAD_SIZE_MB
    value: "{{ .Values.env.maxUploadSizeMB }}"
  - name: LOG_LEVEL
    value: "{{ .Values.env.logLevel }}"
```

**Override :**
```bash
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --set env.logLevel=DEBUG \
  --set env.maxUploadSizeMB=1000
```

## Service - Exposition

### NodePort Configuration

```yaml
# values.yaml
service:
  type: NodePort
  port: 8000
  nodePort: 30080
```

**Justification :**
- **NodePort** : Simple, pas d'Ingress Controller requis
- **Port 30080** : Dans range NodePort (30000-32767)
- **Port 8000** : Port interne du container

**Alternatives rejetées :**

| Type | Raison rejetée |
|------|----------------|
| **ClusterIP** | Pas d'accès externe (nécessite port-forward) |
| **LoadBalancer** | Coûteux, overkill pour 1 replica, dépend du cloud provider |
| **Ingress** | Complexe pour usage simple, nécessite Ingress Controller |

**Accès :**

```bash
# kind avec port mapping
http://localhost:8000

# Cluster standard
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[0].address}')
curl http://$NODE_IP:30080/api/health
```

### Migration future : Ingress

```yaml
# Pour production avec TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: pcap-analyzer
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/proxy-body-size: "500m"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - pcap.example.com
      secretName: pcap-tls
  rules:
    - host: pcap.example.com
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

## Storage - PersistentVolumeClaim

### Configuration

```yaml
# values.yaml
persistence:
  enabled: true
  accessMode: ReadWriteOnce
  size: 10Gi
  storageClass: standard
```

**Justification :**

| Paramètre | Valeur | Raison |
|-----------|--------|--------|
| `accessMode` | ReadWriteOnce | Montage sur 1 node seulement (1 replica) |
| `size` | 10Gi | ~100 uploads de 50 MB + rapports |
| `storageClass` | standard | StorageClass par défaut kind/GKE |

**Structure montée :**
```
/data/
├── pcap_analyzer.db          # SQLite (~10 MB)
├── uploads/                  # PCAP files (~5 GB)
│   ├── task1.pcap
│   └── task2.pcap
└── reports/                  # HTML + JSON (~5 GB)
    ├── task1.html
    ├── task1.json
    ├── task2.html
    └── task2.json
```

### StorageClass par provider

| Provider | StorageClass | Backing |
|----------|--------------|---------|
| **kind** | standard | hostPath (local disk) |
| **GKE** | standard | pd-standard (Google Persistent Disk) |
| **EKS** | gp2 | EBS (AWS Elastic Block Store) |
| **AKS** | default | Azure Disk |

**Lister disponibles :**
```bash
kubectl get storageclass
```

**Utiliser classe spécifique :**
```bash
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --set persistence.storageClass=fast-ssd
```

### Backup et Restore

**Backup :**
```bash
# Créer snapshot avec kubectl
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- \
  tar czf - /data > backup-$(date +%Y%m%d).tar.gz
```

**Restore :**
```bash
# Restaurer dans nouveau PVC
kubectl cp backup-20251213.tar.gz \
  pcap-analyzer/pcap-analyzer-xxx:/tmp/

kubectl exec -n pcap-analyzer pcap-analyzer-xxx -- \
  tar xzf /tmp/backup-20251213.tar.gz -C /
```

**Alternative : Volume Snapshots (si supporté)**
```yaml
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: pcap-data-snapshot
spec:
  volumeSnapshotClassName: csi-snapclass
  source:
    persistentVolumeClaimName: pcap-analyzer
```

## Déploiement sur kind (local)

### Création cluster avec port mapping

```bash
cat <<EOF | kind create cluster --name pcap-analyzer --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080  # NodePort dans le cluster
    hostPort: 8000        # Port sur localhost
    protocol: TCP
EOF
```

**Mapping :**
```
Browser (localhost:8000)
    ↓
Docker port forward (8000→30080)
    ↓
kind node (30080)
    ↓
Kubernetes Service NodePort (30080→8000)
    ↓
Pod pcap-analyzer (8000)
```

### Chargement image Docker

```bash
# Build image
docker build -t pcap-analyzer:latest .

# Load dans kind (pas de registry)
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# Vérifier
docker exec -it pcap-analyzer-control-plane crictl images | grep pcap
```

**Pourquoi `pullPolicy: Never` ?**
```yaml
# values.yaml
image:
  pullPolicy: Never  # Pour kind, image déjà chargée
```

Si `pullPolicy: Always` → erreur `ErrImagePull` (pas de registry)

### Installation Helm

```bash
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --create-namespace \
  --namespace pcap-analyzer \
  --wait \
  --timeout 5m
```

**Flags :**
- `--create-namespace` : Crée namespace si inexistant
- `--wait` : Attend que pod soit Ready
- `--timeout 5m` : Échec si pas ready en 5min

**Vérification :**
```bash
# Tous les objets
kubectl get all -n pcap-analyzer

# Résultat attendu
NAME                                 READY   STATUS    RESTARTS   AGE
pod/pcap-analyzer-7d5d644f84-69wrl   1/1     Running   0          2m

NAME                    TYPE       CLUSTER-IP     EXTERNAL-IP   PORT(S)
service/pcap-analyzer   NodePort   10.96.169.81   <none>        8000:30080/TCP

NAME                            READY   UP-TO-DATE   AVAILABLE
deployment.apps/pcap-analyzer   1/1     1            1

NAME                                       DESIRED   CURRENT   READY
replicaset.apps/pcap-analyzer-7d5d644f84   1         1         1
```

## Gestion du cycle de vie

### Updates

```bash
# 1. Rebuild image avec nouveau tag
docker build -t pcap-analyzer:v1.1.0 .

# 2. Charger dans kind
kind load docker-image pcap-analyzer:v1.1.0 --name pcap-analyzer

# 3. Upgrade Helm
helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer \
  --set image.tag=v1.1.0 \
  --namespace pcap-analyzer

# 4. Vérifier rolling update
kubectl rollout status deployment/pcap-analyzer -n pcap-analyzer
```

**Rollback si problème :**
```bash
# Revenir à version précédente
helm rollback pcap-analyzer -n pcap-analyzer

# Ou version spécifique
helm rollback pcap-analyzer 2 -n pcap-analyzer
```

### Scaling (impossible actuellement)

```bash
# ⚠️ Ne fonctionne pas (voir limitations)
kubectl scale deployment/pcap-analyzer --replicas=3 -n pcap-analyzer
# → 2/3 pods crashloop (SQLite lock, PVC RWO)
```

**Pour scaler :** Voir section Migration

### Monitoring

```bash
# Logs temps réel
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f

# Depuis timestamp
kubectl logs -n pcap-analyzer deployment/pcap-analyzer --since=1h

# Logs du container précédent (si crashloop)
kubectl logs -n pcap-analyzer deployment/pcap-analyzer --previous

# Événements
kubectl get events -n pcap-analyzer --sort-by='.lastTimestamp'

# Métriques (nécessite metrics-server)
kubectl top pod -n pcap-analyzer
```

### Debugging

```bash
# Décrire pod (voir events, status)
kubectl describe pod -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer

# Shell dans le pod
kubectl exec -it -n pcap-analyzer deployment/pcap-analyzer -- /bin/sh

# Test health check
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- \
  python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/api/health').read())"

# Port forward (si NodePort inaccessible)
kubectl port-forward -n pcap-analyzer svc/pcap-analyzer 8000:8000
```

## Sécurité

### Sécurité applicative (v4.21.0)

L'application PCAP Analyzer intègre des contrôles de sécurité robustes (score 91.5%, production ready) :

| Couche | Protection | Standard |
|--------|------------|----------|
| **Input Validation** | PCAP magic number, file size checks (10 GB max) | OWASP ASVS 5.2.2, CWE-434 |
| **Decompression Bomb** | Ratio monitoring (1000:1 warning, 10000:1 critical) | OWASP ASVS 5.2.3, CWE-770 |
| **Resource Limits** | OS-level limits (4 GB RAM, 3600s CPU) | NIST SC-5, CWE-770 |
| **Error Handling** | Stack trace removal, path sanitization | CWE-209, NIST SI-10/11 |
| **PII Redaction** | IP/MAC/credentials redaction in logs | GDPR, CWE-532 |
| **Audit Logging** | 50+ security event types, SIEM-ready | NIST AU-2, AU-3 |

**Modules de sécurité :**
- `src/utils/file_validator.py` - Validation PCAP
- `src/utils/decompression_monitor.py` - Protection bombs
- `src/utils/resource_limits.py` - Limites OS
- `src/utils/error_sanitizer.py` - Sanitization
- `src/utils/pii_redactor.py` - Redaction PII
- `src/utils/audit_logger.py` - Audit trail

📖 Documentation complète : [SECURITY.md](../SECURITY.md) | [docs/security/](security/)

### Sécurité Kubernetes

**Bonnes pratiques implémentées :**

```yaml
# Non-root user dans le pod
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

# Pod Security Standards
podSecurityContext:
  seccompProfile:
    type: RuntimeDefault

# Container Security
containerSecurityContext:
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: false  # /data nécessite écriture
```

**Network Policies (recommandé pour production) :**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pcap-analyzer
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: pcap-analyzer
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8000
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 53  # DNS seulement
```

## Migration vers architecture distribuée

### Limitations actuelles

| Composant | Limitation | Impact |
|-----------|------------|--------|
| SQLite | Base locale, pas de locking distribué | 1 replica max |
| PVC RWO | Montage sur 1 node seulement | 1 pod max |
| APScheduler | Queue en mémoire | Perdue au restart |

### Architecture cible (multi-replicas)

```yaml
# values-distributed.yaml
replicaCount: 3

database:
  type: postgresql
  host: postgres.default.svc.cluster.local
  port: 5432
  name: pcap_analyzer

storage:
  type: s3
  endpoint: minio.default.svc.cluster.local
  bucket: pcap-reports

queue:
  type: celery
  broker: redis://redis.default.svc.cluster.local:6379/0
```

### Composants à ajouter

#### 1. PostgreSQL (base partagée)

```bash
# Installer via Helm
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgres bitnami/postgresql \
  --set auth.database=pcap_analyzer \
  --set primary.persistence.size=20Gi
```

**Schema migration :**
```sql
-- SQLite actuel
CREATE TABLE tasks (...);

-- PostgreSQL (identique, mais avec transactions ACID)
CREATE TABLE tasks (...);
```

#### 2. MinIO ou S3 (stockage distribué)

```bash
# MinIO local
helm install minio bitnami/minio \
  --set auth.rootUser=admin \
  --set auth.rootPassword=password \
  --set defaultBuckets=pcap-reports
```

**Code change :**
```python
# Avant (local)
with open(f"/data/uploads/{task_id}.pcap", "wb") as f:
    f.write(content)

# Après (S3)
s3_client.upload_fileobj(
    content,
    bucket="pcap-reports",
    key=f"uploads/{task_id}.pcap"
)
```

#### 3. Redis + Celery (queue distribuée)

```bash
# Redis
helm install redis bitnami/redis

# Code Celery
from celery import Celery

celery_app = Celery('tasks', broker='redis://redis:6379/0')

@celery_app.task
def analyze_pcap_task(task_id: str):
    # Worker démarre sur n'importe quel replica
    analyze_pcap(task_id)
```

### Ingress avec TLS

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-body-size: "500m"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [pcap.example.com]
      secretName: pcap-tls
  rules:
    - host: pcap.example.com
      http:
        paths:
          - path: /
            backend:
              service:
                name: pcap-analyzer
                port: 8000
```

## Ressources

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Helm Documentation](https://helm.sh/docs/)
- [kind - local Kubernetes](https://kind.sigs.k8s.io/)
- [Chart README complet](../helm-chart/pcap-analyzer/README.md)
- [Architecture globale](ARCHITECTURE.md)
- [Architecture Docker](DOCKER.md)
