# PCAP Analyzer - Helm Chart

Chart Helm pour déployer PCAP Analyzer sur un cluster Kubernetes.

## Prérequis

- Kubernetes 1.19+
- Helm 3.0+
- PersistentVolume disponible (si `persistence.enabled=true`)
- Image Docker `pcap-analyzer:latest` chargée dans le cluster

## Installation

### Installation rapide avec kind (local)

```bash
# 1. Créer un cluster kind avec port mapping
cat <<EOF | kind create cluster --name pcap-analyzer --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: 8000
    protocol: TCP
EOF

# 2. Build et charger l'image
docker build -t pcap-analyzer:latest ../../
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# 3. Installer le chart
helm install pcap-analyzer . \
  --create-namespace \
  --namespace pcap-analyzer

# 4. Vérifier le déploiement
kubectl get all -n pcap-analyzer
```

Accéder à l'application: `http://localhost:8000`

### Installation sur cluster Kubernetes existant

```bash
# Si l'image n'est pas dans un registry public, chargez-la:
# docker tag pcap-analyzer:latest your-registry/pcap-analyzer:latest
# docker push your-registry/pcap-analyzer:latest

helm install pcap-analyzer . \
  --namespace pcap-analyzer \
  --create-namespace \
  --set image.repository=your-registry/pcap-analyzer \
  --set image.pullPolicy=Always
```

## Configuration

### Paramètres principaux

| Paramètre | Description | Valeur par défaut |
|-----------|-------------|-------------------|
| `replicaCount` | Nombre de replicas (**limité à 1**) | `1` |
| `image.repository` | Repository de l'image Docker | `pcap-analyzer` |
| `image.tag` | Tag de l'image | `latest` |
| `image.pullPolicy` | Politique de pull de l'image | `Never` (pour kind) |
| `service.type` | Type de service Kubernetes | `NodePort` |
| `service.port` | Port interne du service | `8000` |
| `service.nodePort` | Port NodePort exposé | `30080` |
| `persistence.enabled` | Activer le stockage persistant | `true` |
| `persistence.size` | Taille du PVC | `10Gi` |
| `persistence.storageClass` | StorageClass à utiliser | `standard` |
| `resources.limits.memory` | Limite mémoire | `4Gi` |
| `resources.limits.cpu` | Limite CPU | `2` |
| `resources.requests.memory` | Requête mémoire | `1Gi` |
| `resources.requests.cpu` | Requête CPU | `1` |

### Variables d'environnement de l'application

| Paramètre | Description | Valeur par défaut |
|-----------|-------------|-------------------|
| `env.maxUploadSizeMB` | Taille max upload PCAP (MB) | `500` |
| `env.reportTTLHours` | Durée de rétention des rapports (heures) | `24` |
| `env.dataDir` | Répertoire de données dans le pod | `/data` |
| `env.logLevel` | Niveau de log (DEBUG/INFO/WARNING/ERROR) | `INFO` |
| `env.maxQueueSize` | Taille max de la queue d'analyse | `5` |

## Exemples d'utilisation

### Modifier la taille du stockage

```bash
helm install pcap-analyzer . \
  --set persistence.size=20Gi \
  --namespace pcap-analyzer
```

### Augmenter les ressources

```bash
helm install pcap-analyzer . \
  --set resources.limits.memory=8Gi \
  --set resources.limits.cpu=4 \
  --namespace pcap-analyzer
```

### Utiliser un fichier de valeurs personnalisé

Créer un fichier `my-values.yaml`:

```yaml
replicaCount: 1

image:
  repository: my-registry/pcap-analyzer
  tag: v1.0.0
  pullPolicy: Always

service:
  type: LoadBalancer  # Pour cloud provider avec LB

persistence:
  size: 50Gi
  storageClass: fast-ssd

resources:
  limits:
    memory: 8Gi
    cpu: 4
  requests:
    memory: 2Gi
    cpu: 2

env:
  maxUploadSizeMB: "1000"
  reportTTLHours: "48"
  logLevel: "DEBUG"
```

Installer avec:

```bash
helm install pcap-analyzer . -f my-values.yaml --namespace pcap-analyzer
```

## Gestion du déploiement

### Vérifier le statut

```bash
# Tous les objets
kubectl get all -n pcap-analyzer

# Pods uniquement
kubectl get pods -n pcap-analyzer

# PVC
kubectl get pvc -n pcap-analyzer

# Événements
kubectl get events -n pcap-analyzer --sort-by='.lastTimestamp'
```

### Voir les logs

```bash
# Logs en temps réel
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f

# Logs des 100 dernières lignes
kubectl logs -n pcap-analyzer deployment/pcap-analyzer --tail=100
```

### Health check

```bash
# Via kubectl exec
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- curl -s localhost:8000/api/health

# Via port-forward (si NodePort non accessible)
kubectl port-forward -n pcap-analyzer svc/pcap-analyzer 8000:8000 &
curl http://localhost:8000/api/health
```

### Mettre à jour l'application

```bash
# 1. Rebuild l'image avec un nouveau tag
docker build -t pcap-analyzer:v1.0.1 ../../

# 2. Charger dans kind (si kind)
kind load docker-image pcap-analyzer:v1.0.1 --name pcap-analyzer

# 3. Upgrade avec Helm
helm upgrade pcap-analyzer . \
  --set image.tag=v1.0.1 \
  --namespace pcap-analyzer

# Ou redémarrer le déploiement (si tag latest)
kubectl rollout restart deployment/pcap-analyzer -n pcap-analyzer
```

### Redimensionner le PVC

**Attention:** Le redimensionnement de PVC n'est possible que si la StorageClass le supporte (`allowVolumeExpansion: true`).

```bash
# Éditer le PVC
kubectl edit pvc pcap-analyzer -n pcap-analyzer

# Modifier spec.resources.requests.storage
# Sauvegarder et quitter

# Redémarrer le pod pour appliquer
kubectl rollout restart deployment/pcap-analyzer -n pcap-analyzer
```

### Désinstaller

```bash
# Désinstaller le chart
helm uninstall pcap-analyzer -n pcap-analyzer

# Supprimer le namespace (supprime aussi le PVC)
kubectl delete namespace pcap-analyzer

# Ou garder le PVC pour réutilisation
# Ne pas supprimer le namespace, et réinstaller plus tard
```

## Monitoring et Debug

### Accéder au shell du pod

```bash
kubectl exec -it -n pcap-analyzer deployment/pcap-analyzer -- /bin/sh
```

### Utilisation des ressources

```bash
# Nécessite metrics-server installé
kubectl top pod -n pcap-analyzer
kubectl top node
```

### Décrire le pod (pour debug)

```bash
kubectl describe pod -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer
```

### Tester depuis l'intérieur du pod

```bash
# Upload test
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- sh -c "
  curl -X POST http://localhost:8000/api/upload \
    -F 'file=@/data/test.pcap'
"

# Vérifier l'espace disque
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- df -h /data
```

## Architecture et Limitations

### Architecture déployée

```
┌─────────────────────────────────────┐
│         NodePort Service            │
│     (ClusterIP:8000 → 30080)        │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│         Deployment                  │
│         (1 replica)                 │
│  ┌─────────────────────────────┐   │
│  │  Pod: pcap-analyzer         │   │
│  │  - FastAPI (port 8000)      │   │
│  │  - Liveness probe           │   │
│  │  - Readiness probe          │   │
│  │                              │   │
│  │  Volume: /data              │   │
│  └──────────┬──────────────────┘   │
└─────────────┼──────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│    PersistentVolumeClaim (10Gi)     │
│    - SQLite database                │
│    - PCAP uploads                   │
│    - Generated reports              │
└─────────────────────────────────────┘
```

### Limitations importantes

1. **1 replica seulement**
   - SQLite est une base de données fichier locale (pas de concurrence multi-pod)
   - Le stockage persistant (PVC) est en mode `ReadWriteOnce` (1 seul pod)
   - La queue d'analyse est en mémoire (APScheduler)

2. **Pas de haute disponibilité**
   - Si le pod redémarre, les analyses en cours sont perdues
   - Les rapports persistent grâce au PVC

3. **Pas de load balancing**
   - Le NodePort expose directement le pod unique

### Migration vers architecture distribuée

Pour déployer avec plusieurs replicas en production, il faudrait:

**Base de données:**
- Migrer SQLite → PostgreSQL (chart bitnami/postgresql)
- Utiliser un service externe PostgreSQL (RDS, Cloud SQL, etc.)

**Stockage:**
- Remplacer le stockage local par S3/MinIO
- Utiliser ReadWriteMany PVC avec NFS/CephFS

**Queue:**
- Remplacer APScheduler par Celery + Redis/RabbitMQ
- Utiliser chart bitnami/redis

**Service:**
- Passer de NodePort à LoadBalancer (cloud) ou Ingress
- Ajouter TLS/HTTPS via Ingress + cert-manager

**Exemple d'architecture distribuée:**

```yaml
replicaCount: 3

externalDatabase:
  host: postgres.default.svc.cluster.local
  port: 5432
  database: pcap_analyzer

externalRedis:
  host: redis.default.svc.cluster.local
  port: 6379

storage:
  type: s3
  s3:
    endpoint: minio.default.svc.cluster.local
    bucket: pcap-reports
```

## Sécurité

### Bonnes pratiques

1. **Ne pas utiliser `latest` en production**
   ```yaml
   image:
     tag: v1.0.0  # Version spécifique
     pullPolicy: Always
   ```

2. **Utiliser des secrets pour les credentials**
   ```bash
   kubectl create secret generic pcap-secrets \
     --from-literal=db-password=xxx \
     -n pcap-analyzer
   ```

3. **Limiter les ressources**
   - Toujours définir `resources.limits` et `resources.requests`
   - Éviter le `BestEffort` QoS

4. **Network Policies** (si supportées)
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: pcap-analyzer-netpol
   spec:
     podSelector:
       matchLabels:
         app.kubernetes.io/name: pcap-analyzer
     policyTypes:
     - Ingress
     ingress:
     - from:
       - podSelector: {}
       ports:
       - protocol: TCP
         port: 8000
   ```

5. **SecurityContext** (déjà dans deployment.yaml)
   ```yaml
   securityContext:
     runAsNonRoot: true
     runAsUser: 1000
     fsGroup: 1000
   ```

## Dépannage

### Le pod ne démarre pas

```bash
# Vérifier les événements
kubectl describe pod -n pcap-analyzer <pod-name>

# Causes communes:
# - Image non disponible (ImagePullBackOff)
# - PVC non bound (Pending)
# - Ressources insuffisantes (Insufficient cpu/memory)
```

### Le PVC reste en Pending

```bash
kubectl describe pvc pcap-analyzer -n pcap-analyzer

# Solutions:
# - Vérifier que le StorageClass existe: kubectl get sc
# - Pour kind: utiliser storageClass: "standard"
# - Vérifier les nodes ont de l'espace disque
```

### L'application ne répond pas

```bash
# Vérifier les health probes
kubectl get pods -n pcap-analyzer -o wide

# Vérifier les logs
kubectl logs -n pcap-analyzer deployment/pcap-analyzer --tail=100

# Tester en direct
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- curl localhost:8000/api/health
```

### Impossible d'accéder via NodePort

```bash
# kind: vérifier le port mapping
docker ps | grep pcap-analyzer

# Vérifier le service
kubectl get svc -n pcap-analyzer

# Alternative: port-forward
kubectl port-forward -n pcap-analyzer svc/pcap-analyzer 8000:8000
# Puis accéder à http://localhost:8000
```

## Support

Pour plus d'informations:
- Documentation principale: [README.md](../../README.md)
- Issues: [GitHub Issues](https://github.com/MacFlurry/pcap_analyzer/issues)
- Chart values: [values.yaml](values.yaml)
