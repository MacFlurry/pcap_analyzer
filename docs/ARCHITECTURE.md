# Architecture Design - PCAP Analyzer

## Vue d'ensemble

PCAP Analyzer est une application d'analyse de fichiers PCAP conçue avec une architecture hybride permettant une utilisation **CLI** (ligne de commande) ou **Web** (interface moderne).

## Principes de conception

### 1. Séparation des responsabilités

```
┌─────────────────────────────────────────┐
│         Couche Présentation             │
│  ┌──────────────┐   ┌─────────────┐   │
│  │  CLI (Click) │   │  Web (FastAPI)│   │
│  └──────────────┘   └─────────────┘   │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Couche Métier                   │
│  ┌──────────────────────────────────┐  │
│  │   Core Analyzers (17 modules)    │  │
│  │  • TCP, DNS, Retransmissions     │  │
│  │  • RTT, Jitter, Anomalies        │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
                    │
┌─────────────────────────────────────────┐
│         Couche Infrastructure           │
│  ┌──────────┐  ┌─────────┐  ┌────────┐ │
│  │ dpkt     │  │ Scapy   │  │ SQLite │ │
│  └──────────┘  └─────────┘  └────────┘ │
└─────────────────────────────────────────┘
```

**Justification :**
- **CLI et Web partagent le même moteur d'analyse** → Pas de duplication de code
- **Analyseurs indépendants** → Facilite les tests et la maintenance
- **Abstraction infrastructure** → Possibilité de changer dpkt/Scapy sans impacter le métier

### 2. Architecture hybride dpkt + Scapy

**Problème :** Scapy est lent pour extraire les métadonnées de milliers de paquets.

**Solution :** Utiliser dpkt (rapide) pour l'extraction, Scapy pour l'analyse approfondie.

```python
# Phase 1: Extraction rapide avec dpkt (3-5x plus rapide)
for ts, buf in dpkt.pcap.Reader(pcap_file):
    eth = dpkt.ethernet.Ethernet(buf)
    metadata.append(extract_basic_info(eth))

# Phase 2: Analyse approfondie avec Scapy (quand nécessaire)
packets_scapy = rdpcap(pcap_file)
for analyzer in deep_analyzers:
    analyzer.analyze(packets_scapy)
```

**Résultat :** 1.7x speedup global (93.3s → 55.2s sur 131k paquets)

### 3. Architecture asynchrone (Web)

**Problème :** L'analyse PCAP peut prendre plusieurs minutes → blocage du serveur web.

**Solution :** Worker asynchrone avec queue et SSE pour la progression.

```
┌──────────┐                      ┌───────────┐
│ Browser  │─────upload PCAP─────>│  FastAPI  │
└────┬─────┘                      └─────┬─────┘
     │                                   │
     │                            ┌──────▼──────┐
     │                            │   Worker    │
     │                            │  (asyncio)  │
     │                            └──────┬──────┘
     │                                   │
     │    ┌──────SSE events──────────────┘
     │    │  {phase: "tcp", progress: 45%}
     ▼    ▼
┌────────────┐                    ┌──────────┐
│ Progress   │◄───────────────────│  SQLite  │
│   Page     │    task status     └──────────┘
└────────────┘
```

**Composants :**

1. **FastAPI** : Framework web moderne, async-first, auto-documentation OpenAPI
2. **APScheduler** : Queue en mémoire avec max 5 tâches concurrentes
3. **Server-Sent Events (SSE)** : Push temps réel sans polling
4. **SQLite + aiosqlite** : Base légère, suffisante pour usage monoposte
5. **Background worker** : `asyncio.create_task()` pour analyses non-bloquantes

**Justification des choix :**

| Composant | Choix | Alternative rejetée | Raison |
|-----------|-------|---------------------|--------|
| Framework Web | **FastAPI** | Flask | Async native, validation automatique (Pydantic), OpenAPI |
| Queue | **APScheduler** | Celery | Pas besoin de Redis pour usage monoposte |
| Base de données | **SQLite** | PostgreSQL | Simplicité, pas de setup, suffisant pour 1 utilisateur |
| Temps réel | **SSE** | WebSocket | Unidirectionnel suffit, plus simple que WebSocket |
| Async runtime | **asyncio** | Threads | Meilleure performance I/O, moins de overhead |

### 4. Sécurité

**Protection XSS :**
```python
# Jinja2 autoescape activé par défaut
templates = Jinja2Templates(directory="templates", autoescape=True)
```

**Protection Path Traversal :**
```python
# Validation stricte des chemins
def validate_pcap_path(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(UPLOAD_DIR):
        raise SecurityError("Path traversal attempt")
    return resolved
```

**Validation uploads :**
```python
# Vérification magic bytes PCAP/PCAPNG
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

def is_valid_pcap(data: bytes) -> bool:
    return data[:4] in (PCAP_MAGIC, PCAPNG_MAGIC, ...)
```

**Limites :**
- Max upload : 500 MB (configurable)
- Max queue : 5 analyses concurrentes
- TTL rapports : 24h (cleanup automatique)

## Architecture des analyseurs

### Pattern : Strategy + Factory

```python
# Interface commune
class BaseAnalyzer:
    def analyze(self, packets) -> dict:
        raise NotImplementedError

# Implémentations spécialisées
class RetransmissionAnalyzer(BaseAnalyzer):
    def analyze(self, packets) -> dict:
        # Détection RTO/Fast Retrans/Generic
        ...

class DNSAnalyzer(BaseAnalyzer):
    def analyze(self, packets) -> dict:
        # Timeouts DNS, latences par domaine
        ...

# Factory
def create_analyzers() -> list[BaseAnalyzer]:
    return [
        TimestampAnalyzer(),
        TCPHandshakeAnalyzer(),
        RetransmissionAnalyzer(),
        RTTAnalyzer(),
        # ... 13 autres
    ]
```

**Avantages :**
- **Extensibilité** : Ajouter un analyseur = créer une classe
- **Testabilité** : Chaque analyseur testé indépendamment
- **Réutilisabilité** : CLI et Web utilisent la même factory

### Analyseurs (17 modules)

| Analyseur | Responsabilité | Sortie clé |
|-----------|----------------|-----------|
| `timestamp_analyzer` | Gaps temporels, pauses applicatives | `suspicious_gaps[]` |
| `tcp_handshake` | Latence SYN-SYNACK, échecs connexion | `slow_handshakes[]` |
| `retransmission` | Classification RTO/Fast/Generic | `retransmissions[]` |
| `rtt_analyzer` | Round Trip Time min/avg/max | `rtt_stats{}` |
| `tcp_window` | Saturation fenêtre TCP | `zero_windows[]` |
| `dns_analyzer` | Timeouts, latences par domaine | `slow_queries[]` |
| `tcp_reset` | RST anormaux, connexions avortées | `resets[]` |
| `ip_fragmentation` | Fragments IP, PMTU | `fragmented_flows[]` |
| `burst` | Pics soudains de trafic | `burst_events[]` |
| `asymmetric_traffic` | Trafic unidirectionnel | `asymmetric_flows[]` |
| ... | ... | ... |

Voir [../src/analyzers/](../src/analyzers/) pour le code complet.

## Flux de données

### CLI (mode synchrone)

```
┌──────────────┐
│ pcap_analyzer│
│   analyze    │
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌─────────────┐
│ Load PCAP    │────>│  dpkt       │
│   (dpkt)     │     │  extraction │
└──────┬───────┘     └─────────────┘
       │
       ▼
┌──────────────┐     ┌─────────────┐
│ Reload PCAP  │────>│  Scapy      │
│  (Scapy)     │     │  analysis   │
└──────┬───────┘     └─────────────┘
       │
       ▼
┌──────────────┐
│ 17 Analyzers │
│  (parallel)  │
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌─────────────┐
│ Report Gen.  │────>│ HTML + JSON │
│  (Jinja2)    │     │   reports/  │
└──────────────┘     └─────────────┘
```

**Temps typique :** 55s pour 131k paquets (26 MB)

### Web (mode asynchrone)

```
┌──────────┐
│ Browser  │
└────┬─────┘
     │ POST /api/upload
     ▼
┌─────────────────┐
│   FastAPI       │
│  • Valider file │
│  • Sauver upload│
│  • Créer task   │
└────┬────────────┘
     │
     ▼
┌─────────────────┐       ┌──────────┐
│  APScheduler    │──────>│  SQLite  │
│  • Enqueue task │       │  tasks   │
│  • Max 5 jobs   │       └──────────┘
└────┬────────────┘
     │
     ▼
┌─────────────────┐
│  Async Worker   │
│  • CLI analyze  │───┐
│  • SSE updates  │   │
└─────────────────┘   │
     │                │
     ▼                ▼
┌──────────┐     ┌─────────────┐
│ /reports │     │ SSE stream  │
│  *.html  │     │ to browser  │
└──────────┘     └─────────────┘
```

**Timeline :**
1. T+0s : Upload → Task créée (status: pending)
2. T+1s : Worker démarre (status: processing)
3. T+1-55s : Updates SSE (phase, progress%, packets)
4. T+55s : Rapport généré (status: completed)
5. T+24h : Cleanup automatique (deleted)

## Persistence et stockage

### SQLite schema

```sql
CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    status TEXT NOT NULL,  -- pending/processing/completed/failed/expired
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    expires_at TIMESTAMP,
    total_packets INTEGER,
    packets_processed INTEGER,
    error_message TEXT
);
```

**Indexes :**
- `idx_status` : Filtrer par statut (affichage historique)
- `idx_expires_at` : Cleanup rapide des anciens rapports

### Fichiers

```
/data/
├── uploads/              # Fichiers PCAP uploadés
│   └── {task_id}.pcap
├── reports/              # Rapports générés
│   ├── {task_id}.html
│   └── {task_id}.json
└── pcap_analyzer.db      # Base SQLite
```

**Cleanup automatique :**
- **APScheduler** : Job quotidien à 3h du matin
- Supprime tasks avec `expires_at < NOW()`
- Supprime fichiers associés (upload + rapports)

## Performance et optimisation

### 1. Parsing hybride dpkt + Scapy

| Méthode | Temps (131k packets) | Speedup |
|---------|----------------------|---------|
| Scapy only | 93.3s | 1.0x |
| dpkt + Scapy | 55.2s | **1.7x** |

**12/17 analyseurs** utilisent dpkt pour extraction rapide.

### 2. Memory management

```python
# Cleanup périodique pour longues captures
if packet_count % 10000 == 0:
    gc.collect()
```

**Évite :** Memory leaks sur captures > 500k paquets

### 3. Docker multi-stage build

```dockerfile
# Stage 1: Builder (900 MB)
FROM python:3.11-slim as builder
RUN apt-get install gcc g++ libpcap-dev
RUN pip install --prefix=/install -r requirements.txt

# Stage 2: Runtime (485 MB)
FROM python:3.11-slim
COPY --from=builder /install /usr/local
```

**Gain :** 900 MB → 485 MB (46% réduction)

## Extensibilité future

### Migration vers architecture distribuée

**Limitations actuelles (1 replica) :**
- SQLite → pas de concurrence multi-pods
- Stockage local → ReadWriteOnce PVC
- APScheduler → queue en mémoire, perdue au restart

**Migration nécessaire :**

```yaml
# Avant (current)
database: SQLite (local)
storage: /data (PVC RWO)
queue: APScheduler (memory)
replicas: 1

# Après (distributed)
database: PostgreSQL (external)
storage: S3/MinIO (distributed)
queue: Celery + Redis (external)
replicas: 3+
```

**Composants à ajouter :**

1. **PostgreSQL** : Base partagée entre replicas
   ```yaml
   - name: DATABASE_URL
     value: postgresql://user:pass@postgres:5432/pcap
   ```

2. **S3/MinIO** : Stockage objet distribué
   ```python
   s3_client.upload_file(pcap_path, bucket, f"uploads/{task_id}.pcap")
   ```

3. **Celery + Redis** : Queue distribuée
   ```python
   @celery_app.task
   def analyze_pcap_task(task_id: str):
       # Worker démarre sur n'importe quel replica
   ```

4. **Load Balancer** : Ingress avec sticky sessions
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: Ingress
   metadata:
     annotations:
       nginx.ingress.kubernetes.io/affinity: "cookie"
   ```

## Observabilité

### Logs structurés

```python
import logging
import json

logger = logging.getLogger(__name__)
logger.info(json.dumps({
    "timestamp": datetime.now().isoformat(),
    "level": "INFO",
    "message": "Analysis started",
    "task_id": task_id,
    "filename": filename
}))
```

**Format JSON** → Compatible avec ELK, Grafana Loki

### Health checks

```python
@router.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "uptime_seconds": time.time() - start_time,
        "active_analyses": worker.get_active_count(),
        "queue_size": worker.get_queue_size(),
        "disk_space_gb": shutil.disk_usage("/data").free / (1024**3)
    }
```

Utilisé par :
- **Docker Compose** : healthcheck
- **Kubernetes** : liveness/readiness probes

### Métriques (future)

```python
# Prometheus metrics (à ajouter)
from prometheus_client import Counter, Histogram

analysis_duration = Histogram('analysis_duration_seconds', 'Time to analyze PCAP')
analysis_total = Counter('analysis_total', 'Total analyses', ['status'])

@analysis_duration.time()
def analyze_pcap(pcap_path):
    # ...
    analysis_total.labels(status='success').inc()
```

## Sécurité et conformité

### Données sensibles

**⚠️ Les fichiers PCAP peuvent contenir :**
- Paquets réseau complets (headers + payload)
- Potentiellement des données sensibles (credentials, PII)

**Recommandations :**
- Nettoyer les PCAPs avant upload (tcpdump -s 96 pour headers seulement)
- Activer chiffrement au repos (volume encryption)
- TTL court (24h) pour minimiser exposition
- Pas de logs de payload

### Conformité RGPD

- **Données personnelles** : Possibles dans les paquets
- **Durée de conservation** : 24h max (configurable)
- **Droit à l'oubli** : Suppression manuelle via API DELETE (à implémenter)
- **Chiffrement** : TLS en transit, volume encryption au repos

## Documentation détaillée

- [Architecture Docker](DOCKER.md)
- [Architecture Kubernetes](KUBERNETES.md)
- [Helm Chart](../helm-chart/pcap-analyzer/README.md)
