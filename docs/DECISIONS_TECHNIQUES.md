# Décisions Techniques - PCAP Analyzer Web Interface

**Date:** 2025-12-12
**Version:** 1.0
**Statut:** Validé

## Résumé Exécutif

Ce document consolide les décisions techniques majeures pour la dockerisation du PCAP Analyzer avec interface web. Toutes les décisions sont basées sur des sources officielles et des benchmarks vérifiables.

## Stack Technique Validée

### Backend: **FastAPI + Uvicorn** ✅

**Décision:** FastAPI avec Uvicorn (serveur ASGI)

**Justification:**
- **Performance:** 15,000-20,000 req/sec vs Flask 2,000-3,000 req/sec
- **Async natif:** Essentiel pour analyses longues sans bloquer
- **Validation automatique:** Pydantic pour sécurité upload
- **Documentation auto:** OpenAPI/Swagger intégré
- **WebSocket/SSE natif:** Communication temps réel

**Sources:**
- [FastAPI Official Benchmarks](https://fastapi.tiangolo.com/benchmarks/)
- [FastAPI vs Flask 2025](https://strapi.io/blog/fastapi-vs-flask-python-framework-comparison)

### Frontend: **Vanilla JavaScript + Tailwind CSS** ✅

**Décision:** Pas de framework lourd, JavaScript moderne ES6+

**Justification:**
- **Simplicité:** UI limitée (upload, progression, rapport)
- **Cohérence:** Réutilise CSS existant des rapports HTML
- **Performance:** Pas de bundle JS lourd
- **Maintenance:** Moins de complexité

**Composants:**
- Tailwind CSS via CDN (design moderne responsive)
- Fetch API pour upload async
- EventSource API pour Server-Sent Events
- Drag & Drop API native

### Communication Temps Réel: **Server-Sent Events (SSE)** ✅

**Décision:** SSE au lieu de WebSockets

**Justification:**
- **Simplicité:** Communication unidirectionnelle serveur → client suffisante
- **Reconnexion auto:** Gérée nativement par EventSource
- **HTTP/2 compatible:** Pas de handshake spécial
- **Overhead minimal:** ~5 bytes/message vs WebSocket 2 bytes

**Sources:**
- [SSE vs WebSockets 2025](https://dev.to/haraf/server-sent-events-sse-vs-websockets-vs-long-polling-whats-best-in-2025-5ep8)
- [RxDB Real-Time Guide](https://rxdb.info/articles/websockets-sse-polling-webrtc-webtransport.html)

### Stockage: **Filesystem + SQLite** ✅

**Décision:**
- Fichiers PCAP/Rapports: Filesystem (volumes Docker)
- Métadonnées: SQLite (task_id, status, paths)

**Justification:**
- **Simplicité:** Pas besoin PostgreSQL pour ce volume
- **Performance:** Accès direct filesystem pour fichiers volumineux
- **Atomicité:** SQLite ACID pour tracking tâches
- **Portabilité:** Fichier unique, backup simple

**Structure:**
```
/data/
├── uploads/          # PCAP temporaires (suppression immédiate)
├── reports/          # HTML/JSON (TTL 24h)
└── pcap_analyzer.db  # SQLite (métadonnées)
```

### Queue Système: **asyncio.Queue (in-process)** ✅

**Décision:** Pas de Celery/RQ, utilisation asyncio.Queue native

**Justification:**
- **Simplicité:** Analyseur single-threaded (dpkt/Scapy)
- **Overhead évité:** Pas besoin Redis/RabbitMQ
- **Suffisant:** 1-2 analyses simultanées max par instance

**Scalabilité future:** Si besoin >10 req/sec, migration vers Celery + Redis

### Image Docker: **python:3.11-slim-bookworm** ✅

**Décision:** python:3.11-slim-bookworm pour image finale

**Justification:**
- **Taille:** 149MB uncompressed (vs 1GB pour python:3.11)
- **Compatibilité:** glibc requis pour wheels numpy/scapy
- **Sécurité:** Base Debian stable avec patches

**Alternatives écartées:**
- alpine: Incompatible wheels (musl libc)
- distroless: Pas de shell (debugging impossible)

**Sources:**
- [Python Docker Images 2025](https://pythonspeed.com/articles/base-image-python-docker-images/)
- [Docker Hub Python](https://hub.docker.com/_/python)

### Multi-Stage Build: **OUI (3 stages)** ✅

**Décision:** Dockerfile multi-stage pour optimisation

**Justification:**
- **Réduction 50-60%:** Séparation build/runtime
- **Sécurité:** Pas d'outils build (gcc, pip) en production
- **Cache:** Layers optimisés pour CI/CD

**Structure:**
1. **Stage Builder:** Compilation dépendances
2. **Stage Runtime-deps:** Installation dans image propre
3. **Stage Final:** Application + user non-root

**Taille estimée finale:** ~236 MB (vs ~850 MB sans multi-stage)

### Cleanup Automatique: **APScheduler (in-process)** ✅

**Décision:** APScheduler avec CronTrigger

**Justification:**
- **Simplicité:** Pas besoin cron système dans conteneur
- **Portabilité:** Fonctionne identique tous OS
- **Pythonic:** Configuration en code, testable

**Stratégie:**
- PCAP: Suppression IMMÉDIATE après analyse
- Rapports: TTL 24h (cleanup hourly)
- Métadonnées SQLite: Marquées 'expired'

## Architecture Globale

```
┌─────────────────────────────────────────────┐
│          CLIENT (Browser)                   │
│  Upload → Progress (SSE) → Report HTML      │
└─────────────────┬───────────────────────────┘
                  │ HTTP/SSE
┌─────────────────┴───────────────────────────┐
│       DOCKER CONTAINER                       │
│  ┌──────────────────────────────────────┐   │
│  │ FastAPI + Uvicorn (Port 8000)        │   │
│  │  /upload | /progress | /report       │   │
│  └──────────────┬───────────────────────┘   │
│                 │                            │
│  ┌──────────────┴───────────────────────┐   │
│  │ Background Queue (asyncio)            │   │
│  │   └─> PCAP Analyzer (existing)       │   │
│  │       - analyze_pcap_hybrid()        │   │
│  │       - StreamingProcessor           │   │
│  │       - 17 Analyzers                 │   │
│  └──────────────────────────────────────┘   │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │ STORAGE (Volume /data)                │   │
│  │  - uploads/ (PCAP temp)              │   │
│  │  - reports/ (HTML/JSON 24h)          │   │
│  │  - pcap_analyzer.db (SQLite)         │   │
│  └──────────────────────────────────────┘   │
│                                              │
│  ┌──────────────────────────────────────┐   │
│  │ APScheduler (Cleanup hourly)         │   │
│  └──────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

## Flux de Données

### 1. Upload PCAP
```
Client → POST /upload
   ↓
Validation (extension, taille, magic bytes)
   ↓
Sauvegarde /data/uploads/{task_id}.pcap
   ↓
SQLite INSERT (status='pending')
   ↓
Queue enqueue(task_id)
   ↓
Response {"task_id": "uuid"}
```

### 2. Analyse (Background)
```
Worker pickup task_id
   ↓
SQLite UPDATE status='processing'
   ↓
analyze_pcap_hybrid() + SSE callbacks
   ↓
Sauvegarde /data/reports/{task_id}.html
   ↓
SQLite UPDATE status='completed'
   ↓
DELETE /data/uploads/{task_id}.pcap
```

### 3. Progression Temps Réel
```
Client → GET /progress/{task_id} (SSE)
   ↓
StreamingResponse
   ↓
Emissions:
  data: {"phase": "metadata", "progress": 45}
  data: {"phase": "analysis", "progress": 78}
  data: {"phase": "completed"}
```

### 4. Cleanup (Hourly)
```
APScheduler trigger
   ↓
Scan /data/reports/* (mtime >24h)
   ↓
DELETE fichiers expirés
   ↓
SQLite UPDATE status='expired'
```

## Dépendances

### Python (requirements-web.txt)
```
# Existantes (héritées du CLI)
scapy>=2.5.0,<3.0
dpkt>=1.9.8,<2.0
pyyaml>=6.0,<7.0
jinja2>=3.1.2,<4.0
numpy>=1.24.0
psutil>=5.9.0,<6.0

# Nouvelles (web)
fastapi>=0.104.0,<1.0
uvicorn[standard]>=0.24.0,<1.0
python-multipart>=0.0.6    # Upload fichiers
aiofiles>=23.2.1           # Opérations fichiers async
apscheduler>=3.10.0        # Cleanup scheduler
```

### Système (Dockerfile)
```bash
# Runtime uniquement
libpcap0.8  # Pour scapy/dpkt
```

## Sécurité

### Validation Upload
```python
# Validation stricte 3 niveaux
1. Extension: .pcap, .pcapng uniquement
2. Taille: Max 500MB (configurable)
3. Magic bytes: Header PCAP valide
```

### Isolation Conteneur
```yaml
security_opt:
  - no-new-privileges:true
read_only: true
cap_drop: [ALL]
user: pcapuser (UID 1000, non-root)
```

### Headers Sécurité
```
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

## Performance

### Benchmarks Attendus
- Overhead web: <10% vs CLI
- 131k paquets (26MB): ~60s (vs 55s CLI)
- Concurrent analyses: 2 max
- Mémoire: 2-4GB selon taille PCAP

### Optimisations
- Streaming automatique >100MB
- Garbage collection périodique
- Cache Docker layers
- Multi-stage build

## Configuration

### Variables d'Environnement
```bash
MAX_UPLOAD_SIZE_MB=500      # Limite upload
REPORT_TTL_HOURS=24         # Rétention rapports
DATA_DIR=/data              # Stockage
LOG_LEVEL=INFO              # Niveau logs
MAX_QUEUE_SIZE=5            # Taille queue
```

### docker-compose.yml
```yaml
version: '3.8'
services:
  pcap-analyzer:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - pcap_data:/data
    environment:
      - MAX_UPLOAD_SIZE_MB=500
      - REPORT_TTL_HOURS=24
    security_opt:
      - no-new-privileges:true
    restart: unless-stopped
```

## Plan d'Implémentation

### Phase 1: Backend API (Sprint 1-2, 2 semaines)
- [ ] Structure projet FastAPI
- [ ] Endpoints /upload, /progress, /report
- [ ] Queue asyncio + worker
- [ ] Wrapper analyze_pcap_hybrid()
- [ ] Tests unitaires

### Phase 2: Frontend (Sprint 3, 1 semaine)
- [ ] Page upload (drag & drop)
- [ ] Page progression (SSE)
- [ ] Affichage rapport HTML
- [ ] Design responsive Tailwind

### Phase 3: Docker (Sprint 4, 1 semaine)
- [ ] Dockerfile multi-stage
- [ ] Docker Compose
- [ ] Configuration ENV vars
- [ ] Health check

### Phase 4: Tests & QA (Sprint 5, 1 semaine)
- [ ] Tests end-to-end
- [ ] Scan sécurité (Trivy)
- [ ] Tests performance
- [ ] Documentation

**Durée totale:** 5 sprints (5 semaines)

## Risques et Mitigations

| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| PCAP >500MB | Moyenne | Élevé | StreamingProcessor déjà optimisé |
| SSE déconnexion | Moyenne | Moyen | Reconnexion auto EventSource |
| Queue saturée | Faible | Moyen | Limite maxsize=5 |
| Disk space full | Moyenne | Élevé | Cleanup agressif + monitoring |

## Références

### Documentation Officielle
- [FastAPI](https://fastapi.tiangolo.com/)
- [Docker Multi-Stage](https://docs.docker.com/get-started/docker-concepts/building-images/multi-stage-builds/)
- [Server-Sent Events MDN](https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events)

### Performance
- [FastAPI Benchmarks](https://fastapi.tiangolo.com/benchmarks/)
- [Python Docker Images 2025](https://pythonspeed.com/articles/base-image-python-docker-images/)

### Sécurité
- [Docker Security](https://docs.docker.com/engine/security/)
- [OWASP Docker Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

---

**Approuvé pour implémentation**
**Prochaine étape:** Développement backend (Agent Développeur)
