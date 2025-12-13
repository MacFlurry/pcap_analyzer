# Architecture Docker - PCAP Analyzer

## Vue d'ensemble

L'architecture Docker de PCAP Analyzer utilise un **multi-stage build** pour optimiser la taille de l'image et un **docker-compose** pour orchestrer l'application en développement.

## Dockerfile - Multi-stage Build

### Architecture de build

```dockerfile
# ┌─────────────────────────────────────┐
# │   Stage 1: Builder (~900 MB)        │
# │  • Compile dependencies             │
# │  • Install dev tools (gcc, g++)     │
# │  • Build Python wheels              │
# └─────────────────────────────────────┘
#                  │
#                  │ COPY binaries only
#                  ▼
# ┌─────────────────────────────────────┐
# │   Stage 2: Runtime (~485 MB)        │
# │  • Minimal base image               │
# │  • Copy compiled packages           │
# │  • No dev tools                     │
# └─────────────────────────────────────┘
```

### Stage 1 : Builder

```dockerfile
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment in /opt/venv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt requirements-web.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-web.txt
```

**Justification :**
- **gcc/g++** : Nécessaires pour compiler les bindings C (dpkt, Scapy)
- **libpcap-dev** : Headers pour lier avec libpcap
- **virtual env** : Isolation propre des dépendances
- **--no-cache-dir** : Évite de stocker le cache pip (~200 MB économisés)

### Stage 2 : Runtime

```dockerfile
FROM python:3.11-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create non-root user
RUN groupadd -r pcapuser && useradd -r -g pcapuser pcapuser

# Setup application
WORKDIR /app
COPY --chown=pcapuser:pcapuser src/ ./src/
COPY --chown=pcapuser:pcapuser app/ ./app/
COPY --chown=pcapuser:pcapuser templates/ ./templates/
COPY --chown=pcapuser:pcapuser config.yaml ./

# Create data directory
RUN mkdir -p /data && chown pcapuser:pcapuser /data

USER pcapuser
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Justification :**
- **libpcap0.8** : Runtime library (pas les headers de dev)
- **Non-root user** : Sécurité (principe de moindre privilège)
- **COPY --chown** : Évite un `chown` supplémentaire, réduit les layers
- **Single WORKDIR** : Simplifie les paths
- **uvicorn** : Server ASGI performant pour FastAPI

### Optimisations appliquées

| Optimisation | Gain | Impact |
|--------------|------|--------|
| Multi-stage build | -415 MB | 46% réduction (900→485 MB) |
| --no-cache-dir | -200 MB | Pas de cache pip inutile |
| rm apt lists | -50 MB | Cache apt supprimé |
| .dockerignore | -100 MB | Exclut venv/, tests/, .git |
| Slim base image | -300 MB | vs image full Python |

**Total :** Image finale **485 MB** (vs ~1.2 GB sans optimisations)

## Docker Compose - Architecture de développement

### Structure

```yaml
version: '3.8'

services:
  pcap-analyzer:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    volumes:
      - pcap-data:/data
    environment:
      - MAX_UPLOAD_SIZE_MB=500
      - REPORT_TTL_HOURS=24
      - DATA_DIR=/data
      - LOG_LEVEL=INFO
      - MAX_QUEUE_SIZE=5
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  pcap-data:
    driver: local
```

### Justification des choix

#### 1. Volume nommé `pcap-data`

**Problème :** Les bind mounts (`./data:/data`) exposent le système de fichiers local.

**Solution :** Volume Docker géré par Docker Engine.

```yaml
volumes:
  pcap-data:
    driver: local
```

**Avantages :**
- **Isolation** : Données séparées du code source
- **Persistence** : Survit aux `docker-compose down`
- **Performance** : Meilleur sur macOS/Windows (pas de synchro FS)
- **Portable** : Fonctionne identiquement sur tous les OS

**Commandes utiles :**
```bash
# Inspecter le volume
docker volume inspect pcap_analyzer_pcap-data

# Backup
docker run --rm -v pcap_analyzer_pcap-data:/data \
  -v $(pwd):/backup alpine tar czf /backup/data.tar.gz /data

# Restore
docker run --rm -v pcap_analyzer_pcap-data:/data \
  -v $(pwd):/backup alpine tar xzf /backup/data.tar.gz -C /
```

#### 2. Health check avec Python

**Pourquoi pas curl ?**
- Curl n'est pas installé dans l'image (minimale)
- Ajout curl = +10 MB à l'image

**Solution :** Python `urllib.request` (déjà disponible)

```yaml
healthcheck:
  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"]
```

**Timeline :**
- `start_period: 40s` : Donne 40s pour démarrer l'app
- `interval: 30s` : Vérifie toutes les 30s
- `timeout: 10s` : Échec si pas de réponse en 10s
- `retries: 3` : 3 échecs = container unhealthy

**États :**
```
starting (0-40s) → healthy (ok) → unhealthy (3 failures)
                                       ↓
                                  restart container
```

#### 3. Variables d'environnement

```yaml
environment:
  - MAX_UPLOAD_SIZE_MB=500      # Limite upload PCAP
  - REPORT_TTL_HOURS=24         # Durée de vie rapports
  - DATA_DIR=/data              # Répertoire persistance
  - LOG_LEVEL=INFO              # DEBUG/INFO/WARNING/ERROR
  - MAX_QUEUE_SIZE=5            # Analyses concurrentes max
```

**Override avec .env :**
```bash
# .env (git ignored)
MAX_UPLOAD_SIZE_MB=1000
LOG_LEVEL=DEBUG
```

```yaml
# docker-compose.yml
env_file:
  - .env  # Optionnel
```

#### 4. Pas de restart policy en dev

**Absent volontairement :**
```yaml
# restart: always  # ❌ Pas en docker-compose
```

**Raison :** En développement, on veut voir les crashes pour debugger.

**Pour production :** Utiliser Kubernetes (voir [KUBERNETES.md](KUBERNETES.md))

## Workflow de développement

### Lancement rapide

```bash
# Build et start
docker-compose up -d

# Logs temps réel
docker-compose logs -f

# Rebuild après changement code
docker-compose up -d --build

# Stop et cleanup
docker-compose down
docker volume rm pcap_analyzer_pcap-data  # Optionnel: supprime données
```

### Hot reload (mode dev)

**Problème :** Rebuild complet à chaque changement de code.

**Solution :** Bind mount du code source + uvicorn --reload

```yaml
# docker-compose.dev.yml (override)
services:
  pcap-analyzer:
    volumes:
      - pcap-data:/data
      - ./app:/app/app:ro        # Mount code web
      - ./src:/app/src:ro        # Mount code CLI
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    environment:
      - LOG_LEVEL=DEBUG
```

**Usage :**
```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

**Modifications :** Auto-reload instantané (pas de rebuild)

### Debugging

#### Logs applicatifs

```bash
# Tous les logs
docker-compose logs -f

# Logs app seulement
docker-compose logs -f pcap-analyzer

# Dernières 100 lignes
docker-compose logs --tail=100 pcap-analyzer

# Depuis timestamp
docker-compose logs --since="2025-12-13T18:00:00"
```

#### Shell dans le container

```bash
# Shell interactif
docker-compose exec pcap-analyzer /bin/sh

# Commande directe
docker-compose exec pcap-analyzer ls -la /data

# Tester health check manuellement
docker-compose exec pcap-analyzer python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/api/health').read())"
```

#### Inspecter le système de fichiers

```bash
# Lister uploads
docker-compose exec pcap-analyzer ls -lh /data/uploads

# Lister rapports
docker-compose exec pcap-analyzer ls -lh /data/reports

# Taille DB
docker-compose exec pcap-analyzer ls -lh /data/pcap_analyzer.db
```

## Gestion des ressources

### Limites mémoire/CPU

```yaml
services:
  pcap-analyzer:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 1G
```

**Justification :**
- **Limites** : Évite qu'une analyse lourde monopolise le host
- **Reservations** : Garantit des ressources minimales
- **4G mémoire** : Suffisant pour analyser PCAP de 500 MB

**Monitoring :**
```bash
# Stats temps réel
docker stats pcap_analyzer_pcap-analyzer_1

# Résultat
CONTAINER    CPU %   MEM USAGE / LIMIT   MEM %   NET I/O    BLOCK I/O
pcap-...     15.2%   256MiB / 4GiB      6.4%    1.2MB/0    50MB/20MB
```

### Nettoyage

```bash
# Supprimer containers arrêtés
docker-compose down

# Supprimer aussi les volumes (⚠️ données perdues)
docker-compose down -v

# Nettoyer images non utilisées
docker image prune -a

# Nettoyer tout Docker (⚠️ destructif)
docker system prune -a --volumes
```

## Sécurité Docker

### 1. Non-root user

```dockerfile
RUN groupadd -r pcapuser && useradd -r -g pcapuser pcapuser
USER pcapuser
```

**Protection :** Container compromise ≠ root sur le host

### 2. Read-only filesystem (optionnel)

```yaml
services:
  pcap-analyzer:
    read_only: true
    tmpfs:
      - /tmp
      - /run
    volumes:
      - pcap-data:/data  # Seul répertoire writable
```

**Trade-off :** Plus sécurisé mais complexifie debugging

### 3. Secrets management

**❌ Mauvais :**
```yaml
environment:
  - DB_PASSWORD=secret123  # Visible dans docker inspect
```

**✅ Bon :**
```yaml
secrets:
  db_password:
    file: ./secrets/db_password.txt

services:
  pcap-analyzer:
    secrets:
      - db_password
```

```python
# app/main.py
with open('/run/secrets/db_password') as f:
    db_password = f.read().strip()
```

### 4. Network isolation

```yaml
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # Pas d'accès Internet

services:
  pcap-analyzer:
    networks:
      - frontend  # Accès web

  # Future: PostgreSQL backend
  postgres:
    networks:
      - backend  # Isolé d'Internet
```

## CI/CD avec Docker

### Build dans GitHub Actions

```yaml
# .github/workflows/test.yml
- name: Build Docker image
  run: docker build -t pcap-analyzer:test .

- name: Test Docker image
  run: |
    docker run -d --name test-container -p 8000:8000 pcap-analyzer:test
    sleep 10
    curl -f http://localhost:8000/api/health
    docker stop test-container
```

**Validations :**
- ✅ Image build sans erreur
- ✅ Container démarre
- ✅ Health check répond

### Multi-platform build

```bash
# Build pour AMD64 + ARM64
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 \
  -t pcap-analyzer:latest .
```

**Use case :** Déploiement sur AWS Graviton (ARM), Apple Silicon (M1/M2)

## Troubleshooting

### Container ne démarre pas

```bash
# Voir les logs de démarrage
docker-compose logs pcap-analyzer

# Causes communes:
# - Port 8000 déjà utilisé → changer le port
# - Volume permission denied → vérifier chown
# - Dépendances manquantes → vérifier requirements.txt
```

### Health check fail

```bash
# Tester manuellement
docker-compose exec pcap-analyzer curl localhost:8000/api/health

# Vérifier les logs
docker-compose logs --tail=50 pcap-analyzer

# Redémarrer
docker-compose restart pcap-analyzer
```

### Performance lente

```bash
# Vérifier ressources
docker stats

# Augmenter limites
# docker-compose.yml
deploy:
  resources:
    limits:
      memory: 8G  # Double la mémoire
```

## Comparaison Docker vs Kubernetes

| Aspect | Docker Compose | Kubernetes |
|--------|----------------|------------|
| **Usage** | Développement local | Production |
| **Scaling** | 1 container | N replicas (avec migration) |
| **Persistence** | Volume Docker | PVC + S3/MinIO |
| **Health** | Healthcheck | Liveness/Readiness probes |
| **Networking** | Bridge | Services + Ingress |
| **Updates** | Manual rebuild | Rolling updates |
| **Monitoring** | docker stats | Prometheus + Grafana |

**Recommandation :**
- **Dev local** : Docker Compose (simple, rapide)
- **Production** : Kubernetes (résilience, scaling)

Voir [KUBERNETES.md](KUBERNETES.md) pour l'architecture production.

## Ressources

- [Dockerfile reference](https://docs.docker.com/engine/reference/builder/)
- [Docker Compose file](https://docs.docker.com/compose/compose-file/)
- [Multi-stage builds](https://docs.docker.com/build/building/multi-stage/)
- [Best practices](https://docs.docker.com/develop/dev-best-practices/)
