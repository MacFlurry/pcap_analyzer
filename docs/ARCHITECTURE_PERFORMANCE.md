# Architecture Performance - PCAP Analyzer Web

**Date:** 2025-12-12
**Baseline CLI:** 55s pour 131k paquets (26MB)
**Target Web:** <60s (overhead <10%)

---

## Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT (Browser)                         │
│  Upload PCAP → Progress (SSE) → Download Report                │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP/HTTPS
                         │ GZip Compression
                         │ Keep-Alive
                         ↓
┌─────────────────────────────────────────────────────────────────┐
│                    DOCKER CONTAINER                              │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ FastAPI + Uvicorn (1 worker, async)                        │ │
│  │  - POST /upload      → Chunked transfer (1MB chunks)       │ │
│  │  - GET /progress/:id → SSE (1 msg/1000 packets)            │ │
│  │  - GET /report/:id   → Streaming response                  │ │
│  │  - GET /health       → Memory/Disk checks                  │ │
│  └────────────────────┬───────────────────────────────────────┘ │
│                       │                                          │
│  ┌────────────────────┴───────────────────────────────────────┐ │
│  │ asyncio.Queue (maxsize=5)                                  │ │
│  │  - FIFO queue pour analyses                                │ │
│  │  - Reject si full (503 Service Unavailable)                │ │
│  │  - Timeout 30 min par analyse                              │ │
│  └────────────────────┬───────────────────────────────────────┘ │
│                       │                                          │
│  ┌────────────────────┴───────────────────────────────────────┐ │
│  │ Background Worker (CPU-bound)                              │ │
│  │  ┌──────────────────────────────────────────────────────┐  │ │
│  │  │ analyze_pcap_hybrid() - RÉUTILISE CODE CLI EXISTANT  │  │ │
│  │  │  Phase 1: dpkt metadata (~25s, 45%)                  │  │ │
│  │  │  Phase 2: Scapy deep inspection (~30s, 55%)          │  │ │
│  │  │  - StreamingProcessor (auto >100MB)                  │  │ │
│  │  │  - MemoryOptimizer (GC avec cooldown)                │  │ │
│  │  │  - SSE progress callbacks                            │  │ │
│  │  └──────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ STORAGE (Volume /data)                                     │ │
│  │  /data/                                                    │ │
│  │  ├── uploads/          PCAP temporaires (DELETE immédiat) │ │
│  │  ├── reports/          HTML/JSON (TTL 24h)                │ │
│  │  ├── logs/             Rotation 10MB x5                   │ │
│  │  └── pcap_analyzer.db SQLite (métadonnées)                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ APScheduler (Cleanup Hourly)                               │ │
│  │  - Delete reports >24h                                     │ │
│  │  - Update SQLite status='expired'                          │ │
│  │  - Logs rotation                                           │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Resource Limits:                                               │
│  - Memory: 4GB (hard), 1GB (soft)                              │
│  - CPU: 2 cores max, 1 core min                                │
│  - Disk: /data volume (SSD recommandé)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow de Données

### 1. Upload PCAP

```
Client                    FastAPI                    Storage
  │                         │                           │
  │─── POST /upload ───────>│                           │
  │    (multipart/form)     │                           │
  │                         │                           │
  │                         │ Validate:                 │
  │                         │ - Extension (.pcap)       │
  │                         │ - Size (<500MB)           │
  │                         │ - Magic bytes             │
  │                         │                           │
  │                         │─── Save (chunked) ───────>│
  │                         │    /data/uploads/task.pcap│
  │                         │                           │
  │                         │ SQLite INSERT             │
  │                         │ status='pending'          │
  │                         │                           │
  │                         │ Queue.put(task_id)        │
  │                         │                           │
  │<─── 200 OK ─────────────│                           │
  │    {"task_id": "uuid"}  │                           │
  │                         │                           │
```

**Temps estimé:** <5s pour 100MB

---

### 2. Analyse (Background Worker)

```
Queue                  Worker                   StreamingProcessor
  │                      │                            │
  │─── pickup() ────────>│                            │
  │    task_id           │                            │
  │                      │                            │
  │                      │ SQLite UPDATE              │
  │                      │ status='processing'        │
  │                      │                            │
  │                      │─── analyze_pcap_hybrid() ──>│
  │                      │    - Phase 1: dpkt (~25s)  │
  │                      │      * Metadata extraction │
  │                      │      * Fast parsers        │
  │                      │                            │
  │                      │    - Phase 2: Scapy (~30s) │
  │                      │      * DNS/ICMP deep       │
  │                      │      * Protocol analysis   │
  │                      │                            │
  │                      │    - SSE callbacks         │
  │                      │      every 1000 packets    │
  │                      │                            │
  │                      │    - GC triggers           │
  │                      │      if memory >90%        │
  │                      │                            │
  │                      │<─── results ────────────────│
  │                      │                            │
  │                      │ Save report                │
  │                      │ /data/reports/task.html    │
  │                      │                            │
  │                      │ SQLite UPDATE              │
  │                      │ status='completed'         │
  │                      │                            │
  │                      │ DELETE PCAP                │
  │                      │ /data/uploads/task.pcap    │
  │                      │                            │
  │<─── task_done() ─────│                            │
  │                      │                            │
```

**Temps estimé:** 55-60s pour 131k paquets (baseline: 55s)

---

### 3. Progress Monitoring (SSE)

```
Client                    FastAPI                    Worker
  │                         │                           │
  │─── GET /progress/:id ──>│                           │
  │    EventSource          │                           │
  │                         │                           │
  │                         │ StreamingResponse         │
  │<─── SSE stream ─────────│                           │
  │                         │                           │
  │    data: {"phase": "metadata", "progress": 45}      │
  │<────────────────────────│<──────────────────────────│
  │    (every 1000 packets) │                           │
  │                         │                           │
  │    data: {"phase": "analysis", "progress": 78}      │
  │<────────────────────────│<──────────────────────────│
  │                         │                           │
  │    data: {"phase": "completed"}                     │
  │<────────────────────────│<──────────────────────────│
  │                         │                           │
  │    Connection close     │                           │
  │                         │                           │
```

**Latency:** <500ms par événement

---

### 4. Report Download

```
Client                    FastAPI                    Storage
  │                         │                           │
  │─── GET /report/:id ────>│                           │
  │                         │                           │
  │                         │ SQLite SELECT             │
  │                         │ status='completed'?       │
  │                         │                           │
  │                         │─── Read (chunked) ───────>│
  │                         │    /data/reports/task.html│
  │                         │                           │
  │<─── StreamingResponse ──│<──────────────────────────│
  │    (64KB chunks)        │                           │
  │    Content-Encoding:    │                           │
  │    gzip (5x compress)   │                           │
  │                         │                           │
```

**Temps estimé:** <1s pour rapport 1MB (compressed)

---

## Optimisations Clés

### 1. Image Docker (<250 MB)

```dockerfile
# Stage 1: Builder (gcc, g++, build deps)
FROM python:3.11-slim-bookworm AS builder
RUN apt-get install gcc g++ libpcap-dev
RUN pip install -r requirements.txt --no-cache-dir
# → ~300 MB (jetée après build)

# Stage 2: Runtime deps
FROM python:3.11-slim-bookworm AS runtime-deps
RUN apt-get install libpcap0.8  # Runtime only (pas gcc)
COPY --from=builder /opt/venv /opt/venv
# → ~200 MB

# Stage 3: Final
FROM python:3.11-slim-bookworm
COPY --from=runtime-deps /opt/venv /opt/venv
COPY src/ ./src/
# → ~226 MB ✅
```

**Techniques:**
- Multi-stage build (50-60% réduction)
- .dockerignore agressif (tests, docs, .git)
- pip --no-cache-dir
- apt clean && rm -rf /var/lib/apt/lists/*

---

### 2. Runtime Async (FastAPI)

```python
# ✅ CORRECT: Upload async, analyse background
@app.post("/upload")
async def upload_pcap(file: UploadFile):
    # I/O async (pas bloquant)
    async with aiofiles.open(path, 'wb') as f:
        while chunk := await file.read(1024*1024):  # 1MB chunks
            await f.write(chunk)

    # Enqueue (pas bloquant)
    await queue.put(task_id)

# ❌ INCORRECT: Analyse dans endpoint (bloque event loop 55s!)
@app.post("/upload")
async def upload_pcap(file: UploadFile):
    results = analyze_pcap_hybrid(path)  # BLOQUE!
```

**Principes:**
- 1 worker uvicorn (CPU-bound, pas de gain multi-worker)
- async/await pour I/O (fichiers, DB, SSE)
- Background worker pour CPU-bound (analyse)

---

### 3. Mémoire (DÉJÀ Optimisé)

```python
# StreamingProcessor: Auto-chunking basé sur taille
class StreamingProcessor:
    SMALL_FILE   = 100 MB  → Load all (fast)
    MEDIUM_FILE  = 500 MB  → Chunks 20k packets
    LARGE_FILE   = 2 GB    → Chunks 10k packets (aggressive)

# MemoryOptimizer: GC intelligent avec cooldown
class MemoryOptimizer:
    def trigger_gc(self):
        # Cooldown 5s entre GC
        if time.time() - last_gc < 5:
            return 0

        # Skip si 3 GC vides consécutifs
        if consecutive_empty_gcs >= 3:
            return 0

        gc.collect()
```

**Pas besoin de réoptimiser!** Juste wrapper avec SSE callbacks.

---

### 4. CPU (Hybrid Mode DÉJÀ Optimisé)

```python
# Phase 1: dpkt (3-5x plus rapide que Scapy)
parser = FastPacketParser(pcap_file)  # dpkt
for metadata in parser.parse():
    timestamp_analyzer.process_packet(metadata)  # Fast!
    handshake_analyzer.process_packet(metadata)
    # ... 10 autres analyzers dpkt

# Phase 2: Scapy uniquement pour deep inspection
for packet in scapy_packets:
    if packet.haslayer(DNS):
        dns_analyzer.process_packet(packet)  # Scapy
    if packet.haslayer(ICMP):
        icmp_analyzer.process_packet(packet)  # Scapy
```

**Performance:**
- Phase 1: ~25s (dpkt metadata)
- Phase 2: ~30s (Scapy deep)
- **Total: ~55s** (baseline CLI)

---

### 5. Réseau

```python
# Compression gzip (70-80% réduction)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Chunked transfer (streaming, pas load complet)
async def stream_file(path):
    async with aiofiles.open(path, 'rb') as f:
        while chunk := await f.read(65536):  # 64KB
            yield chunk

return StreamingResponse(stream_file(path))

# SSE optimisé (pas trop de messages)
if packet_idx % 1000 == 0:  # 1 message par 1000 packets
    await send_sse({"progress": int((packet_idx / total) * 100)})
```

---

### 6. Cleanup Agressif

```python
# PCAP: Suppression IMMÉDIATE post-analyse
async def analyze_task(task_id: str, pcap_path: str):
    try:
        results = analyze_pcap_hybrid(pcap_path)
        await save_report(task_id, results)
    finally:
        # TOUJOURS supprimer (même si erreur)
        Path(pcap_path).unlink(missing_ok=True)

# Rapports: TTL 24h (APScheduler hourly)
@scheduler.scheduled_job('cron', hour='*')  # Every hour
async def cleanup_expired_reports():
    cutoff = time.time() - (24 * 3600)
    for report in Path("/data/reports").glob("*.html"):
        if report.stat().st_mtime < cutoff:
            report.unlink()
```

---

## Métriques Performance

### Baseline CLI (Référence)

| Métrique | Valeur | Méthode Mesure |
|----------|--------|----------------|
| Temps total | 55s | hyperfine (10 runs) |
| Throughput | 2,382 pkt/s | 131k / 55s |
| Phase 1 (dpkt) | ~25s | cProfile |
| Phase 2 (Scapy) | ~30s | cProfile |
| Peak memory | ~500 MB | tracemalloc |
| Memory/packet | ~3.8 KB | 500MB / 131k |

### Target Web

| Métrique | Target | Overhead Max | Validation |
|----------|--------|--------------|------------|
| Temps total | <60s | +9% (5s) | benchmark_cli_vs_web.py |
| Throughput | >2,183 pkt/s | -8% | benchmark_cli_vs_web.py |
| Peak memory | <600 MB | +20% | benchmark_memory.py |
| Upload (100MB) | <5s | N/A | locustfile.py |
| SSE latency | <500ms | N/A | Manual test |
| Image Docker | <250 MB | N/A | docker images |
| Build time | <5 min | N/A | time docker build |

---

## Points d'Attention

### ❌ Anti-Patterns à Éviter

1. **Multiple uvicorn workers pour CPU-bound**
   ```bash
   # ❌ MAUVAIS: 4 workers = 4x contention CPU
   uvicorn app:main --workers 4

   # ✅ CORRECT: 1 worker + background queue
   uvicorn app:main --workers 1
   ```

2. **Analyse synchrone dans endpoint**
   ```python
   # ❌ MAUVAIS: Bloque event loop 55s
   @app.post("/upload")
   async def upload(file):
       return analyze_pcap_hybrid(file)  # BLOQUE!

   # ✅ CORRECT: Async I/O + background worker
   @app.post("/upload")
   async def upload(file):
       await save_file(file)  # Async I/O
       await queue.put(task_id)  # Background
       return {"task_id": task_id}
   ```

3. **Load PCAP complet en mémoire**
   ```python
   # ❌ MAUVAIS: 500MB PCAP = 500MB RAM
   content = await file.read()  # Load all!
   with open(path, 'wb') as f:
       f.write(content)

   # ✅ CORRECT: Chunked transfer
   async with aiofiles.open(path, 'wb') as f:
       while chunk := await file.read(1024*1024):
           await f.write(chunk)
   ```

4. **GC sans cooldown (Issue #4)**
   ```python
   # ❌ MAUVAIS: GC après chaque chunk (spam!)
   for chunk in chunks:
       process(chunk)
       gc.collect()  # Trop fréquent!

   # ✅ CORRECT: GC avec cooldown (déjà implémenté)
   memory_optimizer.trigger_gc(force=False)  # Cooldown 5s
   ```

---

### ✅ Best Practices

1. **Réutiliser code CLI existant**
   - `analyze_pcap_hybrid()` DÉJÀ optimisé
   - Juste wrapper avec SSE callbacks
   - Pas de duplication code

2. **Streaming automatique >100MB**
   - `StreamingProcessor` DÉJÀ implémenté
   - Chunking adaptatif (20k/10k packets)
   - GC intelligent avec cooldown

3. **Monitoring intégré**
   - `MemoryOptimizer.get_memory_stats()`
   - Health check avec metrics
   - Logging JSON structuré

4. **Security by default**
   - User non-root (UID 1000)
   - Read-only filesystem (sauf /data)
   - Upload validation (extension, taille, magic bytes)
   - no-new-privileges, cap_drop

---

## Scaling Horizontal (Optionnel)

### Multiple Containers

```yaml
# docker-compose.scale.yml
services:
  pcap-analyzer:
    # ... config normale ...
    deploy:
      replicas: 3  # 3 instances

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
```

### Nginx Load Balancer

```nginx
upstream pcap_backend {
    least_conn;  # Route vers moins chargé
    server pcap-analyzer-1:8000;
    server pcap-analyzer-2:8000;
    server pcap-analyzer-3:8000;
}

server {
    listen 80;

    location / {
        proxy_pass http://pcap_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";  # SSE
    }
}
```

**Attention:** Queue in-memory (asyncio) = pas de partage entre containers!

**Solution si requis:** Migrer vers Celery + Redis (out of scope MVP).

---

## Ressources

- **Plan complet:** `docs/PLAN_PERFORMANCE.md`
- **Checklist:** `docs/CHECKLIST_PERFORMANCE.md`
- **Scripts:** `scripts/README.md`
- **Dockerfile:** `Dockerfile` (multi-stage)
- **Compose:** `docker-compose.yml`

---

**Architecture validée - Prête pour implémentation**
