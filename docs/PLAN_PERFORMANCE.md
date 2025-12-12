# Plan d'Optimisation Performance - PCAP Analyzer Web

**Date:** 2025-12-12
**Version:** 1.0
**Agent:** Performance
**Baseline CLI:** 131k paquets, 26MB, 55 secondes

---

## Table des Matières

1. [Baseline et Objectifs](#1-baseline-et-objectifs)
2. [Image Docker](#2-image-docker)
3. [Runtime Performance](#3-runtime-performance)
4. [Optimisation Mémoire](#4-optimisation-mémoire)
5. [Optimisation CPU](#5-optimisation-cpu)
6. [Optimisation Stockage](#6-optimisation-stockage)
7. [Optimisation Réseau](#7-optimisation-réseau)
8. [Analyses Concurrentes](#8-analyses-concurrentes)
9. [Scripts de Benchmarking](#9-scripts-de-benchmarking)
10. [Monitoring et Métriques](#10-monitoring-et-métriques)
11. [Checklist de Validation](#11-checklist-de-validation)

---

## 1. Baseline et Objectifs

### 1.1 Baseline CLI (Référence Absolue)

**PCAP de référence:** `tests/data/sample.pcap` (ou équivalent)
- Taille fichier: **26 MB**
- Nombre de paquets: **131,000**
- Temps d'exécution CLI: **55 secondes**
- Mode: **Hybrid dpkt+Scapy**
- Mémoire peak: **~300-500 MB** (estimation)

**Performance CLI mesurée:**
- Throughput: **2,382 paquets/sec** (131k / 55s)
- Mémoire/paquet: **~3.8 KB** (500MB / 131k)
- Phase 1 (dpkt metadata): **~20-25s** (45%)
- Phase 2 (Scapy deep): **~30-35s** (55%)

### 1.2 Objectifs Web (Overhead <10%)

| Métrique | CLI Baseline | Web Target | Overhead Max |
|----------|--------------|------------|--------------|
| **Temps total** | 55s | 60s | +9% (5s) |
| **Throughput** | 2,382 pkt/s | >2,183 pkt/s | -8% |
| **Mémoire peak** | ~500 MB | <600 MB | +20% |
| **Upload time (100MB)** | N/A | <5s | N/A |
| **SSE latency** | N/A | <500ms | N/A |
| **Mémoire pour 500MB PCAP** | ~2-3 GB | <4 GB | +33% |

**Philosophie:** Les optimisations sont DÉJÀ en place (streaming, memory optimizer, dpkt). L'objectif n'est PAS de réoptimiser l'analyseur, mais de **préserver** ses performances dans le conteneur web.

---

## 2. Image Docker

### 2.1 Objectif: <250 MB

**Stratégie Multi-Stage Build (3 étapes)**

```dockerfile
# ============================================
# STAGE 1: Builder (Compilation dépendances)
# ============================================
FROM python:3.11-slim-bookworm AS builder

# Installer uniquement build-deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Créer virtualenv pour isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copier requirements et installer
COPY requirements.txt requirements-web.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt -r requirements-web.txt

# ============================================
# STAGE 2: Runtime dependencies
# ============================================
FROM python:3.11-slim-bookworm AS runtime-deps

# Installer UNIQUEMENT runtime libs (pas gcc, g++)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Copier virtualenv depuis builder
COPY --from=builder /opt/venv /opt/venv

# ============================================
# STAGE 3: Final (Application)
# ============================================
FROM python:3.11-slim-bookworm

# Installer runtime libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copier virtualenv
COPY --from=runtime-deps /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Créer user non-root
RUN groupadd -r pcapuser && useradd -r -g pcapuser -u 1000 pcapuser

# Créer répertoires
RUN mkdir -p /app /data/uploads /data/reports && \
    chown -R pcapuser:pcapuser /app /data

WORKDIR /app

# Copier UNIQUEMENT code source (pas .git, tests, docs)
COPY --chown=pcapuser:pcapuser src/ ./src/
COPY --chown=pcapuser:pcapuser web/ ./web/
COPY --chown=pcapuser:pcapuser config.yaml ./

USER pcapuser

EXPOSE 8000

CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### 2.2 Optimisations Image

**Techniques de réduction:**

1. **.dockerignore** agressif:
   ```
   .git/
   .github/
   tests/
   docs/
   reports/
   *.md
   .pytest_cache/
   __pycache__/
   *.pyc
   .venv/
   venv/
   ```

2. **Cache layers optimisé:**
   - Copier requirements AVANT code source
   - Utiliser `--no-cache-dir` pour pip
   - Nettoyer apt cache: `rm -rf /var/lib/apt/lists/*`

3. **Comparaison bases:**
   | Image | Taille uncompressed | Pros | Cons | Recommandation |
   |-------|---------------------|------|------|----------------|
   | `python:3.11` | ~1 GB | Complet | Très lourd | ❌ Non |
   | `python:3.11-slim` | ~149 MB | glibc (wheels numpy/scapy) | OK | ✅ **OUI** |
   | `python:3.11-alpine` | ~50 MB | Très léger | musl libc (pas de wheels) | ❌ Non |
   | `gcr.io/distroless/python3` | ~60 MB | Sécurisé | Pas de shell (debug impossible) | ⚠️ Production only |

**Verdict:** `python:3.11-slim-bookworm` (déjà dans DECISIONS_TECHNIQUES.md)

### 2.3 Taille estimée finale

```
python:3.11-slim-bookworm        149 MB
+ Python dependencies (venv)      ~70 MB
+ Application code                 ~5 MB
+ Runtime libs (libpcap)           ~2 MB
= TOTAL                          ~226 MB ✅ (<250 MB target)
```

### 2.4 Benchmark: Temps de build

**Mesure à effectuer:**
```bash
# Premier build (sans cache)
time docker build -t pcap-analyzer:latest .

# Rebuild après modif code (avec cache layers)
time docker build -t pcap-analyzer:latest .
```

**Target:** <5 min (premier build), <30s (rebuild avec cache)

---

## 3. Runtime Performance

### 3.1 FastAPI Async Best Practices

**Règles d'or:**
1. **JAMAIS bloquer l'event loop** avec opérations synchrones lourdes
2. **Utiliser async/await** pour I/O (fichiers, DB)
3. **Déléguer CPU-bound** au background worker (analyse PCAP)

**Architecture:**
```python
# ✅ CORRECT: Upload async, analyse en background
@app.post("/upload")
async def upload_pcap(file: UploadFile):
    # I/O async (pas bloquant)
    async with aiofiles.open(pcap_path, 'wb') as f:
        await f.write(await file.read())

    # Enqueue pour worker (pas bloquant)
    await task_queue.put(task_id)

    return {"task_id": task_id}

# ❌ INCORRECT: Analyse synchrone dans endpoint
@app.post("/upload")
async def upload_pcap(file: UploadFile):
    # BLOQUE l'event loop pendant 55s!
    results = analyze_pcap_hybrid(pcap_path)  # ❌ MAUVAIS
    return results
```

### 3.2 Configuration Uvicorn

**Workers:**
```bash
# ❌ MAUVAIS: Multiple workers pour CPU-bound
uvicorn web.main:app --workers 4  # Analyse PCAP utilise déjà 100% CPU!

# ✅ CORRECT: 1 worker + background queue
uvicorn web.main:app --workers 1 --host 0.0.0.0 --port 8000
```

**Pourquoi 1 worker?**
- Analyse PCAP = CPU-bound (100% d'un core)
- Multiple workers = contention CPU (pas de gain, overhead)
- Queue interne = 1 analyse à la fois

**Si scaling horizontal nécessaire:**
```bash
# Option 1: Multiple conteneurs (Kubernetes HPA)
kubectl scale deployment pcap-analyzer --replicas=3

# Option 2: Load balancer externe (nginx)
upstream pcap_backend {
    server container1:8000;
    server container2:8000;
    server container3:8000;
}
```

### 3.3 Streaming Upload (Chunked)

**Upload par chunks (éviter load complet en mémoire):**
```python
from fastapi import UploadFile
import aiofiles

async def save_upload_chunked(file: UploadFile, dest_path: str):
    """Save uploaded file in chunks (memory-efficient)."""
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks

    async with aiofiles.open(dest_path, 'wb') as f:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            await f.write(chunk)
```

**Benchmark upload:**
| Taille PCAP | Temps upload target | Throughput |
|-------------|---------------------|------------|
| 10 MB | <1s | >10 MB/s |
| 100 MB | <5s | >20 MB/s |
| 500 MB | <20s | >25 MB/s |

### 3.4 Connection Pooling SQLite

**Partage connexion entre requêtes:**
```python
from contextlib import asynccontextmanager
import aiosqlite

# Global connection pool
db_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage DB connection lifecycle."""
    global db_pool
    db_pool = await aiosqlite.connect("/data/pcap_analyzer.db")
    yield
    await db_pool.close()

app = FastAPI(lifespan=lifespan)
```

**Éviter:** Ouvrir/fermer connexion à chaque requête (overhead ~5-10ms/req)

---

## 4. Optimisation Mémoire

### 4.1 État Actuel (DÉJÀ Optimisé)

**Outils existants:**
- `StreamingProcessor`: Chunking automatique pour fichiers >100MB
- `MemoryOptimizer`: GC intelligent avec cooldown (fix Issue #4)
- `MemoryMonitor`: Tracking consommation par phase
- Mode adaptatif basé sur taille fichier

**Seuils StreamingProcessor actuels:**
```python
SMALL_FILE_THRESHOLD   = 100 MB  # Load all in memory
MEDIUM_FILE_THRESHOLD  = 500 MB  # Chunked (20k packets)
LARGE_FILE_THRESHOLD   = 2 GB    # Aggressive streaming (10k packets)
```

### 4.2 Limites Docker (Configurable)

**docker-compose.yml:**
```yaml
services:
  pcap-analyzer:
    image: pcap-analyzer:latest
    deploy:
      resources:
        limits:
          memory: 4G  # Hard limit (OOM killer à 4GB)
        reservations:
          memory: 1G  # Soft reservation
```

**Correspondance limites / taille PCAP:**
| Taille PCAP | Memory Limit | Ratio |
|-------------|--------------|-------|
| <100 MB | 2 GB | 20x |
| 100-500 MB | 4 GB | 8-40x |
| 500MB-2GB | 8 GB | 4-16x |
| >2 GB | 16 GB | <8x |

**Recommandation par défaut:** `memory: 4G` (suffit pour 90% des cas)

### 4.3 Monitoring Mémoire (Déjà Implémenté)

**Utiliser psutil existant:**
```python
from src.performance.memory_optimizer import MemoryOptimizer

# Dans le worker background
optimizer = MemoryOptimizer(memory_limit_mb=3500)  # 3.5GB pour Docker 4GB

# Pendant analyse
if optimizer.check_memory_pressure():
    collected = optimizer.trigger_gc(force=True)
    logger.warning(f"Memory pressure: collected {collected} objects")

# À la fin
report = optimizer.get_memory_report()
logger.info(f"Peak memory: {report['peak_mb']:.2f} MB")
```

**SSE progress avec mémoire:**
```python
async def progress_sse(task_id: str):
    """Send progress with memory stats."""
    while True:
        stats = optimizer.get_memory_stats()
        yield {
            "phase": current_phase,
            "progress": percent,
            "memory_mb": stats.process_mb,
            "memory_percent": (stats.process_mb / memory_limit_mb) * 100
        }
```

### 4.4 Garbage Collection Stratégie

**DÉJÀ IMPLÉMENTÉ avec cooldown (Issue #4):**
- Cooldown: 5s entre GC attempts
- Skip si 3 GC consécutifs vides
- Reset tracking entre phases

**Pas besoin de modification!** Les optimisations sont déjà présentes.

---

## 5. Optimisation CPU

### 5.1 État Actuel (Hybrid Mode)

**Performance mode hybride (DÉJÀ Optimisé):**
- Phase 1: dpkt (3-5x plus rapide que Scapy)
- Phase 2: Scapy uniquement pour DNS/ICMP
- Throughput actuel: **2,382 paquets/sec**

**Aucune optimisation CPU supplémentaire requise** sauf si profiling détecte bottlenecks.

### 5.2 Limites Docker CPU

**docker-compose.yml:**
```yaml
services:
  pcap-analyzer:
    deploy:
      resources:
        limits:
          cpus: '2.0'  # Max 2 cores
        reservations:
          cpus: '1.0'  # Min 1 core
```

**Recommandation:** Pas de limite CPU (laisser utiliser 100% d'un core)

### 5.3 Profiling (cProfile)

**Script de profiling détaillé:**
```python
# scripts/profile_analysis.py
import cProfile
import pstats
from src.cli import analyze_pcap_hybrid

def profile_pcap(pcap_file: str):
    """Profile PCAP analysis with cProfile."""
    profiler = cProfile.Profile()
    profiler.enable()

    results = analyze_pcap_hybrid(pcap_file)

    profiler.disable()

    # Afficher top 20 fonctions (cumulative time)
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(20)

    # Sauvegarder pour visualisation
    stats.dump_stats('profile_output.prof')

if __name__ == "__main__":
    import sys
    profile_pcap(sys.argv[1])
```

**Analyse:**
```bash
# Profiling
python scripts/profile_analysis.py tests/data/sample.pcap

# Visualisation avec snakeviz
pip install snakeviz
snakeviz profile_output.prof
```

**Seuils d'alerte:** Si une fonction prend >20% du temps total, investiguer.

### 5.4 py-spy pour Production

**Profiling sans redémarrage:**
```bash
# Dans le conteneur Docker
pip install py-spy

# Profiler le process uvicorn (30s sample)
py-spy top --pid <uvicorn_pid> --duration 30

# Générer flamegraph
py-spy record --pid <uvicorn_pid> --duration 30 --output profile.svg
```

**Usage:** Uniquement si dégradation performance observée en production.

---

## 6. Optimisation Stockage

### 6.1 Cleanup Agressif (APScheduler)

**Stratégie (déjà dans DECISIONS_TECHNIQUES.md):**
```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

scheduler = AsyncIOScheduler()

async def cleanup_expired_reports():
    """Delete reports older than 24h."""
    import time
    from pathlib import Path

    reports_dir = Path("/data/reports")
    cutoff_time = time.time() - (24 * 3600)

    deleted = 0
    for report_file in reports_dir.glob("*.html"):
        if report_file.stat().st_mtime < cutoff_time:
            report_file.unlink()
            deleted += 1

    logger.info(f"Cleanup: deleted {deleted} expired reports")

# Run every hour
scheduler.add_job(
    cleanup_expired_reports,
    trigger=CronTrigger(minute=0),  # XX:00 every hour
    id="cleanup_reports"
)

scheduler.start()
```

**Cleanup PCAP immédiat (après analyse):**
```python
async def analyze_task(task_id: str, pcap_path: str):
    """Background analysis task."""
    try:
        # Analyse
        results = analyze_pcap_hybrid(pcap_path)

        # Sauvegarder rapport
        await save_report(task_id, results)

    finally:
        # TOUJOURS supprimer PCAP (même si erreur)
        if Path(pcap_path).exists():
            Path(pcap_path).unlink()
            logger.info(f"Deleted PCAP: {pcap_path}")
```

### 6.2 Rotation Logs

**Utiliser logging.handlers.RotatingFileHandler:**
```python
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler(
    "/data/logs/pcap_analyzer.log",
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5  # Garder 5 fichiers (50MB total)
)
```

### 6.3 Limites Uploads

**Validation taille (config):**
```python
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "500"))

@app.post("/upload")
async def upload_pcap(file: UploadFile):
    # Validation taille
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {MAX_UPLOAD_SIZE_MB}MB)"
        )
```

**FastAPI built-in limit:**
```python
app = FastAPI()
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_request_size=MAX_UPLOAD_SIZE_MB * 1024 * 1024
)
```

### 6.4 Volumes Docker Performants

**docker-compose.yml:**
```yaml
volumes:
  pcap_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /var/lib/pcap_analyzer/data  # SSD recommandé
```

**Performance tips:**
- Utiliser SSD (pas HDD)
- Éviter NFS/CIFS (latence)
- tmpfs pour /tmp si disponible (RAM disk)

---

## 7. Optimisation Réseau

### 7.1 Compression Responses (gzip)

**Middleware FastAPI:**
```python
from fastapi.middleware.gzip import GZipMiddleware

app.add_middleware(GZipMiddleware, minimum_size=1000)
```

**Gain:** ~70-80% réduction taille pour HTML/JSON (text-based)

**Benchmark:**
| Response Type | Uncompressed | Compressed | Ratio |
|---------------|--------------|------------|-------|
| HTML report (1MB) | 1,000 KB | ~200 KB | 5x |
| JSON results (500KB) | 500 KB | ~100 KB | 5x |

### 7.2 Chunked Transfer Encoding

**FastAPI StreamingResponse pour rapports volumineux:**
```python
from fastapi.responses import StreamingResponse

@app.get("/report/{task_id}")
async def get_report(task_id: str):
    """Stream HTML report (chunked)."""
    report_path = f"/data/reports/{task_id}.html"

    async def file_iterator():
        async with aiofiles.open(report_path, 'rb') as f:
            while chunk := await f.read(65536):  # 64KB chunks
                yield chunk

    return StreamingResponse(
        file_iterator(),
        media_type="text/html",
        headers={"Content-Disposition": f"inline; filename={task_id}.html"}
    )
```

### 7.3 SSE Optimisé

**Pas trop de messages (overhead):**
```python
# ❌ MAUVAIS: 1 message par paquet (131k messages!)
for i, packet in enumerate(packets):
    await send_sse({"progress": i})

# ✅ CORRECT: 1 message tous les 1000 paquets
if i % 1000 == 0:
    await send_sse({"progress": int((i / total) * 100)})
```

**Target latency:** <500ms entre événement et réception client

**Format SSE minimal:**
```
data: {"phase":"metadata","progress":45}\n\n
data: {"phase":"analysis","progress":78}\n\n
data: {"phase":"completed"}\n\n
```

### 7.4 Keep-Alive Connections

**Uvicorn config:**
```python
uvicorn.run(
    app,
    host="0.0.0.0",
    port=8000,
    timeout_keep_alive=30  # 30s keep-alive (défaut: 5s)
)
```

**Avantage:** Réutilisation connexions TCP (pas de handshake répété)

---

## 8. Analyses Concurrentes

### 8.1 Queue avec Limite

**asyncio.Queue (in-process):**
```python
from asyncio import Queue, create_task

# Queue globale
analysis_queue = Queue(maxsize=5)  # Max 5 analyses en attente

@app.post("/upload")
async def upload_pcap(file: UploadFile):
    # Vérifier capacité
    if analysis_queue.full():
        raise HTTPException(
            status_code=503,
            detail="Analysis queue full, try again later"
        )

    # Enqueue
    await analysis_queue.put(task_id)

    return {"task_id": task_id, "queue_position": analysis_queue.qsize()}
```

### 8.2 Worker Background

**1 worker = 1 analyse à la fois (CPU-bound):**
```python
async def analysis_worker():
    """Background worker processing queue."""
    while True:
        task_id = await analysis_queue.get()

        try:
            logger.info(f"Starting analysis: {task_id}")
            await run_analysis(task_id)
            logger.info(f"Completed analysis: {task_id}")
        except Exception as e:
            logger.error(f"Analysis failed: {task_id} - {e}")
        finally:
            analysis_queue.task_done()

# Démarrer worker au startup
@app.on_event("startup")
async def startup_event():
    create_task(analysis_worker())
```

### 8.3 Timeout Analyses

**Protection contre analyses infinies:**
```python
import asyncio

async def run_analysis_with_timeout(task_id: str, timeout: int = 1800):
    """Run analysis with 30min timeout."""
    try:
        await asyncio.wait_for(
            run_analysis(task_id),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.error(f"Analysis timeout: {task_id}")
        await update_task_status(task_id, "timeout")
```

**Timeout par défaut:** 30 minutes (1800s)

### 8.4 Load Shedding (Optionnel)

**Rejeter requêtes si overload:**
```python
from fastapi import Request

@app.middleware("http")
async def load_shedding(request: Request, call_next):
    """Reject requests if system overloaded."""
    mem_stats = memory_optimizer.get_memory_stats()

    # Si mémoire >90%, rejeter uploads
    if mem_stats.percent > 90 and request.url.path == "/upload":
        return JSONResponse(
            status_code=503,
            content={"detail": "Service overloaded, try again later"}
        )

    return await call_next(request)
```

---

## 9. Scripts de Benchmarking

### 9.1 Benchmark CLI vs Web

**Script:** `scripts/benchmark_cli_vs_web.py`

```python
#!/usr/bin/env python3
"""
Benchmark CLI vs Web overhead.

Usage:
    python scripts/benchmark_cli_vs_web.py <pcap_file>

Output:
    CLI Time: 55.23s
    Web Time: 58.45s
    Overhead: 3.22s (5.8%)
    Status: ✅ PASS (<10% overhead)
"""

import time
import sys
import subprocess
import requests
from pathlib import Path

def benchmark_cli(pcap_file: str) -> float:
    """Benchmark CLI mode."""
    start = time.perf_counter()

    subprocess.run(
        ["python", "-m", "src.cli", "analyze", pcap_file, "--no-report"],
        check=True,
        capture_output=True
    )

    return time.perf_counter() - start

def benchmark_web(pcap_file: str, api_url: str = "http://localhost:8000") -> float:
    """Benchmark Web mode."""
    # Upload
    start = time.perf_counter()

    with open(pcap_file, 'rb') as f:
        response = requests.post(
            f"{api_url}/upload",
            files={"file": f}
        )

    task_id = response.json()["task_id"]

    # Poll jusqu'à completion
    while True:
        status_resp = requests.get(f"{api_url}/status/{task_id}")
        status = status_resp.json()["status"]

        if status == "completed":
            break
        elif status == "failed":
            raise Exception("Analysis failed")

        time.sleep(1)

    return time.perf_counter() - start

def main():
    if len(sys.argv) < 2:
        print("Usage: python benchmark_cli_vs_web.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    print("=" * 60)
    print("BENCHMARK: CLI vs Web Overhead")
    print("=" * 60)
    print(f"PCAP: {pcap_file}")
    print(f"Size: {Path(pcap_file).stat().st_size / (1024*1024):.2f} MB")
    print()

    # CLI benchmark (3 runs)
    print("Running CLI benchmark (3 iterations)...")
    cli_times = [benchmark_cli(pcap_file) for _ in range(3)]
    cli_avg = sum(cli_times) / len(cli_times)
    print(f"  CLI times: {cli_times}")
    print(f"  CLI average: {cli_avg:.2f}s")
    print()

    # Web benchmark (3 runs)
    print("Running Web benchmark (3 iterations)...")
    web_times = [benchmark_web(pcap_file) for _ in range(3)]
    web_avg = sum(web_times) / len(web_times)
    print(f"  Web times: {web_times}")
    print(f"  Web average: {web_avg:.2f}s")
    print()

    # Overhead
    overhead = web_avg - cli_avg
    overhead_pct = (overhead / cli_avg) * 100

    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"CLI Time:    {cli_avg:.2f}s")
    print(f"Web Time:    {web_avg:.2f}s")
    print(f"Overhead:    {overhead:.2f}s ({overhead_pct:.1f}%)")
    print()

    # Validation
    if overhead_pct < 10:
        print("✅ PASS: Overhead <10%")
        sys.exit(0)
    else:
        print("❌ FAIL: Overhead >=10%")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### 9.2 Profiling Mémoire

**Script:** `scripts/benchmark_memory.py`

```python
#!/usr/bin/env python3
"""
Memory profiling for PCAP analysis.

Usage:
    python scripts/benchmark_memory.py <pcap_file>

Output:
    File: sample.pcap (26 MB)
    Packets: 131,000

    Peak Memory: 487 MB
    Memory/Packet: 3.7 KB
    GC Collections: 12

    Status: ✅ PASS (<4 GB for 500MB PCAP)
"""

import sys
import tracemalloc
from pathlib import Path
from src.cli import analyze_pcap_hybrid
from src.config import get_config

def profile_memory(pcap_file: str):
    """Profile memory usage."""
    tracemalloc.start()

    # Baseline
    snapshot_start = tracemalloc.take_snapshot()

    # Analyse
    config = get_config()
    results = analyze_pcap_hybrid(pcap_file, config)

    # Peak
    current, peak = tracemalloc.get_traced_memory()
    snapshot_end = tracemalloc.take_snapshot()

    tracemalloc.stop()

    # Stats
    file_size = Path(pcap_file).stat().st_size
    total_packets = results.get("protocol_distribution", {}).get("total_packets", 0)

    print("=" * 60)
    print("MEMORY PROFILING")
    print("=" * 60)
    print(f"File: {Path(pcap_file).name} ({file_size / (1024*1024):.2f} MB)")
    print(f"Packets: {total_packets:,}")
    print()
    print(f"Peak Memory: {peak / (1024*1024):.0f} MB")
    print(f"Memory/Packet: {(peak / total_packets) / 1024:.1f} KB")
    print()

    # Top 10 allocations
    print("Top 10 Memory Allocations:")
    stats = snapshot_end.compare_to(snapshot_start, 'lineno')
    for i, stat in enumerate(stats[:10], 1):
        print(f"  {i}. {stat}")
    print()

    # Validation
    max_memory_mb = 4000  # 4GB
    if peak / (1024*1024) < max_memory_mb:
        print(f"✅ PASS: Peak memory <{max_memory_mb}MB")
    else:
        print(f"❌ FAIL: Peak memory >={max_memory_mb}MB")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python benchmark_memory.py <pcap_file>")
        sys.exit(1)

    profile_memory(sys.argv[1])
```

### 9.3 Load Testing (Locust)

**Script:** `scripts/locustfile.py`

```python
from locust import HttpUser, task, between, events
from pathlib import Path
import time

class PCAPAnalyzerUser(HttpUser):
    """Load test user for PCAP Analyzer."""

    wait_time = between(5, 15)  # Wait 5-15s between tasks

    def on_start(self):
        """Setup test data."""
        self.pcap_file = "tests/data/sample.pcap"

    @task(10)
    def upload_and_analyze(self):
        """Upload PCAP and wait for completion."""
        # Upload
        with open(self.pcap_file, 'rb') as f:
            response = self.client.post(
                "/upload",
                files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
            )

        if response.status_code != 200:
            return

        task_id = response.json()["task_id"]

        # Poll status (max 120s)
        start = time.time()
        while time.time() - start < 120:
            status_resp = self.client.get(f"/status/{task_id}")
            status = status_resp.json()["status"]

            if status == "completed":
                # Get report
                self.client.get(f"/report/{task_id}")
                return
            elif status == "failed":
                return

            time.sleep(2)

    @task(1)
    def health_check(self):
        """Health check endpoint."""
        self.client.get("/health")

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Print test start info."""
    print("=" * 60)
    print("LOAD TEST STARTED")
    print("=" * 60)

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Print test results."""
    print("=" * 60)
    print("LOAD TEST RESULTS")
    print("=" * 60)
    print(f"Total Requests: {environment.stats.total.num_requests}")
    print(f"Total Failures: {environment.stats.total.num_failures}")
    print(f"Average Response Time: {environment.stats.total.avg_response_time:.0f}ms")
    print(f"RPS: {environment.stats.total.current_rps:.2f}")
```

**Run load test:**
```bash
# Web UI
locust -f scripts/locustfile.py --host=http://localhost:8000

# Headless (10 users, 2 users/sec spawn, 2min)
locust -f scripts/locustfile.py \
    --host=http://localhost:8000 \
    --users 10 \
    --spawn-rate 2 \
    --run-time 2m \
    --headless
```

### 9.4 Hyperfine (CLI Benchmark)

**Benchmark CLI simple:**
```bash
# Install hyperfine
brew install hyperfine  # macOS
# ou apt install hyperfine  # Linux

# Benchmark CLI (10 runs)
hyperfine \
    --warmup 1 \
    --runs 10 \
    --export-markdown benchmark_results.md \
    'python -m src.cli analyze tests/data/sample.pcap --no-report'
```

**Output:**
```
Benchmark 1: python -m src.cli analyze tests/data/sample.pcap --no-report
  Time (mean ± σ):     55.234 s ±  1.456 s    [User: 52.1 s, System: 2.8 s]
  Range (min … max):   53.102 s … 57.891 s    10 runs
```

---

## 10. Monitoring et Métriques

### 10.1 Métriques Clés

**Performance:**
| Métrique | Seuil Warning | Seuil Critical | Action |
|----------|---------------|----------------|--------|
| Analysis time | >65s | >80s | Investiguer CPU/Memory |
| Upload time (100MB) | >7s | >10s | Vérifier réseau/disk |
| SSE latency | >800ms | >1500ms | Réduire fréquence messages |
| Memory usage | >3.5GB | >3.8GB | Trigger GC / rejeter uploads |
| Queue size | >3 | >=5 | Load shedding |
| Disk usage (/data) | >80% | >90% | Cleanup forcé |

**Availability:**
| Métrique | Seuil Warning | Seuil Critical |
|----------|---------------|----------------|
| API uptime | <99% | <95% |
| Failed analyses | >5% | >10% |
| Timeout rate | >2% | >5% |

### 10.2 Health Check Endpoint

```python
from fastapi import status
from fastapi.responses import JSONResponse

@app.get("/health")
async def health_check():
    """Health check with system metrics."""
    mem_stats = memory_optimizer.get_memory_stats()
    disk_usage = shutil.disk_usage("/data")

    # Checks
    checks = {
        "memory_ok": mem_stats.percent < 90,
        "disk_ok": (disk_usage.used / disk_usage.total) < 0.90,
        "queue_ok": analysis_queue.qsize() < 5,
    }

    is_healthy = all(checks.values())

    response = {
        "status": "healthy" if is_healthy else "degraded",
        "checks": checks,
        "metrics": {
            "memory_percent": mem_stats.percent,
            "memory_used_mb": mem_stats.process_mb,
            "disk_percent": (disk_usage.used / disk_usage.total) * 100,
            "queue_size": analysis_queue.qsize(),
        }
    }

    status_code = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(content=response, status_code=status_code)
```

### 10.3 Structured Logging

```python
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""

    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
        }

        # Add extra fields
        if hasattr(record, "task_id"):
            log_obj["task_id"] = record.task_id
        if hasattr(record, "duration"):
            log_obj["duration"] = record.duration

        return json.dumps(log_obj)

# Configure
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger = logging.getLogger("pcap_analyzer")
logger.addHandler(handler)

# Usage
logger.info("Analysis completed", extra={
    "task_id": task_id,
    "duration": 55.23,
    "packets": 131000
})
```

### 10.4 Prometheus Metrics (Optionnel)

**Si monitoring avancé requis:**
```python
from prometheus_client import Counter, Histogram, Gauge, generate_latest

# Metrics
analysis_duration = Histogram(
    "pcap_analysis_duration_seconds",
    "Time spent analyzing PCAP"
)
analysis_total = Counter(
    "pcap_analysis_total",
    "Total analyses performed",
    ["status"]
)
queue_size = Gauge(
    "pcap_queue_size",
    "Current analysis queue size"
)

# Usage
@analysis_duration.time()
async def run_analysis(task_id: str):
    # ...
    analysis_total.labels(status="success").inc()

# Endpoint
@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")
```

### 10.5 Dashboard Grafana (Optionnel)

**Stack complet (si requis):**
```yaml
# docker-compose.monitoring.yml
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana_data:/var/lib/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin

volumes:
  prometheus_data:
  grafana_data:
```

**prometheus.yml:**
```yaml
scrape_configs:
  - job_name: 'pcap-analyzer'
    static_configs:
      - targets: ['pcap-analyzer:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

**Dashboards Grafana:**
- Analysis Duration (histogram)
- Queue Size (gauge, real-time)
- Memory Usage (gauge)
- Success/Failure Rate (counter)

**NOTE:** Prometheus/Grafana optionnel, logging JSON suffit pour 90% des cas.

---

## 11. Checklist de Validation

### 11.1 Performance

- [ ] **Benchmark CLI vs Web:** Overhead <10% (target: 55s → <60s)
- [ ] **Throughput:** >2,183 paquets/sec (baseline: 2,382)
- [ ] **Upload time:** <5s pour 100MB PCAP
- [ ] **SSE latency:** <500ms événement → client
- [ ] **Memory peak:** <600MB pour 26MB PCAP
- [ ] **Memory peak:** <4GB pour 500MB PCAP
- [ ] **Docker image:** <250MB (compressed)
- [ ] **Docker build:** <5min (premier), <30s (rebuild cache)

### 11.2 Fonctionnel

- [ ] **Upload validation:** Extension, taille, magic bytes
- [ ] **Queue limit:** Rejet si queue full (maxsize=5)
- [ ] **Timeout:** Analyses >30min = timeout
- [ ] **Cleanup PCAP:** Suppression immédiate post-analyse
- [ ] **Cleanup rapports:** TTL 24h, job hourly
- [ ] **SSE reconnexion:** Auto-reconnect client
- [ ] **Concurrent analyses:** 2 uploads simultanés OK

### 11.3 Sécurité

- [ ] **User non-root:** UID 1000 (pcapuser)
- [ ] **Read-only filesystem:** Sauf /data, /tmp
- [ ] **no-new-privileges:** Flag Docker activé
- [ ] **Capabilities drop:** cap_drop: [ALL]
- [ ] **Upload limit:** 500MB enforced
- [ ] **Path traversal:** Validation chemins
- [ ] **PCAP validation:** Magic bytes check

### 11.4 Observabilité

- [ ] **Health check:** GET /health (200 si OK)
- [ ] **Structured logging:** JSON format
- [ ] **Memory tracking:** Log peak/GC stats
- [ ] **Error logging:** Traceback complets
- [ ] **Metrics endpoint:** /metrics (Prometheus, optionnel)

### 11.5 Scalabilité

- [ ] **Horizontal scaling:** Multiple conteneurs testés
- [ ] **Load balancing:** Nginx upstream config
- [ ] **Resource limits:** Memory/CPU configurables
- [ ] **Volume performance:** SSD recommandé
- [ ] **Load shedding:** Rejet si overload (optionnel)

### 11.6 Tests

- [ ] **Unit tests:** Couverture >80%
- [ ] **Integration tests:** Upload → Analyse → Report
- [ ] **Load test:** 10 users concurrent (Locust)
- [ ] **Stress test:** Queue saturation (5+ uploads)
- [ ] **Benchmark regression:** CLI vs Web <10% overhead

---

## Annexe A: Commandes Utiles

### A.1 Build & Run

```bash
# Build image
docker build -t pcap-analyzer:latest .

# Run conteneur
docker run -d \
    --name pcap-analyzer \
    -p 8000:8000 \
    -v pcap_data:/data \
    -e MAX_UPLOAD_SIZE_MB=500 \
    -e REPORT_TTL_HOURS=24 \
    --memory=4g \
    --cpus=2 \
    --security-opt=no-new-privileges:true \
    pcap-analyzer:latest

# Logs
docker logs -f pcap-analyzer

# Stats runtime
docker stats pcap-analyzer
```

### A.2 Debugging

```bash
# Shell dans conteneur
docker exec -it pcap-analyzer /bin/bash

# Memory profiling live
docker exec pcap-analyzer ps aux --sort=-rss | head -10

# Disk usage
docker exec pcap-analyzer du -sh /data/*

# Network test
curl -X POST http://localhost:8000/upload \
    -F "file=@tests/data/sample.pcap"
```

### A.3 Benchmarking

```bash
# CLI baseline (10 runs)
hyperfine --warmup 1 --runs 10 \
    'python -m src.cli analyze tests/data/sample.pcap --no-report'

# Web vs CLI
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap

# Memory profiling
python scripts/benchmark_memory.py tests/data/sample.pcap

# Load test (Locust)
locust -f scripts/locustfile.py --host=http://localhost:8000 \
    --users 10 --spawn-rate 2 --run-time 2m --headless
```

### A.4 Profiling Production

```bash
# Install py-spy dans conteneur
docker exec pcap-analyzer pip install py-spy

# Top (30s sample)
docker exec pcap-analyzer py-spy top --pid 1 --duration 30

# Flamegraph
docker exec pcap-analyzer py-spy record --pid 1 --duration 30 \
    --output /data/profile.svg
```

---

## Annexe B: Dockerfile Complet Optimisé

```dockerfile
# ============================================
# Multi-Stage Dockerfile for PCAP Analyzer
# Target size: <250 MB
# ============================================

# ============================================
# STAGE 1: Builder (Dependencies compilation)
# ============================================
FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtualenv for isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
WORKDIR /build
COPY requirements.txt requirements-web.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt -r requirements-web.txt

# ============================================
# STAGE 2: Runtime dependencies
# ============================================
FROM python:3.11-slim-bookworm AS runtime-deps

# Install ONLY runtime libs (no gcc, g++)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# ============================================
# STAGE 3: Final (Application)
# ============================================
FROM python:3.11-slim-bookworm

LABEL maintainer="PCAP Analyzer Team"
LABEL description="PCAP Network Analysis Tool"
LABEL version="1.0.0"

# Install runtime libs only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtualenv
COPY --from=runtime-deps /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN groupadd -r pcapuser && \
    useradd -r -g pcapuser -u 1000 -m -d /home/pcapuser pcapuser

# Create directories
RUN mkdir -p /app /data/uploads /data/reports /data/logs && \
    chown -R pcapuser:pcapuser /app /data

WORKDIR /app

# Copy application code (exclude .git, tests, docs via .dockerignore)
COPY --chown=pcapuser:pcapuser src/ ./src/
COPY --chown=pcapuser:pcapuser web/ ./web/
COPY --chown=pcapuser:pcapuser config.yaml ./

# Switch to non-root user
USER pcapuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Expose port
EXPOSE 8000

# Startup command
CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
```

### .dockerignore

```
# Git
.git/
.github/
.gitignore

# Documentation
docs/
*.md
README*
CHANGELOG*
LICENSE

# Tests
tests/
.pytest_cache/
.coverage
htmlcov/

# Python cache
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
*.so

# Virtual environments
.venv/
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Reports (not needed in image)
reports/

# CI/CD
.travis.yml
.gitlab-ci.yml
azure-pipelines.yml

# Misc
.DS_Store
Thumbs.db
```

---

## Annexe C: requirements-web.txt

```
# Web framework dependencies (additional to requirements.txt)

# FastAPI + ASGI server
fastapi>=0.104.0,<1.0
uvicorn[standard]>=0.24.0,<1.0

# File handling
python-multipart>=0.0.6  # Upload multipart/form-data
aiofiles>=23.2.1         # Async file operations

# Scheduling
apscheduler>=3.10.0,<4.0  # Cleanup scheduler

# Database (SQLite async)
aiosqlite>=0.19.0,<1.0

# Optional: Monitoring
# prometheus-client>=0.19.0  # Uncomment if Prometheus needed
```

---

## Résumé Exécutif

### Optimisations Clés

1. **Image Docker:** Multi-stage build → **~226 MB** (<250 MB target)
2. **Runtime:** FastAPI async + 1 worker (CPU-bound)
3. **Mémoire:** StreamingProcessor DÉJÀ optimisé (chunking auto >100MB)
4. **CPU:** Hybrid mode dpkt+Scapy DÉJÀ optimisé (3-5x plus rapide)
5. **Stockage:** Cleanup PCAP immédiat, rapports TTL 24h
6. **Réseau:** GZip compression, chunked transfer, SSE optimisé
7. **Concurrence:** Queue maxsize=5, timeout 30min, load shedding

### Benchmarks Critiques

| Test | Commande | Seuil Pass |
|------|----------|------------|
| CLI vs Web | `python scripts/benchmark_cli_vs_web.py` | Overhead <10% |
| Mémoire | `python scripts/benchmark_memory.py` | Peak <4GB (500MB PCAP) |
| Load | `locust -f scripts/locustfile.py` | Queue handling correct |
| Image | `docker images pcap-analyzer` | <250 MB |

### Mot d'Ordre

**MESURER D'ABORD, OPTIMISER ENSUITE**

Les optimisations CPU/mémoire sont DÉJÀ en place. Le plan se concentre sur:
1. Préserver performance CLI dans conteneur web
2. Monitoring pour détecter régressions
3. Benchmarking reproductible

**Prochaine étape:** Implémenter backend FastAPI en réutilisant `analyze_pcap_hybrid()` existant.

---

**Document approuvé pour implémentation**
**Prochaine validation:** Benchmarks post-déploiement vs baseline CLI
