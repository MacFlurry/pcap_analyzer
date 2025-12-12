# Documentation Performance - PCAP Analyzer Web

**Agent:** Performance
**Date:** 2025-12-12
**Statut:** Prêt pour implémentation

---

## Vue d'Ensemble

Cette documentation couvre l'ensemble des optimisations de performance pour garantir que l'overhead web reste **<10% vs baseline CLI** (55s pour 131k paquets).

**Principe clé:** Les optimisations CPU/mémoire sont DÉJÀ en place dans le code CLI. L'objectif est de **préserver** ces performances dans le conteneur web, pas de les réoptimiser.

---

## Documents Disponibles

### 📋 [PLAN_PERFORMANCE.md](./PLAN_PERFORMANCE.md) - Plan Complet

**Usage:** Document de référence principal (200+ KB)

**Contenu:**
- Baseline CLI et objectifs web détaillés
- Optimisations par domaine (7 sections)
- Scripts de benchmarking complets
- Monitoring et métriques
- Checklist de validation

**Sections clés:**
1. Baseline et Objectifs
2. Image Docker (<250 MB)
3. Runtime Performance (FastAPI async)
4. Optimisation Mémoire (déjà optimisé)
5. Optimisation CPU (hybrid mode déjà optimisé)
6. Optimisation Stockage (cleanup agressif)
7. Optimisation Réseau (gzip, SSE)
8. Analyses Concurrentes (queue, timeout)
9. Scripts de Benchmarking
10. Monitoring et Métriques
11. Checklist de Validation

**Quand le lire:**
- Avant de commencer l'implémentation web
- Pour comprendre les détails techniques
- Pour référence lors du développement

---

### 🏗️ [ARCHITECTURE_PERFORMANCE.md](./ARCHITECTURE_PERFORMANCE.md) - Vue Architecture

**Usage:** Compréhension visuelle du système

**Contenu:**
- Diagrammes ASCII du flow complet
- Architecture conteneur Docker
- Flow de données détaillé (4 scénarios)
- Optimisations clés expliquées
- Anti-patterns à éviter
- Best practices

**Scénarios couverts:**
1. Upload PCAP (chunked transfer)
2. Analyse background (hybrid mode)
3. Progress monitoring (SSE)
4. Report download (streaming)

**Quand le lire:**
- Pour comprendre l'architecture globale
- Avant de coder les endpoints FastAPI
- Pour visualiser les flows de données

---

### ✅ [CHECKLIST_PERFORMANCE.md](./CHECKLIST_PERFORMANCE.md) - Validation

**Usage:** Document de validation avant livraison

**Contenu:**
- 7 catégories de tests
- Commandes exactes à exécuter
- Critères PASS/FAIL clairs
- Troubleshooting si échec
- Résumé validation finale

**Catégories:**
1. Performance (CLI vs Web, Memory, CPU, Load)
2. Image Docker (taille, build time)
3. Runtime (upload, SSE, concurrence)
4. Sécurité (non-root, security opts, validation)
5. Observabilité (health, logs, monitoring)
6. Scalabilité (horizontal scaling, volumes)
7. Cleanup (PCAP, rapports, logs)

**Quand l'utiliser:**
- Avant chaque livraison (sprint)
- Pour validation finale (production)
- Pour debugging si régressions

---

### 🔧 [scripts/README.md](../scripts/README.md) - Scripts Benchmarking

**Usage:** Documentation scripts de test

**Contenu:**
- 4 scripts de benchmarking détaillés
- Usage et exemples pour chaque script
- Output attendu
- Critères de validation
- Workflow complet de validation
- Troubleshooting par script

**Scripts:**
1. `benchmark_cli_vs_web.py` - Overhead <10%
2. `benchmark_memory.py` - Memory profiling
3. `profile_analysis.py` - CPU bottlenecks
4. `locustfile.py` - Load testing

**Quand l'utiliser:**
- Pour exécuter les benchmarks
- Pour comprendre les outputs
- Pour debugging performance

---

### 📊 [DECISIONS_TECHNIQUES.md](./DECISIONS_TECHNIQUES.md) - Décisions Stack

**Usage:** Référence décisions architecture web

**Contenu:**
- Stack technique validée
- Comparatifs avec sources
- Architecture globale
- Flow de données
- Dépendances
- Sécurité
- Performance attendue
- Plan implémentation

**Décisions clés:**
- Backend: FastAPI + Uvicorn
- Frontend: Vanilla JS + Tailwind
- Communication: SSE (pas WebSockets)
- Stockage: Filesystem + SQLite
- Queue: asyncio.Queue (in-process)
- Image: python:3.11-slim-bookworm
- Multi-stage: OUI (3 stages)
- Cleanup: APScheduler (in-process)

**Quand le lire:**
- Avant implémentation (obligatoire)
- Pour comprendre les choix techniques
- Pour éviter de réinventer la roue

---

## Quick Start - Validation Performance

### 1. Mesurer Baseline CLI (Obligatoire)

```bash
# Installer hyperfine (recommandé)
brew install hyperfine  # macOS
# ou apt install hyperfine  # Linux

# Benchmark CLI (10 runs)
hyperfine --warmup 1 --runs 10 \
    'python -m src.cli analyze tests/data/sample.pcap --no-report'

# Output attendu: ~55s ± 2s
```

### 2. Déployer Application Web

```bash
# Build image
docker build -t pcap-analyzer:latest .

# Vérifier taille
docker images pcap-analyzer:latest
# Target: <250 MB

# Démarrer
docker-compose up -d

# Vérifier health
curl http://localhost:8000/health
```

### 3. Valider Performance Web

```bash
# 1. Overhead CLI vs Web
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap
# ✅ Target: Overhead <10%

# 2. Memory profiling
python scripts/benchmark_memory.py tests/data/sample.pcap
# ✅ Target: Peak <600MB pour 26MB PCAP

# 3. Load test (5 min)
pip install locust
locust -f scripts/locustfile.py \
    --host=http://localhost:8000 \
    --users 10 \
    --spawn-rate 2 \
    --run-time 5m \
    --headless
# ✅ Target: Failure rate <10%
```

### 4. Checklist Finale

Suivre **CHECKLIST_PERFORMANCE.md** pour validation complète:
- [ ] Performance (4 tests)
- [ ] Image Docker (2 tests)
- [ ] Runtime (3 tests)
- [ ] Sécurité (3 tests)
- [ ] Observabilité (3 tests)
- [ ] Cleanup (3 tests)

---

## Métriques Cibles - Résumé

| Métrique | CLI Baseline | Web Target | Overhead Max | Script |
|----------|--------------|------------|--------------|--------|
| **Temps total** | 55s | <60s | +9% | benchmark_cli_vs_web.py |
| **Throughput** | 2,382 pkt/s | >2,183 pkt/s | -8% | benchmark_cli_vs_web.py |
| **Peak memory** | ~500 MB | <600 MB | +20% | benchmark_memory.py |
| **Upload 100MB** | N/A | <5s | N/A | Manual |
| **SSE latency** | N/A | <500ms | N/A | Manual |
| **Image size** | N/A | <250 MB | N/A | docker images |
| **Failure rate** | 0% | <10% | N/A | locustfile.py |

---

## Workflow Développement

### Phase 1: Lecture Documentation (1h)

1. Lire **DECISIONS_TECHNIQUES.md** (décisions stack)
2. Lire **ARCHITECTURE_PERFORMANCE.md** (vue architecture)
3. Parcourir **PLAN_PERFORMANCE.md** (sections pertinentes)

### Phase 2: Implémentation Backend (Sprint 1-2)

1. Créer structure FastAPI (`web/main.py`)
2. Implémenter endpoints:
   - POST /upload (chunked, validation)
   - GET /progress/:id (SSE)
   - GET /status/:id (SQLite)
   - GET /report/:id (streaming)
   - GET /health (metrics)
3. Wrapper `analyze_pcap_hybrid()` avec SSE callbacks
4. Setup queue asyncio.Queue (maxsize=5)
5. Background worker (1 seul, CPU-bound)
6. APScheduler cleanup (hourly)

### Phase 3: Tests Performance (Sprint 3)

1. Benchmark CLI vs Web
   ```bash
   python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap
   ```
2. Memory profiling
   ```bash
   python scripts/benchmark_memory.py tests/data/sample.pcap --detailed
   ```
3. CPU profiling (si bottlenecks détectés)
   ```bash
   python scripts/profile_analysis.py tests/data/sample.pcap --output profile.prof
   snakeviz profile.prof
   ```

### Phase 4: Load Testing (Sprint 4)

1. Test nominal (10 users, 5 min)
   ```bash
   locust -f scripts/locustfile.py --host=http://localhost:8000 \
       --users 10 --spawn-rate 2 --run-time 5m --headless
   ```
2. Stress test (queue saturation)
   ```bash
   locust -f scripts/locustfile.py --host=http://localhost:8000 \
       --users 20 --spawn-rate 5 --run-time 10m --headless
   ```

### Phase 5: Validation Finale (Sprint 5)

1. Suivre **CHECKLIST_PERFORMANCE.md** intégralement
2. Corriger échecs (voir troubleshooting)
3. Valider tous critères PASS
4. Livraison production

---

## Points Clés - À Retenir

### ✅ DO

1. **Réutiliser code CLI existant**
   - `analyze_pcap_hybrid()` DÉJÀ optimisé (hybrid dpkt+Scapy)
   - Juste wrapper avec SSE callbacks
   - Pas de duplication code

2. **Utiliser optimisations existantes**
   - `StreamingProcessor` pour fichiers >100MB
   - `MemoryOptimizer` avec GC cooldown
   - Pas besoin de réoptimiser!

3. **Async pour I/O, background pour CPU**
   - FastAPI async pour upload/download
   - Background worker pour analyse (CPU-bound)
   - 1 seul worker uvicorn (pas de gain multi-worker)

4. **Mesurer avant d'optimiser**
   - Baseline CLI: 55s (référence absolue)
   - Benchmark après chaque modif
   - Optimisation précoce = racine du mal

### ❌ DON'T

1. **Ne PAS réoptimiser l'analyseur**
   - Code CLI déjà optimisé (hybrid mode)
   - Focus sur préservation performance

2. **Ne PAS utiliser multiple workers**
   - Analyse = CPU-bound (100% d'un core)
   - Multiple workers = contention CPU

3. **Ne PAS load PCAP en mémoire**
   - Toujours chunked transfer (1MB chunks)
   - StreamingProcessor pour analyse

4. **Ne PAS spam GC**
   - Cooldown 5s entre GC (déjà implémenté)
   - Skip si 3 GC vides consécutifs

---

## Troubleshooting Rapide

### Overhead >10%

**Diagnostic:**
```bash
# Profiler CPU
python scripts/profile_analysis.py tests/data/sample.pcap
```

**Solutions:**
- Vérifier limites Docker CPU/Memory
- Vérifier pas d'autres processus
- Optimiser hot paths (si bottlenecks >20%)

---

### Memory >4GB

**Diagnostic:**
```bash
# Memory profiling détaillé
python scripts/benchmark_memory.py tests/data/sample.pcap --detailed
```

**Solutions:**
- Vérifier streaming mode activé
- Vérifier GC triggering
- Chercher memory leaks (top allocations)

---

### Image >250MB

**Diagnostic:**
```bash
docker history pcap-analyzer:latest
```

**Solutions:**
- Vérifier .dockerignore (tests, docs exclus)
- Vérifier pip --no-cache-dir
- Vérifier apt clean dans Dockerfile

---

### Load Test Fail

**Diagnostic:**
```bash
# Logs pendant load test
docker logs -f pcap-analyzer
docker stats pcap-analyzer
```

**Solutions:**
- Vérifier queue handling (503 si full)
- Vérifier timeout 30min
- Augmenter limites Docker

---

## Support

**Questions techniques:**
- Consulter **PLAN_PERFORMANCE.md** (détails)
- Consulter **ARCHITECTURE_PERFORMANCE.md** (visuel)

**Validation:**
- Suivre **CHECKLIST_PERFORMANCE.md**
- Exécuter scripts dans **scripts/README.md**

**Décisions architecture:**
- Référence **DECISIONS_TECHNIQUES.md**

---

## Changements Futurs (Post-MVP)

### Si Scaling Requis (>10 req/sec)

1. Migrer vers **Celery + Redis**
   - Queue distribuée (partage entre containers)
   - Workers dédiés (scalables)
   - Résultats persistés

2. **Prometheus + Grafana**
   - Métriques détaillées
   - Dashboards temps réel
   - Alertes automatiques

3. **Kubernetes HPA**
   - Auto-scaling horizontal
   - Load balancing natif
   - Health checks avancés

**Note:** Pas requis pour MVP (queue in-process suffit)

---

**Prochaine étape:** Implémentation backend FastAPI (Agent Développeur)
**Référence:** DECISIONS_TECHNIQUES.md + ARCHITECTURE_PERFORMANCE.md
