# Benchmarking Scripts

Scripts de benchmarking et profiling pour valider les performances de l'analyseur PCAP.

## Capture Raspberry Pi (SSH + tcpdump + tshark)

Deux scripts ont été ajoutés pour capturer depuis un Raspberry Pi puis analyser localement:

- `scripts/raspi_remote_tcpdump.sh`: helper à exécuter sur le Raspberry (capture tcpdump avec timeout).
- `scripts/capture_from_raspberry.sh`: orchestration locale (upload helper via SSH, capture distante, récupération PCAP, stats `tshark`, puis `pcap_analyzer`).

Usage local:

```bash
scripts/capture_from_raspberry.sh \
  --host 192.168.25.15 \
  --user omegabk \
  --key ~/.ssh/id_ed25519_raspberry \
  --duration 120 \
  --iface any \
  --filter "tcp or udp" \
  --name raspi_lab
```

## Scripts Disponibles

### 1. benchmark_cli_vs_web.py

Compare les performances CLI vs Web pour valider que l'overhead web reste <10%.

**Usage:**
```bash
# Benchmark basique (3 iterations)
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap

# Custom iterations
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap --iterations 5

# Custom web URL
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap --web-url http://192.168.1.100:8000

# Save results to JSON
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap --output results.json
```

**Output:**
```
========================================
BENCHMARK: CLI vs Web Overhead
========================================
PCAP: sample.pcap
Size: 26.00 MB
Packets: 131,000

=== CLI Benchmark (3 iterations) ===
Run 1: 54.23s
Run 2: 55.67s
Run 3: 54.89s
Average: 54.93s

=== Web Benchmark (3 iterations) ===
Run 1: 57.12s
Run 2: 58.34s
Run 3: 57.89s
Average: 57.78s

========================================
RESULTS
========================================
CLI Time:    54.93s
Web Time:    57.78s
Overhead:    2.85s (5.2%)

CLI Throughput: 2,384 packets/sec
Web Throughput: 2,267 packets/sec

✅ PASS: Overhead <10%
```

**Critères de validation:**
- Overhead <10% vs CLI baseline
- Status: PASS/FAIL

---

### 2. benchmark_memory.py

Profile la consommation mémoire pendant l'analyse pour détecter les fuites et valider les limites.

**Usage:**
```bash
# Profiling basique
python scripts/benchmark_memory.py tests/data/sample.pcap

# Mode détaillé (top 20 allocations)
python scripts/benchmark_memory.py tests/data/sample.pcap --detailed

# Save report
python scripts/benchmark_memory.py tests/data/sample.pcap --output memory_report.json
```

**Output:**
```
========================================
MEMORY PROFILING
========================================
File: sample.pcap (26.00 MB)
Packets: 131,000

========================================
MEMORY STATISTICS
========================================
Peak Memory:        487 MB
Current Memory:     245 MB
Memory Increase:    452 MB
Memory/Packet:      3.7 KB

========================================
VALIDATION
========================================
File Size:          26.00 MB
Peak Memory:        487.00 MB
Memory/File Ratio:  18.73x

✅ Memory/File ratio acceptable (<25x)
✅ Peak memory within 4GB limit
✅ Memory per packet acceptable (<10KB)

Status: ✅ PASS
```

**Critères de validation:**
- Memory/File ratio <25x (petits fichiers <100MB)
- Peak memory <4GB (limite Docker)
- Memory/Packet <10KB

---

### 3. profile_analysis.py

Profile CPU pour identifier les bottlenecks et fonctions lentes.

**Requis:**
```bash
pip install snakeviz
```

**Usage:**
```bash
# Profiling basique (top 20 fonctions)
python scripts/profile_analysis.py tests/data/sample.pcap

# Top 30 fonctions
python scripts/profile_analysis.py tests/data/sample.pcap --top 30

# Save profiling data
python scripts/profile_analysis.py tests/data/sample.pcap --output profile.prof

# Generate flamegraph (requires py-spy)
pip install py-spy
python scripts/profile_analysis.py tests/data/sample.pcap --flamegraph
```

**Visualisation:**
```bash
# Interactive browser visualization
snakeviz profile.prof
```

**Output:**
```
========================================
CPU PROFILING
========================================
File: sample.pcap
Packets: 131,000

========================================
PROFILING STATISTICS
========================================
Total Time:     55.23s
Total Calls:    1,234,567
Time/Packet:    0.42ms

Top 20 Functions (Cumulative Time):
------------------------------------------------------------
  ncalls  tottime  percall  cumtime  percall filename:lineno(function)
  131000    2.345    0.000   15.234    0.000 fast_parser.py:45(parse_packet)
   50000    1.234    0.000   10.123    0.000 protocol_analyzer.py:78(analyze)
  ...

========================================
BOTTLENECK ANALYSIS
========================================
⚠️  Bottlenecks detected (>15% of total time):

  - fast_parser.py:45(parse_packet)
    Time: 15.23s (27.6%)
    Calls: 131,000

RECOMMENDATIONS:
  - Consider optimizing functions with high cumtime
  - Check if functions are called too frequently (ncalls)
  - Profile with py-spy for production profiling
  - Use snakeviz for interactive visualization
```

---

### 4. locustfile.py

Load testing pour tester la concurrence et les limites du système.

**Requis:**
```bash
pip install locust
```

**Usage:**

**Mode interactif (Web UI):**
```bash
locust -f scripts/locustfile.py --host=http://localhost:8000
# Ouvrir http://localhost:8089
```

**Mode headless:**
```bash
# 10 users, 2 users/sec spawn, 5 minutes
locust -f scripts/locustfile.py \
    --host=http://localhost:8000 \
    --users 10 \
    --spawn-rate 2 \
    --run-time 5m \
    --headless

# Stress test (queue saturation)
locust -f scripts/locustfile.py \
    --host=http://localhost:8000 \
    --users 20 \
    --spawn-rate 5 \
    --run-time 10m \
    --headless
```

**Variables d'environnement:**
```bash
# Custom PCAP file
export PCAP_FILE=/path/to/large.pcap

# Custom wait time
export MAX_WAIT_TIME=1200  # 20 minutes

locust -f scripts/locustfile.py --host=http://localhost:8000
```

**Output:**
```
========================================
LOAD TEST RESULTS
========================================
Total Requests:          1,234
Total Failures:          45
Failure Rate:            3.6%
Average Response Time:   12,345ms
Median Response Time:    10,234ms
95th Percentile:         25,678ms
99th Percentile:         45,123ms
Max Response Time:       67,890ms
Requests/sec:            2.15

Endpoint Breakdown:
Endpoint                       Requests   Failures   Avg (ms)   95% (ms)
--------------------------------------------------------------------------------
POST /upload                        250         5     1,234      2,345
GET /status/[task_id]             1,000        10       123        234
GET /report/[task_id]               234         5     5,678      8,901
GET /health                         250         0        12         23

========================================
VALIDATION
========================================
✅ Failure rate acceptable (<10%): 3.6%
✅ Average response time acceptable: 12,345ms
✅ 95th percentile acceptable: 25,678ms

Status: ✅ PASS
```

**Critères de validation:**
- Failure rate <10%
- Average response time <60s
- 95th percentile <120s
- Queue handling correct (503 si full)

---

## Workflow Complet

### 1. Validation Initiale (Baseline CLI)

```bash
# Mesurer baseline CLI (hyperfine recommandé)
hyperfine --warmup 1 --runs 10 \
    'python -m src.cli analyze tests/data/sample.pcap --no-report'
```

### 2. Profiling Détaillé (Avant Optimisation)

```bash
# Memory profiling
python scripts/benchmark_memory.py tests/data/sample.pcap --detailed

# CPU profiling
python scripts/profile_analysis.py tests/data/sample.pcap --output baseline.prof

# Visualiser
snakeviz baseline.prof
```

### 3. Validation Web (Après Déploiement)

```bash
# Démarrer application web
docker-compose up -d

# Attendre démarrage
sleep 10

# Benchmark CLI vs Web
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap

# Load test
locust -f scripts/locustfile.py \
    --host=http://localhost:8000 \
    --users 10 \
    --spawn-rate 2 \
    --run-time 5m \
    --headless
```

### 4. Validation Finale (Checklist)

```bash
# 1. Overhead <10%
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap
# ✅ PASS: Overhead 5.2%

# 2. Memory limits
python scripts/benchmark_memory.py tests/data/sample.pcap
# ✅ PASS: Peak 487 MB <4GB

# 3. Load handling
locust -f scripts/locustfile.py --host=http://localhost:8000 --users 10 --run-time 2m --headless
# ✅ PASS: Failure rate 3.6%

# 4. Image size
docker images pcap-analyzer
# ✅ PASS: 226 MB <250MB
```

---

## Troubleshooting

### Benchmark CLI vs Web échoue

**Symptôme:** Overhead >10%

**Solutions:**
1. Vérifier limites Docker (CPU/Memory)
2. Vérifier pas d'autres processus consommant ressources
3. Profiler endpoint web pour bottlenecks
4. Vérifier latence réseau (si API distante)

### Memory profiling échoue

**Symptôme:** Peak memory >4GB

**Solutions:**
1. Vérifier streaming mode activé (auto >100MB)
2. Vérifier GC triggering correctement
3. Chercher fuites mémoire dans analyzers
4. Augmenter chunk size pour aggressive streaming

### Load test échoue

**Symptôme:** Failure rate >10%

**Solutions:**
1. Vérifier queue handling (503 si full)
2. Vérifier timeout configuration (30min)
3. Vérifier load shedding (si activé)
4. Augmenter limites ressources Docker

---

## Métriques Cibles

| Métrique | CLI Baseline | Web Target | Script |
|----------|--------------|------------|--------|
| Temps total | 55s | <60s | benchmark_cli_vs_web.py |
| Throughput | 2,382 pkt/s | >2,183 pkt/s | benchmark_cli_vs_web.py |
| Peak memory | ~500 MB | <600 MB | benchmark_memory.py |
| Memory/Packet | ~3.8 KB | <10 KB | benchmark_memory.py |
| Upload (100MB) | N/A | <5s | locustfile.py |
| SSE latency | N/A | <500ms | locustfile.py |
| Failure rate | 0% | <10% | locustfile.py |

---

## Ressources

- **hyperfine:** https://github.com/sharkdp/hyperfine
- **Locust:** https://locust.io
- **snakeviz:** https://jiffyclub.github.io/snakeviz/
- **py-spy:** https://github.com/benfred/py-spy
- **cProfile:** https://docs.python.org/3/library/profile.html
