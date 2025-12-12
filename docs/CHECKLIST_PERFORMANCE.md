# Checklist de Validation Performance

**Version:** 1.0
**Date:** 2025-12-12
**Baseline CLI:** 131k paquets, 26MB, 55 secondes

---

## 1. Performance (Tests Obligatoires)

### 1.1 Benchmark CLI vs Web

**Objectif:** Overhead web <10% vs CLI baseline

**Commande:**
```bash
python scripts/benchmark_cli_vs_web.py tests/data/sample.pcap
```

**Critères de validation:**
- [ ] CLI time: ~55s (±10%)
- [ ] Web time: <60s
- [ ] Overhead: <10% (target: <5.5s)
- [ ] Throughput CLI: ~2,382 pkt/s
- [ ] Throughput Web: >2,183 pkt/s
- [ ] Status: PASS

**Troubleshooting si FAIL:**
- Vérifier limites Docker CPU/Memory
- Vérifier pas d'autres processus lourds
- Profiler endpoint web
- Vérifier latence réseau (si API distante)

---

### 1.2 Memory Profiling

**Objectif:** Peak memory <4GB pour fichiers ≤500MB

**Commande:**
```bash
python scripts/benchmark_memory.py tests/data/sample.pcap
```

**Critères de validation:**
- [ ] Peak memory: <600MB pour 26MB PCAP
- [ ] Memory/File ratio: <25x (petits fichiers)
- [ ] Memory/Packet: <10KB
- [ ] Memory increase acceptable
- [ ] Status: PASS

**Troubleshooting si FAIL:**
- Vérifier streaming mode activé (>100MB)
- Vérifier GC triggering
- Chercher memory leaks
- Augmenter chunk size

---

### 1.3 CPU Profiling (Optionnel mais recommandé)

**Objectif:** Identifier bottlenecks (>15% cumtime)

**Commande:**
```bash
python scripts/profile_analysis.py tests/data/sample.pcap --output profile.prof
snakeviz profile.prof
```

**Critères de validation:**
- [ ] Total time: ~55s
- [ ] Time/packet: <1ms
- [ ] Aucune fonction >20% cumtime
- [ ] Bottlenecks acceptables (<15%)

**Troubleshooting si bottlenecks:**
- Optimiser fonctions lentes
- Vérifier ncalls (appels répétés)
- Utiliser py-spy pour profiling production

---

### 1.4 Load Testing

**Objectif:** Handling 10 users concurrents, failure rate <10%

**Commande:**
```bash
locust -f scripts/locustfile.py \
    --host=http://localhost:8000 \
    --users 10 \
    --spawn-rate 2 \
    --run-time 5m \
    --headless
```

**Critères de validation:**
- [ ] Failure rate: <10%
- [ ] Average response time: <60s
- [ ] 95th percentile: <120s
- [ ] Queue handling correct (503 si full)
- [ ] Pas de memory leak (check docker stats)
- [ ] Status: PASS

**Troubleshooting si FAIL:**
- Vérifier queue maxsize=5
- Vérifier timeout 30min
- Vérifier load shedding
- Augmenter limites Docker

---

## 2. Image Docker

### 2.1 Taille Image

**Objectif:** <250 MB (compressed)

**Commande:**
```bash
docker build -t pcap-analyzer:latest .
docker images pcap-analyzer:latest
```

**Critères de validation:**
- [ ] Image size: <250 MB
- [ ] Layers optimisés (cache efficace)
- [ ] Multi-stage build correct
- [ ] .dockerignore appliqué

**Troubleshooting si trop gros:**
- Vérifier .dockerignore (exclusions)
- Vérifier pas de fichiers tests/docs
- Vérifier pip install --no-cache-dir
- Vérifier apt clean dans layers

---

### 2.2 Temps de Build

**Objectif:** <5 min (premier), <30s (rebuild cache)

**Commande:**
```bash
# Premier build (sans cache)
time docker build --no-cache -t pcap-analyzer:latest .

# Rebuild (avec cache, modif code)
echo "# test" >> src/cli.py
time docker build -t pcap-analyzer:latest .
git checkout src/cli.py
```

**Critères de validation:**
- [ ] Premier build: <5 min
- [ ] Rebuild cache: <30s
- [ ] Cache layers efficace

**Troubleshooting si lent:**
- Vérifier ordre COPY (requirements avant code)
- Vérifier multi-stage optimisé
- Vérifier pas de COPY inutiles

---

## 3. Runtime

### 3.1 Upload Performance

**Objectif:** <5s pour 100MB, <20s pour 500MB

**Test manuel:**
```bash
# Générer fichier test 100MB
dd if=/dev/zero of=/tmp/test100mb.pcap bs=1M count=100

# Upload
time curl -X POST http://localhost:8000/upload \
    -F "file=@/tmp/test100mb.pcap"
```

**Critères de validation:**
- [ ] Upload 100MB: <5s
- [ ] Upload 500MB: <20s
- [ ] Chunked transfer correct
- [ ] Pas de load complet mémoire

---

### 3.2 SSE Latency

**Objectif:** <500ms événement → client

**Test manuel (browser console):**
```javascript
const eventSource = new EventSource('/progress/task_id');
let lastTime = Date.now();
eventSource.onmessage = (e) => {
    const latency = Date.now() - lastTime;
    console.log(`Latency: ${latency}ms`);
    lastTime = Date.now();
};
```

**Critères de validation:**
- [ ] Latency moyenne: <500ms
- [ ] Pas trop de messages (1 per 1000 packets)
- [ ] Reconnexion auto fonctionne
- [ ] Pas de memory leak

---

### 3.3 Concurrent Analyses

**Objectif:** 2 analyses simultanées OK, 6e rejected (queue full)

**Test manuel:**
```bash
# Lancer 6 uploads en parallèle
for i in {1..6}; do
    curl -X POST http://localhost:8000/upload \
        -F "file=@tests/data/sample.pcap" &
done
wait
```

**Critères de validation:**
- [ ] 5 premiers: 200 OK (queued)
- [ ] 6e: 503 Service Unavailable (queue full)
- [ ] Queue FIFO correcte
- [ ] Analyses terminées sans crash

---

## 4. Sécurité

### 4.1 User Non-Root

**Commande:**
```bash
docker run --rm pcap-analyzer:latest whoami
```

**Critères de validation:**
- [ ] Output: `pcapuser` (pas `root`)
- [ ] UID: 1000

---

### 4.2 Security Options

**Commande:**
```bash
docker inspect pcap-analyzer | jq '.[0].HostConfig.SecurityOpt'
```

**Critères de validation:**
- [ ] `no-new-privileges:true` présent
- [ ] `cap_drop: [ALL]` configuré

---

### 4.3 Upload Validation

**Test manuel:**
```bash
# Test extension invalide
curl -X POST http://localhost:8000/upload \
    -F "file=@/etc/passwd"

# Test fichier trop gros (>500MB)
dd if=/dev/zero of=/tmp/toobig.pcap bs=1M count=600
curl -X POST http://localhost:8000/upload \
    -F "file=@/tmp/toobig.pcap"
```

**Critères de validation:**
- [ ] Extension invalide: 400 Bad Request
- [ ] Fichier trop gros: 413 Payload Too Large
- [ ] Magic bytes PCAP validés
- [ ] Path traversal bloqué

---

## 5. Observabilité

### 5.1 Health Check

**Commande:**
```bash
curl -i http://localhost:8000/health
```

**Critères de validation:**
- [ ] Status: 200 OK (si healthy)
- [ ] Status: 503 Service Unavailable (si degraded)
- [ ] JSON response avec metrics
- [ ] Memory/disk checks présents

---

### 5.2 Logging

**Commande:**
```bash
docker logs pcap-analyzer --tail 50
```

**Critères de validation:**
- [ ] Format JSON structuré
- [ ] Timestamp UTC ISO 8601
- [ ] Log level correct (INFO par défaut)
- [ ] Pas de secrets loggés
- [ ] Task ID tracé

---

### 5.3 Memory Tracking

**Commande:**
```bash
# Pendant analyse longue
docker stats pcap-analyzer --no-stream
```

**Critères de validation:**
- [ ] Memory usage visible
- [ ] Peak memory <4GB (limit)
- [ ] Pas de memory leak (stable après GC)
- [ ] CPU usage correct (~100% pendant analyse)

---

## 6. Scalabilité (Optionnel)

### 6.1 Horizontal Scaling

**Test:**
```bash
# Démarrer 3 instances
docker-compose up -d --scale pcap-analyzer=3

# Load balancer nginx (config requise)
```

**Critères de validation:**
- [ ] 3 conteneurs démarrés
- [ ] Chacun écoute port différent
- [ ] Load balancer distribue requêtes
- [ ] Pas de partage état (stateless)

---

### 6.2 Volume Performance

**Test:**
```bash
# Test écriture
docker exec pcap-analyzer dd if=/dev/zero of=/data/test bs=1M count=100

# Test lecture
docker exec pcap-analyzer dd if=/data/test of=/dev/null bs=1M
```

**Critères de validation:**
- [ ] Write speed: >50 MB/s (SSD)
- [ ] Read speed: >100 MB/s (SSD)
- [ ] Pas de NFS/CIFS lent

---

## 7. Cleanup

### 7.1 PCAP Cleanup

**Test:**
```bash
# Upload et attendre fin analyse
curl -X POST http://localhost:8000/upload -F "file=@tests/data/sample.pcap"

# Vérifier PCAP supprimé
docker exec pcap-analyzer ls /data/uploads/
```

**Critères de validation:**
- [ ] PCAP supprimé immédiatement post-analyse
- [ ] Même si analyse échoue (finally block)

---

### 7.2 Reports Cleanup

**Test:**
```bash
# Créer vieux rapport
docker exec pcap-analyzer touch -t 202512101200 /data/reports/old_report.html

# Attendre cleanup job (1h)
sleep 3700

# Vérifier suppression
docker exec pcap-analyzer ls /data/reports/
```

**Critères de validation:**
- [ ] Rapports >24h supprimés
- [ ] Job APScheduler tourne hourly
- [ ] SQLite statut='expired' updaté

---

### 7.3 Logs Rotation

**Commande:**
```bash
docker exec pcap-analyzer ls -lh /data/logs/
```

**Critères de validation:**
- [ ] Max 5 fichiers logs (RotatingFileHandler)
- [ ] Taille max 10MB par fichier
- [ ] Total <50MB

---

## Résumé Validation

### Checklist Complète

**Performance:**
- [ ] CLI vs Web: Overhead <10%
- [ ] Memory: Peak <4GB pour 500MB PCAP
- [ ] CPU: Pas de bottlenecks >20%
- [ ] Load: Failure rate <10%

**Image Docker:**
- [ ] Taille: <250 MB
- [ ] Build: <5 min (premier)
- [ ] Cache: <30s (rebuild)

**Runtime:**
- [ ] Upload: <5s pour 100MB
- [ ] SSE: Latency <500ms
- [ ] Queue: Max 5, 6e rejected

**Sécurité:**
- [ ] Non-root: pcapuser UID 1000
- [ ] Security opts: no-new-privileges
- [ ] Upload validation: Extension, taille, magic bytes

**Observabilité:**
- [ ] Health check: 200/503
- [ ] Logging: JSON structuré
- [ ] Monitoring: Memory/CPU tracking

**Cleanup:**
- [ ] PCAP: Suppression immédiate
- [ ] Rapports: TTL 24h
- [ ] Logs: Rotation 10MB/50MB total

---

## Actions si Validation Échoue

### Overhead >10%
1. Profiler CPU (profile_analysis.py)
2. Vérifier limites Docker
3. Vérifier pas de contention I/O
4. Optimiser hot paths

### Memory >4GB
1. Vérifier streaming activé
2. Vérifier GC cooldown
3. Profiler allocations (benchmark_memory.py)
4. Augmenter chunk size

### Load test fail
1. Vérifier queue handling
2. Vérifier timeout config
3. Augmenter limites ressources
4. Activer load shedding

### Image >250MB
1. Auditer .dockerignore
2. Vérifier pip --no-cache-dir
3. Vérifier pas de deps inutiles
4. Optimiser layers

---

**Document de validation - Utiliser AVANT livraison production**
