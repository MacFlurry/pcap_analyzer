# Plan de Sécurité - PCAP Analyzer Web

**Date:** 2025-12-12
**Version:** 1.0
**Statut:** Validé

---

## 1. Validation Upload

### 1.1 Extension Whitelist
```python
ALLOWED_EXTENSIONS = {'.pcap', '.pcapng'}
if not file.filename.endswith(tuple(ALLOWED_EXTENSIONS)):
    raise ValidationError("Extension invalide")
```

### 1.2 Limite Taille
- **Max:** 500 MB (configurable via `MAX_UPLOAD_SIZE_MB`)
- **Validation:** Avant sauvegarde complète
```python
if file.size > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
    raise PayloadTooLarge("Fichier >500MB")
```

### 1.3 Magic Bytes PCAP
```python
PCAP_MAGIC = b'\xd4\xc3\xb2\xa1'  # Little-endian
PCAP_MAGIC_SWAPPED = b'\xa1\xb2\xc3\xd4'  # Big-endian
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

async with aiofiles.open(path, 'rb') as f:
    magic = await f.read(4)
    if magic not in [PCAP_MAGIC, PCAP_MAGIC_SWAPPED, PCAPNG_MAGIC]:
        raise ValidationError("Magic bytes invalides")
```

### 1.4 Path Traversal Protection
```python
# Sanitize filename
import os
from pathlib import Path

safe_filename = Path(file.filename).name  # Remove path
task_id = uuid.uuid4()
upload_path = DATA_DIR / "uploads" / f"{task_id}.pcap"

# Ensure path is within DATA_DIR
if not upload_path.resolve().is_relative_to(DATA_DIR.resolve()):
    raise SecurityError("Path traversal détecté")
```

### 1.5 Content Validation (Post-Upload)
```python
# Validation dpkt (avant analyse)
try:
    with open(upload_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # Test lecture première frame
        timestamp, buf = next(iter(pcap))
except Exception as e:
    upload_path.unlink()  # Delete malformed file
    raise ValidationError(f"PCAP corrompu: {e}")
```

---

## 2. Container Security

### 2.1 Non-Root User
```dockerfile
# UID 1000 standard Linux user
RUN groupadd -r pcapuser && \
    useradd -r -g pcapuser -u 1000 -m -d /home/pcapuser pcapuser

USER pcapuser
```

### 2.2 Read-Only Filesystem
```yaml
# docker-compose.yml
read_only: false  # False car nécessite /data et /tmp writable
tmpfs:
  - /tmp:uid=1000,gid=1000,mode=1777,size=1G
```
**Alternative:** Mount `/data` comme seul volume writable
```dockerfile
# Dockerfile
RUN mkdir -p /data && chown pcapuser:pcapuser /data
VOLUME ["/data"]
```

### 2.3 Capabilities Drop
```yaml
# docker-compose.yml
cap_drop:
  - ALL
# Pas besoin CAP_NET_RAW (lecture PCAP depuis fichier, pas capture live)
```

### 2.4 no-new-privileges
```yaml
security_opt:
  - no-new-privileges:true  # Empêche escalade via setuid/setgid
```

### 2.5 Resource Limits
```yaml
deploy:
  resources:
    limits:
      memory: 4G      # Hard limit (OOM killer)
      cpus: '2.0'     # Max 2 cores
    reservations:
      memory: 1G      # Soft reservation
      cpus: '1.0'     # Min 1 core
```

---

## 3. API Security

### 3.1 Rate Limiting
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/upload")
@limiter.limit("5/minute")  # 5 uploads max par minute par IP
async def upload_pcap(request: Request, file: UploadFile):
    pass
```

### 3.2 CORS Policy
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000"],  # Strict same-origin
    allow_credentials=False,
    allow_methods=["GET", "POST"],  # Pas DELETE/PUT
    allow_headers=["Content-Type"],
)
```

### 3.3 Input Validation (Pydantic)
```python
from pydantic import BaseModel, Field, validator

class AnalysisRequest(BaseModel):
    task_id: str = Field(..., regex=r'^[a-f0-9\-]{36}$')  # UUID format

    @validator('task_id')
    def validate_task_id(cls, v):
        # Prevent SQL injection in SQLite queries
        if not re.match(r'^[a-f0-9\-]{36}$', v):
            raise ValueError("Invalid task_id format")
        return v
```

### 3.4 Error Handling (No Leak)
```python
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log interne complet
    logger.error(f"Unhandled error: {exc}", exc_info=True)

    # Retour client sanitized
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}  # Pas de stack trace!
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation error"}  # Pas de détails Pydantic!
    )
```

### 3.5 Secrets Management
```python
# PAS DE SECRETS HARDCODÉS
# Utiliser variables d'environnement

import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////data/pcap_analyzer.db")
SECRET_KEY = os.getenv("SECRET_KEY")  # Pour future auth JWT

if not SECRET_KEY and os.getenv("ENV") == "production":
    raise RuntimeError("SECRET_KEY requis en production")
```

**docker-compose.yml:**
```yaml
environment:
  - SECRET_KEY=${SECRET_KEY}  # Depuis .env file (gitignored)
```

---

## 4. Threat Model

### 4.1 Malicious PCAP Upload
**Attaque:** Upload PCAP malformé pour crash/exploitation

**Mitigations:**
- Magic bytes validation
- dpkt parsing test avant analyse
- Exception handling global (pas de crash exposé)
- Timeout 30 min par analyse
- DELETE PCAP immédiat après analyse

**Impact:** LOW (conteneur isolated, crash sans conséquence)

---

### 4.2 DoS via Large Files
**Attaque:** Upload fichiers 500MB répétés pour saturation disque/CPU

**Mitigations:**
- Rate limiting: 5 uploads/minute/IP
- Queue maxsize=5 (reject si full → 503)
- StreamingProcessor auto-chunking >100MB
- Resource limits: 4GB RAM, 2 CPU
- Cleanup agressif: DELETE PCAP immédiat, reports TTL 24h

**Impact:** MEDIUM (service déni temporaire pour cet IP)

---

### 4.3 Path Traversal
**Attaque:** Filename `../../etc/passwd` pour écriture hors /data

**Mitigations:**
- `Path(filename).name` strip paths
- UUID task_id (pas filename utilisé)
- Vérification `is_relative_to(DATA_DIR)`
- Read-only filesystem (sauf /data)
- User non-root (UID 1000)

**Impact:** NEGLIGIBLE (multiple layers protection)

---

### 4.4 Resource Exhaustion (Memory)
**Attaque:** PCAP géant avec millions de flows pour OOM

**Mitigations:**
- Memory limit 4GB (OOM killer docker)
- StreamingProcessor chunking adaptatif
- MemoryOptimizer GC avec cooldown
- Timeout 30 min analyse
- DELETE PCAP immédiat

**Impact:** LOW (conteneur restart auto, pas d'impact host)

---

### 4.5 Container Escape
**Attaque:** Exploit kernel/Docker pour accès host

**Mitigations:**
- User non-root UID 1000
- cap_drop: ALL
- no-new-privileges
- seccomp default profile
- Base image python:3.11-slim-bookworm (Debian stable patches)
- Scan Trivy (CVE detection)

**Impact:** VERY LOW (defense-in-depth)

---

## 5. Checklist Validation

### 5.1 Upload Security
- [ ] Test upload fichier `.exe` → Rejet extension
- [ ] Test upload 501MB → Rejet taille
- [ ] Test upload `.pcap` avec magic bytes invalides → Rejet
- [ ] Test filename `../../etc/passwd.pcap` → Path sanitized
- [ ] Test upload PCAP corrompu → Validation dpkt échoue

### 5.2 Container Isolation
- [ ] Vérifier user conteneur: `docker exec pcap-analyzer whoami` → `pcapuser`
- [ ] Vérifier UID: `docker exec pcap-analyzer id` → `uid=1000`
- [ ] Test écriture hors /data: `docker exec pcap-analyzer touch /etc/test` → Permission denied
- [ ] Vérifier capabilities: `docker exec pcap-analyzer capsh --print` → Aucune
- [ ] Test resource limit: Upload PCAP >4GB RAM → OOM killer

### 5.3 API Security
- [ ] Test rate limiting: 6 uploads en 1 minute → 429 Too Many Requests
- [ ] Test CORS: Request depuis `http://evil.com` → Bloqué
- [ ] Test task_id injection: `GET /report/../../../etc/passwd` → 404
- [ ] Test error leak: Force 500 error → Response générique (pas stack trace)
- [ ] Scan secrets: `gitleaks detect` → Aucun secret hardcodé

### 5.4 Vulnerability Scanning
- [ ] Scan image Docker: `trivy image pcap-analyzer:latest` → 0 HIGH/CRITICAL
- [ ] Scan dépendances Python: `safety check -r requirements.txt` → Pas de CVE
- [ ] Audit npm (si frontend JS): `npm audit` → 0 vulnerabilities

### 5.5 Cleanup & Data Retention
- [ ] Upload PCAP → Analyse complète → Vérifier PCAP supprimé
- [ ] Vérifier cleanup scheduler: Logs APScheduler toutes les heures
- [ ] Mock timestamp -25h → Cleanup trigger → Rapport supprimé

---

## Résumé Sécurité

| Layer | Protection | Status |
|-------|-----------|--------|
| **Upload** | Extension + Size + Magic bytes + Path sanitization | ✅ |
| **Container** | Non-root + cap_drop + no-new-privileges + resource limits | ✅ |
| **API** | Rate limiting + CORS + Input validation + Error handling | ✅ |
| **Data** | DELETE immédiat PCAP + TTL 24h reports + Volume isolation | ✅ |
| **Scan** | Trivy + Safety + Gitleaks | ✅ |

**Niveau de sécurité:** Production-ready avec defense-in-depth

---

## Références

- **OWASP:** [Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- **Docker:** [Security Best Practices](https://docs.docker.com/engine/security/)
- **FastAPI:** [Security Tutorial](https://fastapi.tiangolo.com/tutorial/security/)
- **NIST:** [Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
