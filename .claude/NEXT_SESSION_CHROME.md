# Session Chrome - Guide de Reprise

## État Actuel du Projet

### ✅ Travail Complété (v4.19.0)
- **Coverage global**: 49.5% → **72.45%** (+22.95%)
- **107 tests** créés pour le web UI
- Tests de sécurité: CSRF, multi-tenant, path traversal, file upload
- Tous les tests passent ✓

### 📋 Modules Testés
| Module | Coverage | Tests |
|--------|----------|-------|
| views.py | 100% | 7 tests |
| reports.py | 98.61% | 13 tests |
| path_validator.py | 94.12% | 20 tests |
| file_validator.py | 90.48% | - |
| csrf.py | 97.30% | - |
| worker.py | 88.08% | 10 tests |
| health.py | 83.33% | 5 tests |
| auth.py | 73.10% | 22 tests |
| progress.py | 48.84% | 11 tests |
| upload.py | 66.67% | 11 tests |

---

## 🎯 Objectif Session Chrome

**Tester l'interface web avec l'extension Chrome pour:**
1. Lancer l'application Docker
2. Récupérer le mot de passe admin initial
3. Naviguer dans l'interface web
4. Tester l'upload de fichiers PCAP
5. Vérifier les rapports HTML générés

---

## 📝 Instructions pour `claude --chrome`

### 1. Lancement de l'Application

```bash
# Démarrer Docker Compose
cd /Users/omegabk/investigations/pcap_analyzer
docker-compose up -d

# Vérifier que les conteneurs sont actifs
docker-compose ps

# Attendre ~10 secondes que l'application démarre
sleep 10
```

### 2. Récupération du Mot de Passe Admin

```bash
# Récupérer le mot de passe admin initial depuis le secret Docker
docker exec pcap-analyzer cat /run/secrets/admin_password

# Alternative: depuis le host
cat /var/run/secrets/admin_password 2>/dev/null || \
  docker exec pcap-analyzer cat /run/secrets/admin_password
```

**Stocker dans une variable:**
```bash
ADMIN_PASSWORD=$(docker exec pcap-analyzer cat /run/secrets/admin_password)
echo "Admin password: $ADMIN_PASSWORD"
```

### 3. Accès à l'Interface Web

**URL de l'application:**
- Local: `http://localhost:8000`
- Credentials admin:
  - Username: `admin`
  - Password: `<du secret Docker>`

**Pages à tester:**
- `/` - Page d'accueil (redirect vers login si non auth)
- `/login` - Page de connexion
- `/admin` - Panel admin (liste utilisateurs, approbations)
- `/history` - Historique des analyses
- `/change-password` - Changement de mot de passe

### 4. Test d'Upload PCAP

**Générer un fichier PCAP de test:**
```bash
# Créer un PCAP valide minimaliste
python3 << 'EOF'
import struct

# PCAP Global Header
magic = struct.pack('I', 0xa1b2c3d4)  # Magic number (little-endian)
version_major = struct.pack('H', 2)
version_minor = struct.pack('H', 4)
thiszone = struct.pack('i', 0)
sigfigs = struct.pack('I', 0)
snaplen = struct.pack('I', 65535)
network = struct.pack('I', 1)  # Ethernet

header = magic + version_major + version_minor + thiszone + sigfigs + snaplen + network

# Packet (minimal Ethernet frame)
ts_sec = struct.pack('I', 1700000000)
ts_usec = struct.pack('I', 0)
incl_len = struct.pack('I', 60)
orig_len = struct.pack('I', 60)
packet_data = b'\x00' * 60

packet = ts_sec + ts_usec + incl_len + orig_len + packet_data

with open('/tmp/test_upload.pcap', 'wb') as f:
    f.write(header + packet)

print("PCAP file created: /tmp/test_upload.pcap")
EOF
```

**Scénario d'upload via l'interface:**
1. Se connecter avec admin credentials
2. Aller sur la page d'accueil (upload form)
3. Sélectionner `/tmp/test_upload.pcap`
4. Uploader le fichier
5. Observer la page de progression
6. Vérifier le rapport HTML généré

### 5. Navigation avec Extension Chrome

**Avec l'extension Chrome activée, tu pourras:**
```bash
# Ouvrir Chrome sur l'application
open -a "Google Chrome" "http://localhost:8000"

# Prendre des screenshots pour documentation
screencapture -x /tmp/screenshot_login.png

# Naviguer vers des pages spécifiques
open -a "Google Chrome" "http://localhost:8000/admin?token=<JWT>"
```

**Commandes Chrome utiles:**
- Clic sur élément: `click("#element-id")`
- Remplir formulaire: `fill("#username", "admin")`
- Submit: `submit("#login-form")`
- Navigation: `navigate("http://localhost:8000/history")`

---

## 🔍 Points à Vérifier

### Sécurité
- [ ] Login require authentication
- [ ] CSRF token présent sur formulaires
- [ ] Multi-tenant: user ne voit que ses tâches
- [ ] Path traversal bloqué
- [ ] Upload validation (magic bytes, taille)

### Fonctionnalités
- [ ] Upload PCAP réussi
- [ ] Progression en temps réel (SSE)
- [ ] Rapport HTML généré
- [ ] Download rapport JSON
- [ ] Historique filtré par utilisateur
- [ ] Admin voit tous les utilisateurs

### UI/UX
- [ ] Design responsive
- [ ] Messages d'erreur clairs
- [ ] Loading states
- [ ] Dark mode toggle fonctionne

---

## 📊 Prochaines Étapes (Après Chrome)

### Coverage à Améliorer
1. **progress.py** (48.84% → 70%+)
   - SSE generator difficile à tester
   - Besoin de tests avec mock asyncio.sleep

2. **upload.py** (66.67% → 85%+)
   - Chemins d'erreur non couverts
   - Tests pour queue pleine, disk full

3. **services/analyzer.py** (63.33% → 70%+)
   - Intégration avec Scapy
   - Tests avec vrais fichiers PCAP

### Issues GitHub à Fermer
- [ ] #18 - Web UI Security Test Suite ✓ (fait)
- [ ] #16 - File Upload Validation ✓ (fait)
- [ ] #17 - CSRF Protection ✓ (fait)

### Documentation
- [ ] Créer TESTING.md avec guide de tests
- [ ] Mettre à jour README avec coverage badges
- [ ] Documenter l'architecture de sécurité

---

## 🚀 Commandes Rapides

```bash
# Tout en un - Lancer et tester
cd /Users/omegabk/investigations/pcap_analyzer
docker-compose up -d && sleep 10
ADMIN_PW=$(docker exec pcap-analyzer cat /run/secrets/admin_password)
echo "Admin: admin / $ADMIN_PW"
open -a "Google Chrome" "http://localhost:8000"

# Run tests
python -m pytest tests/test_*.py -v --cov=app --cov-report=html

# Arrêter
docker-compose down
```

---

**Date de création**: 2025-12-21
**Coverage global**: 72.45%
**Dernier commit**: v4.19.0 - Test Coverage Improvement
