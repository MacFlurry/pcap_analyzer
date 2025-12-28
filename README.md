# PCAP Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-5.4.0-blue.svg)](CHANGELOG.md)
[![Tests](https://img.shields.io/badge/tests-850%2B%20passing-brightgreen.svg)](.github/workflows/test.yml)
[![Security](https://img.shields.io/badge/security-100%25%20OWASP%20ASVS-brightgreen.svg)](SECURITY.md)
[![Coverage](https://img.shields.io/badge/coverage-64.43%25-brightgreen.svg)](htmlcov/index.html)

Analyseur automatisé de fichiers PCAP pour diagnostiquer les problèmes de latence et de performance réseau.

**CLI rapide et puissant** • **Rapports HTML interactifs** • **Interface web moderne** • **Production ready**

## 📋 Prérequis

Selon le mode de déploiement choisi :

**Option 1: CLI local (recommandé)**
- [Python 3.11+](https://www.python.org/downloads/)
- libpcap (installé automatiquement sur macOS/Linux)

**Option 2: Docker Compose (optionnel)**
- [Docker](https://docs.docker.com/get-docker/) et [Docker Compose](https://docs.docker.com/compose/install/)

**Option 3: Kubernetes (optionnel, production)**
- [Docker](https://docs.docker.com/get-docker/)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) (Kubernetes in Docker)
- [kubectl](https://kubernetes.io/docs/tasks/tools/) (client Kubernetes)
- [helm](https://helm.sh/docs/intro/install/) (gestionnaire de packages Kubernetes)

## 🚀 Démarrage rapide

### Option 1: CLI local (recommandé)

Installation et utilisation simple en ligne de commande :

```bash
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Créer et activer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -e .

# Analyser un fichier PCAP
pcap_analyzer analyze capture.pcap
```

**Avantages :**
- ⚡ Installation en 30 secondes
- 🔒 Sécurité renforcée (score 91.5%, production ready)
- 📊 Rapports HTML interactifs avec graphiques Plotly.js
- 🎯 Analyse complète : TCP, DNS, jitter, retransmissions, RTT

### Option 2: Docker Compose (optionnel)

Interface web avec upload drag-and-drop :

```bash
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Configuration (optionnelle)
cp .env.example .env
# Éditer .env pour configurer les mots de passe et secrets

# Démarrer avec PostgreSQL (développement)
docker-compose --profile dev up -d

# Ou démarrer en production (sans Adminer)
docker-compose --profile prod up -d
```

Accéder à :
- Application : http://localhost:8000
- Adminer (dev) : http://localhost:8080
- MailHog (dev) : http://localhost:8025 (pour tester les emails)

#### Configuration Email (Optionnel)

L'application supporte les notifications email via SMTP. En développement, **MailHog** est utilisé pour capturer les emails localement sans serveur réel.

**Variables d'environnement (.env) :**
```bash
MAIL_ENABLED=true
SMTP_HOST=localhost
SMTP_PORT=1025
MAIL_FROM=noreply@pcaplab.com
```

📖 [Guide complet de configuration Email](docs/EMAIL_SETUP.md)

#### Configuration PostgreSQL

**Variables d'environnement (.env) :**
```bash
# Requis en production
POSTGRES_PASSWORD=votre_mot_de_passe_securise
SECRET_KEY=votre_cle_secrete_32_chars_minimum

# Optionnel (ports personnalisés)
APP_PORT=8000
POSTGRES_PORT=5432
ADMINER_PORT=8080
```

**Générer des secrets sécurisés :**
```bash
# Mot de passe PostgreSQL
openssl rand -base64 32

# Secret key pour JWT/sessions
openssl rand -hex 32
```

**Connexion à PostgreSQL via Adminer :**
1. Ouvrir http://localhost:8080
2. Système : `PostgreSQL`
3. Serveur : `postgres`
4. Utilisateur : `pcap`
5. Mot de passe : (voir .env)
6. Base de données : `pcap_analyzer`

**Connexion directe via psql :**
```bash
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer
```

**Commandes utiles :**
```bash
# Voir les logs
docker-compose logs -f

# Arrêter les services
docker-compose down

# Supprimer les volumes (ATTENTION : perte de données)
docker-compose down -v

# Nettoyer les anciennes images
./scripts/cleanup_docker.sh
```

### Option 3: Kubernetes (optionnel, production)

#### Avec Ingress (recommandé)

```bash
# Build l'image
docker build -t pcap-analyzer:latest .

# Créer le cluster kind avec ports Ingress
kind create cluster --name pcap-analyzer --config kind-config.yaml
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# Installer l'Ingress controller nginx
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml

# Attendre que l'Ingress soit prêt
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s

# Déployer avec Helm (Ingress activé par défaut)
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --create-namespace --namespace pcap-analyzer

# Ajouter l'entrée dans /etc/hosts
echo "127.0.0.1 pcap.local" | sudo tee -a /etc/hosts

# Accéder à l'application
open http://pcap.local
```

#### Sans Ingress (NodePort)

```bash
# Modifier values.yaml pour désactiver Ingress
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --create-namespace --namespace pcap-analyzer \
  --set ingress.enabled=false \
  --set service.type=NodePort \
  --set service.nodePort=30080

# Accéder à http://localhost:8000
```

📖 [Guide Kubernetes complet](helm-chart/pcap-analyzer/README.md)

## 📋 Fonctionnalités

### Analyse réseau
- **TCP** : Retransmissions (RTO/Fast/Generic), handshakes, fenêtres
- **DNS** : Timeouts, latences, erreurs
- **Jitter** : Graphiques interactifs temps réel avec RTT overlay
- **Anomalies** : Gaps temporels, bursts, fragmentation IP
- **Support complet IPv4/IPv6**
- **Messages contextuels** basés sur RFC (SSH, mDNS, HTTP...)

### Sécurité (v5.0)
- **Compliance** : OWASP ASVS 4.0 (100%), CWE Top 25 (100%), GDPR
- **Authentication** : JWT avec bcrypt, admin approval workflow, rate limiting
- **Multi-tenant** : Isolation CWE-639 compliant, ownership tracking
- **Protection** : Path traversal, CSRF, XSS, injection, decompression bombs
- **TLS/SSL** : PostgreSQL encryption support (configurable)
- **Audit** : Logging sécurisé avec PII redaction, admin action tracking
- **Tests** : 730+ tests (49.75% coverage), 100% security test pass rate
- **Documentation** : [SECURITY.md](SECURITY.md) - Threat model & controls

### Interface Web (optionnelle)
- **Upload drag & drop** de fichiers PCAP
- **Progression en temps réel** (Server-Sent Events)
- **Rapports interactifs** HTML/JSON avec mode sombre
- **Historique** des analyses (rétention 24h)
- **API REST** complète

📖 [Data Retention & Cleanup Policy](docs/DATA_RETENTION_POLICY.md)

### Notifications Email (v4.27)
- **Inscription** : Email de confirmation envoyé dès la création du compte (statut PENDING).
- **Approbation** : Notification envoyée à l'utilisateur dès que son compte est activé par un admin.
- **Asynchrone** : Envoi non bloquant via `FastAPI BackgroundTasks`.
- **Templates** : Emails HTML responsifs basés sur Jinja2.
- **Dev-friendly** : Intégration MailHog pour le test en local.

### Authentication & Admin Workflow (v5.0)
- **User Registration** : Self-service avec approbation admin requise
- **Admin Approval** : Les nouveaux comptes doivent être approuvés par un admin
- **Enhanced Password Policy:** NIST-compliant passwords (min 12 chars), zxcvbn strength validation, and password history (prevents reuse of last 5).
- **Self-Service Password Reset:** Secure token-based recovery via email with anti-enumeration protection.
- **Role-Based Access Control (RBAC):** Granular permissions for admins and users.
- **Admin Visibility:** Administrators can view and manage all users' uploads, with a clear owner identification column in the history view.
- **Rate Limiting** : Protection brute force (1s → 2s → 5s après 4-6 échecs)
- **Multi-Tenant** : Isolation stricte des données par `owner_id` (CWE-639)
- **Admin Actions** : Approve/block/unblock/delete users, view all tasks
- **Session Security** : JWT avec expiration 30min, SECRET_KEY enforced en production
- **Audit Logging** : Toutes les actions admin sont loggées

📖 [Admin Approval Workflow Guide](docs/ADMIN_APPROVAL_WORKFLOW.md)

### Performance
- **Architecture hybride** dpkt + Scapy (1.7x plus rapide)
- **Docker optimisé** 485 MB (multi-stage build)
- **Tests automatisés** Ubuntu/macOS × Python 3.11/3.12

## 💻 Utilisation

### CLI (mode principal)

```bash
# Analyser un fichier
pcap_analyzer analyze capture.pcap

# Avec filtres
pcap_analyzer analyze capture.pcap --latency 0.5

# Capture SSH distante (optionnel, voir config.yaml)
pcap_analyzer capture --duration 600

# Afficher les détails des retransmissions
pcap_analyzer analyze capture.pcap --details
```

**Rapports générés** :
- `reports/pcap_analysis_<timestamp>.html` - Rapport interactif avec graphiques
- `reports/pcap_analysis_<timestamp>.json` - Données structurées

### Interface web (optionnelle)

```bash
# Docker Compose
docker-compose up -d
open http://localhost:8000

# Kubernetes avec Ingress
open http://pcap.local

# Kubernetes - Commandes utiles
kubectl get pods -n pcap-analyzer
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f
kubectl get ingress -n pcap-analyzer
```

**Workflow :** Upload PCAP → Progression temps réel → Rapport HTML → Historique

## 🔧 Configuration

Créer `config.yaml` (optionnel) :

```yaml
thresholds:
  packet_gap: 1.0
  syn_synack_delay: 0.1
  rtt_threshold: 0.1
  jitter_warning: 0.03   # 30ms
  jitter_critical: 0.05  # 50ms

reports:
  output_dir: reports

pii_redaction:
  mode: PRODUCTION  # PRODUCTION | DEVELOPMENT | DEBUG
  redact_ip_addresses: true
  redact_mac_addresses: true
  legal_basis: "legitimate_interest"
  retention_days: 90
```

Configuration complète : voir `config.yaml.example`

## 📊 API REST (Interface web)

### Authentication Endpoints
| Endpoint | Description | Auth Required |
|----------|-------------|---------------|
| `POST /api/register` | User registration (requires admin approval) | No |
| `POST /api/token` | Login (OAuth2 password flow) | No |
| `GET /api/users/me` | Get current user info | Yes |
| `PUT /api/users/me` | Update password | Yes |
| `GET /api/csrf/token` | Get CSRF token | Yes |

### Analysis Endpoints
| Endpoint | Description | Auth Required |
|----------|-------------|---------------|
| `POST /api/upload` | Upload PCAP file | Yes |
| `GET /api/progress/{task_id}` | Real-time progress (SSE) | Yes |
| `GET /api/status/{task_id}` | Task status | Yes |
| `GET /api/history` | Analysis history (filtered by owner) | Yes |
| `GET /api/reports/{task_id}/html` | HTML report | Yes |
| `GET /api/reports/{task_id}/json` | JSON report | Yes |
| `DELETE /api/reports/{task_id}` | Delete report | Yes |

### Admin Endpoints
| Endpoint | Description | Admin Only |
|----------|-------------|------------|
| `GET /api/users` | List all users (with pagination & filters) | Yes |
| `POST /api/admin/users` | Create user with temp password | Yes |
| `PUT /api/admin/users/{id}/approve` | Approve user registration | Yes |
| `PUT /api/admin/users/{id}/block` | Block user account | Yes |
| `PUT /api/admin/users/{id}/unblock` | Unblock user account | Yes |
| `DELETE /api/admin/users/{id}` | Delete user account + associated files (GDPR) | Yes |
| `POST /api/admin/users/bulk/approve` | Approve multiple users at once | Yes |
| `POST /api/admin/users/bulk/block` | Block multiple users at once | Yes |

### System Endpoints
| Endpoint | Description | Auth Required |
|----------|-------------|---------------|
| `GET /api/health` | Health check | No |
| `GET /` | Homepage | No |
| `GET /login` | Login page | No |
| `GET /admin` | Admin panel | Admin only |

**Authentication Example:**
```bash
# Register
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username": "john", "email": "john@example.com", "password": "SecurePass123!"}'

# Login (after admin approval)
curl -X POST http://localhost:8000/api/token \
  -d "username=john&password=SecurePass123!"
# → {"access_token": "eyJ...", "token_type": "bearer"}

# Upload PCAP (with auth)
curl -X POST http://localhost:8000/api/upload \
  -H "Authorization: Bearer eyJ..." \
  -F "file=@capture.pcap"
# → {"task_id": "abc123", "status": "pending"}
```

📖 [Complete API Documentation](docs/API_DOCUMENTATION.md)

## 🧪 Tests

```bash
# Tous les tests (SQLite)
pytest -k "not postgresql"

# Tests avec PostgreSQL (requires DATABASE_URL)
DATABASE_URL=postgresql://pcap:password@localhost:5432/pcap_analyzer_test pytest

# Tests de sécurité uniquement
pytest tests/security/ -v

# Tests d'authentification
pytest tests/test_auth.py -v

# Avec couverture
pytest --cov=app --cov=src --cov-report=html
open htmlcov/index.html

# Tests par marker
pytest -m unit        # Tests unitaires
pytest -m integration # Tests d'intégration
pytest -m security    # Tests de sécurité
```

**Résultats v4.27** :
- **Total** : 750+ tests ✅
- **Auth** : 35+ passing ✅
- **Emails** : Intégration MailHog validée ✅
- **Storage** : Zéro fichier orphelin après suppression (RGPD) ✅
- **Security** : 50+ passing ✅ (100% pass rate)
- **PostgreSQL Integration** : 30+ passing ✅
- **Coverage** : ~38% global, 85%+ sur les modules critiques (Email, Auth, Cleanup)
- **No regressions** : 0 failed tests

📖 [Testing Guide](docs/TESTING_GUIDE.md)

## 📦 Déploiement

**CLI local (recommandé)** : Installation rapide et sécurisée
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
pcap_analyzer analyze capture.pcap
```

**Docker Compose (optionnel)** : Développement local avec interface web
```bash
# Avec PostgreSQL (recommandé)
cp .env.example .env  # Configurer les secrets
docker-compose --profile dev up -d
docker-compose logs -f

# Accès
# - Application : http://localhost:8000
# - Adminer : http://localhost:8080
# - PostgreSQL : localhost:5432
```

**Kubernetes (optionnel)** : Production avec haute disponibilité
- Chart Helm avec health probes, PVC, NodePort
- Voir [helm-chart/pcap-analyzer/README.md](helm-chart/pcap-analyzer/README.md)
- Limitation : 1 replica (SQLite local)

**Production distribuée** : PostgreSQL + S3 + Redis requis (roadmap v5.0)

## 🏗️ Structure

```
pcap_analyzer/
├── src/                   # CLI + analyseurs (mode principal)
│   ├── analyzers/         # 17 analyseurs TCP/DNS/Jitter/etc
│   ├── exporters/         # Génération rapports HTML/JSON
│   ├── utils/             # Sécurité, validation, logging
│   └── cli.py            # Interface ligne de commande
├── app/                   # Interface web (optionnelle)
│   ├── api/routes/        # Endpoints REST
│   ├── services/          # Worker, DB, Analyzer
│   ├── templates/         # UI (upload, progress, history)
│   └── static/            # CSS/JS
├── tests/                 # Tests pytest
│   ├── test_security.py   # Tests de sécurité
│   └── security/          # Suite de tests détaillée
├── docs/                  # Documentation
│   ├── security/          # Documentation sécurité
│   └── archive/           # Versions archivées
├── helm-chart/            # Déploiement Kubernetes (optionnel)
├── examples/              # POC et exemples
├── scripts/               # Utilitaires
└── docker-compose.yml     # Dev environment (optionnel)
```

## 📚 Documentation

- **Sécurité** : [SECURITY.md](SECURITY.md) - Threat model, compliance, controls
- **Changelog** : [CHANGELOG.md](CHANGELOG.md) - Historique des versions
- **Kubernetes** : [helm-chart/pcap-analyzer/README.md](helm-chart/pcap-analyzer/README.md)
- **Tests** : [tests/README.md](tests/README.md)
- **Scripts** : [scripts/README.md](scripts/README.md)

## 🤝 Contribution

Contributions bienvenues ! Ouvrir une issue ou PR.

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📄 Licence

MIT - voir [LICENSE](LICENSE)

## 🔗 Liens

- **Repository** : https://github.com/MacFlurry/pcap_analyzer
- **Issues** : https://github.com/MacFlurry/pcap_analyzer/issues
- **Releases** : https://github.com/MacFlurry/pcap_analyzer/releases
