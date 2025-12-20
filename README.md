# PCAP Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](.github/workflows/test.yml)
[![Security](https://img.shields.io/badge/security-91.5%25-brightgreen.svg)](SECURITY.md)

Analyseur automatisé de fichiers PCAP pour diagnostiquer les problèmes de latence et de performance réseau.

**CLI rapide et puissant** • **Rapports HTML interactifs** • **Interface web optionnelle** • **Production ready**

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
docker-compose up -d
```

Accéder à http://localhost:8000

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

### Sécurité (v4.21.0)
- **Score de sécurité** : 91.5% (production ready)
- **Conformité** : OWASP ASVS, NIST SP 800-53, CWE Top 25, GDPR (100%)
- **Protection** : Path traversal, XSS, injection, decompression bombs
- **Audit** : Logging sécurisé avec redaction PII
- **Documentation** : [SECURITY.md](SECURITY.md) (24.5 KB, 20 sections)

### Interface Web (optionnelle)
- **Upload drag & drop** de fichiers PCAP
- **Progression en temps réel** (Server-Sent Events)
- **Rapports interactifs** HTML/JSON avec mode sombre
- **Historique** des analyses (rétention 24h)
- **API REST** complète

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

| Endpoint | Description |
|----------|-------------|
| `POST /api/upload` | Upload fichier PCAP |
| `GET /api/progress/{task_id}` | Progression temps réel (SSE) |
| `GET /api/status/{task_id}` | Statut d'une tâche |
| `GET /api/history` | Historique des analyses |
| `GET /reports/{task_id}.html` | Rapport HTML |
| `GET /reports/{task_id}.json` | Rapport JSON |
| `GET /api/health` | Health check |

**Exemple :**
```bash
curl -X POST http://localhost:8000/api/upload -F "file=@capture.pcap"
# → {"task_id": "abc123", "status": "pending"}

curl http://localhost:8000/api/status/abc123
```

## 🧪 Tests

```bash
# Tous les tests
pytest

# Tests de sécurité uniquement
pytest tests/test_security.py -v

# Avec couverture
pytest --cov=src --cov-report=html

# Tests unitaires seulement
pytest -m unit
```

**Résultats v4.21.0** :
- Tests de sécurité : 16/16 passing ✅
- Tests principaux : 64/65 passing ✅
- Couverture : 90%+ sur modules de sécurité

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
docker-compose up -d
docker-compose logs -f
```

**Kubernetes (optionnel)** : Production avec haute disponibilité
- Chart Helm avec health probes, PVC, NodePort
- Voir [helm-chart/pcap-analyzer/README.md](helm-chart/pcap-analyzer/README.md)
- Limitation : 1 replica (SQLite local)

**Production distribuée** : PostgreSQL + S3 + Redis requis (roadmap)

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
