# PCAP Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](.github/workflows/test.yml)

Analyseur automatisé de fichiers PCAP pour diagnostiquer les problèmes de latence et de performance réseau.

**Interface web moderne** • **Rapports HTML interactifs** • **Analyse en temps réel** • **Kubernetes ready**

## 🚀 Démarrage rapide

### Option 1: Docker Compose (recommandé)

```bash
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer
docker-compose up -d
```

Accéder à http://localhost:8000

### Option 2: Kubernetes (production)

```bash
# Build et charger l'image
docker build -t pcap-analyzer:latest .
kind create cluster --name pcap-analyzer --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: 8000
EOF
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# Déployer avec Helm
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --create-namespace --namespace pcap-analyzer
```

📖 [Guide Kubernetes complet](helm-chart/pcap-analyzer/README.md)

### Option 3: CLI local

```bash
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Créer et activer un environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -e .

# Utiliser l'analyseur
pcap_analyzer analyze capture.pcap
```

## 📋 Fonctionnalités

### Interface Web
- **Upload drag & drop** de fichiers PCAP
- **Progression en temps réel** (Server-Sent Events)
- **Rapports interactifs** HTML/JSON avec mode sombre
- **Historique** des analyses (rétention 24h)
- **API REST** complète

### Analyse réseau
- **TCP** : Retransmissions (RTO/Fast/Generic), handshakes, fenêtres
- **DNS** : Timeouts, latences, erreurs
- **Anomalies** : Gaps temporels, bursts, fragmentation IP
- **Support complet IPv4/IPv6**
- **Messages contextuels** basés sur RFC (SSH, mDNS, HTTP...)

### Performance
- **Architecture hybride** dpkt + Scapy (1.7x plus rapide)
- **Docker optimisé** 485 MB (multi-stage build)
- **Tests automatisés** Ubuntu/macOS × Python 3.11/3.12

## 💻 Utilisation

### Interface web

```bash
# Docker Compose
docker-compose up -d
open http://localhost:8000

# Kubernetes
kubectl get pods -n pcap-analyzer
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f
```

**Workflow :** Upload PCAP → Progression temps réel → Rapport HTML → Historique

### CLI

```bash
# Analyser un fichier
pcap_analyzer analyze capture.pcap

# Avec filtres
pcap_analyzer analyze capture.pcap --latency 0.5

# Capture SSH distante (optionnel, voir config.yaml)
pcap_analyzer capture --duration 600
```

## 🔧 Configuration

Créer `config.yaml` (optionnel) :

```yaml
thresholds:
  packet_gap: 1.0
  syn_synack_delay: 0.1
  rtt_threshold: 0.1

reports:
  output_dir: reports
```

Configuration complète : voir `config.yaml` exemple

## 📊 API REST

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

# Avec couverture
pytest --cov=src --cov-report=html

# Tests unitaires seulement
pytest -m unit
```

## 📦 Déploiement

**Docker Compose :** Développement local
```bash
docker-compose up -d
docker-compose logs -f
```

**Kubernetes :** Production
- Chart Helm avec health probes, PVC, NodePort
- Voir [helm-chart/pcap-analyzer/README.md](helm-chart/pcap-analyzer/README.md)
- Limitation : 1 replica (SQLite local)

**Production distribuée :** PostgreSQL + S3 + Redis requis

## 🏗️ Structure

```
pcap_analyzer/
├── app/                    # Interface web FastAPI
│   ├── api/routes/        # Endpoints REST
│   ├── services/          # Worker, DB, Analyzer
│   ├── templates/         # UI (upload, progress, history)
│   └── static/            # CSS/JS
├── src/                   # CLI + analyseurs
│   ├── analyzers/         # 17 analyseurs TCP/DNS/etc
│   └── cli.py            # Interface ligne de commande
├── helm-chart/            # Déploiement Kubernetes
├── tests/                 # Tests pytest
└── docker-compose.yml     # Dev environment
```

## 📚 Documentation

- [Guide Kubernetes/Helm](helm-chart/pcap-analyzer/README.md)
- [Tests](tests/README.md)
- [Scripts](scripts/README.md)
- [Changelog](CHANGELOG.md)

## 🤝 Contribution

Contributions bienvenues ! Ouvrir une issue ou PR.

## 📄 Licence

MIT - voir [LICENSE](LICENSE)
