# PCAP Analyzer - Analyseur automatisé des causes de latence réseau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9-3.12](https://img.shields.io/badge/python-3.9%20|%203.10%20|%203.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](.github/workflows/test.yml)
[![GitHub issues](https://img.shields.io/github/issues/MacFlurry/pcap_analyzer)](https://github.com/MacFlurry/pcap_analyzer/issues)
[![Latest Release](https://img.shields.io/github/v/release/MacFlurry/pcap_analyzer?include_prereleases)](https://github.com/MacFlurry/pcap_analyzer/releases)

**Version 4.0.0**

Outil avancé d'analyse automatisée de fichiers PCAP avec **interface web moderne**. Il permet d'identifier et de diagnostiquer de manière intelligente les causes de latence et de problèmes réseau, avec une interface utilisateur intuitive, des rapports HTML interactifs avec support du mode sombre, et des messages contextuels basés sur les RFC officielles.

Conforme aux standards RFC 793 (TCP), RFC 2581 (Congestion Control), RFC 6298 (RTO), RFC 4253 (SSH), RFC 6762 (mDNS). Support complet IPv4 et IPv6.

## 🌟 Nouveautés Version 4.0.0

### Interface Web avec Docker

- **Application Web Moderne** : Interface web complète avec FastAPI et analyse en temps réel
- **Docker Multi-stage** : Déploiement simplifié avec image optimisée (485 MB)
- **Progression Temps Réel** : Server-Sent Events (SSE) pour suivre l'analyse en direct
- **Base de Données SQLite** : Historique des analyses avec rétention 24h automatique
- **Rapports Persistants** : Accès aux rapports HTML/JSON via URLs dédiées

### Messages Intelligents et Contextuels

- **Erreurs en Français** : Traduction automatique des erreurs techniques en messages compréhensibles
- **Analyse Jitter Contextuelle** : Messages adaptés par service (SSH, mDNS, HTTP, etc.)
  - **SSH (RFC 4253)** : Impact sur terminaux interactifs
  - **mDNS (RFC 6762)** : Aucun impact (broadcast tolérant au jitter)
  - **HTTP** : Impact sur requête/réponse
- **Classification Retransmissions** : 3 types avec explications claires
  - **RTO** (délai ≥ 200ms) : Timeout grave, perte de paquets
  - **Fast Retransmission** (délai ≤ 50ms) : Détection rapide via duplicate ACKs
  - **Generic Retransmission** (50-200ms) : Congestion modérée

### Améliorations UX

- **Affichage Taux Retransmission** : Pas d'extrapolation trompeuse pour flows < 1s
  - Avant: "195 retransmissions (burst rate: 11837.5/sec)" ❌
  - Maintenant: "195 retransmissions in 16.5ms" ✅
- **Support IPv6 Amélioré** : Parsing correct des ports avec `rfind(":")` pour IPv6
- **Frontend Réactif** : Mise à jour automatique des compteurs et statuts

## Fonctionnalités Clés

### Interface Web (Nouveau en v4.0)

*   **🌐 Interface Web Moderne** : Application web complète avec upload, analyse temps réel et visualisation des rapports
*   **📊 Progression en Temps Réel** : Suivi SSE (Server-Sent Events) de l'analyse avec phases et pourcentages
*   **💾 Historique des Analyses** : Base SQLite avec rétention automatique 24h
*   **🐳 Déploiement Docker** : Multi-stage build optimisé (485 MB) avec docker-compose
*   **🔄 Nettoyage Automatique** : Suppression automatique des anciens rapports après 24h
*   **📱 Interface Responsive** : Design adaptatif mobile/desktop avec mode sombre

### Analyse Réseau

*   **Rapports HTML Interactifs :** Visualisation claire et pédagogique des problèmes détectés, avec des explications contextuelles basées sur les RFC officielles et des suggestions d'investigation. Support automatique du mode sombre avec excellent contraste et lisibilité.
*   **Analyse TCP Intelligente :** Détection nuancée des retransmissions (RTO/Fast Retrans/Generic), des handshakes lents, et des problèmes de fenêtre TCP. Conforme RFC 793 et RFC 2581.
*   **Messages Contextuels :** Interprétations adaptées au service détecté (SSH, mDNS, HTTP, DNS) basées sur les RFC officielles (4253, 6762, etc.)
*   **Diagnostic DNS Approfondi :** Identification des timeouts, des réponses lentes et des erreurs DNS, avec détail par domaine.
*   **Détection d'Anomalies :** Analyse des gaps temporels (différenciant pauses applicatives et incidents réseau), des bursts de trafic, de la fragmentation IP et du trafic asymétrique.
*   **Support IPv6 Complet :** Analyse transparente des flux IPv4 et IPv6 à travers tous les analyseurs, avec gestion robuste des ports hexadécimaux et parsing IPv6 correct.
*   **Capture à Distance via SSH (Optionnelle) :** Possibilité de lancer des captures `tcpdump` sur des serveurs distants et de les analyser automatiquement. Non requis pour l'analyse locale.

### Qualité et Performance

*   **🚀 Mode Hybride (dpkt + Scapy) :** Architecture optimisée utilisant dpkt pour l'extraction rapide des métadonnées (3-5x plus rapide) et Scapy pour l'inspection approfondie des protocoles complexes. **1.7x speedup global** sur l'analyse complète.
*   **Optimisation Mémoire :** Gestion intelligente de la mémoire avec cleanup périodique pour les captures de longue durée.
*   **Tests Complets :** Suite de tests unitaires et d'intégration avec couverture >80% (pytest).
*   **CI/CD :** Tests automatisés sur Ubuntu et macOS avec Python 3.9-3.12.
*   **Sécurité Renforcée :** Protection contre XSS, path traversal, validation stricte des entrées, et messages d'erreur traduits.

## Installation

### Option 1: Interface Web avec Docker Compose (Recommandé pour développement)

```bash
# Cloner le repository
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Lancer l'application web
docker-compose up -d

# Accéder à l'interface web
# http://localhost:8000
```

**Fonctionnalités Web:**
- Upload de fichiers PCAP (glisser-déposer)
- Analyse en temps réel avec barre de progression
- Visualisation des rapports HTML/JSON
- Historique des analyses (24h de rétention)
- Gestion automatique du nettoyage

**Arrêter l'application:**
```bash
docker-compose down
```

### Option 2: Déploiement Kubernetes avec kind + Helm (Recommandé pour testing/production)

**Prérequis:**
- Docker installé
- kubectl installé ([doc officielle](https://kubernetes.io/docs/tasks/tools/))
- kind installé: `brew install kind` (macOS) ou voir [kind.sigs.k8s.io](https://kind.sigs.k8s.io/docs/user/quick-start/)
- Helm installé: `brew install helm` (macOS) ou voir [helm.sh](https://helm.sh/docs/intro/install/)

**Installation:**

```bash
# 1. Cloner le repository
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# 2. Build l'image Docker
docker build -t pcap-analyzer:latest .

# 3. Créer le cluster kind avec port mapping
cat <<EOF | kind create cluster --name pcap-analyzer --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30080
    hostPort: 8000
    protocol: TCP
EOF

# 4. Charger l'image dans le cluster kind
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# 5. Déployer avec Helm
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --create-namespace \
  --namespace pcap-analyzer

# 6. Vérifier le déploiement
kubectl get all -n pcap-analyzer

# Accéder à l'interface web
# http://localhost:8000
```

**Configuration Helm:**

Le chart Helm utilise les valeurs par défaut suivantes (`helm-chart/pcap-analyzer/values.yaml`):

```yaml
replicaCount: 1  # Limité à 1 (SQLite + stockage local)

image:
  repository: pcap-analyzer
  tag: latest
  pullPolicy: Never

service:
  type: NodePort
  port: 8000
  nodePort: 30080

persistence:
  enabled: true
  size: 10Gi
  storageClass: standard

resources:
  limits:
    memory: 4Gi
    cpu: "2"
  requests:
    memory: 1Gi
    cpu: "1"
```

**Personnaliser les valeurs:**

```bash
# Modifier les ressources, taille du stockage, etc.
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --set persistence.size=20Gi \
  --set resources.limits.memory=8Gi \
  --namespace pcap-analyzer
```

**Gestion du déploiement:**

```bash
# Voir les logs
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f

# Vérifier la santé de l'application
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- curl localhost:8000/api/health

# Mise à jour de l'application
helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer -n pcap-analyzer

# Désinstaller
helm uninstall pcap-analyzer -n pcap-analyzer

# Supprimer le cluster
kind delete cluster --name pcap-analyzer
```

**Limitations Kubernetes:**
- **1 replica seulement** : L'application utilise SQLite (base locale) et un stockage fichier local pour les rapports
- **Pas de load balancing** : Le NodePort expose directement le pod unique
- **Pas de haute disponibilité** : Si le pod redémarre, les analyses en cours sont perdues

Pour une architecture multi-replicas en production, il faudrait migrer vers:
- Base de données externe (PostgreSQL)
- Stockage distribué (S3, MinIO)
- Queue distribuée (Redis, RabbitMQ)

### Option 3: Installation CLI (Analyse locale)

#### Prérequis

*   Python 3.9, 3.10, 3.11 ou 3.12
*   `libpcap` (installé automatiquement via les dépendances)

**Pour la capture distante uniquement (optionnel) :**
*   `tcpdump` installé sur le serveur distant
*   Accès SSH avec authentification par clé au serveur de capture
*   Configuration SSH dans `config.yaml`

#### Étapes

```bash
# Cloner le repository
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# (Optionnel) Créer et activer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer le package et les dépendances
pip install -e .

# Pour le développement (inclut pytest, flake8, mypy, etc.)
pip install -e ".[dev]"
# ou
pip install -r requirements-dev.txt
```

## Configuration

Le fichier `config.yaml` à la racine du projet permet de personnaliser :
*   **Seuils de détection** (requis) : RTT, retransmissions, DNS, etc.
*   **Paramètres SSH** (optionnel) : Uniquement nécessaire pour la commande `capture`
*   **Répertoire de sortie** des rapports

Configuration minimale pour l'analyse locale :
```yaml
thresholds:
  packet_gap: 1.0
  syn_synack_delay: 0.1
  # ... autres seuils

reports:
  output_dir: reports
```

## Utilisation

### Interface Web avec Docker Compose

```bash
# Démarrer l'application
docker-compose up -d

# Accéder à l'interface web
open http://localhost:8000

# Voir les logs
docker-compose logs -f pcap-analyzer

# Arrêter l'application
docker-compose down
```

**Workflow:**
1. Glisser-déposer un fichier PCAP
2. Voir la progression en temps réel (SSE)
3. Consulter le rapport HTML interactif
4. Télécharger le rapport JSON si besoin
5. Accéder à l'historique des analyses

### Interface Web avec Kubernetes (kind + Helm)

```bash
# Vérifier le statut du cluster
kubectl get pods -n pcap-analyzer
kubectl get pvc -n pcap-analyzer

# Accéder à l'application
open http://localhost:8000

# Voir les logs en temps réel
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f

# Vérifier la santé de l'application
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- curl localhost:8000/api/health

# Redémarrer le pod
kubectl rollout restart deployment/pcap-analyzer -n pcap-analyzer

# Mettre à jour l'application
# 1. Rebuild l'image
docker build -t pcap-analyzer:latest .

# 2. Recharger l'image dans kind
kind load docker-image pcap-analyzer:latest --name pcap-analyzer

# 3. Redémarrer le déploiement
kubectl rollout restart deployment/pcap-analyzer -n pcap-analyzer

# Désinstaller et nettoyer
helm uninstall pcap-analyzer -n pcap-analyzer
kind delete cluster --name pcap-analyzer
```

**Monitoring:**

```bash
# Utilisation des ressources
kubectl top pod -n pcap-analyzer

# Événements du namespace
kubectl get events -n pcap-analyzer --sort-by='.lastTimestamp'

# Décrire le pod pour debug
kubectl describe pod -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer

# Accéder au shell du pod
kubectl exec -it -n pcap-analyzer deployment/pcap-analyzer -- /bin/sh
```

**Workflow (identique à Docker Compose):**
1. Glisser-déposer un fichier PCAP
2. Voir la progression en temps réel (SSE)
3. Consulter le rapport HTML interactif
4. Télécharger le rapport JSON si besoin
5. Accéder à l'historique des analyses

### CLI - Analyser un fichier PCAP

```bash
pcap_analyzer analyze ma_capture.pcap
# Génère automatiquement un rapport HTML et JSON dans le dossier reports/
```

### CLI - Lancer une capture et analyser (via SSH)

```bash
# Capture de 10 minutes sur le serveur configuré (config.yaml) et analyse auto.
pcap_analyzer capture --duration 600
```

### Options Avancées CLI

```bash
# Filtrer par seuil de latence (ne montrer que les flux avec latence > seuil)
pcap_analyzer analyze capture.pcap --latency 0.5

# Spécifier un fichier de configuration personnalisé
pcap_analyzer analyze capture.pcap --config my_config.yaml

# Ne pas générer de rapports (affichage console uniquement)
pcap_analyzer analyze capture.pcap --no-report

# Limiter l'affichage des détails
pcap_analyzer analyze capture.pcap --details-limit 10
```

## Architecture

### Structure du Projet

```
pcap_analyzer/
├── app/                         # Application Web (FastAPI)
│   ├── main.py                  # Point d'entrée FastAPI
│   ├── api/                     # Routes API
│   │   ├── routes/
│   │   │   ├── upload.py        # Upload fichier PCAP
│   │   │   ├── progress.py      # SSE pour progression
│   │   │   └── reports.py       # Endpoints rapports
│   ├── models/                  # Modèles Pydantic
│   │   └── schemas.py           # TaskInfo, TaskStatus, etc.
│   ├── services/                # Services métier
│   │   ├── analyzer.py          # Wrapper analyse PCAP
│   │   ├── database.py          # SQLite avec aiosqlite
│   │   └── worker.py            # Worker async pour analyses
│   ├── static/                  # Fichiers statiques
│   │   ├── css/                 # Styles (glassmorphism design)
│   │   └── js/                  # JavaScript (progress.js, history.js)
│   └── templates/               # Templates Jinja2
│       ├── index.html           # Page upload
│       ├── progress.html        # Page progression
│       └── history.html         # Historique des analyses
│
├── helm-chart/                  # Déploiement Kubernetes
│   └── pcap-analyzer/           # Chart Helm
│       ├── Chart.yaml           # Métadonnées du chart
│       ├── values.yaml          # Configuration par défaut
│       └── templates/           # Templates Kubernetes
│           ├── deployment.yaml  # Deployment avec health probes
│           ├── service.yaml     # Service NodePort
│           ├── pvc.yaml         # PersistentVolumeClaim
│           └── _helpers.tpl     # Helpers Helm
│
├── src/                         # Code source CLI
│   ├── cli.py                   # Interface en ligne de commande
│   ├── config.py                # Gestion de la configuration
│   ├── ssh_capture.py           # Module de capture SSH/tcpdump
│   ├── report_generator.py      # Générateur de rapports JSON/HTML
│   ├── analyzer_factory.py      # Factory pour créer les analyseurs
│   │
│   ├── analyzers/               # 17 analyseurs spécialisés
│   │   ├── timestamp_analyzer.py      # Analyse des timestamps et gaps
│   │   ├── tcp_handshake.py           # Analyse handshake TCP
│   │   ├── syn_retransmission.py      # Retransmissions SYN détaillées
│   │   ├── retransmission.py          # Retransmissions et anomalies
│   │   ├── rtt_analyzer.py            # Round Trip Time
│   │   ├── tcp_window.py              # Fenêtres TCP et saturation
│   │   ├── icmp_pmtu.py               # ICMP et PMTU
│   │   ├── dns_analyzer.py            # Résolutions DNS
│   │   ├── tcp_reset.py               # Analyse TCP RST
│   │   ├── ip_fragmentation.py        # Fragmentation IP
│   │   ├── top_talkers.py             # Top talkers
│   │   ├── throughput.py              # Débit et throughput
│   │   ├── tcp_timeout.py             # Timeouts TCP
│   │   ├── asymmetric_traffic.py      # Trafic asymétrique
│   │   ├── burst.py                   # Bursts de paquets
│   │   ├── temporal_pattern.py        # Patterns temporels
│   │   └── sack_analyzer.py           # Analyse SACK/D-SACK
│   │
│   ├── exporters/               # Générateurs de rapports
│   │   └── html_report.py       # Rapport HTML avec messages contextuels
│   │
│   └── utils/                   # Utilitaires
│       ├── packet_utils.py      # Extraction d'infos paquets (IPv4/IPv6)
│       └── tcp_utils.py         # Utilitaires TCP (flags, longueur logique)
│
├── templates/                   # Templates Jinja2 pour rapports CLI
│   ├── report_template.html
│   └── static/css/
│       └── report.css           # Styles avec support mode sombre
│
├── docker-compose.yml           # Configuration Docker Compose
├── Dockerfile                   # Multi-stage build (485 MB)
├── requirements.txt             # Dépendances Python CLI
├── requirements-web.txt         # Dépendances Python Web
├── tests/                       # Tests unitaires et d'intégration
├── config.yaml                  # Configuration (seuils, SSH optionnel)
└── reports/                     # Rapports générés (ignoré par git)
```

### Options de Déploiement

**Docker Compose (Développement):**
- Rapide à démarrer (`docker-compose up -d`)
- Idéal pour le développement local
- Rebuild facile des images
- Logs simples (`docker-compose logs -f`)

**Kubernetes + Helm (Testing/Production):**
- Déploiement standardisé avec chart Helm
- Health probes (liveness, readiness)
- Gestion des ressources (CPU, mémoire)
- PersistentVolumeClaim pour les données
- Monitoring avec kubectl
- Limitation: 1 replica (SQLite + stockage local)

### Flux de Données - Interface Web

```
┌──────────────┐
│  UTILISATEUR │
│  (Browser)   │
└──────┬───────┘
       │
       │ 1. Upload PCAP
       ▼
┌──────────────────┐
│   FastAPI        │
│   /api/upload    │
└──────┬───────────┘
       │
       │ 2. Enqueue task
       ▼
┌──────────────────┐     ┌──────────────────┐
│   Worker         │────▶│   SQLite DB      │
│   (Async)        │     │   (aiosqlite)    │
└──────┬───────────┘     └──────────────────┘
       │
       │ 3. Analyze PCAP
       ▼
┌──────────────────┐
│   CLI Analyzer   │
│   (dpkt + Scapy) │
└──────┬───────────┘
       │
       │ 4. Generate reports
       ▼
┌──────────────────┐
│   HTML + JSON    │
│   Reports        │
└──────┬───────────┘
       │
       │ 5. SSE updates
       ▼
┌──────────────────┐
│   Progress Page  │
│   (progress.js)  │
└──────────────────┘
```

## Performance

Le PCAP Analyzer utilise une **architecture hybride optimisée** qui combine:
- **dpkt** pour l'extraction rapide des métadonnées (phase 1)
- **Scapy** pour l'inspection approfondie des protocoles complexes (phase 2)

### Benchmarks

**Test:** Capture de 131,408 paquets (26 MB, 4 heures de trafic)

| Version | Temps | Analyseurs dpkt | Speedup |
|---------|-------|----------------|---------|
| **Ancienne** (Scapy seul) | 93.3 sec | 0/17 | 1.0x (baseline) |
| **Actuelle** (Hybride dpkt + Scapy) | 55.2 sec | 12/17 | **1.7x** ⚡ |

**Gain:** 38 secondes économisées (40% de réduction)

### Docker Image

**Taille:** 485 MB (multi-stage build optimisé)
- Stage 1 (builder): Compile avec gcc/g++/libpcap-dev
- Stage 2 (runtime): Copie seulement les binaires compilés

Sans multi-stage build: ~800-900 MB

## Tests

Le projet dispose d'une suite complète de tests unitaires et d'intégration.

### Exécuter tous les tests

```bash
pytest
```

### Exécuter avec couverture

```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html  # Visualiser le rapport de couverture
```

### Tests spécifiques

```bash
# Tests unitaires uniquement
pytest -m unit

# Tests d'intégration uniquement
pytest -m integration

# Tests en parallèle
pytest -n auto
```

Voir [tests/README.md](tests/README.md) pour plus de détails.

## API REST (Interface Web)

### Endpoints Disponibles

| Endpoint | Méthode | Description |
|----------|---------|-------------|
| `/` | GET | Page d'accueil (upload) |
| `/progress/{task_id}` | GET | Page de progression |
| `/api/upload` | POST | Upload fichier PCAP |
| `/api/progress/{task_id}` | GET | SSE progression temps réel |
| `/api/status/{task_id}` | GET | Statut actuel d'une tâche |
| `/api/history` | GET | Historique des analyses |
| `/reports/{task_id}.html` | GET | Rapport HTML |
| `/reports/{task_id}.json` | GET | Rapport JSON |
| `/api/health` | GET | Health check |

### Exemples d'Utilisation

```bash
# Upload un fichier PCAP
curl -X POST http://localhost:8000/api/upload \
  -F "file=@capture.pcap"
# Retourne: {"task_id": "abc123", "status": "pending"}

# Vérifier le statut
curl http://localhost:8000/api/status/abc123

# Télécharger le rapport JSON
curl http://localhost:8000/reports/abc123.json > report.json

# Voir l'historique
curl http://localhost:8000/api/history
```

## Contribution & Licence

Les contributions sont les bienvenues ! N'hésitez pas à :
*   Signaler des bugs
*   Proposer de nouvelles fonctionnalités
*   Améliorer la documentation

Licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Changelog

Voir [CHANGELOG.md](CHANGELOG.md) pour l'historique complet des versions.
