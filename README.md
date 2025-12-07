# PCAP Analyzer - Analyseur automatisé des causes de latence réseau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8-3.12](https://img.shields.io/badge/python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](.github/workflows/test.yml)
[![GitHub issues](https://img.shields.io/github/issues/MacFlurry/pcap_analyzer)](https://github.com/MacFlurry/pcap_analyzer/issues)
[![Latest Release](https://img.shields.io/github/v/release/MacFlurry/pcap_analyzer?include_prereleases)](https://github.com/MacFlurry/pcap_analyzer/releases)

**Version 3.0.0**

Outil avancé d'analyse automatisée de fichiers PCAP. Il permet d'identifier et de diagnostiquer de manière intelligente les causes de latence et de problèmes réseau, avec une interface utilisateur intuitive et des rapports HTML modernes avec support du mode sombre.

Conforme aux standards RFC 793 (TCP), RFC 2581 (Congestion Control), et RFC 6298 (RTO). Support complet IPv4 et IPv6.

## Fonctionnalités Clés

### Analyse Réseau

*   **Rapports HTML Interactifs :** Visualisation claire et pédagogique des problèmes détectés, avec des explications contextuelles et des suggestions d'investigation. Support automatique du mode sombre avec excellent contraste et lisibilité.
*   **Analyse TCP Intelligente :** Détection nuancée des retransmissions (RTO/Fast Retrans), des handshakes lents, et des problèmes de fenêtre TCP. Conforme RFC 793 et RFC 2581.
*   **Diagnostic DNS Approfondi :** Identification des timeouts, des réponses lentes et des erreurs DNS, avec détail par domaine.
*   **Détection d'Anomalies :** Analyse des gaps temporels (différenciant pauses applicatives et incidents réseau), des bursts de trafic, de la fragmentation IP et du trafic asymétrique.
*   **Support IPv6 Complet :** Analyse transparente des flux IPv4 et IPv6 à travers tous les analyseurs, avec gestion robuste des ports hexadécimaux.
*   **Capture à Distance via SSH (Optionnelle) :** Possibilité de lancer des captures `tcpdump` sur des serveurs distants et de les analyser automatiquement. Non requis pour l'analyse locale.

### Qualité et Performance

*   **Optimisation Mémoire :** Gestion intelligente de la mémoire avec cleanup périodique pour les captures de longue durée.
*   **Tests Complets :** Suite de tests unitaires et d'intégration avec couverture >80% (pytest).
*   **CI/CD :** Tests automatisés sur Ubuntu et macOS avec Python 3.8-3.12.
*   **Sécurité Renforcée :** Protection contre XSS, path traversal, et validation stricte des entrées.

## Installation

### Prérequis

*   Python 3.8, 3.9, 3.10, 3.11 ou 3.12
*   `libpcap` (installé automatiquement via les dépendances)

**Pour la capture distante uniquement (optionnel) :**
*   `tcpdump` installé sur le serveur distant
*   Accès SSH avec authentification par clé au serveur de capture
*   Configuration SSH dans `config.yaml`

### Étapes

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

## Utilisation Rapide

### Analyser un fichier PCAP

```bash
pcap_analyzer analyze ma_capture.pcap
# Génère automatiquement un rapport HTML et JSON dans le dossier reports/
```

### Lancer une capture et analyser (via SSH)

```bash
# Capture de 10 minutes sur le serveur configuré (config.yaml) et analyse auto.
pcap_analyzer capture --duration 600
```

## Nouveautés Version 3.0.0

### Changements Majeurs

*   **Support IPv6 Complet** : Tous les analyseurs gèrent maintenant IPv4 et IPv6 de manière transparente
*   **Configuration SSH Optionnelle** : SSH n'est plus requis pour l'analyse locale, seulement pour la capture distante
*   **Mode Sombre Automatique** : Les rapports HTML s'adaptent automatiquement au thème système avec un excellent contraste

### Améliorations

*   **Rapports HTML Refactorisés** :
    - CSS externe modulaire avec variables de thème
    - Support du mode sombre via `@media (prefers-color-scheme: dark)`
    - Meilleure lisibilité dans tous les thèmes
*   **Gestion Robuste des Ports** : Correction du parsing des ports hexadécimaux retournés par Scapy
*   **Affichage Optimisé** : Affichage du nom de fichier uniquement (pas le chemin complet) dans les rapports
*   **Tests Améliorés** : Compatibilité Python 3.8-3.12, tous les tests passent sur toutes les plateformes

### Corrections de Bugs

*   Fixed: KeyError dans l'analyseur de patterns temporels
*   Fixed: Parsing des ports TCP en hexadécimal
*   Fixed: Lisibilité en mode sombre (info-boxes, alertes, titres)

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

## Documentation

### Architecture

#### Structure du Projet

```
pcap_analyzer/
├── src/                         # Code source
│   ├── cli.py                   # Interface en ligne de commande (point d'entrée)
│   ├── config.py                # Gestion de la configuration
│   ├── ssh_capture.py           # Module de capture SSH/tcpdump (optionnel)
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
│   └── utils/                   # Utilitaires
│       ├── packet_utils.py      # Extraction d'infos paquets (IPv4/IPv6)
│       └── tcp_utils.py         # Utilitaires TCP (flags, longueur logique)
│
├── templates/                   # Templates Jinja2 pour rapports HTML
│   ├── report_template.html
│   └── static/css/
│       └── report.css           # Styles avec support mode sombre
│
├── tests/                       # Tests unitaires et d'intégration
├── config.yaml                  # Configuration (seuils, SSH optionnel)
└── reports/                     # Rapports générés (ignoré par git)
```

#### Flux de Données

```
┌──────────────┐
│   CAPTURE    │ Option 1: Capture distante via SSH (optionnel)
│   (SSH)      ├──────────────────────────────┐
└──────────────┘                              │
                                              │
┌──────────────┐                              │
│   PCAP FILE  │ Option 2: Fichier existant  │
│   (Local)    ├──────────────────────────────┤
└──────────────┘                              │
                                              ▼
                                    ┌──────────────────┐
                                    │  Load PCAP       │
                                    │  (Scapy)         │
                                    └────────┬─────────┘
                                             │
                    ┌────────────────────────┴────────────────────────┐
                    │                                                  │
                    ▼                                                  ▼
        ┌───────────────────────┐                         ┌───────────────────────┐
        │  17 ANALYZERS         │                         │   LATENCY FILTER      │
        │  Process packets      │◄────────────────────────┤   (-l option)         │
        │  in streaming mode    │                         └───────────────────────┘
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │  AGGREGATED RESULTS   │
        │  (Python Dict)        │
        └───────────┬───────────┘
                    │
                    ├──────────────────────┬──────────────────────┐
                    │                      │                      │
                    ▼                      ▼                      ▼
        ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
        │  Console Output  │  │   JSON Report    │  │   HTML Report    │
        │  (Rich)          │  │   (Structured)   │  │   (Visual)       │
        └──────────────────┘  └──────────────────┘  └──────────────────┘
```

### Analyseurs Disponibles

| Analyseur | Description | RFC |
|-----------|-------------|-----|
| `TCPHandshakeAnalyzer` | Détecte et mesure les délais de handshake TCP (SYN/SYN-ACK/ACK) | RFC 793 |
| `RetransmissionAnalyzer` | Détecte retransmissions (RTO, Fast Retrans), DUP ACKs, out-of-order | RFC 793, 2581, 6298 |
| `RTTAnalyzer` | Mesure Round Trip Time par flux et globalement | RFC 793, 1323 |
| `DNSAnalyzer` | Analyse requêtes/réponses DNS, détecte timeouts | - |
| `TimestampAnalyzer` | Détecte gaps temporels et pauses applicatives | - |
| `BurstAnalyzer` | Identifie les bursts de trafic | - |
| `AsymmetricAnalyzer` | Détecte trafic asymétrique entre flux | - |

### API des Analyseurs

Tous les analyseurs héritent de `BaseAnalyzer` et implémentent l'interface suivante :

```python
from src.analyzers.base_analyzer import BaseAnalyzer
from scapy.all import Packet
from typing import List, Dict, Any

class MonAnalyseur(BaseAnalyzer):
    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Traite un paquet individuel."""
        pass

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et retourne les résultats."""
        return {}

    # Méthode de commodité (héritée)
    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """Analyse une liste de paquets."""
        pass
```

### Exemples d'Utilisation Programmatique

```python
from scapy.all import rdpcap
from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer
from src.analyzers.retransmission import RetransmissionAnalyzer

# Charger une capture
packets = rdpcap("ma_capture.pcap")

# Analyser les handshakes TCP
handshake_analyzer = TCPHandshakeAnalyzer(
    syn_synack_threshold=0.1,  # 100ms
    total_threshold=0.3        # 300ms
)
handshake_results = handshake_analyzer.analyze(packets)

print(f"Handshakes détectés : {handshake_results['total_handshakes']}")
print(f"Handshakes lents : {handshake_results['slow_handshakes']}")

# Analyser les retransmissions
retrans_analyzer = RetransmissionAnalyzer()
retrans_results = retrans_analyzer.analyze(packets)

print(f"Retransmissions totales : {retrans_results['total_retransmissions']}")
print(f"RTOs : {retrans_results['rto_count']}")
print(f"Fast Retrans : {retrans_results['fast_retrans_count']}")
```

## Contribution & Licence

Les contributions sont les bienvenues ! N'hésitez pas à :
*   Signaler des bugs
*   Proposer de nouvelles fonctionnalités
*   Améliorer la documentation

Licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.