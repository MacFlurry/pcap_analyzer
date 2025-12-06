# PCAP Analyzer - Analyseur automatisé des causes de latence réseau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8-3.12](https://img.shields.io/badge/python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](.github/workflows/test.yml)
[![GitHub issues](https://img.shields.io/github/issues/MacFlurry/pcap_analyzer)](https://github.com/MacFlurry/pcap_analyzer/issues)
[![Latest Release](https://img.shields.io/github/v/release/MacFlurry/pcap_analyzer?include_prereleases)](https://github.com/MacFlurry/pcap_analyzer/releases)

**Version 2.0.0**

Outil avancé d'analyse automatisée de fichiers PCAP. Il permet d'identifier et de diagnostiquer de manière intelligente les causes de latence et de problèmes réseau, avec une interface utilisateur intuitive.

Conforme aux standards RFC 793 (TCP), RFC 2581 (Congestion Control), et RFC 6298 (RTO). Supporte IPv4 et IPv6.

## Fonctionnalités Clés

### Analyse Réseau

*   **Rapports HTML Interactifs :** Visualisation claire et pédagogique des problèmes détectés, avec des explications contextuelles et des suggestions d'investigation.
*   **Analyse TCP Intelligente :** Détection nuancée des retransmissions (RTO/Fast Retrans), des handshakes lents, et des problèmes de fenêtre TCP. Conforme RFC 793 et RFC 2581.
*   **Diagnostic DNS Approfondi :** Identification des timeouts, des réponses lentes et des erreurs DNS, avec détail par domaine.
*   **Détection d'Anomalies :** Analyse des gaps temporels (différenciant pauses applicatives et incidents réseau), des bursts de trafic, de la fragmentation IP et du trafic asymétrique.
*   **Support IPv6 :** Analyse transparente des flux IPv4 et IPv6 à travers tous les analyseurs.
*   **Capture à Distance via SSH :** Possibilité de lancer des captures `tcpdump` sur des serveurs distants et de les analyser automatiquement.

### Qualité et Performance

*   **Optimisation Mémoire :** Gestion intelligente de la mémoire avec cleanup périodique pour les captures de longue durée.
*   **Tests Complets :** Suite de tests unitaires et d'intégration avec couverture >80% (pytest).
*   **CI/CD :** Tests automatisés sur Ubuntu et macOS avec Python 3.8-3.12.
*   **Sécurité Renforcée :** Protection contre XSS, path traversal, et validation stricte des entrées.

## Installation

### Prérequis

*   Python 3.8, 3.9, 3.10, 3.11 ou 3.12
*   `libpcap` (installé automatiquement via les dépendances)
*   `tcpdump` installé sur le serveur distant (pour la capture SSH)
*   Accès SSH avec authentification par clé au serveur de capture

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

Le fichier `config.yaml` à la racine du projet permet de personnaliser les seuils de détection et les paramètres SSH.

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

Le projet est organisé en modules spécialisés :

*   `src/analyzers/` : Analyseurs TCP, DNS, etc. (tous héritent de `BaseAnalyzer`)
*   `src/utils/` : Utilitaires pour manipulation de paquets (support IPv4/IPv6)
*   `src/report_generator.py` : Génération de rapports HTML sécurisés
*   `src/cli.py` : Interface en ligne de commande
*   `templates/` : Templates Jinja2 pour les rapports HTML

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