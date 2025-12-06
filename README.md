# PCAP Analyzer - Analyseur automatisé des causes de latence réseau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues/MacFlurry/pcap_analyzer)](https://github.com/MacFlurry/pcap_analyzer/issues)
[![Latest Release](https://img.shields.io/github/v/release/MacFlurry/pcap_analyzer?include_prereleases)](https://github.com/MacFlurry/pcap_analyzer/releases)

**Version 2.0.0**

Outil avancé d'analyse automatisée de fichiers PCAP. Il permet d'identifier et de diagnostiquer de manière intelligente les causes de latence et de problèmes réseau, avec une interface utilisateur intuitive.

## Fonctionnalités Clés

*   **Rapports HTML Interactifs :** Visualisation claire et pédagogique des problèmes détectés, avec des explications contextuelles et des suggestions d'investigation.
*   **Analyse TCP Intelligente :** Détection nuancée des retransmissions (RTO/Fast Retrans), des handshakes lents, et des problèmes de fenêtre TCP.
*   **Diagnostic DNS Approfondi :** Identification des timeouts, des réponses lentes et des erreurs DNS, avec détail par domaine.
*   **Détection d'Anomalies :** Analyse des gaps temporels (différenciant pauses applicatives et incidents réseau), des bursts de trafic, de la fragmentation IP et du trafic asymétrique.
*   **Capture à Distance via SSH :** Possibilité de lancer des captures `tcpdump` sur des serveurs distants et de les analyser automatiquement.

## Installation

### Prérequis

*   Python 3.8 ou supérieur.
*   `tcpdump` installé sur le serveur distant (pour la capture SSH).
*   Accès SSH avec authentification par clé au serveur de capture.

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

## Contribution & Licence

Les contributions sont les bienvenues ! N'hésitez pas à :
*   Signaler des bugs
*   Proposer de nouvelles fonctionnalités
*   Améliorer la documentation

Licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.