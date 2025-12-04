# PCAP Analyzer - Analyseur automatisé des causes de latence réseau

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues/MacFlurry/pcap_analyzer)](https://github.com/MacFlurry/pcap_analyzer/issues)

Outil d'analyse automatisée de fichiers PCAP pour identifier et diagnostiquer les causes de latence réseau. Conçu pour les administrateurs réseau, ingénieurs DevOps et équipes d'infrastructure.

## Fonctionnalités

L'analyseur détecte et analyse automatiquement **8 dimensions clés** impactant la latence réseau :

### 1. ⏱️ Gestion et analyse des horodatages
- Détection automatique des ruptures de flux
- Identification des délais anormaux entre paquets
- Signalement des segments avec latence visible
- Calcul de statistiques temporelles (min, max, moyenne, médiane)

### 2. 🤝 Analyse du handshake TCP
- Mesure des délais SYN → SYN/ACK → ACK
- Identification du côté suspect (client, réseau, serveur)
- Détection des handshakes lents
- Analyse complète et incomplète des connexions

### 2bis. 🔄 Détection des retransmissions SYN
- Détection automatique des retransmissions SYN multiples
- Analyse de la timeline complète (1er SYN, retransmissions, SYN/ACK)
- Identification précise du problème (serveur lent, perte réseau, timeout)
- Calcul du délai total de handshake incluant les retransmissions
- Corrélation avec les timestamps TCP pour diagnostic avancé

### 3. 🔄 Détection des retransmissions et anomalies TCP
- Comptage des retransmissions par flux
- Détection des DUP ACK
- Identification des paquets Out-of-Order
- Classification par sévérité (faible/moyen/critique)
- Corrélation avec timestamps

### 4. ⏲️ Calcul et suivi du RTT
- Mesure du Round Trip Time par flux TCP
- Calcul RTT moyen, minimum, maximum
- Détection de pics anormaux
- Série temporelle pour visualisation

### 5. 🪟 Analyse des fenêtres TCP et saturation applicative
- Détection Zero Window
- Identification de fenêtres basses persistantes
- Corrélation avec RTT et retransmissions
- Graphique d'évolution de la fenêtre par flux

### 6. 📡 Détection des problèmes PMTU et ICMP
- Analyse des erreurs ICMP "Fragmentation needed"
- Détection "Destination unreachable"
- Suggestions techniques (ajustement MTU)
- Classification des types ICMP

### 7. 🌐 Analyse des résolutions DNS
- Mesure du temps de réponse DNS
- Détection de timeouts
- Identification des requêtes répétées
- Liste des domaines problématiques

## Installation

### Prérequis

- Python 3.8 ou supérieur
- tcpdump installé sur le serveur distant (pour la capture SSH)
- Accès SSH au serveur de capture

### Installation depuis les sources

```bash
# Cloner le repository
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate  # Sur Linux/macOS
# ou
venv\Scripts\activate     # Sur Windows

# Installer les dépendances
pip install --upgrade pip
pip install -r requirements.txt

# Installer le package en mode développement
pip install -e .
```

### Installation rapide (sans venv)

```bash
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer
pip install -e .
```

## Configuration

Le fichier `config.yaml` à la racine du projet contient tous les paramètres configurables :

```yaml
# Seuils de détection
thresholds:
  # Timestamps
  packet_gap: 1.0              # Délai anormal entre paquets (secondes)
  
  # Handshake TCP
  syn_synack_delay: 0.1        # Délai SYN→SYN/ACK (secondes)
  handshake_total: 0.3         # Handshake complet (secondes)
  
  # Retransmissions SYN
  syn_retrans_threshold: 2.0   # Seuil retransmissions SYN (secondes)
  
  # RTT (Round Trip Time)
  rtt_warning: 0.1             # RTT avertissement (secondes)
  rtt_critical: 0.5            # RTT critique (secondes)
  
  # Retransmissions TCP - Logique hybride (seuils absolus + taux)
  # La sévérité est déterminée par DEUX critères combinés :
  # 1. Seuil absolu minimum requis (évite faux positifs sur petits flux)
  # 2. Taux de perte en % (critère principal de sévérité)
  #
  # Exemples :
  # - 100 paquets, 5 retrans (5%) → Aucune alerte (< 10 seuil minimum)
  # - 100 paquets, 15 retrans (15%) → CRITICAL (≥10 seuil ET ≥5% taux)
  # - 10000 paquets, 15 retrans (0.15%) → LOW (≥10 seuil ET ≥0.1% taux)
  # - 10000 paquets, 500 retrans (5%) → CRITICAL (≥10 seuil ET 5% taux)
  # - Tout flux avec ≥100 retrans → CRITICAL (garde-fou volume important)
  
  retransmission_low: 10       # Seuil minimum absolu pour déclencher analyse
  retransmission_medium: 50    # Seuil moyen (garde-fou)
  retransmission_critical: 100 # Seuil critique absolu (force alerte même si taux bas)
  
  retransmission_rate_low: 1.0       # 1% de taux de perte → LOW
  retransmission_rate_medium: 3.0    # 3% de taux de perte → MEDIUM
  retransmission_rate_critical: 5.0  # 5% de taux de perte → CRITICAL
  
  # TCP Window
  low_window_threshold: 8192   # Fenêtre TCP basse (bytes)
  zero_window_duration: 0.1    # Durée Zero Window (secondes)
  
  # DNS
  dns_response_warning: 0.1    # Réponse DNS avertissement (secondes)
  dns_response_critical: 1.0   # Réponse DNS critique (secondes)
  dns_timeout: 5.0             # Timeout DNS (secondes)

# Configuration SSH pour capture distante
ssh:
  host: "192.168.25.15"
  port: 22
  username: "root"
  key_file: "/path/to/ssh/key"  # Optionnel

  tcpdump:
    interface: "any"
    filter: "host 192.168.25.67"
    snaplen: 65535
```

### Personnalisation

Créez votre propre fichier de configuration et utilisez l'option `-c` :

```bash
pcap_analyzer analyze capture.pcap -c my_config.yaml
```

## Utilisation

### 1. Analyse d'un fichier PCAP existant

#### Analyse complète

```bash
pcap_analyzer analyze capture.pcap
```

#### Analyse avec filtrage par latence

Filtre toutes les métriques de latence pour ne garder que celles >= 2 secondes :

```bash
pcap_analyzer analyze capture.pcap -l 2.0
```

**Ce qui est filtré avec `-l 2.0` :**
- ✅ Gaps temporels >= 2 secondes
- ✅ Handshakes TCP >= 2 secondes
- ✅ Mesures RTT >= 2 secondes
- ✅ Réponses DNS >= 2 secondes
- ✅ Timeouts DNS (toujours inclus)

**Exemple :** Avec `-l 2`, vous ne verrez que les problèmes de latence vraiment significatifs (>= 2s), ce qui permet de se concentrer sur les problèmes majeurs.

#### Afficher les détails des retransmissions

L'option `-d` (ou `--details`) affiche le détail de chaque retransmission détectée :

```bash
# Afficher les détails des retransmissions (20 premières par défaut)
pcap_analyzer analyze capture.pcap -d

# Afficher jusqu'à 50 retransmissions
pcap_analyzer analyze capture.pcap -d --details-limit 50

# Combiner avec filtrage de latence et sans rapport
pcap_analyzer analyze capture.pcap -l 2.0 -d --no-report
```

**Sortie exemple :**
```
🔍 Détails des retransmissions (11/11):
   (Wireshark: filtre 'tcp.analysis.retransmission' affiche 22 paquets)

  #1: Paquet 467 (retrans de #466)
      Seq: 1065153881, Délai: 205.0ms
      10.28.104.211:16586 → 10.179.161.14:10100
```

> **Note Wireshark :** L'analyseur compte les **segments retransmis** (ex: 11), tandis que Wireshark avec le filtre `tcp.analysis.retransmission` affiche le double (ex: 22 paquets) car il inclut à la fois les paquets originaux et leurs retransmissions.

#### Options disponibles

```bash
pcap_analyzer analyze [OPTIONS] PCAP_FILE

Options:
  -l, --latency FLOAT        Seuil de latence en secondes pour le filtrage
  -c, --config PATH          Fichier de configuration personnalisé
  -o, --output TEXT          Nom de base pour les rapports de sortie
  --no-report                Ne pas générer de rapports HTML/JSON
  -d, --details              Afficher les détails des retransmissions
  --details-limit INTEGER    Nombre max de retransmissions à afficher (défaut: 20)
  --help                     Afficher l'aide
```

### 2. Capture depuis un serveur distant via SSH

#### Capture de 60 secondes (défaut)

```bash
pcap_analyzer capture
```

#### Capture personnalisée

```bash
# Capture de 120 secondes
pcap_analyzer capture -d 120

# Avec filtre BPF personnalisé
pcap_analyzer capture -d 60 -f "host 192.168.1.100"

# Sans analyse automatique
pcap_analyzer capture -d 60 --no-analyze

# Avec analyse filtrée par latence
pcap_analyzer capture -d 60 -l 2.0
```

#### Options disponibles

```bash
pcap_analyzer capture [OPTIONS]

Options:
  -d, --duration INTEGER     Durée de capture en secondes (défaut: 60)
  -f, --filter TEXT          Filtre BPF personnalisé
  -o, --output TEXT          Nom du fichier PCAP local de sortie
  -c, --config PATH          Fichier de configuration personnalisé
  --analyze/--no-analyze     Analyser automatiquement après capture
  -l, --latency FLOAT        Seuil de latence pour l'analyse
  --help                     Afficher l'aide
```

### 3. Afficher la configuration

```bash
pcap_analyzer show-config
```

## Flux de travail complet

### Scénario 1 : Capture et analyse depuis un serveur distant

```bash
# 1. Lancer une capture de 120 secondes sur le serveur 192.168.25.15
#    filtrant le trafic de 192.168.25.67
pcap_analyzer capture -d 120

# Le système va :
# - Se connecter en SSH au serveur
# - Lancer tcpdump avec les paramètres configurés
# - Télécharger le PCAP en local
# - Lancer automatiquement l'analyse
# - Générer les rapports JSON et HTML
```

### Scénario 2 : Analyse d'un PCAP existant avec filtrage

```bash
# Analyser uniquement les paquets avec latence >= 2 secondes
pcap_analyzer analyze capture.pcap -l 2.0

# Résultat : rapports dans le dossier "reports/"
# - pcap_analysis_YYYYMMDD_HHMMSS.json
# - pcap_analysis_YYYYMMDD_HHMMSS.html
```

### Scénario 3 : Workflow personnalisé

```bash
# 1. Capturer sans analyser
pcap_analyzer capture -d 60 --no-analyze -o my_capture.pcap

# 2. Analyser plus tard avec configuration spécifique
pcap_analyzer analyze my_capture.pcap -c custom_config.yaml -l 1.5
```

## Rapports générés

### Rapport JSON

Contient toutes les données brutes de l'analyse :
- Résultats détaillés de chaque analyseur
- Timestamps de tous les événements
- Statistiques complètes par flux
- Données exploitables pour post-traitement

### Rapport HTML

Rapport visuel et interactif incluant :
- Vue d'ensemble avec indicateurs clés
- Tableaux détaillés par dimension d'analyse
- Code couleur pour identifier rapidement les problèmes
- Suggestions techniques pour résoudre les problèmes détectés
- Design responsive pour consultation sur mobile

## Architecture

```
pcap_analyzer/
├── src/
│   ├── analyzers/              # Modules d'analyse
│   │   ├── timestamp_analyzer.py
│   │   ├── tcp_handshake.py
│   │   ├── retransmission.py
│   │   ├── rtt_analyzer.py
│   │   ├── tcp_window.py
│   │   ├── icmp_pmtu.py
│   │   └── dns_analyzer.py
│   ├── cli.py                  # Interface CLI
│   ├── ssh_capture.py          # Capture SSH
│   ├── report_generator.py     # Générateur de rapports
│   └── config.py               # Gestion configuration
├── config.yaml                 # Configuration
├── requirements.txt
├── setup.py
└── README.md
```

## Exemples de sortie

### Console

```
📊 Résultats de l'analyse

⏱️ Analyse des timestamps:
  - Total: 15234 paquets
  - Durée: 120.5 secondes
  - 3 gap(s) temporel(s) détecté(s)

🔴 3 gap(s) temporel(s) anormal(aux) détecté(s):

  Gap #1:
    - Entre paquets 1456 et 1457
    - Durée: 2.345s
    - Direction: 192.168.25.67 → 10.0.0.1
    - Protocole: TCP

📊 Analyse des handshakes TCP:
  - Total: 45
  - Complets: 42
  - Incomplets: 3

🔴 5 handshake(s) lent(s) détecté(s):

  192.168.25.67:54321 → 10.0.0.1:443
    - Durée totale: 0.456s
    - SYN→SYN/ACK: 0.423s
    - SYN/ACK→ACK: 0.033s
    - Côté suspect: server
```

### Rapport HTML

Le rapport HTML offre une visualisation complète avec :
- Cartes résumés colorées
- Tableaux triables
- Badges de sévérité
- Suggestions d'amélioration
- Design professionnel

## Cas d'usage

### Diagnostic de latence applicative

```bash
# Capturer pendant un incident de performance
pcap_analyzer capture -d 300 -f "host app.server.com"

# Identifier rapidement :
# - Les problèmes de handshake TCP
# - Les retransmissions excessives
# - Les problèmes de fenêtre TCP (application lente)
# - Les timeouts DNS
```

### Analyse de problème réseau

```bash
# Analyser une capture existante avec filtrage agressif
pcap_analyzer analyze incident.pcap -l 0.5

# Obtenir uniquement les paquets avec latence > 500ms
# Identifier la root cause : réseau, serveur, client, DNS, PMTU
```

### Monitoring continu

```bash
#!/bin/bash
# Script de monitoring périodique

while true; do
    pcap_analyzer capture -d 300 -o "monitor_$(date +%s).pcap"
    sleep 300
done

# Génère des rapports toutes les 5 minutes
# Permet de suivre l'évolution des performances
```

## Troubleshooting

### Problème de connexion SSH

```
Erreur: Échec d'authentification SSH
```

**Solution :**
- Vérifiez les paramètres SSH dans `config.yaml`
- Assurez-vous que votre clé SSH est correctement configurée
- Testez la connexion manuellement : `ssh user@host`

### Fichier PCAP trop volumineux

```
Erreur: Memory Error lors du chargement
```

**Solution :**
- Utilisez un filtre BPF plus restrictif lors de la capture
- Réduisez la durée de capture
- Utilisez l'option `-l` pour filtrer par latence

### Permissions tcpdump

```
Erreur: tcpdump: permission denied
```

**Solution :**
- Assurez-vous que l'utilisateur SSH a les droits sudo
- Configurez sudoers pour permettre tcpdump sans mot de passe :
  ```
  user ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
  ```

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Signaler des bugs
- Proposer de nouvelles fonctionnalités
- Améliorer la documentation

## Licence

MIT License - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Support

Pour toute question ou problème :
- Consultez le [Guide de dépannage](TROUBLESHOOTING.md)
- Ouvrez une [issue sur GitHub](https://github.com/MacFlurry/pcap_analyzer/issues)

---

**Développé pour les équipes réseau et infrastructure** 🚀
