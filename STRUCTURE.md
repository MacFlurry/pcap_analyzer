# Structure du projet PCAP Analyzer

```
pcap_analyzer/
│
├── 📄 README.md                 # Documentation complète
├── 📄 QUICKSTART.md             # Guide de démarrage rapide
├── 📄 TEST.md                   # Guide de tests et validation
├── 📄 STRUCTURE.md              # Ce fichier - vue d'ensemble
│
├── ⚙️ config.yaml               # Configuration (seuils, SSH, rapports)
├── 📦 requirements.txt          # Dépendances Python
├── 📦 setup.py                  # Configuration d'installation
├── 🔧 install.sh                # Script d'installation
├── 📝 .gitignore                # Fichiers à ignorer par git
│
└── src/                         # Code source
    │
    ├── 📄 __init__.py
    ├── 🎯 cli.py                # Interface en ligne de commande (point d'entrée)
    ├── ⚙️ config.py             # Gestion de la configuration
    ├── 🌐 ssh_capture.py        # Module de capture SSH/tcpdump
    ├── 📊 report_generator.py   # Générateur de rapports JSON/HTML
    │
    └── analyzers/               # Modules d'analyse (8 dimensions)
        │
        ├── 📄 __init__.py
        │
        ├── ⏱️ timestamp_analyzer.py     # 1. Analyse des timestamps et gaps
        ├── 🤝 tcp_handshake.py          # 2. Analyse handshake TCP
        ├── 🔄 syn_retransmission.py     # 2bis. Retransmissions SYN détaillées
        ├── 🔄 retransmission.py         # 3. Retransmissions et anomalies
        ├── ⏲️ rtt_analyzer.py           # 4. Round Trip Time
        ├── 🪟 tcp_window.py             # 5. Fenêtres TCP et saturation
        ├── 📡 icmp_pmtu.py              # 6. ICMP et PMTU
        └── 🌐 dns_analyzer.py           # 7. Résolutions DNS
```

## Flux de données

```
┌─────────────────────────────────────────────────────────────────┐
│                     PCAP ANALYZER WORKFLOW                       │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐
│   CAPTURE    │ Option 1: Capture distante via SSH
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
        │  ANALYZERS (8 modules)│                         │   LATENCY FILTER      │
        │  - Timestamps         │◄────────────────────────┤   (-l option)         │
        │  - TCP Handshake      │                         └───────────────────────┘
        │  - SYN Retransmissions│
        │  - Retransmissions    │
        │  - RTT                │
        │  - TCP Window         │
        │  - ICMP/PMTU          │
        │  - DNS                │
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

## Modules détaillés

### 1. CLI (`cli.py`)

**Point d'entrée principal de l'application**

Commandes disponibles :
- `analyze` : Analyse un fichier PCAP
- `capture` : Capture via SSH puis analyse
- `show-config` : Affiche la configuration

Options importantes :
- `-l, --latency` : Filtre par latence minimale
- `-c, --config` : Fichier de configuration personnalisé
- `-o, --output` : Nom des rapports de sortie

### 2. SSH Capture (`ssh_capture.py`)

**Gestion de la capture distante**

Fonctionnalités :
- Connexion SSH (clé ou mot de passe)
- Exécution de tcpdump distant
- Téléchargement du PCAP via SFTP
- Nettoyage automatique du fichier distant

### 3. Analyzers

#### 3.1 Timestamp Analyzer
- Détecte les gaps temporels entre paquets
- Calcule statistiques d'intervalles
- Identifie les ruptures de flux

#### 3.2 TCP Handshake Analyzer
- Suit les phases SYN → SYN/ACK → ACK
- Mesure les délais de chaque étape
- Identifie le côté suspect (client/réseau/serveur)

#### 3.2bis SYN Retransmission Analyzer (Nouveau)
- Détecte les retransmissions SYN multiples
- Analyse la timeline complète de tentatives de connexion
- Identifie le problème exact :
  - `server_delayed_response` : serveur répond tardivement au 1er SYN
  - `packet_loss` : perte de paquets SYN dans le réseau
  - `no_response` : serveur ne répond jamais
- Corrèle avec les TCP timestamps pour diagnostic précis
- Calcule statistiques (min, max, moyenne des délais)

#### 3.3 Retransmission Analyzer
- Détecte retransmissions TCP
- Compte DUP ACK
- Identifie paquets Out-of-Order
- Détecte Zero Window
- Classe par sévérité

#### 3.4 RTT Analyzer
- Associe segments aux ACK
- Calcule RTT par flux
- Détecte pics anormaux
- Génère série temporelle

#### 3.5 TCP Window Analyzer
- Surveille taille fenêtre TCP
- Détecte Zero Window
- Identifie fenêtres basses
- Détermine goulot d'étranglement

#### 3.6 ICMP Analyzer
- Parse messages ICMP
- Détecte "Fragmentation Needed" (PMTU)
- Identifie "Destination Unreachable"
- Suggère corrections (MTU)

#### 3.7 DNS Analyzer
- Mesure temps de réponse DNS
- Détecte timeouts
- Identifie requêtes répétées
- Liste domaines problématiques

### 4. Report Generator (`report_generator.py`)

**Génération de rapports**

Formats :
- **JSON** : Données structurées pour traitement automatique
- **HTML** : Rapport visuel avec code couleur

Template HTML inclut :
- Vue d'ensemble (cartes métriques)
- Tableaux détaillés par dimension
- Badges de sévérité
- Suggestions techniques

### 5. Config Manager (`config.py`)

**Gestion de la configuration**

Structure :
```python
config.thresholds        # Seuils de détection
config.ssh_config        # Paramètres SSH
config.report_config     # Options de rapport
```

## Points d'extension

### Ajouter un nouvel analyseur

1. Créer `src/analyzers/mon_analyzer.py`
2. Implémenter la classe avec méthode `analyze(packets)`
3. Ajouter dans `src/analyzers/__init__.py`
4. Intégrer dans `cli.py` (fonction `analyze_pcap`)
5. Ajouter section dans le template HTML

### Personnaliser les rapports

Éditer `report_generator.py` :
- Modifier `HTML_TEMPLATE` pour le style
- Ajouter nouvelles sections
- Personnaliser les graphiques

### Ajouter des seuils

1. Ajouter dans `config.yaml` section `thresholds`
2. Utiliser dans l'analyseur via `config.get('thresholds.mon_seuil')`

## Dépendances principales

- **scapy** : Parse et analyse des paquets réseau
- **paramiko** : Connexions SSH et SFTP
- **rich** : Interface console colorée et barres de progression
- **click** : Framework CLI
- **jinja2** : Génération de templates HTML
- **pyyaml** : Lecture de la configuration

## Fichiers de sortie

```
pcap_analyzer/
└── reports/                              # Créé automatiquement
    ├── pcap_analysis_20250103_143022.json
    ├── pcap_analysis_20250103_143022.html
    ├── pcap_analysis_20250103_145533.json
    └── pcap_analysis_20250103_145533.html
```

## Variables d'environnement (optionnel)

Vous pouvez définir :
```bash
export PCAP_ANALYZER_CONFIG=/path/to/custom_config.yaml
export PCAP_ANALYZER_REPORTS_DIR=/path/to/reports
```

## Logs

Actuellement, logs affichés sur console via Rich.

Pour enregistrer dans un fichier :
```bash
pcap_analyzer analyze capture.pcap 2>&1 | tee analysis.log
```

## Performance

- **Mémoire** : ~100MB + taille du PCAP
- **CPU** : Mono-thread (analyse séquentielle)
- **Vitesse** : ~5000-10000 paquets/seconde

Optimisations possibles :
- Analyse en streaming (pas tout en mémoire)
- Parallélisation des analyseurs
- Cache des résultats intermédiaires

---

Cette structure modulaire permet une maintenance facile et l'ajout de nouvelles fonctionnalités sans impacter le code existant.
