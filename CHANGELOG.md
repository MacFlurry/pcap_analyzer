# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

## [Unreleased]

## [3.0.0] - 2025-12-07

### 🚀 Changements Majeurs

- **Support IPv6 Complet** : Tous les analyseurs gèrent maintenant IPv4 et IPv6 de manière transparente
  - Détection automatique du protocole IP (IPv4/IPv6)
  - Extraction unifiée des adresses IP via `get_ip_layer()`, `get_src_ip()`, `get_dst_ip()`
  - Gestion robuste des ports hexadécimaux retournés par Scapy pour IPv6
  - Badge dynamique "IPv4 & IPv6" dans les rapports HTML

- **Configuration SSH Optionnelle** : SSH n'est plus requis pour l'analyse locale
  - SSH uniquement nécessaire pour la commande `capture` (capture distante)
  - Commande `analyze` fonctionne sans configuration SSH
  - Validation SSH conditionnelle via `validate_ssh_config()`

- **Mode Sombre Automatique** : Les rapports HTML s'adaptent au thème système
  - Détection automatique via `@media (prefers-color-scheme: dark)`
  - Excellent contraste et lisibilité dans tous les thèmes
  - Variables CSS pour cohérence visuelle

### ✨ Ajouts

- **Option `-d` / `--details`** : Affiche le détail de chaque retransmission détectée
  - Numéro du paquet retransmis et du paquet original
  - Numéro de séquence TCP
  - Délai entre l'original et la retransmission
  - Adresses IP et ports source/destination
  - Option `--details-limit N` pour contrôler le nombre affiché (défaut: 20)

- **Note Wireshark** : Clarification dans l'affichage que notre comptage de retransmissions (ex: 11) diffère de Wireshark qui affiche le double (ex: 22 paquets) car il inclut originaux + retransmissions

- **Analyseur de retransmissions SYN** : Nouvelle dimension d'analyse pour détecter les problèmes de handshake TCP
  - Détecte automatiquement les retransmissions SYN multiples (client qui retente la connexion)
  - Analyse la timeline complète : 1er SYN, retransmissions, et réception du SYN/ACK
  - Diagnostic précis du problème :
    - `server_delayed_response` : le serveur répond tardivement au premier SYN
    - `packet_loss` : perte de paquets SYN dans le réseau
    - `no_response` : le serveur ne répond jamais
  - Corrélation avec les TCP timestamps pour identifier quel SYN a été traité
  - Calcul de statistiques (min, max, moyenne des délais)
  - Section dédiée dans le rapport HTML avec timeline détaillée
  - Configuration via `syn_retrans_threshold` dans config.yaml (défaut: 2.0 secondes)

**Exemple d'utilisation :**
```bash
pcap_analyzer analyze capture.pcap -d                    # Détails (20 max)
pcap_analyzer analyze capture.pcap -d --details-limit 50 # Détails (50 max)
```

### 🎨 Améliorations

- **Rapports HTML Refactorisés** :
  - CSS externe modulaire avec variables de thème (`templates/static/css/report.css`)
  - Support du mode sombre via `@media (prefers-color-scheme: dark)`
  - Meilleure lisibilité des info-boxes, alertes, et titres dans tous les thèmes
  - CSS embarqué dans les rapports pour portabilité

- **Gestion Robuste des Ports** : Correction du parsing des ports hexadécimaux retournés par Scapy
  - Détection automatique du format (entier ou hexadécimal)
  - Normalisation dans tous les analyseurs de flux TCP
  - Évite les `ValueError: invalid literal for int() with base 10`

- **Affichage Optimisé** : Affichage du nom de fichier uniquement (pas le chemin complet) dans les rapports
  - Plus lisible et portable
  - Utilisation de `Path(pcap_file).name` dans `report_generator.py`

- **Tests Améliorés** : Compatibilité Python 3.9-3.12, tous les tests passent sur toutes les plateformes
  - 46/46 tests passing sur Ubuntu et macOS
  - Support de Python 3.9, 3.10, 3.11, 3.12
  - CI/CD avec GitHub Actions
  - Retrait du support Python 3.8 (EOL octobre 2024)

### 🔧 Corrections de Bugs

- **Fixed: KeyError dans l'analyseur de patterns temporels**
  - Utilisation de `defaultdict(list, ...)` dans `_cleanup_excess_sources()`
  - Évite les crashes lors du nettoyage mémoire

- **Fixed: Parsing des ports TCP en hexadécimal**
  - Ajout de logique de normalisation dans 5 analyseurs
  - Gestion des ports retournés comme chaînes hex ('e0a') par Scapy

- **Fixed: Lisibilité en mode sombre**
  - Info-boxes : fond bleu foncé (#1a3a52) avec texte clair
  - Alertes success : fond vert foncé avec contraste amélioré
  - Titres h4 : couleur bleue claire (#90caf9, #81c784)

- **Fixed: Retours de type booléen**
  - `is_syn()`, `is_synack()`, `has_ip_layer()` retournent maintenant `bool` au lieu de `Flag`
  - Wrapper `bool()` pour compatibilité avec les assertions de test

- **Fixed: Type hints pour meilleure compatibilité**
  - Utilisation de `Tuple` au lieu de `tuple` (from typing)
  - Correction dans `icmp_pmtu.py` et `ssh_capture.py`

### 📝 Documentation

- Consolidation de la documentation dans README.md
  - Architecture complète avec structure du projet et flux de données
  - Fusion de STRUCTURE.md dans README.md
  - Suppression de fichiers redondants (QUICKSTART.md, TEST.md, TROUBLESHOOTING.md)
- Mise à jour pour refléter les 17 analyseurs
- Documentation du support IPv6 complet
- Exemples d'utilisation programmatique mis à jour

### 🗑️ Suppressions

- Suppression de fichiers de documentation redondants :
  - QUICKSTART.md (contenu intégré dans README.md)
  - TEST.md (informations de test dans README.md et tests/README.md)
  - TROUBLESHOOTING.md (obsolète, focalisé sur SSH)
  - STRUCTURE.md (fusionné dans README.md Architecture)

## [1.0.3] - 2025-12-04

### ✨ Amélioration

- **Détection de fenêtres TCP améliorée** : Réduction drastique des faux positifs
  - Ignore maintenant les 10 premiers paquets (handshake + slow start) pour le calcul de `min_window`
  - Ignore les flux très courts (< 20 paquets) car pas assez de données pour être pertinent
  - Ajout de détection de persistance : un problème n'est signalé que si fenêtre basse > 20% du temps
  - Distinction entre fenêtre initiale basse (normal) et fenêtre persistante basse (problème)

**Avant :** Tous les flux avec fenêtre initiale < 8192 bytes étaient signalés comme problématiques

**Maintenant :** Seuls les flux longs avec fenêtres basses **persistantes** (> 20% du temps hors handshake) sont signalés

### 📝 Documentation

- Ajout d'instructions pour installation avec environnement virtuel (venv)
  - README.md : Guide complet venv (Linux/macOS/Windows)
  - QUICKSTART.md : Instructions venv intégrées
  - Option d'installation sans venv également documentée

## [1.0.2] - 2025-01-04

### ✨ Amélioration

- **Option `-l` améliorée** : Filtre maintenant **toutes** les métriques de latence, pas seulement les gaps temporels
  - TCPHandshakeAnalyzer : Filtre handshakes >= seuil
  - RTTAnalyzer : Filtre mesures RTT >= seuil
  - DNSAnalyzer : Filtre réponses DNS >= seuil
  - Timeouts DNS toujours inclus (considérés comme latence infinie)

**Avant :** `-l 2` = détectait uniquement les gaps temporels >= 2s

**Maintenant :** `-l 2` = filtre TOUTES les latences (gaps, handshakes, RTT, DNS) >= 2s

### 📝 Documentation

- Clarification de l'option `-l` dans README.md et QUICKSTART.md
- Ajout d'exemples explicites sur ce qui est filtré

## [1.0.1] - 2025-01-04

### 🔧 Corrections

- **Fix SSH key path expansion** : Le tilde `~` dans les chemins de clés SSH (`~/.ssh/id_rsa`) est maintenant correctement expansé
  - Correction dans `src/ssh_capture.py` : Utilisation de `os.path.expanduser()`
  - Résout l'erreur "No authentication methods available"

### ✨ Ajouts

- **Script de test SSH** : Nouveau script `test_ssh.py` pour vérifier la connexion SSH avant capture
  - Vérifie la configuration
  - Teste la connexion et sudo
  - Valide la disponibilité de tcpdump

- **Documentation** :
  - `TROUBLESHOOTING.md` : Guide complet de dépannage
  - `LICENSE` : Licence MIT
  - `config.yaml.example` : Fichier de configuration exemple
  - Badges GitHub dans README.md

### 🔒 Sécurité

- Nettoyage des informations sensibles dans les fichiers de configuration
- Toutes les IPs privées et noms d'utilisateur remplacés par des exemples génériques

### 📝 Documentation

- Mise à jour de tous les guides avec des exemples génériques
- Ajout du lien GitHub dans tous les fichiers de documentation
- Correction des chemins pour compatibilité multi-plateforme

## [1.0.0] - 2025-01-03

### ✨ Version initiale

#### Fonctionnalités principales

- **7 analyseurs de latence réseau** :
  1. Analyse des timestamps et gaps temporels
  2. Analyse du handshake TCP (SYN/SYN-ACK/ACK)
  3. Détection des retransmissions et anomalies TCP
  4. Calcul et suivi du RTT (Round Trip Time)
  5. Analyse des fenêtres TCP et saturation applicative
  6. Détection des problèmes ICMP et PMTU
  7. Analyse des résolutions DNS

- **Capture SSH automatisée** :
  - Connexion SSH avec clé ou mot de passe
  - Exécution de tcpdump sur serveur distant
  - Téléchargement automatique du PCAP
  - Nettoyage des fichiers distants

- **Génération de rapports** :
  - Rapport JSON avec données structurées
  - Rapport HTML professionnel avec code couleur
  - Visualisation des problèmes par sévérité

- **Interface CLI** :
  - Commande `analyze` pour analyser un PCAP
  - Commande `capture` pour capturer depuis SSH
  - Commande `show-config` pour afficher la configuration
  - Option `-l` pour filtrer par latence minimale
  - Configuration via fichier YAML

- **Documentation complète** :
  - README.md détaillé
  - QUICKSTART.md pour démarrage rapide
  - TEST.md pour validation
  - STRUCTURE.md pour architecture

#### Technologies

- Python 3.9+
- Scapy pour analyse de paquets
- Paramiko pour SSH/SFTP
- Rich pour interface console
- Click pour CLI
- Jinja2 pour génération HTML

---

## Légende

- ✨ Nouvelles fonctionnalités
- 🔧 Corrections de bugs
- 📝 Documentation
- 🔒 Sécurité
- ⚡ Performance
- 🎨 Style/UI
- 🗑️ Suppressions

[1.0.1]: https://github.com/MacFlurry/pcap_analyzer/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/MacFlurry/pcap_analyzer/releases/tag/v1.0.0
