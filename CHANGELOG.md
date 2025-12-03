# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/lang/fr/).

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

- Python 3.8+
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
