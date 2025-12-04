# Guide de démarrage rapide

## Installation en 3 étapes

### 1. Installer l'application

```bash
# Cloner et accéder au répertoire
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Créer un environnement virtuel (recommandé)
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances et le package
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### 2. Configurer l'accès SSH

Éditez le fichier `config.yaml` :

```yaml
ssh:
  host: "192.168.1.100"         # ← Votre serveur
  username: "your_username"     # ← Votre utilisateur
  key_file: "~/.ssh/id_rsa"     # ← Chemin vers votre clé SSH

  tcpdump:
    interface: "any"
    filter: "host 192.168.1.50"  # ← IP à surveiller
```

### 3. Lancer votre première capture

```bash
pcap_analyzer capture -d 60
```

C'est tout ! L'outil va :
1. Se connecter au serveur via SSH
2. Lancer tcpdump pendant 60 secondes
3. Télécharger le fichier PCAP
4. L'analyser automatiquement
5. Générer un rapport HTML dans `reports/`

## Utilisation courante

### Analyser un fichier PCAP existant

```bash
# Analyse complète
pcap_analyzer analyze mon_fichier.pcap

# Filtrer pour ne garder que les latences >= 2 secondes
# (Gaps, handshakes TCP, RTT, DNS >= 2s)
pcap_analyzer analyze mon_fichier.pcap -l 2
```

### Capture personnalisée

```bash
# Capture de 2 minutes
pcap_analyzer capture -d 120

# Capture avec filtre spécifique
pcap_analyzer capture -d 60 -f "tcp port 443"

# Capture sans analyse automatique
pcap_analyzer capture -d 60 --no-analyze
```

### Voir les rapports

Les rapports sont générés dans le dossier `reports/` :
- `pcap_analysis_YYYYMMDD_HHMMSS.html` - Rapport visuel
- `pcap_analysis_YYYYMMDD_HHMMSS.json` - Données brutes

Ouvrez le fichier HTML dans votre navigateur pour voir l'analyse complète.

## Interpréter les résultats

### Codes couleur dans le rapport HTML

- 🟢 **Vert** : Tout va bien, aucun problème détecté
- 🟡 **Jaune/Orange** : Avertissement, attention requise
- 🔴 **Rouge** : Problème critique nécessitant investigation

### Principales métriques

1. **Gaps temporels** : Interruptions dans le flux de paquets
2. **Handshakes lents** : Connexions TCP qui mettent du temps à s'établir
2bis. **Retransmissions SYN** : Détection des tentatives multiples de connexion (serveur lent, perte réseau)
3. **Retransmissions** : Paquets renvoyés (signe de pertes)
4. **RTT élevé** : Temps de réponse réseau élevé
5. **Zero Window** : L'application ne consomme pas assez vite les données
6. **ICMP PMTU** : Problèmes de taille de paquets (MTU)
7. **DNS lent/timeout** : Résolutions DNS problématiques

### Identifier la root cause

Le rapport indique le **côté suspect** pour chaque problème :

- **Serveur** : Le serveur est lent à répondre
- **Client** : Le client est lent à traiter
- **Réseau** : Le réseau introduit de la latence
- **Application** : L'application ne consomme pas les données assez vite
- **DNS** : Les serveurs DNS sont lents ou injoignables

## Exemples de scénarios

### Scénario 1 : Application web lente

```bash
# Capturer pendant 5 minutes pendant que les utilisateurs se plaignent
pcap_analyzer capture -d 300 -f "host serveur-web.local"

# Ouvrir le rapport HTML
# Chercher :
# - Handshakes lents → Serveur surchargé ?
# - RTT élevé → Problème réseau ?
# - Zero Window → Application lente à traiter ?
```

### Scénario 2 : Problème de connexion intermittent

```bash
# Capturer et filtrer uniquement les latences >= 1 seconde
pcap_analyzer capture -d 120 -l 1.0

# Le rapport montrera uniquement :
# - Les gaps temporels >= 1s
# - Les handshakes TCP >= 1s
# - Les RTT >= 1s
# - Les réponses DNS >= 1s
```

### Scénario 3 : Analyser un incident passé

```bash
# Vous avez déjà un PCAP d'un incident
pcap_analyzer analyze incident_20250103.pcap

# Générer un rapport ciblé sur les gros problèmes
pcap_analyzer analyze incident_20250103.pcap -l 0.5
```

## Personnalisation des seuils

Pour ajuster la sensibilité de détection, éditez `config.yaml` :

```yaml
thresholds:
  # Augmenter pour réduire les faux positifs
  packet_gap: 2.0              # Au lieu de 1.0
  rtt_warning: 0.2             # Au lieu de 0.1
  retransmission_critical: 50  # Au lieu de 30
```

Puis utilisez votre config :

```bash
pcap_analyzer analyze capture.pcap -c config_strict.yaml
```

## Dépannage rapide

### "Échec d'authentification SSH"

- Vérifiez que vous pouvez vous connecter manuellement : `ssh user@host`
- Vérifiez `config.yaml` (host, username, key_file)
- Si vous utilisez un mot de passe, ajoutez `password: "xxx"` dans config.yaml

### "tcpdump: permission denied"

Configurez sudo sans mot de passe pour tcpdump :

```bash
# Sur le serveur distant, en tant que root
echo "votre_user ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump" >> /etc/sudoers.d/tcpdump
```

### "Memory Error"

Le PCAP est trop volumineux. Solutions :

```bash
# 1. Capturer avec un filtre plus restrictif
pcap_analyzer capture -d 60 -f "tcp port 443"

# 2. Réduire la durée
pcap_analyzer capture -d 30

# 3. Utiliser le filtrage par latence
pcap_analyzer analyze gros_fichier.pcap -l 1.0
```

## Commandes utiles

```bash
# Afficher la configuration actuelle
pcap_analyzer show-config

# Aide générale
pcap_analyzer --help

# Aide sur une commande spécifique
pcap_analyzer capture --help
pcap_analyzer analyze --help
```

## Prochaines étapes

1. Consultez le [README.md](README.md) complet pour plus de détails
2. Ajustez les seuils dans `config.yaml` selon vos besoins
3. Automatisez les captures périodiques pour du monitoring continu
4. Intégrez les rapports JSON dans vos outils de monitoring

---

Besoin d'aide ? Consultez la documentation complète ou ouvrez une issue.
