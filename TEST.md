# Tests et validation

## Validation de l'installation

### 1. Vérifier l'installation

```bash
# L'installation doit être sans erreur
./install.sh

# Vérifier que la commande est disponible
which pcap_analyzer
pcap_analyzer --help
```

### 2. Tester la configuration

```bash
# Afficher la configuration par défaut
pcap_analyzer show-config

# Devrait afficher tous les seuils et paramètres SSH
```

### 3. Test avec un fichier PCAP (si disponible)

```bash
# Si vous avez un fichier PCAP existant
pcap_analyzer analyze test.pcap

# Avec filtrage
pcap_analyzer analyze test.pcap -l 1.0

# Sans génération de rapports
pcap_analyzer analyze test.pcap --no-report
```

### 4. Test de la capture SSH

**Important** : Éditez d'abord `config.yaml` avec vos vraies informations SSH !

```bash
# Test de connexion SSH (sans capture)
# Assurez-vous de pouvoir vous connecter manuellement d'abord :
ssh votre_user@192.168.25.15

# Si la connexion fonctionne, testez la capture :
pcap_analyzer capture -d 10  # Capture de 10 secondes seulement
```

## Tests unitaires des modules

### Test du module de timestamps

```python
from src.analyzers import TimestampAnalyzer
from scapy.all import rdpcap

# Charger un PCAP
packets = rdpcap('test.pcap')

# Analyser
analyzer = TimestampAnalyzer(gap_threshold=1.0)
results = analyzer.analyze(packets)

print(f"Gaps détectés: {results['gaps_detected']}")
print(analyzer.get_gaps_summary())
```

### Test du module TCP Handshake

```python
from src.analyzers import TCPHandshakeAnalyzer
from scapy.all import rdpcap

packets = rdpcap('test.pcap')

analyzer = TCPHandshakeAnalyzer()
results = analyzer.analyze(packets)

print(f"Handshakes: {results['total_handshakes']}")
print(f"Lents: {results['slow_handshakes']}")
print(analyzer.get_summary())
```

### Test du module de retransmissions

```python
from src.analyzers import RetransmissionAnalyzer
from scapy.all import rdpcap

packets = rdpcap('test.pcap')

analyzer = RetransmissionAnalyzer()
results = analyzer.analyze(packets)

print(f"Retransmissions: {results['total_retransmissions']}")
print(analyzer.get_summary())
```

### Test du module RTT

```python
from src.analyzers import RTTAnalyzer
from scapy.all import rdpcap

packets = rdpcap('test.pcap')

analyzer = RTTAnalyzer()
results = analyzer.analyze(packets)

print(f"Mesures RTT: {results['total_measurements']}")
print(analyzer.get_summary())
```

### Test du module DNS

```python
from src.analyzers import DNSAnalyzer
from scapy.all import rdpcap

packets = rdpcap('test.pcap')

analyzer = DNSAnalyzer()
results = analyzer.analyze(packets)

print(f"Requêtes DNS: {results['total_queries']}")
print(f"Timeouts: {results['timeout_transactions']}")
print(analyzer.get_summary())
```

### Test du module ICMP

```python
from src.analyzers import ICMPAnalyzer
from scapy.all import rdpcap

packets = rdpcap('test.pcap')

analyzer = ICMPAnalyzer()
results = analyzer.analyze(packets)

print(f"Messages ICMP: {results['total_icmp_messages']}")
print(f"Problèmes PMTU: {results['pmtu_issues_count']}")
print(analyzer.get_summary())
```

## Test du générateur de rapports

```python
from src.report_generator import ReportGenerator

# Créer des données de test
test_results = {
    'timestamps': {'gaps_detected': 0, 'total_packets': 1000},
    'tcp_handshake': {'slow_handshakes': 0},
    'retransmission': {'total_retransmissions': 0},
    'rtt': {'flows_with_high_rtt': 0},
    'tcp_window': {'flows_with_issues': 0},
    'icmp': {'pmtu_issues_count': 0},
    'dns': {'timeout_transactions': 0}
}

gen = ReportGenerator()
files = gen.generate_report(test_results, 'test.pcap', 'test_report')

print(f"Rapport JSON: {files['json']}")
print(f"Rapport HTML: {files['html']}")
```

## Résolution de problèmes lors des tests

### ImportError: No module named 'scapy'

```bash
pip install scapy
```

### ImportError: No module named 'src'

```bash
# Vous devez être dans le répertoire pcap_analyzer
cd pcap_analyzer
python3 -m src.cli --help
```

### SSH Connection Error

1. Vérifiez la connexion manuelle :
   ```bash
   ssh user@host
   ```

2. Vérifiez les paramètres dans config.yaml

3. Pour debug SSH :
   ```bash
   ssh -vvv user@host
   ```

### Permission Denied (tcpdump)

Sur le serveur distant :
```bash
# Permettre tcpdump sans sudo
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# OU configurer sudoers
echo "user ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump" | sudo tee /etc/sudoers.d/tcpdump
```

## Checklist de validation complète

- [ ] Installation sans erreur (`./install.sh`)
- [ ] Commande `pcap_analyzer` disponible
- [ ] `pcap_analyzer --help` fonctionne
- [ ] `pcap_analyzer show-config` affiche la config
- [ ] Analyse d'un PCAP existant fonctionne
- [ ] Rapport JSON généré correctement
- [ ] Rapport HTML généré et s'ouvre dans le navigateur
- [ ] Connexion SSH au serveur distant réussie (si configuré)
- [ ] Capture SSH + téléchargement fonctionne (si configuré)
- [ ] Analyse automatique après capture fonctionne

## Validation des fonctionnalités

Pour chaque fichier PCAP testé, vérifier que le rapport contient :

- [ ] Statistiques de timestamps (nombre de paquets, durée)
- [ ] Détection de gaps si présents
- [ ] Analyse des handshakes TCP
- [ ] Comptage des retransmissions
- [ ] Mesures RTT
- [ ] Analyse des fenêtres TCP
- [ ] Détection ICMP/PMTU si présents
- [ ] Analyse DNS si présentes

## Performance attendue

Sur un PCAP de taille moyenne (10 000 paquets) :
- Temps de chargement : < 5 secondes
- Temps d'analyse : < 10 secondes
- Génération de rapports : < 2 secondes
- **Total** : < 20 secondes

Sur un gros PCAP (100 000 paquets) :
- Temps total : < 2 minutes

Si les performances sont inférieures, utilisez le filtrage par latence (`-l`) pour réduire le jeu de données.

## Exemples de commandes de test

```bash
# Test rapide
pcap_analyzer analyze test.pcap --no-report

# Test avec tous les rapports
pcap_analyzer analyze test.pcap -o test_results

# Test avec filtrage agressif
pcap_analyzer analyze test.pcap -l 0.5

# Test de capture courte (10 secondes)
pcap_analyzer capture -d 10 --no-analyze

# Test de capture + analyse
pcap_analyzer capture -d 10 -l 1.0
```

---

Une fois tous les tests validés, l'application est prête pour une utilisation en production !
