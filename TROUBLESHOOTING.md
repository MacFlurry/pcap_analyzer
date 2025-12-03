# Guide de dépannage

## Problèmes d'authentification SSH

### Symptôme : "No authentication methods available"

```
Connexion SSH à 192.168.25.15...
Connexion SSH fermée
❌ Erreur lors de la capture: Erreur SSH: No authentication methods available
```

### Causes possibles

1. **Clé SSH non trouvée** : Le chemin vers la clé est incorrect
2. **Permissions de la clé** : La clé doit avoir les bonnes permissions (600)
3. **Agent SSH** : L'agent SSH n'est pas configuré

### Solutions

#### 1. Vérifier le chemin de la clé SSH

Dans `config.yaml`, le tilde `~` est automatiquement expansé :

```yaml
ssh:
  key_file: "~/.ssh/id_rsa"  # ✓ Correct (tilde expansé automatiquement)
```

Vous pouvez aussi utiliser le chemin absolu :

```yaml
ssh:
  key_file: "/home/username/.ssh/id_rsa"  # ✓ Correct aussi
```

#### 2. Vérifier les permissions de la clé

```bash
chmod 600 ~/.ssh/id_rsa
```

#### 3. Tester la connexion SSH manuellement

```bash
ssh -i ~/.ssh/id_rsa your_username@your_server_ip
```

Si cela fonctionne, l'outil devrait aussi fonctionner.

#### 4. Utiliser le script de test

Avant de lancer une capture, testez la connexion :

```bash
cd pcap_analyzer
python3 test_ssh.py
```

Ce script va :
- Vérifier la configuration SSH
- Tester la connexion
- Vérifier que tcpdump est disponible
- Tester sudo

### Sortie attendue du test

```
Test de connexion SSH

Configuration SSH :
  Host: 192.168.1.100
  Port: 22
  Username: your_username
  Key file: ~/.ssh/id_rsa
  Key file (expansé): /home/username/.ssh/id_rsa
  Key file existe: True

Tentative de connexion...

Connexion SSH à 192.168.1.100...
✓ Connecté avec succès

Exécution de 'hostname'...
✓ Hostname: server01

Test de sudo (whoami)...
✓ Sudo fonctionne: root

Vérification de tcpdump...
✓ tcpdump trouvé: /usr/sbin/tcpdump

Connexion SSH fermée

✓ Test de connexion SSH réussi !
```

---

## Autres problèmes courants

### Problème : "tcpdump: permission denied"

**Symptôme :**
```
sudo tcpdump: permission denied
```

**Solution :**

Sur le serveur distant, configurez sudo sans mot de passe pour tcpdump :

```bash
# Sur le serveur distant
sudo visudo -f /etc/sudoers.d/tcpdump

# Ajoutez cette ligne (remplacez 'your_username' par votre username)
your_username ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump, /usr/bin/pkill
```

Ou donnez les capabilities à tcpdump :

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```

### Problème : "Module not found"

**Symptôme :**
```
ModuleNotFoundError: No module named 'scapy'
```

**Solution :**

Réinstallez les dépendances :

```bash
cd pcap_analyzer
pip install -r requirements.txt
```

### Problème : "Fichier PCAP vide"

**Symptôme :**
Le fichier PCAP est créé mais vide (0 bytes).

**Solutions :**

1. Vérifiez le filtre BPF dans `config.yaml` :
   ```yaml
   filter: "host 192.168.25.67"  # Assurez-vous que du trafic existe
   ```

2. Testez sans filtre :
   ```bash
   pcap_analyzer capture -d 10 -f ""
   ```

3. Vérifiez l'interface réseau :
   ```bash
   # Sur le serveur distant
   ip addr show
   ```

### Problème : "Timeout lors de la capture"

**Symptôme :**
La capture se bloque et ne se termine jamais.

**Solution :**

1. Utilisez une durée plus courte pour tester :
   ```bash
   pcap_analyzer capture -d 10
   ```

2. Vérifiez que tcpdump n'est pas déjà en cours :
   ```bash
   # Sur le serveur distant
   sudo pkill tcpdump
   ```

### Problème : "Memory Error"

**Symptôme :**
```
MemoryError: Unable to allocate array
```

**Solution :**

Le fichier PCAP est trop volumineux. Utilisez le filtrage :

```bash
# Filtrer par latence
pcap_analyzer analyze gros_fichier.pcap -l 1.0

# Ou utiliser un filtre BPF plus restrictif lors de la capture
pcap_analyzer capture -d 60 -f "tcp port 443"
```

---

## Checklist de débogage

Avant d'ouvrir un ticket, vérifiez :

- [ ] La connexion SSH manuelle fonctionne : `ssh -i ~/.ssh/key user@host`
- [ ] Le chemin de la clé dans `config.yaml` est correct
- [ ] Les permissions de la clé sont correctes : `chmod 600 ~/.ssh/key`
- [ ] Le script de test fonctionne : `python3 test_ssh.py`
- [ ] tcpdump est installé sur le serveur distant : `which tcpdump`
- [ ] sudo fonctionne pour tcpdump : `sudo tcpdump --version`
- [ ] Les dépendances Python sont installées : `pip list | grep scapy`

---

## Logs de débogage

Pour obtenir plus d'informations sur les erreurs :

```bash
# Activer le mode verbose de Python
python3 -v -m src.cli capture -d 10 2>&1 | tee debug.log

# Pour SSH, utilisez le script de test qui affiche plus de détails
python3 test_ssh.py
```

---

## Support

Si le problème persiste après avoir suivi ce guide :

1. Exécutez `python3 test_ssh.py` et sauvegardez la sortie
2. Vérifiez la connexion SSH manuelle
3. Consultez les fichiers de log
4. Ouvrez une issue avec les informations collectées

---

## Corrections apportées

### Version 1.0.1 (2025-01-04)

**Fix : Expansion du tilde (~) dans le chemin de la clé SSH**

Le chemin `~/.ssh/id_ed25519_raspberry` dans `config.yaml` n'était pas automatiquement expansé, causant l'erreur "No authentication methods available".

**Correction appliquée :**
- `src/ssh_capture.py` : Ajout de `os.path.expanduser()` lors de l'initialisation de `key_file`
- Ajout du script `test_ssh.py` pour tester la connexion avant capture

**Migration :**
Aucune action nécessaire si vous utilisez déjà `~/` dans votre config. Pour être certain, réinstallez :

```bash
cd pcap_analyzer
pip install -e . --upgrade
```
