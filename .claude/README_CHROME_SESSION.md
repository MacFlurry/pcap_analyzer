# 🎯 Quick Start - Chrome Extension Session

**Pour reprendre avec `claude --chrome`**

---

## Commandes Rapides

### 1. Lancer l'Application (30 secondes)
```bash
cd /Users/omegabk/investigations/pcap_analyzer
docker-compose up -d
sleep 10
```

### 2. Récupérer le Mot de Passe Admin
```bash
ADMIN_PW=$(docker exec pcap-analyzer cat /run/secrets/admin_password)
echo "✅ Username: admin"
echo "✅ Password: $ADMIN_PW"
```

### 3. Ouvrir Chrome
```bash
open -a "Google Chrome" "http://localhost:8000"
```

**Credentials:**
- Username: `admin`
- Password: `<voir ci-dessus>`

---

## Test PCAP Upload

### Créer un PCAP de Test
```bash
python3 /Users/omegabk/investigations/pcap_analyzer/generate_test_pcap.py
# Crée: /tmp/test_upload.pcap
```

### Scénario d'Upload
1. Login avec admin credentials
2. Page d'accueil → Upload form
3. Sélectionner `/tmp/test_upload.pcap`
4. Uploader
5. Observer progression (SSE stream)
6. Voir rapport HTML

---

## Pages à Tester

- ✅ `/` - Accueil (upload)
- ✅ `/login` - Connexion
- ✅ `/admin` - Panel admin
- ✅ `/history` - Historique analyses
- ✅ `/change-password` - Changement mot de passe

---

## Documentation Complète

📖 Voir: [NEXT_SESSION_CHROME.md](./NEXT_SESSION_CHROME.md)

---

**Status**: 72.45% coverage ✅ Production-ready
