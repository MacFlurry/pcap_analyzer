#!/bin/bash

# Configuration
REMOTE_HOST="192.168.25.15"
REMOTE_USER="omegabk"
SSH_KEY="$HOME/.ssh/id_ed25519_raspberry"
DURATION=600  # 10 minutes
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REMOTE_FILE="/tmp/capture_${TIMESTAMP}.pcap"
LOCAL_FILE="capture_remote_${TIMESTAMP}.pcap"

echo "========================================================"
echo "🚀 Démarrage de la séquence de capture (10 min)"
echo "   Remote: $REMOTE_USER@$REMOTE_HOST"
echo "   File: $LOCAL_FILE"
echo "========================================================"

# 1. Lancement du générateur de trafic (bruit de fond enrichi)
echo "🌊 [Local] Lancement du générateur de trafic (Web, DNS, Erreurs)..."
(
    while true; do
        # --- Trafic Web Normal ---
        curl -s -I https://www.google.com >/dev/null 2>&1
        curl -s -I https://www.github.com >/dev/null 2>&1

        # --- Trafic DNS (UDP) ---
        # Valide
        nslookup github.com 8.8.8.8 >/dev/null 2>&1
        # Invalide (NXDOMAIN pour tester la section DNS Errors)
        nslookup domaine.inexistant.test 8.8.8.8 >/dev/null 2>&1

        # --- Trafic Anomalique (Tests de détection) ---
        # Connexion vers un port fermé local (Doit générer un TCP RST - Connection Refused)
        curl -m 1 http://127.0.0.1:65432 >/dev/null 2>&1

        # Connexion vers une IP improbable (Doit générer un Timeout ou Host Unreachable)
        curl -m 1 http://10.255.255.1 >/dev/null 2>&1

        # --- ICMP ---
        ping -c 1 1.1.1.1 >/dev/null 2>&1

        # Pause courte
        sleep 0.5
    done
) &
TRAFFIC_PID=$!
echo "   PID Trafic: $TRAFFIC_PID"

# 2. Capture distante
echo "📡 [Remote] Lancement de tcpdump ($DURATION sec)..."
# On utilise timeout côté serveur pour être sûr qu'il s'arrête
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "sudo timeout $DURATION tcpdump -i any -w $REMOTE_FILE"

# 3. Arrêt du trafic
echo "🛑 [Local] Arrêt du générateur de trafic..."
kill $TRAFFIC_PID

# 4. Récupération du fichier
echo "⬇️ [Local] Téléchargement du fichier PCAP..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "./$LOCAL_FILE"

if [ ! -f "$LOCAL_FILE" ]; then
    echo "❌ Erreur: Le fichier $LOCAL_FILE n'a pas été récupéré."
    exit 1
fi

# 5. Nettoyage distant
echo "🧹 [Remote] Nettoyage..."
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "sudo rm $REMOTE_FILE"

# 6. Analyse
echo "📊 [Local] Lancement de l'analyse..."
# Activation venv gérée par le shell appelant ou chemin direct
source venv/bin/activate
python3 -m src.cli analyze "$LOCAL_FILE" -d

echo "========================================================"
echo "✅ Séquence terminée."
echo "========================================================"
