#!/bin/bash
# Script d'installation pour PCAP Analyzer

set -e

echo "======================================"
echo "Installation de PCAP Analyzer"
echo "======================================"
echo ""

# Vérifie Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
echo "✓ Python $PYTHON_VERSION détecté"

# Vérifie pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

echo "✓ pip3 détecté"
echo ""

# Installation des dépendances
echo "Installation des dépendances..."
pip3 install -r requirements.txt

echo ""
echo "Installation de PCAP Analyzer..."
pip3 install -e .

echo ""
echo "======================================"
echo "✓ Installation terminée avec succès !"
echo "======================================"
echo ""
echo "Commandes disponibles :"
echo "  pcap_analyzer analyze <fichier.pcap>      - Analyser un fichier PCAP"
echo "  pcap_analyzer capture                      - Capturer depuis un serveur distant"
echo "  pcap_analyzer show-config                  - Afficher la configuration"
echo ""
echo "Pour commencer :"
echo "  1. Éditez config.yaml avec vos paramètres SSH"
echo "  2. Lancez : pcap_analyzer capture"
echo ""
echo "Documentation complète : voir README.md"
echo ""
