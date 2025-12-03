#!/usr/bin/env python3
"""
Script de test pour vérifier la connexion SSH
"""

import sys
import os

# Ajouter le répertoire src au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.config import get_config
from src.ssh_capture import SSHCapture
from rich.console import Console

console = Console()

def test_ssh_connection():
    """Test de connexion SSH"""
    console.print("[bold cyan]Test de connexion SSH[/bold cyan]\n")

    # Charger la configuration
    cfg = get_config()
    ssh_config = cfg.ssh_config

    console.print(f"Configuration SSH :")
    console.print(f"  Host: {ssh_config.get('host')}")
    console.print(f"  Port: {ssh_config.get('port', 22)}")
    console.print(f"  Username: {ssh_config.get('username')}")
    console.print(f"  Key file: {ssh_config.get('key_file', 'N/A')}")

    # Expansion du tilde pour vérification
    key_file = ssh_config.get('key_file')
    if key_file:
        expanded_key = os.path.expanduser(key_file)
        console.print(f"  Key file (expansé): {expanded_key}")
        console.print(f"  Key file existe: {os.path.exists(expanded_key)}")

    console.print("\n[yellow]Tentative de connexion...[/yellow]\n")

    try:
        # Créer l'instance SSH
        ssh = SSHCapture(
            host=ssh_config.get('host'),
            username=ssh_config.get('username'),
            port=ssh_config.get('port', 22),
            password=ssh_config.get('password'),
            key_file=ssh_config.get('key_file')
        )

        # Tester la connexion
        ssh.connect()

        # Exécuter une commande simple
        console.print("\n[cyan]Exécution de 'hostname'...[/cyan]")
        stdout, stderr, exit_code = ssh.execute_command("hostname")

        if exit_code == 0:
            console.print(f"[green]✓ Hostname: {stdout.strip()}[/green]")
        else:
            console.print(f"[red]✗ Erreur: {stderr}[/red]")

        # Tester sudo
        console.print("\n[cyan]Test de sudo (whoami)...[/cyan]")
        stdout, stderr, exit_code = ssh.execute_command("whoami", sudo=True)

        if exit_code == 0:
            console.print(f"[green]✓ Sudo fonctionne: {stdout.strip()}[/green]")
        else:
            console.print(f"[yellow]⚠ Sudo: {stderr}[/yellow]")

        # Vérifier tcpdump
        console.print("\n[cyan]Vérification de tcpdump...[/cyan]")
        stdout, stderr, exit_code = ssh.execute_command("which tcpdump")

        if exit_code == 0:
            console.print(f"[green]✓ tcpdump trouvé: {stdout.strip()}[/green]")
        else:
            console.print(f"[red]✗ tcpdump non trouvé[/red]")

        ssh.disconnect()

        console.print("\n[bold green]✓ Test de connexion SSH réussi ![/bold green]")
        return True

    except Exception as e:
        console.print(f"\n[bold red]✗ Erreur: {e}[/bold red]")
        return False

if __name__ == '__main__':
    success = test_ssh_connection()
    sys.exit(0 if success else 1)
