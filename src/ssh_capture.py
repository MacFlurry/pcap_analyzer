"""
Module de capture PCAP via SSH
Permet d'exécuter tcpdump sur un serveur distant et récupérer le fichier PCAP
"""

import paramiko
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class SSHCaptureError(Exception):
    """Exception levée lors d'erreurs de capture SSH"""
    pass


class SSHCapture:
    """Gestionnaire de capture PCAP via SSH"""

    def __init__(self, host: str, username: str, port: int = 22,
                 password: Optional[str] = None, key_file: Optional[str] = None):
        """
        Initialise la connexion SSH

        Args:
            host: Adresse du serveur distant
            username: Nom d'utilisateur SSH
            port: Port SSH (défaut: 22)
            password: Mot de passe SSH (optionnel)
            key_file: Chemin vers la clé privée SSH (optionnel)
        """
        self.host = host
        self.username = username
        self.port = port
        self.password = password
        # Expanse le tilde (~) dans le chemin de la clé
        self.key_file = os.path.expanduser(key_file) if key_file else None
        self.client = None

    def connect(self) -> None:
        """Établit la connexion SSH"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
            }

            if self.key_file and os.path.exists(self.key_file):
                connect_kwargs['key_filename'] = self.key_file
            elif self.password:
                connect_kwargs['password'] = self.password
            else:
                # Tente l'authentification par agent SSH
                connect_kwargs['look_for_keys'] = True

            console.print(f"[cyan]Connexion SSH à {self.host}...[/cyan]")
            self.client.connect(**connect_kwargs, timeout=10)
            console.print("[green]✓ Connecté avec succès[/green]")

        except paramiko.AuthenticationException:
            raise SSHCaptureError("Échec d'authentification SSH")
        except paramiko.SSHException as e:
            raise SSHCaptureError(f"Erreur SSH: {e}")
        except Exception as e:
            raise SSHCaptureError(f"Erreur de connexion: {e}")

    def disconnect(self) -> None:
        """Ferme la connexion SSH"""
        if self.client:
            self.client.close()
            console.print("[cyan]Connexion SSH fermée[/cyan]")

    def execute_command(self, command: str, sudo: bool = False) -> tuple[str, str, int]:
        """
        Exécute une commande sur le serveur distant

        Args:
            command: Commande à exécuter
            sudo: Si True, exécute avec sudo

        Returns:
            Tuple (stdout, stderr, exit_code)
        """
        if not self.client:
            raise SSHCaptureError("Pas de connexion SSH active")

        if sudo:
            command = f"sudo {command}"

        stdin, stdout, stderr = self.client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()

        return stdout.read().decode('utf-8'), stderr.read().decode('utf-8'), exit_code

    def capture_packets(self, interface: str = "any", filter_expr: str = "",
                        duration: int = 60, output_file: str = None,
                        packet_count: int = None) -> str:
        """
        Lance une capture tcpdump sur le serveur distant

        Args:
            interface: Interface réseau à capturer (défaut: "any")
            filter_expr: Expression de filtre BPF (ex: "host 192.168.1.1")
            duration: Durée de capture en secondes (défaut: 60)
            output_file: Nom du fichier de sortie distant (si None, généré automatiquement)
            packet_count: Nombre de paquets à capturer (si None, capture pendant duration)

        Returns:
            Chemin du fichier PCAP sur le serveur distant
        """
        if not self.client:
            raise SSHCaptureError("Pas de connexion SSH active")

        # Génère un nom de fichier unique si non fourni
        if output_file is None:
            timestamp = int(time.time())
            output_file = f"/tmp/capture_{timestamp}.pcap"

        # Construit la commande tcpdump
        tcpdump_cmd = f"tcpdump -i {interface} -w {output_file} -s 65535"

        if filter_expr:
            tcpdump_cmd += f" {filter_expr}"

        if packet_count:
            tcpdump_cmd += f" -c {packet_count}"

        console.print(f"[cyan]Lancement de la capture sur {self.host}...[/cyan]")
        console.print(f"[dim]Interface: {interface}[/dim]")
        if filter_expr:
            console.print(f"[dim]Filtre: {filter_expr}[/dim]")
        console.print(f"[dim]Durée: {duration}s[/dim]")
        console.print(f"[dim]Commande: {tcpdump_cmd}[/dim]")

        try:
            # Lance tcpdump en arrière-plan
            stdin, stdout, stderr = self.client.exec_command(f"sudo {tcpdump_cmd}")

            # Attend la durée spécifiée avec une barre de progression
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Capture en cours ({duration}s)...", total=duration)
                for _ in range(duration):
                    time.sleep(1)
                    progress.update(task, advance=1)

            # Tue le processus tcpdump
            self.execute_command("sudo pkill -2 tcpdump", sudo=False)
            time.sleep(2)  # Attente pour que tcpdump termine l'écriture

            # Vérifie que le fichier existe
            stdout_check, stderr_check, exit_code = self.execute_command(
                f"ls -lh {output_file}", sudo=True
            )

            if exit_code != 0:
                raise SSHCaptureError(f"Fichier PCAP non créé: {stderr_check}")

            console.print(f"[green]✓ Capture terminée: {output_file}[/green]")
            console.print(f"[dim]{stdout_check.strip()}[/dim]")

            return output_file

        except Exception as e:
            raise SSHCaptureError(f"Erreur lors de la capture: {e}")

    def download_file(self, remote_path: str, local_path: str) -> None:
        """
        Télécharge un fichier depuis le serveur distant

        Args:
            remote_path: Chemin du fichier distant
            local_path: Chemin de destination local
        """
        if not self.client:
            raise SSHCaptureError("Pas de connexion SSH active")

        try:
            console.print(f"[cyan]Téléchargement du fichier PCAP...[/cyan]")

            sftp = self.client.open_sftp()

            # Récupère la taille du fichier pour la barre de progression
            file_size = sftp.stat(remote_path).st_size

            with Progress(console=console) as progress:
                task = progress.add_task(
                    f"[cyan]Téléchargement de {os.path.basename(remote_path)}",
                    total=file_size
                )

                def progress_callback(transferred, total):
                    progress.update(task, completed=transferred)

                sftp.get(remote_path, local_path, callback=progress_callback)

            sftp.close()

            console.print(f"[green]✓ Fichier téléchargé: {local_path}[/green]")

        except Exception as e:
            raise SSHCaptureError(f"Erreur lors du téléchargement: {e}")

    def cleanup_remote_file(self, remote_path: str) -> None:
        """
        Supprime un fichier sur le serveur distant

        Args:
            remote_path: Chemin du fichier à supprimer
        """
        if not self.client:
            return

        try:
            self.execute_command(f"rm -f {remote_path}", sudo=True)
            console.print(f"[dim]✓ Fichier distant supprimé: {remote_path}[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠ Impossible de supprimer {remote_path}: {e}[/yellow]")

    def capture_and_download(self, local_path: str, interface: str = "any",
                             filter_expr: str = "", duration: int = 60,
                             cleanup: bool = True) -> str:
        """
        Capture et télécharge un fichier PCAP en une seule opération

        Args:
            local_path: Chemin de destination local
            interface: Interface réseau à capturer
            filter_expr: Expression de filtre BPF
            duration: Durée de capture en secondes
            cleanup: Si True, supprime le fichier distant après téléchargement

        Returns:
            Chemin du fichier PCAP local
        """
        remote_file = None

        try:
            self.connect()
            remote_file = self.capture_packets(
                interface=interface,
                filter_expr=filter_expr,
                duration=duration
            )
            self.download_file(remote_file, local_path)

            if cleanup and remote_file:
                self.cleanup_remote_file(remote_file)

            return local_path

        finally:
            self.disconnect()


def capture_from_config(config: Dict[str, Any], local_path: str,
                       duration: int = 60, filter_override: str = None) -> str:
    """
    Effectue une capture en utilisant la configuration fournie

    Args:
        config: Configuration SSH (dictionnaire)
        local_path: Chemin de destination local
        duration: Durée de capture en secondes
        filter_override: Filtre BPF personnalisé (remplace celui de la config)

    Returns:
        Chemin du fichier PCAP local
    """
    ssh_config = config.get('ssh', {})
    tcpdump_config = ssh_config.get('tcpdump', {})

    capture = SSHCapture(
        host=ssh_config.get('host'),
        username=ssh_config.get('username'),
        port=ssh_config.get('port', 22),
        password=ssh_config.get('password'),
        key_file=ssh_config.get('key_file')
    )

    filter_expr = filter_override or tcpdump_config.get('filter', '')

    return capture.capture_and_download(
        local_path=local_path,
        interface=tcpdump_config.get('interface', 'any'),
        filter_expr=filter_expr,
        duration=duration,
        cleanup=True
    )
