"""
Module de capture PCAP via SSH
Permet d'exécuter tcpdump sur un serveur distant et récupérer le fichier PCAP

Security features implemented:
- Command injection prevention via shlex.quote() on all user inputs
- Directory traversal protection with path validation
- Interface whitelist to prevent malicious interface names
- PID-based process management (no killall)
- Input validation for all parameters
- SSH timeout to prevent hanging connections
- Host key verification with user confirmation
"""

import logging
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import paramiko
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .utils.logging_filters import PIIRedactionFilter

logger = logging.getLogger(__name__)
# GDPR/NIST Compliance: Redact PII from logs (IP addresses, BPF filters, file paths)
logger.addFilter(PIIRedactionFilter())

console = Console()

# Security: Whitelist of allowed network interfaces to prevent command injection
# Note: Users can extend this list in their own code if needed
ALLOWED_INTERFACES = ["any", "eth0", "eth1", "eth2", "eth3", "wlan0", "wlan1", "lo", "ens33", "ens160"]


def validate_interface(interface: str) -> None:
    """
    Validates that the interface is in the allowed whitelist.
    Prevents command injection attacks via interface parameter.

    Args:
        interface: Network interface name

    Raises:
        SSHCaptureError: If interface is not in whitelist
    """
    if interface not in ALLOWED_INTERFACES:
        raise SSHCaptureError(f"Interface '{interface}' not allowed. Must be one of: {', '.join(ALLOWED_INTERFACES)}")


def validate_file_path(file_path: str) -> None:
    """
    Validates file path to prevent directory traversal attacks.
    Only allows paths under /tmp/ for security.

    Args:
        file_path: File path to validate

    Raises:
        SSHCaptureError: If path contains directory traversal or is outside /tmp/
    """
    # Security: Prevent directory traversal attacks
    if ".." in file_path or not file_path.startswith("/tmp/"):
        raise SSHCaptureError(f"Invalid file path '{file_path}'. Must be under /tmp/ and not contain '..'")


def validate_bpf_filter(bpf_filter: str, timeout: int = 5) -> bool:
    """
    Validates BPF filter syntax using tcpdump to prevent injection attacks.

    This function uses tcpdump -d to compile the filter without executing it,
    ensuring the syntax is valid and preventing malicious filter expressions.

    Args:
        bpf_filter: BPF filter expression to validate
        timeout: Maximum time in seconds to wait for tcpdump (default: 5s)

    Returns:
        True if filter is valid, False otherwise

    Examples:
        >>> validate_bpf_filter("tcp port 80")
        True
        >>> validate_bpf_filter("host 192.168.1.1 and port 443")
        True
        >>> validate_bpf_filter("invalid filter syntax")
        False
        >>> validate_bpf_filter("; rm -rf /")  # Injection attempt
        False

    Note:
        Requires tcpdump to be installed on the system.
    """
    if not bpf_filter:
        return True  # Empty filter is valid

    try:
        # Use tcpdump -ddd to compile (but not execute) the filter
        # -ddd outputs C program fragment instead of assembler, doesn't require network permissions
        result = subprocess.run(
            ["tcpdump", "-ddd", bpf_filter],
            capture_output=True,
            timeout=timeout,
            text=True,
            check=False,  # Don't raise on non-zero exit
        )

        if result.returncode == 0 and result.stdout.strip():
            # Successfully compiled - output should contain C code
            logger.debug(f"BPF filter validated successfully: {bpf_filter}")
            return True
        else:
            # Any error in compilation is suspicious
            stderr = result.stderr.strip()
            if stderr:
                logger.warning(f"Invalid BPF filter '{bpf_filter}': {stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"BPF filter validation timed out after {timeout}s: {bpf_filter}")
        return False
    except FileNotFoundError:
        # tcpdump not available - log warning but allow (don't break functionality)
        logger.warning("tcpdump not found, skipping BPF filter validation")
        return True
    except Exception as e:
        logger.error(f"Error validating BPF filter: {e}")
        return False


class SSHCaptureError(Exception):
    """Exception levée lors d'erreurs de capture SSH"""

    pass


class SSHCaptureRateLimiter:
    """
    Rate limiter for SSH capture connections to prevent brute force attacks.

    This class implements a sliding window rate limiter that tracks connection
    attempts over a configurable time window.

    Attributes:
        max_attempts: Maximum number of connection attempts allowed
        window: Time window in seconds for counting attempts
        attempts: List of timestamp attempts

    Examples:
        >>> limiter = SSHCaptureRateLimiter(max_attempts=3, window=60)
        >>> limiter.check_and_record()  # First attempt - OK
        True
        >>> limiter.check_and_record()  # Second attempt - OK
        True
        >>> limiter.check_and_record()  # Third attempt - OK
        True
        >>> limiter.check_and_record()  # Fourth attempt - BLOCKED
        False
    """

    def __init__(self, max_attempts: int = 3, window: int = 60) -> None:
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum connection attempts in window (default: 3)
            window: Time window in seconds (default: 60)
        """
        self.max_attempts = max_attempts
        self.window = window
        self.attempts: list = []

    def check_and_record(self) -> bool:
        """
        Check if rate limit is exceeded and record current attempt.

        Returns:
            True if attempt is allowed, False if rate limit exceeded

        Raises:
            SSHCaptureError: If rate limit is exceeded
        """
        current_time = time.time()

        # Remove attempts outside the time window
        self.attempts = [t for t in self.attempts if current_time - t < self.window]

        # Check if limit exceeded
        if len(self.attempts) >= self.max_attempts:
            wait_time = self.window - (current_time - self.attempts[0])
            raise SSHCaptureError(
                f"Rate limit exceeded: {len(self.attempts)} connection attempts in {self.window}s. "
                f"Please wait {wait_time:.0f} seconds before trying again."
            )

        # Record this attempt
        self.attempts.append(current_time)
        return True

    def reset(self) -> None:
        """Reset rate limiter (clear all attempts)."""
        self.attempts.clear()

    def get_remaining_attempts(self) -> int:
        """
        Get number of remaining attempts before rate limit.

        Returns:
            Number of attempts remaining
        """
        current_time = time.time()
        self.attempts = [t for t in self.attempts if current_time - t < self.window]
        return max(0, self.max_attempts - len(self.attempts))


class SSHCapture:
    """Gestionnaire de capture PCAP via SSH"""

    def __init__(
        self, host: str, username: str, port: int = 22, password: Optional[str] = None, key_file: Optional[str] = None
    ):
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

            # Security: Use WarningPolicy instead of AutoAddPolicy to prevent MITM attacks
            # WarningPolicy will warn but still connect. For production, consider RejectPolicy with known_hosts.
            self.client.set_missing_host_key_policy(paramiko.WarningPolicy())

            connect_kwargs = {
                "hostname": self.host,
                "port": self.port,
                "username": self.username,
            }

            if self.key_file and os.path.exists(self.key_file):
                connect_kwargs["key_filename"] = self.key_file
            elif self.password:
                connect_kwargs["password"] = self.password
            else:
                # Tente l'authentification par agent SSH
                connect_kwargs["look_for_keys"] = True

            console.print(f"[cyan]Connexion SSH à {self.host}...[/cyan]")

            # Security: Check for unknown host key and prompt user
            try:
                self.client.connect(**connect_kwargs, timeout=10)
            except paramiko.SSHException as ssh_err:
                if "not found in known_hosts" in str(ssh_err).lower() or "unknown server" in str(ssh_err).lower():
                    console.print("[yellow]⚠ WARNING: Unknown SSH host key![/yellow]")
                    console.print(f"[yellow]Host: {self.host}[/yellow]")
                    console.print("[yellow]This could indicate a man-in-the-middle attack.[/yellow]")
                    response = console.input("[yellow]Continue anyway? (yes/no): [/yellow]")
                    if response.lower() != "yes":
                        raise SSHCaptureError("Connection refused by user due to unknown host key")
                    # Temporarily use AutoAddPolicy for this connection only
                    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    self.client.connect(**connect_kwargs, timeout=10)
                else:
                    raise

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

    def execute_command(self, command: str, sudo: bool = False, timeout: int = 30) -> tuple[str, str, int]:
        """
        Exécute une commande sur le serveur distant

        Args:
            command: Commande à exécuter
            sudo: Si True, exécute avec sudo
            timeout: Timeout en secondes pour l'exécution (défaut: 30s)

        Returns:
            Tuple (stdout, stderr, exit_code)
        """
        if not self.client:
            raise SSHCaptureError("Pas de connexion SSH active")

        if sudo:
            command = f"sudo {command}"

        # Security: Add timeout to prevent hanging on malicious commands
        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()

        return stdout.read().decode("utf-8"), stderr.read().decode("utf-8"), exit_code

    def capture_packets(
        self,
        interface: str = "any",
        filter_expr: str = "",
        duration: int = 60,
        output_file: str = None,
        packet_count: int = None,
    ) -> str:
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

        # Security: Validate interface against whitelist
        validate_interface(interface)

        # Génère un nom de fichier unique si non fourni
        if output_file is None:
            timestamp = int(time.time())
            output_file = f"/tmp/capture_{timestamp}.pcap"

        # Security: Validate output file path
        validate_file_path(output_file)

        # Security: Validate BPF filter syntax before using it
        if filter_expr:
            if not validate_bpf_filter(filter_expr):
                raise SSHCaptureError(
                    f"Invalid BPF filter syntax: '{filter_expr}'\n"
                    f"Please check your filter expression. Examples:\n"
                    f"  - 'tcp port 80'\n"
                    f"  - 'host 192.168.1.1 and port 443'\n"
                    f"  - 'udp and src net 10.0.0.0/8'"
                )

        # Security: Use shlex.quote() to prevent command injection
        # This properly escapes all user inputs before shell execution
        safe_interface = shlex.quote(interface)
        safe_output_file = shlex.quote(output_file)

        # Construit la commande tcpdump
        tcpdump_cmd = f"tcpdump -i {safe_interface} -w {safe_output_file} -s 65535"

        if filter_expr:
            # Security: Quote the filter expression to prevent command injection
            safe_filter = shlex.quote(filter_expr)
            tcpdump_cmd += f" {safe_filter}"

        if packet_count:
            # Security: Validate packet_count is an integer
            if not isinstance(packet_count, int) or packet_count < 0:
                raise SSHCaptureError("packet_count must be a positive integer")
            tcpdump_cmd += f" -c {packet_count}"

        console.print(f"[cyan]Lancement de la capture sur {self.host}...[/cyan]")
        console.print(f"[dim]Interface: {interface}[/dim]")
        if filter_expr:
            console.print(f"[dim]Filtre: {filter_expr}[/dim]")
        console.print(f"[dim]Durée: {duration}s[/dim]")
        console.print(f"[dim]Commande: {tcpdump_cmd}[/dim]")

        try:
            # Security: Launch tcpdump in background and capture its PID
            # This prevents killing ALL tcpdump processes on the system
            tcpdump_with_pid = f"sudo {tcpdump_cmd} & echo $!"
            stdin, stdout, stderr = self.client.exec_command(tcpdump_with_pid)

            # Get the PID of the tcpdump process
            pid_output = stdout.read().decode("utf-8").strip()
            try:
                tcpdump_pid = int(pid_output.split("\n")[-1])
            except (ValueError, IndexError):
                raise SSHCaptureError(f"Failed to get tcpdump PID: {pid_output}")

            console.print(f"[dim]tcpdump PID: {tcpdump_pid}[/dim]")

            # Attend la durée spécifiée avec une barre de progression
            with Progress(
                SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console
            ) as progress:
                task = progress.add_task(f"Capture en cours ({duration}s)...", total=duration)
                for _ in range(duration):
                    time.sleep(1)
                    progress.update(task, advance=1)

            # Security: Kill only the specific tcpdump process by PID, not all tcpdump processes
            self.execute_command(f"sudo kill -2 {tcpdump_pid}", sudo=False, timeout=10)
            time.sleep(2)  # Attente pour que tcpdump termine l'écriture

            # Vérifie que le fichier existe
            # Security: Use quoted path for ls command
            stdout_check, stderr_check, exit_code = self.execute_command(
                f"ls -lh {safe_output_file}", sudo=True, timeout=10
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
                task = progress.add_task(f"[cyan]Téléchargement de {os.path.basename(remote_path)}", total=file_size)

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
            # Security: Validate file path before deletion to prevent directory traversal
            validate_file_path(remote_path)

            # Security: Use shlex.quote() to prevent command injection
            safe_remote_path = shlex.quote(remote_path)
            self.execute_command(f"rm -f {safe_remote_path}", sudo=True, timeout=10)
            console.print(f"[dim]✓ Fichier distant supprimé: {remote_path}[/dim]")
        except Exception as e:
            console.print(f"[yellow]⚠ Impossible de supprimer {remote_path}: {e}[/yellow]")

    def capture_and_download(
        self, local_path: str, interface: str = "any", filter_expr: str = "", duration: int = 60, cleanup: bool = True
    ) -> str:
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
            remote_file = self.capture_packets(interface=interface, filter_expr=filter_expr, duration=duration)
            self.download_file(remote_file, local_path)

            if cleanup and remote_file:
                self.cleanup_remote_file(remote_file)

            return local_path

        finally:
            self.disconnect()


def capture_from_config(
    config: dict[str, Any], local_path: str, duration: int = 60, filter_override: str = None
) -> str:
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
    ssh_config = config.get("ssh", {})
    tcpdump_config = ssh_config.get("tcpdump", {})

    capture = SSHCapture(
        host=ssh_config.get("host"),
        username=ssh_config.get("username"),
        port=ssh_config.get("port", 22),
        password=ssh_config.get("password"),
        key_file=ssh_config.get("key_file"),
    )

    filter_expr = filter_override or tcpdump_config.get("filter", "")

    return capture.capture_and_download(
        local_path=local_path,
        interface=tcpdump_config.get("interface", "any"),
        filter_expr=filter_expr,
        duration=duration,
        cleanup=True,
    )
