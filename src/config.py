"""
Module de gestion de la configuration
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class Config:
    """Gestionnaire de configuration pour l'analyseur PCAP"""

    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialise la configuration

        Args:
            config_path: Chemin vers le fichier de configuration YAML
        """
        if config_path is None:
            # Cherche config.yaml à la racine du projet
            project_root = Path(__file__).parent.parent
            config_path = project_root / "config.yaml"

        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        """Charge la configuration depuis le fichier YAML"""
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Fichier de configuration non trouvé: {self.config_path}\n"
                f"Veuillez créer un fichier config.yaml à la racine du projet."
            )

        try:
            with open(self.config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(
                f"Erreur de syntaxe YAML dans {self.config_path}: {e}\n"
                f"Vérifiez que le fichier est correctement formaté."
            )
        except Exception as e:
            raise RuntimeError(f"Erreur lors de la lecture de {self.config_path}: {e}")

        if config is None:
            raise ValueError(
                f"Le fichier de configuration {self.config_path} est vide.\n"
                f"Veuillez ajouter au minimum les sections: thresholds, ssh, reports."
            )

        # Validate configuration structure
        self._validate_config(config)

        # Expand paths in SSH configuration
        self._expand_paths(config)

        return config

    def _validate_config(self, config: dict[str, Any]) -> None:
        """
        Valide la structure de la configuration

        Args:
            config: Configuration chargée depuis le fichier YAML

        Raises:
            ValueError: Si la configuration est invalide
        """
        # Only thresholds and reports are required for local analysis
        # SSH is optional and only validated when needed (for capture command)
        required_sections = ["thresholds", "reports"]
        missing_sections = [section for section in required_sections if section not in config]

        if missing_sections:
            raise ValueError(
                f"Sections manquantes dans {self.config_path}: {', '.join(missing_sections)}\n"
                f"Sections requises: {', '.join(required_sections)}\n"
                f"Note: La section 'ssh' est optionnelle et requise uniquement pour la capture distante"
            )

        # Validate thresholds section
        if not isinstance(config["thresholds"], dict):
            raise ValueError("La section 'thresholds' doit être un dictionnaire")

        required_thresholds = [
            "packet_gap",
            "syn_synack_delay",
            "handshake_total",
            "rtt_warning",
            "rtt_critical",
            "retransmission_low",
            "retransmission_rate_low",
            "dns_response_warning",
            "dns_response_critical",
        ]
        missing_thresholds = [t for t in required_thresholds if t not in config["thresholds"]]
        if missing_thresholds:
            raise ValueError(f"Seuils manquants dans 'thresholds': {', '.join(missing_thresholds)}")

        # Validate thresholds types and values
        for key, value in config["thresholds"].items():
            if not isinstance(value, (int, float)):
                raise ValueError(
                    f"Le seuil '{key}' doit être un nombre (int ou float), " f"reçu: {type(value).__name__} ({value})"
                )
            if value < 0:
                raise ValueError(
                    f"Le seuil '{key}' ne peut pas être négatif: {value}\n"
                    f"Les seuils doivent être des valeurs positives."
                )

        # SSH section is optional - only validate if present
        # It will be validated when needed by validate_ssh_config() method
        if "ssh" in config and config["ssh"] is not None:
            if not isinstance(config["ssh"], dict):
                raise ValueError("La section 'ssh' doit être un dictionnaire")

        # Validate reports section
        if not isinstance(config["reports"], dict):
            raise ValueError("La section 'reports' doit être un dictionnaire")

        if "output_dir" not in config["reports"]:
            raise ValueError("Champ 'output_dir' manquant dans 'reports'")

    def _expand_paths(self, config: dict[str, Any]) -> None:
        """
        Expand user paths (like ~/.ssh/id_rsa) in SSH configuration

        Args:
            config: Configuration to modify in-place
        """
        if "ssh" in config and config["ssh"] is not None and "key_file" in config["ssh"]:
            key_file = config["ssh"]["key_file"]
            if key_file:
                # Expand ~ and environment variables
                expanded = os.path.expanduser(os.path.expandvars(key_file))
                config["ssh"]["key_file"] = expanded

    def validate_ssh_config(self) -> None:
        """
        Validate SSH configuration when needed (for capture command).

        Raises:
            ValueError: If SSH configuration is missing or invalid
        """
        if "ssh" not in self.config or self.config["ssh"] is None:
            raise ValueError(
                "Configuration SSH manquante.\n"
                "La section 'ssh' est requise pour la commande 'capture'.\n"
                "Ajoutez une section 'ssh' dans votre fichier config.yaml avec les champs: host, port, username"
            )

        ssh_config = self.config["ssh"]

        if not isinstance(ssh_config, dict):
            raise ValueError("La section 'ssh' doit être un dictionnaire")

        required_ssh_fields = ["host", "port", "username"]
        missing_ssh = [f for f in required_ssh_fields if f not in ssh_config]

        if missing_ssh:
            raise ValueError(
                f"Champs manquants dans 'ssh': {', '.join(missing_ssh)}\n"
                f"Champs requis pour la capture: {', '.join(required_ssh_fields)}"
            )

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Récupère une valeur de configuration par son chemin

        Args:
            key_path: Chemin de la clé (ex: "thresholds.rtt_warning")
            default: Valeur par défaut si la clé n'existe pas

        Returns:
            Valeur de la configuration
        """
        keys = key_path.split(".")
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    @property
    def thresholds(self) -> dict[str, float]:
        """Retourne tous les seuils configurés"""
        return self.config.get("thresholds", {})

    @property
    def ssh_config(self) -> dict[str, Any]:
        """Retourne la configuration SSH"""
        return self.config.get("ssh", {})

    @property
    def report_config(self) -> dict[str, Any]:
        """Retourne la configuration des rapports"""
        return self.config.get("reports", {})


def get_config(config_path: Optional[str] = None) -> Config:
    """
    Crée et retourne une instance de configuration

    Args:
        config_path: Chemin vers le fichier de configuration.
                     Si None, utilise config.yaml à la racine du projet.

    Returns:
        Instance de Config

    Raises:
        FileNotFoundError: Si le fichier de configuration n'existe pas
        ValueError: Si la configuration est invalide ou mal formatée
    """
    return Config(config_path)
