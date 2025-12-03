"""
Module de gestion de la configuration
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any


class Config:
    """Gestionnaire de configuration pour l'analyseur PCAP"""

    def __init__(self, config_path: str = None):
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

    def _load_config(self) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier YAML"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Fichier de configuration non trouvé: {self.config_path}")

        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Récupère une valeur de configuration par son chemin

        Args:
            key_path: Chemin de la clé (ex: "thresholds.rtt_warning")
            default: Valeur par défaut si la clé n'existe pas

        Returns:
            Valeur de la configuration
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    @property
    def thresholds(self) -> Dict[str, float]:
        """Retourne tous les seuils configurés"""
        return self.config.get('thresholds', {})

    @property
    def ssh_config(self) -> Dict[str, Any]:
        """Retourne la configuration SSH"""
        return self.config.get('ssh', {})

    @property
    def report_config(self) -> Dict[str, Any]:
        """Retourne la configuration des rapports"""
        return self.config.get('reports', {})


# Instance globale de configuration
_config_instance = None


def get_config(config_path: str = None) -> Config:
    """
    Retourne l'instance de configuration (singleton)

    Args:
        config_path: Chemin vers le fichier de configuration

    Returns:
        Instance de Config
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config(config_path)
    return _config_instance
