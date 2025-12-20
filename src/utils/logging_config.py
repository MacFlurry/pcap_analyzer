"""
Centralized logging configuration module.

Implements:
- OpenSSF Secure Coding Guide: Comprehensive logging for security events
- NIST SP 800-92: Guide to Computer Security Log Management
- OWASP Logging Cheat Sheet: Secure logging practices
- Python logging best practices: logging.config, handlers, formatters

Security Features:
- No DEBUG level logging in production (prevents data leaks)
- Log rotation to prevent disk exhaustion (CWE-770)
- Separate audit log for security events
- Structured logging support for SIEM integration
- File permissions set to 0600 (owner read/write only)
"""

import logging
import logging.config
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional

import yaml


class SecureRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    Rotating file handler with secure file permissions.

    Sets file permissions to 0600 (owner read/write only) to prevent
    unauthorized access to logs which may contain sensitive data.
    """

    def _open(self):
        """Override to set secure permissions on log files."""
        # Call parent to create/open file
        stream = super()._open()

        # Set secure permissions (0600 = owner read/write only)
        try:
            os.chmod(self.baseFilename, 0o600)
        except OSError as e:
            # Log warning but don't fail - permissions might already be set
            # or we might not have permission to change them
            logging.warning(f"Could not set secure permissions on {self.baseFilename}: {e}")

        return stream


def _validate_log_level(log_level: str) -> str:
    """
    Validate and normalize log level.

    Args:
        log_level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)

    Returns:
        Normalized log level string

    Raises:
        ValueError: If log level is invalid
    """
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    log_level = log_level.upper()

    if log_level not in valid_levels:
        raise ValueError(f"Invalid log level: {log_level}. Must be one of {valid_levels}")

    return log_level


def _create_log_directory(log_dir: str) -> Path:
    """
    Create log directory with secure permissions.

    Args:
        log_dir: Path to log directory

    Returns:
        Path object for log directory

    Raises:
        OSError: If directory creation fails
    """
    log_path = Path(log_dir).resolve()

    # Create directory if it doesn't exist
    log_path.mkdir(parents=True, exist_ok=True)

    # Set secure permissions (0700 = owner read/write/execute only)
    try:
        os.chmod(log_path, 0o700)
    except OSError as e:
        logging.warning(f"Could not set secure permissions on {log_path}: {e}")

    return log_path


def setup_logging(
    log_dir: str = "logs",
    log_level: str = "INFO",
    enable_console: bool = True,
    enable_file: bool = True,
    enable_audit: bool = True,
    log_format: str = "standard",
    config_file: Optional[str] = None,
) -> None:
    """
    Setup centralized logging configuration.

    Args:
        log_dir: Directory for log files (default: "logs")
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        enable_console: Enable console (stderr) logging
        enable_file: Enable file logging with rotation
        enable_audit: Enable separate audit log for security events
        log_format: Log format ("standard" or "json")
        config_file: Optional path to YAML config file (overrides other params)

    Raises:
        ValueError: If configuration is invalid
        OSError: If log directory creation fails

    Security Notes:
        - NEVER use DEBUG level in production (may leak sensitive data)
        - Log files are created with 0600 permissions (owner read/write only)
        - Audit logs are separated for security event tracking
        - Log rotation prevents disk exhaustion attacks (CWE-770)
    """
    # If config file is provided, use it
    if config_file and os.path.exists(config_file):
        _setup_logging_from_file(config_file, log_dir)
        return

    # Validate log level
    log_level = _validate_log_level(log_level)

    # Security: Warn if DEBUG level is used (should only be in development)
    if log_level == "DEBUG":
        print(
            "WARNING: DEBUG logging enabled. This may expose sensitive data. "
            "Never use DEBUG level in production!",
            file=sys.stderr
        )

    # Create log directory with secure permissions
    log_path = _create_log_directory(log_dir)

    # Build logging configuration dictionary
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
            "audit": {
                "format": "%(asctime)s [SECURITY] %(name)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {},
        "loggers": {},
        "root": {
            "level": log_level,
            "handlers": [],
        },
    }

    # Add JSON formatter if requested (requires python-json-logger)
    if log_format == "json":
        try:
            from pythonjsonlogger import jsonlogger
            config["formatters"]["json"] = {
                "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
            }
        except ImportError:
            print(
                "WARNING: python-json-logger not installed. Falling back to standard format.",
                file=sys.stderr
            )
            log_format = "standard"

    # Console handler (stderr)
    if enable_console:
        config["handlers"]["console"] = {
            "class": "logging.StreamHandler",
            "level": log_level,
            "formatter": log_format if log_format == "json" else "standard",
            "stream": "ext://sys.stderr",
        }
        config["root"]["handlers"].append("console")

    # File handler with rotation
    if enable_file:
        config["handlers"]["file"] = {
            "()": SecureRotatingFileHandler,
            "level": log_level,
            "formatter": log_format if log_format == "json" else "standard",
            "filename": str(log_path / "pcap_analyzer.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "encoding": "utf8",
        }
        config["root"]["handlers"].append("file")

    # Audit file handler (separate log for security events)
    if enable_audit:
        config["handlers"]["audit_file"] = {
            "()": SecureRotatingFileHandler,
            "level": "INFO",
            "formatter": "audit",
            "filename": str(log_path / "security_audit.log"),
            "maxBytes": 10485760,  # 10MB
            "backupCount": 10,  # Keep more audit logs
            "encoding": "utf8",
        }

        # Configure security-related loggers to use audit handler
        security_loggers = [
            "src.utils.file_validator",
            "src.utils.resource_limits",
            "src.ssh_capture",
            "src.utils.audit_logger",
            "src.utils.decompression_monitor",
            "src.utils.error_sanitizer",
        ]

        for logger_name in security_loggers:
            config["loggers"][logger_name] = {
                "level": "INFO",
                "handlers": ["audit_file"],
                "propagate": False,  # Don't propagate to root logger
            }

    # Apply configuration
    logging.config.dictConfig(config)

    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized: level={log_level}, console={enable_console}, "
                f"file={enable_file}, audit={enable_audit}, format={log_format}")
    logger.info(f"Log directory: {log_path}")


def _setup_logging_from_file(config_file: str, log_dir: str) -> None:
    """
    Setup logging from YAML configuration file.

    Args:
        config_file: Path to YAML configuration file
        log_dir: Base directory for log files (used to resolve relative paths)

    Raises:
        ValueError: If configuration file is invalid
        OSError: If configuration file cannot be read
    """
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)

        # Ensure log directory exists
        log_path = _create_log_directory(log_dir)

        # Update file paths to use absolute paths
        if "handlers" in config:
            for handler_name, handler_config in config["handlers"].items():
                if "filename" in handler_config:
                    # Convert relative paths to absolute
                    filename = handler_config["filename"]
                    if not os.path.isabs(filename):
                        # Remove leading "logs/" from filename if present
                        if filename.startswith("logs/"):
                            filename = filename[5:]  # Remove "logs/" prefix
                        handler_config["filename"] = str(log_path / filename)

                # Replace standard RotatingFileHandler with secure version
                if handler_config.get("class") == "logging.handlers.RotatingFileHandler":
                    handler_config["()"] = SecureRotatingFileHandler
                    del handler_config["class"]

        # Apply configuration
        logging.config.dictConfig(config)

        logger = logging.getLogger(__name__)
        logger.info(f"Logging initialized from config file: {config_file}")
        logger.info(f"Log directory: {log_path}")

    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in logging configuration: {e}")
    except Exception as e:
        raise OSError(f"Failed to load logging configuration from {config_file}: {e}")


def get_audit_logger(name: str = "audit") -> logging.Logger:
    """
    Get logger for security audit events.

    This logger writes to the security_audit.log file and is intended
    for logging security-relevant events such as:
    - File validation failures
    - Resource limit violations
    - Authentication failures
    - Path traversal attempts
    - Decompression bomb detection

    Args:
        name: Logger name (default: "audit")

    Returns:
        Logger instance configured for audit logging
    """
    return logging.getLogger(f"src.utils.audit_logger.{name}")


def shutdown_logging() -> None:
    """
    Shutdown logging and flush all handlers.

    Should be called before application exit to ensure all log
    messages are flushed to disk.
    """
    logging.shutdown()
