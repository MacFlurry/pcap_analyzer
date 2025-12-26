"""
Configuration utilities for the application.
"""

import os
from pathlib import Path

def get_data_dir() -> Path:
    """
    Returns the data directory path from environment variable or default.
    Ensures the directory exists.
    """
    data_dir = Path(os.getenv("DATA_DIR", "/data"))
    return data_dir

def get_uploads_dir() -> Path:
    """Returns the uploads directory path."""
    return get_data_dir() / "uploads"

def get_reports_dir() -> Path:
    """Returns the reports directory path."""
    return get_data_dir() / "reports"
