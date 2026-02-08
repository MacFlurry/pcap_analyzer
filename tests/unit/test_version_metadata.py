"""Guards for release metadata/version consistency."""

from pathlib import Path
import re

from src.__version__ import __version__


def test_docker_label_version_matches_package_version():
    root = Path(__file__).resolve().parents[2]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    match = re.search(r'LABEL version="([^"]+)"', dockerfile)
    assert match, "Dockerfile must define LABEL version"
    assert match.group(1) == __version__


def test_readme_badge_version_matches_package_version():
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    match = re.search(r"version-([0-9]+\.[0-9]+\.[0-9]+)-blue\.svg", readme)
    assert match, "README version badge not found"
    assert match.group(1) == __version__


def test_architecture_doc_version_matches_package_version():
    root = Path(__file__).resolve().parents[2]
    architecture = (root / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    match = re.search(r"\*\*Version\*\*:\s*([0-9]+\.[0-9]+\.[0-9]+)", architecture)
    assert match, "docs/ARCHITECTURE.md version line not found"
    assert match.group(1) == __version__
