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


def test_changelog_contains_current_version_section():
    root = Path(__file__).resolve().parents[2]
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{__version__}] - " in changelog, "CHANGELOG.md must contain a section for the current version"


def test_helm_chart_app_version_matches_package_version():
    root = Path(__file__).resolve().parents[2]
    chart = (root / "helm-chart" / "pcap-analyzer" / "Chart.yaml").read_text(encoding="utf-8")
    match = re.search(r'appVersion:\s*"([^"]+)"', chart)
    assert match, "Helm Chart.yaml appVersion not found"
    assert match.group(1) == __version__
