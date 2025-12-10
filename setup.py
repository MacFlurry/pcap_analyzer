"""
Configuration d'installation pour PCAP Analyzer
"""

import sys
from pathlib import Path

from setuptools import find_packages, setup

# Add src to path to import __version__
sys.path.insert(0, str(Path(__file__).parent / "src"))
from __version__ import __version__

# Lecture du README pour la description longue
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

setup(
    name="pcap-analyzer",
    version=__version__,
    description="Analyseur automatisé des causes de latence réseau",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="PCAP Analyzer Contributors",
    author_email="",
    url="https://github.com/MacFlurry/pcap_analyzer",
    license="MIT",
    packages=find_packages(),
    package_data={
        "": ["templates/*.html"],
    },
    include_package_data=True,
    install_requires=[
        "scapy>=2.5.0,<3.0",
        "dpkt>=1.9.8,<2.0",  # Fast packet parsing (3-5x faster than Scapy)
        "paramiko>=3.4.0,<4.0",
        "pyyaml>=6.0,<7.0",
        "jinja2>=3.1.2,<4.0",
        "rich>=13.7.0,<14.0",
        "click>=8.1.7,<9.0",
        "numpy>=1.24.0",  # NumPy 2.x compatible (tested with 2.0.2)
        "psutil>=5.9.0,<6.0",  # Sprint 10: Memory monitoring and system resource tracking
    ],
    entry_points={
        "console_scripts": [
            "pcap_analyzer=src.cli:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="network pcap analysis latency tcp dns icmp monitoring",
)
