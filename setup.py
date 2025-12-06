"""
Configuration d'installation pour PCAP Analyzer
"""

from setuptools import setup, find_packages
from pathlib import Path

# Lecture du README pour la description longue
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding='utf-8')

setup(
    name='pcap-analyzer',
    version='2.0.0',
    description='Analyseur automatisé des causes de latence réseau',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='PCAP Analyzer Contributors',
    author_email='',
    url='https://github.com/MacFlurry/pcap_analyzer',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'paramiko>=3.4.0',
        'pyyaml>=6.0',
        'jinja2>=3.1.2',
        'rich>=13.7.0',
        'click>=8.1.7',
        'numpy>=1.24.0',
    ],
    entry_points={
        'console_scripts': [
            'pcap_analyzer=src.cli:main',
        ],
    },
    python_requires='>=3.8',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: System :: Systems Administration',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    keywords='network pcap analysis latency tcp dns icmp monitoring',
)
