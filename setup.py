#!/usr/bin/env python3
"""Bastion: Setup and installation script.

Autonomous Zero-Trust Identity Graph, Real-Time Threat Detection,
Lateral Movement Analysis, and Forensic Telemetry Kernel in ANSI SQL.
"""

from setuptools import setup, find_packages

setup(
    name="bastion-sql",
    version="1.0.0",
    description="Autonomous Zero-Trust Identity Graph, Real-Time Threat Detection, Lateral Movement Analysis, and Forensic Telemetry Kernel in ANSI SQL",
    author="Aneesh Krishna Parthasarathy",
    author_email="aneeshkrishnaparthasarathy@gmail.com",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "bastion": ["../sql/**/*.sql"],
    },
    entry_points={
        "console_scripts": [
            "bastion=bastion.cli:main",
        ],
    },
    python_requires=">=3.10",
)
