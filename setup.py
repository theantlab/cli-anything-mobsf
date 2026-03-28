"""Installer for cli-anything-mobsf."""
from setuptools import setup, find_namespace_packages

setup(
    name="cli-anything-mobsf",
    version="0.1.0",
    description="CLI-Anything harness for MobSF (Mobile Security Framework)",
    packages=find_namespace_packages(include=["cli_anything.*"]),
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "requests>=2.28",
    ],
    entry_points={
        "console_scripts": [
            "cli-anything-mobsf=cli_anything.mobsf.mobsf_cli:cli",
        ],
    },
)
