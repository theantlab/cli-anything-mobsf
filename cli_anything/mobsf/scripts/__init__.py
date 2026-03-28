"""Bundled helper scripts for the analysis pipeline."""
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent


def script_path(name):
    """Get the absolute path to a bundled script."""
    return SCRIPTS_DIR / name


def dictionary_path():
    """Get the absolute path to the searchstrings dictionary."""
    return SCRIPTS_DIR / "searchstrings.dic"
