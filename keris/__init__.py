"""Keris — Modular Web Pentest Toolkit."""

from importlib import metadata

__all__ = ["__version__"]


def _version() -> str:
    try:
        return metadata.version("keris-toolkit")
    except metadata.PackageNotFoundError:
        return "0.4.4"


__version__ = _version()
