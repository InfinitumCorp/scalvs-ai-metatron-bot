"""Paths for the saved toggle, the geo lockfile, and the downloaded datasets."""

from __future__ import annotations

import os
from pathlib import Path


def source_root() -> Path:
    """Return the product source root that holds data/geo.lock.json."""
    override = os.environ.get("SCALVS_METATRON_ROOT")
    if override:
        return Path(override)
    packaged = Path(__file__).resolve().parents[1]
    if (packaged / "data" / "geo.lock.json").is_file():
        return packaged
    cwd = Path.cwd()
    if (cwd / "data" / "geo.lock.json").is_file():
        return cwd
    return cwd


def settings_path(explicit: Path | str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    override = os.environ.get("SCALVS_METATRON_CONFIG")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "scalvs-metatron" / "settings.json"


def geo_data_dir(explicit: Path | str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    override = os.environ.get("SCALVS_GEO_DATA_DIR")
    if override:
        return Path(override)
    return source_root() / "data" / "geo"


def geo_lock_path(explicit: Path | str | None = None) -> Path:
    if explicit:
        return Path(explicit)
    override = os.environ.get("SCALVS_GEO_LOCKFILE")
    if override:
        return Path(override)
    return source_root() / "data" / "geo.lock.json"
