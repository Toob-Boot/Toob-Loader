"""Platform-safe path resolution for the Toob CLI.

All paths in the Toob ecosystem are resolved through this module to
guarantee Windows / macOS / Linux compatibility.  No module outside
this file should construct Toob-specific paths manually.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

# Sentinel file that identifies the root of a Toob-Loader project.
_PROJECT_MARKER = "CMakeLists.txt"
_PROJECT_SIGNATURE = "toob-boot"

DEFAULT_REGISTRY_URL = "https://github.com/toob-boot/toob-registry.git"


def get_toob_home() -> Path:
    """Return the global Toob home directory (``~/.toob/``).

    Uses ``pathlib.Path.home()`` which resolves correctly on every OS,
    unlike ``$HOME`` which is unreliable on Windows.
    """
    home = Path.home() / ".toob"
    home.mkdir(parents=True, exist_ok=True)
    return home


def get_registry_dir() -> Path:
    """Return the path to the local registry cache (``~/.toob/registry/``)."""
    return get_toob_home() / "registry"


def get_global_config_path() -> Path:
    """Return the path to the global CLI config (``~/.toob/config.toml``)."""
    return get_toob_home() / "config.toml"


def find_project_root(start: Optional[Path] = None) -> Path:
    """Walk upward from *start* (default: cwd) to locate the project root.

    The root is identified by a ``CMakeLists.txt`` whose content contains
    the string ``toob-boot``.

    Raises:
        FileNotFoundError: If no project root is found.
    """
    current = (start or Path.cwd()).resolve()

    for ancestor in (current, *current.parents):
        candidate = ancestor / _PROJECT_MARKER
        if candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8", errors="ignore")
                if _PROJECT_SIGNATURE in text:
                    return ancestor
            except OSError:
                continue

    raise FileNotFoundError(
        "Could not locate a Toob-Loader project root. "
        f"No {_PROJECT_MARKER} containing '{_PROJECT_SIGNATURE}' found "
        f"in any parent of {current}"
    )


def get_hal_dir(project_root: Path) -> Path:
    """Return ``<project>/toobloader/hal/``."""
    return project_root / "toobloader" / "hal"


def get_lockfile_path(project_root: Path) -> Path:
    """Return ``<project>/toob.lock``."""
    return project_root / "toob.lock"


def get_gitignore_path(project_root: Path) -> Path:
    """Return ``<project>/.gitignore``."""
    return project_root / ".gitignore"


def get_device_toml_path(project_root: Path) -> Path:
    """Return the default device manifest path."""
    return project_root / "cli" / "examples" / "manifests" / "device.toml"
