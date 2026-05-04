"""Git-backed registry cache manager.

Manages a shallow clone of the ``toob-chip-list`` repository under
``~/.toob/registry/``.  All network access is confined to this module.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from toob.core.paths import DEFAULT_REGISTRY_URL, get_registry_dir


@dataclass(frozen=True)
class ChipInfo:
    """Immutable metadata for a single chip from ``registry.json``."""

    name: str
    vendor: str
    arch: str
    toolchain: str
    path: str
    version: str
    description: str = ""
    min_toob_version: str = "0.1.0"


@dataclass
class RegistryIndex:
    """Parsed content of ``registry.json``."""

    version: int
    chips: Dict[str, ChipInfo] = field(default_factory=dict)


class RegistryCache:
    """Manages the local shallow-clone of the chip registry."""

    def __init__(
        self,
        registry_dir: Optional[Path] = None,
        remote_url: str = DEFAULT_REGISTRY_URL,
    ) -> None:
        self._dir = registry_dir or get_registry_dir()
        self._remote = remote_url
        self._index: Optional[RegistryIndex] = None

    @property
    def directory(self) -> Path:
        return self._dir

    @property
    def is_initialized(self) -> bool:
        return (self._dir / ".git").is_dir()

    # ------------------------------------------------------------------
    # Network operations
    # ------------------------------------------------------------------

    def sync(self) -> None:
        """Clone or fast-forward pull the registry."""
        if self.is_initialized:
            self._pull()
        else:
            self._clone()
        # Invalidate cached index after sync
        self._index = None

    def _clone(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        _run_git(
            ["clone", "--depth", "1", self._remote, str(self._dir)],
            cwd=self._dir.parent,
        )

    def _pull(self) -> None:
        _run_git(["pull", "--ff-only"], cwd=self._dir)

    # ------------------------------------------------------------------
    # Index access
    # ------------------------------------------------------------------

    def load_index(self) -> RegistryIndex:
        """Parse ``registry.json`` and return a typed index.

        Raises:
            FileNotFoundError: If the registry has never been synced.
        """
        if self._index is not None:
            return self._index

        index_path = self._dir / "registry.json"
        if not index_path.is_file():
            raise FileNotFoundError(
                "Registry not initialized. Run `toob registry sync` first."
            )

        raw = json.loads(index_path.read_text(encoding="utf-8"))
        chips: Dict[str, ChipInfo] = {}
        for name, entry in raw.get("chips", {}).items():
            chips[name] = ChipInfo(
                name=name,
                vendor=entry["vendor"],
                arch=entry["arch"],
                toolchain=entry["toolchain"],
                path=entry["path"],
                version=entry.get("version", "0.0.0"),
                description=entry.get("description", ""),
                min_toob_version=entry.get("min_toob_version", "0.1.0"),
            )

        self._index = RegistryIndex(version=raw.get("version", 1), chips=chips)
        return self._index

    def get_chip(self, name: str) -> ChipInfo:
        """Look up a single chip by name.

        Raises:
            KeyError: If the chip does not exist in the registry.
        """
        idx = self.load_index()
        if name not in idx.chips:
            available = ", ".join(sorted(idx.chips.keys())) or "(none)"
            raise KeyError(
                f"Chip '{name}' not found in registry.  "
                f"Available: {available}"
            )
        return idx.chips[name]

    def list_chips(self) -> Dict[str, ChipInfo]:
        """Return all chips in the registry."""
        return dict(self.load_index().chips)

    def chip_source_path(self, name: str) -> Path:
        """Absolute path to a chip's source directory in the cache."""
        info = self.get_chip(name)
        return self._dir / info.path

    def arch_source_path(self, arch: str) -> Path:
        """Absolute path to an architecture's source directory in the cache."""
        return self._dir / "arch" / arch

    def vendor_source_path(self, vendor: str) -> Path:
        """Absolute path to a vendor's source directory in the cache."""
        return self._dir / "vendor" / vendor

    def toolchain_source_path(self, filename: str) -> Path:
        """Absolute path to a toolchain cmake file in the cache."""
        return self._dir / "toolchains" / filename

    def head_commit(self) -> str:
        """Return the short SHA of the current HEAD in the cache."""
        if not self.is_initialized:
            return "uninitialized"
        result = _run_git(
            ["rev-parse", "--short", "HEAD"], cwd=self._dir, capture=True
        )
        return result.strip()


def _run_git(
    args: list[str],
    cwd: Path,
    capture: bool = False,
) -> str:
    """Execute a ``git`` subprocess.

    Raises:
        SystemExit: On non-zero return code (prints stderr).
    """
    cmd = ["git", *args]
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            check=True,
            capture_output=capture,
            text=True,
        )
        return result.stdout if capture else ""
    except FileNotFoundError:
        print("FATAL: 'git' is not installed or not in PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr or ""
        print(
            f"FATAL: git {' '.join(args)} failed (exit {exc.returncode}):\n{stderr}",
            file=sys.stderr,
        )
        sys.exit(1)
