"""Chip installer — add, spawn, and remove logic.

Handles the file-system operations (copy / remove) and the coordination
between the registry cache, the lockfile, and the project's ``.gitignore``.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List

from toob.core.lockfile import Lockfile
from toob.core.paths import get_gitignore_path, get_hal_dir, get_lockfile_path
from toob.core.registry_cache import ChipInfo, RegistryCache

# Markers used inside .gitignore to fence toob-managed entries.
_GI_START = "# >>> toob-managed (do not edit) >>>"
_GI_END = "# <<< toob-managed <<<"


class ChipInstaller:
    """Orchestrates chip installation, spawning, and removal."""

    def __init__(self, project_root: Path, cache: RegistryCache) -> None:
        self._root = project_root
        self._cache = cache
        self._hal = get_hal_dir(project_root)
        self._lockpath = get_lockfile_path(project_root)
        self._lock = Lockfile.load(self._lockpath)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add(self, chip_name: str) -> None:
        """Install a chip from the registry (not tracked by git)."""
        if self._lock.has_chip(chip_name):
            entry = self._lock.get_chip(chip_name)
            if entry and entry.spawned:
                raise RuntimeError(
                    f"Chip '{chip_name}' is already spawned (locally editable). "
                    "Use `toob chip remove` first if you want to switch to add mode."
                )
            raise RuntimeError(f"Chip '{chip_name}' is already installed.")

        info = self._cache.get_chip(chip_name)
        self._install_chip(info)
        self._install_dependencies(info)

        self._lock.add_chip(
            chip_name,
            version=info.version,
            arch=info.arch,
            vendor=info.vendor,
            spawned=False,
        )
        self._lock.registry_commit = self._cache.head_commit()
        self._lock.save(self._lockpath)

        self._update_gitignore()
        print(f"Installed chip '{chip_name}' (v{info.version})  "
              f"[arch={info.arch}, vendor={info.vendor}]")

    def spawn(self, chip_name: str) -> None:
        """Install a chip as locally editable (tracked by git)."""
        if self._lock.has_chip(chip_name):
            entry = self._lock.get_chip(chip_name)
            if entry and not entry.spawned:
                raise RuntimeError(
                    f"Chip '{chip_name}' is already added (non-spawned). "
                    "Use `toob chip remove` first, then `toob chip spawn`."
                )
            raise RuntimeError(f"Chip '{chip_name}' is already spawned.")

        info = self._cache.get_chip(chip_name)
        self._install_chip(info)
        self._install_dependencies(info)

        self._lock.add_chip(
            chip_name,
            version=info.version,
            arch=info.arch,
            vendor=info.vendor,
            spawned=True,
        )
        self._lock.registry_commit = self._cache.head_commit()
        self._lock.save(self._lockpath)

        self._update_gitignore()
        print(f"Spawned chip '{chip_name}' (v{info.version})  "
              f"[locally editable — tracked by git]")

    def remove(self, chip_name: str) -> None:
        """Uninstall a chip and clean up unshared dependencies."""
        entry = self._lock.remove_chip(chip_name)
        if entry is None:
            raise RuntimeError(f"Chip '{chip_name}' is not installed.")

        # Remove chip source files
        chip_dir = self._hal / "chips" / chip_name
        if chip_dir.is_dir():
            shutil.rmtree(chip_dir)

        # Remove arch layer only if no other chip needs it
        if not self._lock.is_arch_shared(entry.arch, exclude=chip_name):
            arch_dir = self._hal / "arch" / entry.arch
            if arch_dir.is_dir():
                shutil.rmtree(arch_dir)

        # Remove vendor layer only if no other chip needs it
        if not self._lock.is_vendor_shared(entry.vendor, exclude=chip_name):
            vendor_dir = self._hal / "vendor" / entry.vendor
            if vendor_dir.is_dir():
                shutil.rmtree(vendor_dir)

        self._lock.save(self._lockpath)
        self._update_gitignore()
        print(f"Removed chip '{chip_name}'.")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _install_chip(self, info: ChipInfo) -> None:
        """Copy chip source from registry cache into the project."""
        src = self._cache.chip_source_path(info.name)
        dst = self._hal / "chips" / info.name
        self._copy_tree(src, dst)

    def _install_dependencies(self, info: ChipInfo) -> None:
        """Copy arch, vendor, and toolchain files if not already present."""
        # Architecture layer
        arch_dst = self._hal / "arch" / info.arch
        if not arch_dst.is_dir():
            arch_src = self._cache.arch_source_path(info.arch)
            self._copy_tree(arch_src, arch_dst)

        # Vendor layer
        vendor_dst = self._hal / "vendor" / info.vendor
        if not vendor_dst.is_dir():
            vendor_src = self._cache.vendor_source_path(info.vendor)
            self._copy_tree(vendor_src, vendor_dst)

        # Toolchain file
        tc_dst = self._root / "cmake" / info.toolchain
        if not tc_dst.is_file():
            tc_src = self._cache.toolchain_source_path(info.toolchain)
            if tc_src.is_file():
                tc_dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(tc_src), str(tc_dst))

    def _copy_tree(self, src: Path, dst: Path) -> None:
        """Recursively copy *src* to *dst*, overwriting if *dst* exists."""
        if not src.is_dir():
            raise FileNotFoundError(
                f"Registry source path does not exist: {src}\n"
                "The registry may be out of date. Run `toob registry sync`."
            )
        if dst.is_dir():
            shutil.rmtree(dst)
        shutil.copytree(str(src), str(dst))

    def _update_gitignore(self) -> None:
        """Rewrite the toob-managed section of ``.gitignore``.

        Only non-spawned chips and their non-shared dependencies are listed.
        Spawned chips are intentionally left out so they get committed.
        """
        managed_paths = self._compute_gitignore_entries()
        gi_path = get_gitignore_path(self._root)

        existing_lines: List[str] = []
        if gi_path.is_file():
            existing_lines = gi_path.read_text(encoding="utf-8").splitlines()

        # Strip old toob-managed section
        cleaned: List[str] = []
        inside_managed = False
        for line in existing_lines:
            if line.strip() == _GI_START:
                inside_managed = True
                continue
            if line.strip() == _GI_END:
                inside_managed = False
                continue
            if not inside_managed:
                cleaned.append(line)

        # Remove trailing blank lines before appending
        while cleaned and cleaned[-1].strip() == "":
            cleaned.pop()

        if managed_paths:
            cleaned.append("")
            cleaned.append(_GI_START)
            for p in sorted(managed_paths):
                cleaned.append(p)
            cleaned.append(_GI_END)

        cleaned.append("")  # Final newline
        gi_path.write_text("\n".join(cleaned), encoding="utf-8")

    def _compute_gitignore_entries(self) -> List[str]:
        """Determine which HAL paths should be gitignored.

        A path is gitignored only if ALL chips that depend on it are
        non-spawned (added).  If even one spawned chip uses an arch or
        vendor layer, that layer stays out of .gitignore.
        """
        entries: List[str] = []

        # Per-chip entries
        for name, entry in self._lock.chips.items():
            if not entry.spawned:
                entries.append(f"toobloader/hal/chips/{name}/")

        # Arch layers: gitignore only if every chip using it is non-spawned
        arches_used: dict[str, bool] = {}
        for name, entry in self._lock.chips.items():
            if entry.arch not in arches_used:
                arches_used[entry.arch] = True
            if entry.spawned:
                arches_used[entry.arch] = False

        for arch, should_ignore in arches_used.items():
            if should_ignore:
                entries.append(f"toobloader/hal/arch/{arch}/")

        # Vendor layers: same logic
        vendors_used: dict[str, bool] = {}
        for name, entry in self._lock.chips.items():
            if entry.vendor not in vendors_used:
                vendors_used[entry.vendor] = True
            if entry.spawned:
                vendors_used[entry.vendor] = False

        for vendor, should_ignore in vendors_used.items():
            if should_ignore:
                entries.append(f"toobloader/hal/vendor/{vendor}/")

        return entries
