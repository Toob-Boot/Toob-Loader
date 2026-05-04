"""``toob build`` — orchestrated build pipeline.

Sequence:
    1. Resolve chip from device.toml
    2. Run manifest compiler (generates headers + linker scripts)
    3. Run cmake configure (with correct toolchain)
    4. Run ninja build
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Optional

import click

from toob.core.paths import find_project_root


@click.command()
@click.option(
    "--manifest",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to device.toml.  Auto-detected if omitted.",
)
@click.option(
    "--build-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Build output directory.  Default: builds/build_<chip>",
)
@click.option(
    "--toolchain-path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to the cross-compiler bin/ directory.  Auto-detected for Espressif.",
)
def build(
    manifest: Optional[Path],
    build_dir: Optional[Path],
    toolchain_path: Optional[Path],
) -> None:
    """Run the full build pipeline (manifest -> cmake -> ninja)."""
    try:
        root = find_project_root()
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc

    # 1. Resolve device manifest
    if manifest is None:
        manifest = root / "cli" / "examples" / "manifests" / "device.toml"
    if not manifest.is_file():
        raise click.ClickException(f"Device manifest not found: {manifest}")

    toml_data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    device = toml_data.get("device", {})
    chip = device.get("chip")
    vendor = device.get("vendor")
    if not chip or not vendor:
        raise click.ClickException(
            "device.toml must define [device] with 'chip' and 'vendor'."
        )

    click.echo(f"[toob] Target: {vendor}/{chip}")

    # 2. Resolve hardware.json (spawned chips in hal/chips/, or registry)
    hw_json = root / "toobloader" / "hal" / "chips" / chip / "hardware.json"
    if not hw_json.is_file():
        raise click.ClickException(
            f"hardware.json not found for chip '{chip}'. "
            "Run `toob chip add` or `toob chip spawn` first."
        )

    # 3. Determine build directory
    if build_dir is None:
        build_dir = root / "builds" / f"build_{chip}"
    generated_dir = build_dir / "generated"
    generated_dir.mkdir(parents=True, exist_ok=True)

    # 4. Run manifest compiler
    manifest_py = root / "cli" / "manifest_compiler" / "toob_manifest.py"
    if not manifest_py.is_file():
        raise click.ClickException(
            f"Manifest compiler not found at {manifest_py}"
        )

    click.echo("[toob] Running manifest compiler ...")
    _run(
        [sys.executable, str(manifest_py),
         "--toml", str(manifest),
         "--hardware", str(hw_json),
         "--outdir", str(generated_dir)],
        cwd=root,
    )

    # 5. Run SUIT code generator (generate.sh) if available
    generate_sh = root / "cli" / "suit" / "generate.sh"
    if generate_sh.is_file():
        bash = _find_bash()
        if bash:
            click.echo("[toob] Running SUIT code generator ...")
            _run(
                [bash, str(generate_sh),
                 str(generated_dir), str(manifest), chip],
                cwd=root,
            )
        else:
            click.echo("[toob] Skipping SUIT code generator (bash not found).")

    # 6. Resolve toolchain & architecture from chip metadata
    toolchain_name = "toolchain-riscv32.cmake"
    arch = "riscv32"
    toolchain_prefix = "riscv32-unknown-elf-"
    hal_vendor = vendor  # CMake uses HAL directory names, not human-friendly ones

    chip_manifest_path = (
        root / "toobloader" / "hal" / "chips" / chip / "chip_manifest.json"
    )
    if chip_manifest_path.is_file():
        cm = json.loads(chip_manifest_path.read_text(encoding="utf-8"))
        toolchain_name = cm.get("toolchain", toolchain_name)
        arch = cm.get("arch", arch)
        toolchain_prefix = cm.get("toolchain_prefix", toolchain_prefix)
        hal_vendor = cm.get("vendor", hal_vendor)

    toolchain = root / "cmake" / toolchain_name

    # 7. Generate toob_config.cmake (bridges chip identity into CMake)
    config_cmake = generated_dir / "toob_config.cmake"
    config_cmake.write_text(
        f'set(TOOB_ARCH "{arch}")\n'
        f'set(TOOB_VENDOR "{hal_vendor}")\n'
        f'set(TOOB_CHIP "{chip}")\n'
        f'set(CMAKE_TOOLCHAIN_FILE "${{CMAKE_SOURCE_DIR}}/cmake/{toolchain_name}")\n'
        f'set(TOOLCHAIN_PREFIX "{toolchain_prefix}")\n',
        encoding="utf-8",
    )

    # 8. Ensure cross-compiler is in PATH
    if toolchain_path is None:
        toolchain_path = _find_toolchain_bin(toolchain_prefix)
    if toolchain_path:
        os.environ["PATH"] = str(toolchain_path) + os.pathsep + os.environ.get("PATH", "")
        click.echo(f"[toob] Toolchain: {toolchain_path}")

    # 9. CMake configure
    click.echo("[toob] Configuring CMake ...")
    cmake_args = [
        "cmake",
        "-G", "Ninja",
        "-B", str(build_dir),
        "-S", str(root),
        f"-DCMAKE_TOOLCHAIN_FILE={toolchain}",
        f"-DTOOLCHAIN_PREFIX={toolchain_prefix}",
        "-DCMAKE_SYSTEM_NAME=Generic",
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY",
        f"-DTOOB_DEVICE_MANIFEST={manifest}",
    ]
    _run(cmake_args, cwd=root)

    # 10. Build
    click.echo("[toob] Building ...")
    _run(["cmake", "--build", str(build_dir)], cwd=root)

    click.echo("[toob] Build complete.")


def _run(cmd: list[str], cwd: Path) -> None:
    """Run a subprocess, forwarding stdout/stderr."""
    try:
        subprocess.run(
            [str(c) for c in cmd],
            cwd=str(cwd),
            check=True,
        )
    except FileNotFoundError:
        raise click.ClickException(
            f"Command not found: {cmd[0]}. Is it installed and in PATH?"
        )
    except subprocess.CalledProcessError as exc:
        raise click.ClickException(
            f"Command failed (exit {exc.returncode}): "
            f"{' '.join(str(c) for c in cmd)}"
        )


def _find_bash() -> Optional[str]:
    """Locate a working ``bash`` binary.

    On Windows, plain ``bash`` often resolves to WSL which may not be
    installed.  Git-for-Windows ships its own bash under
    ``C:/Program Files/Git/bin/bash.exe`` which is more reliable.
    """
    if sys.platform == "win32":
        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        if git_bash.is_file():
            return str(git_bash)
    return shutil.which("bash")


def _find_toolchain_bin(prefix: str) -> Optional[Path]:
    """Auto-detect the cross-compiler bin directory.

    Searches well-known Espressif install paths on Windows and falls
    back to checking if the compiler is already in PATH.
    """
    # Already in PATH?
    compiler_name = f"{prefix}gcc"
    if shutil.which(compiler_name):
        return None  # No PATH modification needed

    # Espressif IDF standard layout: C:\Espressif\tools\<triplet>\<version>\<triplet>\bin
    if sys.platform == "win32":
        pattern = f"C:/Espressif/tools/{prefix.rstrip('-')}/*/{prefix.rstrip('-')}/bin"
        candidates = sorted(glob.glob(pattern), reverse=True)
        for candidate in candidates:
            if Path(candidate, f"{compiler_name}.exe").is_file():
                return Path(candidate)

    return None

