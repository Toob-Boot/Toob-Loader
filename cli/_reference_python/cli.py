"""Toob CLI — root command group and sub-command registration."""

from __future__ import annotations

import os
import sys

# Ensure UTF-8 output on Windows terminals (prevents UnicodeEncodeError
# when click tries to print characters outside the system codepage).
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

import click  # noqa: E402

from toob import __version__  # noqa: E402
from toob.commands.chip import chip  # noqa: E402
from toob.commands.registry import registry  # noqa: E402
from toob.commands.build import build  # noqa: E402


@click.group()
@click.version_option(version=__version__, prog_name="toob")
def main() -> None:
    """Toob — Hardware Package Manager for the Toob-Boot ecosystem."""


main.add_command(registry)
main.add_command(chip)
main.add_command(build)
