"""``toob chip`` sub-commands — add, spawn, remove, list, info."""

from __future__ import annotations

import click

from toob.core.installer import ChipInstaller
from toob.core.paths import find_project_root
from toob.core.registry_cache import RegistryCache


@click.group()
def chip() -> None:
    """Manage chip HAL packages."""


@chip.command(name="list")
def list_chips() -> None:
    """List all chips available in the registry."""
    cache = RegistryCache()
    try:
        chips = cache.list_chips()
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc

    if not chips:
        click.echo("Registry is empty.")
        return

    click.echo(f"{'Chip':<20} {'Vendor':<12} {'Arch':<16} {'Version':<10}")
    click.echo("-" * 58)
    for name in sorted(chips):
        ci = chips[name]
        click.echo(f"{ci.name:<20} {ci.vendor:<12} {ci.arch:<16} {ci.version:<10}")


@chip.command()
@click.argument("name")
def info(name: str) -> None:
    """Show detailed information about a chip."""
    cache = RegistryCache()
    try:
        ci = cache.get_chip(name)
    except (FileNotFoundError, KeyError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"  Name:          {ci.name}")
    click.echo(f"  Version:       {ci.version}")
    click.echo(f"  Vendor:        {ci.vendor}")
    click.echo(f"  Architecture:  {ci.arch}")
    click.echo(f"  Toolchain:     {ci.toolchain}")
    click.echo(f"  Description:   {ci.description or '(none)'}")
    click.echo(f"  Min Toob:      {ci.min_toob_version}")


@chip.command()
@click.argument("name")
def add(name: str) -> None:
    """Install a chip HAL from the registry."""
    try:
        root = find_project_root()
        cache = RegistryCache()
        installer = ChipInstaller(root, cache)
        installer.add(name)
    except (FileNotFoundError, KeyError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


@chip.command()
@click.argument("name")
def spawn(name: str) -> None:
    """Install a chip HAL as locally editable (tracked by git)."""
    try:
        root = find_project_root()
        cache = RegistryCache()
        installer = ChipInstaller(root, cache)
        installer.spawn(name)
    except (FileNotFoundError, KeyError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc


@chip.command()
@click.argument("name")
def remove(name: str) -> None:
    """Uninstall a chip HAL and its unshared dependencies."""
    try:
        root = find_project_root()
        cache = RegistryCache()
        installer = ChipInstaller(root, cache)
        installer.remove(name)
    except (FileNotFoundError, KeyError, RuntimeError) as exc:
        raise click.ClickException(str(exc)) from exc
