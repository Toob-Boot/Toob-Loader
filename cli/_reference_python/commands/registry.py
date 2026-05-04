"""``toob registry`` sub-commands."""

from __future__ import annotations

import click

from toob.core.registry_cache import RegistryCache


@click.group()
def registry() -> None:
    """Manage the chip registry cache."""


@registry.command()
def sync() -> None:
    """Synchronize the local registry cache with the remote repository."""
    cache = RegistryCache()
    action = "Updating" if cache.is_initialized else "Cloning"
    click.echo(f"[toob] {action} registry from {cache._remote} ...")
    cache.sync()
    click.echo(f"[toob] Registry synced.  HEAD = {cache.head_commit()}")
