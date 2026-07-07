"""Shared AUR helpers used by the audit (`-A`), the IoC scan (`-S`), and the
normalized `pkg-audit` provider — the Python analogue of ``lib/aur-common.sh``.

Kept dependency-light (only ``command`` + the IOC/util helpers) so any of the
three entry points can pull the installed-foreign set, an IOC feed, or run the
JS-cache trace scan without duplicating logic.
"""

from __future__ import annotations

import os
from pathlib import Path

from .. import command
from ..util import matches_any
from . import ioc as aur_ioc

# JS package-manager cache roots scanned for malicious-dependency traces.
JS_CACHE_SUBDIRS = (".npm", ".bun", ".cache/yarn", ".local/share/pnpm", ".cache/pnpm")


def foreign_packages(ctx) -> list[str]:
    """Installed foreign (AUR/manual) package names, minus ``exclude_foreign``."""
    names = command.run(["pacman", "-Qmq"], capture=True).stdout.split()
    return [n for n in names if not matches_any(n, ctx.config.exclude_foreign)]


def ioc_feed(ctx) -> aur_ioc.IOC:
    """The IOC feed client, cache shared across audit/scan/pkg-audit."""
    return aur_ioc.IOC(
        cache_dir=ctx.user_home / ".cache/fettle/ioc",
        campaigns=ctx.config.aur_ioc_campaigns,
        ttl=ctx.config.aur_ioc_cache_ttl,
    )


def js_cache_hits(names, home: Path):
    """Return ``(name, path)`` for every JS-cache entry whose name contains a
    known-malicious dependency name (case-insensitive), pruned at depth 6."""
    if not names:
        return []
    lowered = {n.lower() for n in names}
    hits: list[tuple[str, str]] = []
    for sub in JS_CACHE_SUBDIRS:
        root = home / sub
        if not root.is_dir():
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            if len(Path(dirpath).parts) - base_depth >= 6:
                dirnames[:] = []  # prune deeper than 6 levels
                continue
            for entry in (*dirnames, *filenames):
                el = entry.lower()
                for n in lowered:
                    if n in el:
                        hits.append((n, str(Path(dirpath) / entry)))
    return hits
