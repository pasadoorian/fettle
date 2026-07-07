"""Distro-agnostic orchestration: run the requested actions against a backend.

Section titles and the step counter live here; the backend methods only emit
status. Actions not yet implemented print a note (they raise NotImplementedError
in the ABC) so a half-built backend degrades gracefully.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .backends.base import Context, PackageBackend

# Human-facing section titles (mirrors update.sh's headers).
TITLES = {
    "clean": "Cleaning caches",
    "orphans": "Foreign & orphaned packages",
    "update": "Updating packages",
    "rebuilds": "Rebuild check",
    "python_rebuild": "Python rebuild check",
    "config_drift": "Config file drift",
    "firmware": "Firmware",
    "kernels": "Kernel management",
    "aur_audit": "Package supply-chain audit",
    "aur_scan": "Package supply-chain scan",
    "integrity": "Package integrity",
    "source_audit": "Package supply-chain audit",
}


def _update(backend: "PackageBackend", ctx: "Context") -> None:
    backend.update_system(ctx)
    backend.update_extras(ctx)


# action name -> callable(backend, ctx). Only implemented actions appear here.
HANDLERS = {
    "clean": lambda b, c: b.clean_caches(c),
    "update": _update,
    "orphans": lambda b, c: b.check_foreign_orphans(c),
    "rebuilds": lambda b, c: b.check_rebuilds(c),
    "python_rebuild": lambda b, c: b.check_python_rebuilds(c),
    "config_drift": lambda b, c: b.check_config_drift(c),
    "firmware": lambda b, c: b.firmware_updates(c),
    "kernels": lambda b, c: b.manage_kernels(c),
}


def run(actions: list[str], backend: "PackageBackend", ctx: "Context") -> None:
    out = ctx.output
    out.step_total = len(actions)
    for name in actions:
        out.section(TITLES.get(name, name))
        handler = HANDLERS.get(name)
        if handler is None:
            out.note(f"'{name}' not yet implemented — coming in a later milestone")
            continue
        try:
            handler(backend, ctx)
        except NotImplementedError:
            out.note(f"'{name}' not yet implemented for the {backend.name} backend")
    out.print_summary()
