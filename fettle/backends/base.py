"""The backend contract every distro implements.

A backend advertises the subset of actions it implements via ``supported``; the
CLI hides the rest (no faking an action a distro doesn't have). Action methods
have a default that raises :class:`NotImplementedError`, so a backend only writes
the methods it actually supports — capabilities are added incrementally.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # imported only for type hints — keeps runtime import-free
    from ..config import Config
    from ..output import Output

# Every action name fettle knows about (union across all backends).
ALL_ACTIONS = (
    "clean", "orphans", "update", "rebuilds", "python_rebuild",
    "config_drift", "firmware", "kernels", "aur_audit", "aur_scan",
    "source_audit", "integrity",
)


@dataclass
class Context:
    """Everything a backend action needs, passed in explicitly (never global)."""

    output: "Output"
    config: "Config"
    dry_run: bool = False
    assume_yes: bool = False
    root: Path = Path("/")  # injected so filesystem reads are testable
    sudo_user: str | None = None  # the invoking (non-root) user, for as_user drops
    user_home: Path = Path.home()

    def execute(self, cmd, *, as_user: str | None = None, quiet: bool = False, msg: str = ""):
        """Run a command, honoring dry-run in one place.

        - dry-run: print what would run and execute nothing.
        - quiet: summarize via :meth:`Output.run_quiet` (one-line status).
        - otherwise: stream the command (for interactive upgrades).
        """
        from .. import command

        argv = [str(c) for c in cmd]
        if self.dry_run:
            shown = " ".join(argv)
            self.output.note(f"would run: {'(as ' + as_user + ') ' if as_user else ''}{shown}")
            return command.Proc(0)
        if quiet:
            return self.output.run_quiet(msg or " ".join(argv), argv, as_user=as_user)
        return command.run(argv, as_user=as_user)


@dataclass
class Result:
    ok: bool = True
    summary: str = ""


class PackageBackend(abc.ABC):
    """A distro's package/maintenance operations."""

    name: str = "base"
    supported: set[str] = set()

    def supports(self, action: str) -> bool:
        return action in self.supported

    # -- action methods (overridden per backend in later milestones) ---------
    def clean_caches(self, ctx: Context) -> Result:
        raise NotImplementedError

    def list_foreign(self, ctx: Context) -> list[str]:
        raise NotImplementedError

    def list_orphans(self, ctx: Context) -> list[str]:
        raise NotImplementedError

    def remove_orphans(self, pkgs: list[str], ctx: Context) -> Result:
        raise NotImplementedError

    def update_system(self, ctx: Context) -> Result:
        raise NotImplementedError

    def update_extras(self, ctx: Context) -> Result:
        raise NotImplementedError

    def check_rebuilds(self, ctx: Context) -> list[str]:
        raise NotImplementedError

    def rebuild(self, pkgs: list[str], ctx: Context) -> Result:
        raise NotImplementedError

    def config_drift(self, ctx: Context) -> list[Path]:
        raise NotImplementedError

    def firmware_updates(self, ctx: Context) -> Result:
        raise NotImplementedError

    def manage_kernels(self, ctx: Context) -> Result:
        raise NotImplementedError

    def verify_integrity(self, ctx: Context) -> Result:
        raise NotImplementedError
