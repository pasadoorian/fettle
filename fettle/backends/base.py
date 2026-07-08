"""The backend contract every distro implements.

A backend advertises the subset of actions it implements via ``supported``; the
CLI hides the rest (no faking an action a distro doesn't have). Action methods
have a default that raises :class:`NotImplementedError`, so a backend only writes
the methods it actually supports — capabilities are added incrementally.
``firmware_updates`` is concrete here because fwupd works the same on every distro.
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
    "config_drift", "firmware", "kernels", "aur_audit", "aur_ioc_scan",
    "source_audit", "integrity",
)


@dataclass
class Context:
    """Everything a backend action needs, passed in explicitly (never global)."""

    output: "Output"
    config: "Config"
    dry_run: bool = False
    assume_yes: bool = False
    auto_rebuild: bool = False
    root: Path = Path("/")  # injected so filesystem reads are testable
    sudo_user: str | None = None  # the invoking (non-root) user, for as_user drops
    user_home: Path = Path.home()

    # -- command execution (the dry-run gate lives here) ---------------------
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

    # -- interaction (all honor dry-run / assume_yes) ------------------------
    def confirm(self, question: str, *, default: bool = False) -> bool:
        if self.dry_run:
            return False
        if self.assume_yes:
            return True
        try:
            ans = input(f"  {question} [y/N] ").strip().lower()
        except EOFError:
            return default
        return ans in ("y", "yes")

    def ask(self, prompt: str) -> str:
        if self.dry_run:
            return ""
        try:
            return input(f"  {prompt}").strip()
        except EOFError:
            return ""

    def select(self, items, *, prompt: str) -> list[str]:
        """Per-item y/n/a(=all)/q(=quit) chooser. dry-run -> none; assume_yes -> all."""
        items = list(items)
        if self.dry_run or not items:
            return []
        if self.assume_yes:
            return items
        chosen: list[str] = []
        take_all = False
        for it in items:
            if take_all:
                chosen.append(it)
                continue
            try:
                ans = input(f"  {prompt} '{it}'? [y/n/a=all/q=quit] ").strip().lower()
            except EOFError:
                break
            if ans in ("y", "yes"):
                chosen.append(it)
            elif ans == "a":
                take_all = True
                chosen.append(it)
            elif ans == "q":
                break
        return chosen


@dataclass
class Result:
    ok: bool = True
    summary: str = ""


class PackageBackend(abc.ABC):
    """A distro's package/maintenance operations (one method per action)."""

    name: str = "base"
    supported: set[str] = set()

    def supports(self, action: str) -> bool:
        return action in self.supported

    def supply_chain_sources(self):
        """Package Supply Chain providers for this distro (empty by default)."""
        return []

    # -- actions (overridden per backend; NotImplementedError = not yet built) --
    def clean_caches(self, ctx: Context) -> Result:
        raise NotImplementedError

    def update_system(self, ctx: Context) -> Result:
        raise NotImplementedError

    def update_extras(self, ctx: Context) -> Result:
        raise NotImplementedError

    def check_foreign_orphans(self, ctx: Context) -> Result:
        raise NotImplementedError

    def check_rebuilds(self, ctx: Context) -> Result:
        raise NotImplementedError

    def check_python_rebuilds(self, ctx: Context) -> Result:
        raise NotImplementedError

    def check_config_drift(self, ctx: Context) -> Result:
        raise NotImplementedError

    def manage_kernels(self, ctx: Context) -> Result:
        raise NotImplementedError

    def verify_integrity(self, scan) -> None:
        """sys-audit `packages` check — verify installed files against the package
        DB. Takes a ``secure.base.Scan`` and emits through it (the one distro-
        specific sys-audit check; see PLAN §3.7)."""
        raise NotImplementedError

    def pending_upgrades(self, ctx: Context) -> list[tuple[str, str, str]]:
        """Packages that ``update`` would upgrade, as ``(name, old_ver, new_ver)``.

        Read-only (no root, no system change) — used by ``-u --dry-run`` and the
        Upgrade Checker. Empty list when up to date or the query tool is absent.
        """
        return []

    # -- firmware is distro-neutral: fwupd works everywhere ------------------
    def firmware_updates(self, ctx: Context) -> Result:
        from .. import command

        out = ctx.output
        if not command.which("fwupdmgr"):
            out.note("fwupdmgr not installed; skipping firmware check.")
            return Result()
        ctx.execute(["fwupdmgr", "refresh"], quiet=True, msg="firmware metadata refreshed")
        if ctx.dry_run:
            out.note("would run: fwupdmgr get-updates")
            return Result()
        proc = command.run(["fwupdmgr", "get-updates"], capture=True)
        text = (proc.stdout or "").strip()
        if text and "no updates" not in text.lower() and "No updatable" not in text:
            out.note("firmware updates available:")
            print(text)
            out.summary_add("firmware updates available")
            out.next_step("apply firmware updates: fwupdmgr update")
        else:
            out.ok("no firmware updates available.")
        return Result()
