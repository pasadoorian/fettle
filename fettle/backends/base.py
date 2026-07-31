"""The backend contract every distro implements.

A backend advertises the subset of actions it implements via ``supported``; the
CLI hides the rest (no faking an action a distro doesn't have). Action methods
have a default that raises :class:`NotImplementedError`, so a backend only writes
the methods it actually supports — capabilities are added incrementally.
``firmware_updates`` is concrete here because fwupd works the same on every distro.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # imported only for type hints — keeps runtime import-free
    from ..config import Config
    from ..output import Output

# Every action name fettle knows about (union across all backends).
ALL_ACTIONS = (
    "clean", "orphans", "update", "rebuild_check", "python_rebuild_check",
    "config_drift", "firmware_check", "kernel", "aur_audit", "aur_ioc_scan",
    "pkg_audit", "auto_updates", "hardening_audit",
)


def dir_bytes(path: Path) -> int:
    """Total size of a directory tree; unreadable entries are skipped, not fatal.

    Used to report what a clean actually reclaimed. Measuring the directory rather
    than trusting the package manager's own summary is deliberate: QA found
    ``pacman -Scc --noconfirm`` reporting success while removing nothing, and no
    amount of parsing its output would have caught that.
    """
    total = 0
    try:
        for p in path.rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total += p.stat().st_size
            except OSError:
                continue  # vanished mid-walk, or a sandbox dir we cannot enter
    except OSError:
        return 0
    return total


def human_bytes(n: int) -> str:
    """1234567 -> '1.2 MiB'. Whole units below MiB — '512 KiB' beats '0.5 MiB'."""
    step = 1024.0
    for unit in ("B", "KiB"):
        if abs(n) < step:
            return f"{int(n)} {unit}"
        n /= step
    for unit in ("MiB", "GiB"):
        if abs(n) < step:
            return f"{n:.1f} {unit}"
        n /= step
    return f"{n:.1f} TiB"


@dataclass
class Context:
    """Everything a backend action needs, passed in explicitly (never global)."""

    output: "Output"
    config: "Config"
    dry_run: bool = False
    assume_yes: bool = False
    auto_rebuild: bool = False
    sync: bool = True  # refresh repo data for the dry-run preview (--no-sync opts out)
    force_aur: bool = False  # --force-aur: override the AUR pre-check gate under --yes
    # --full-preview: elevate under --dry-run so a backend that needs root to resolve a
    # full transaction can. Read by the backend only to explain a preview that stayed
    # partial anyway (elevation declined) — the resolver branches on real privilege.
    full_preview: bool = False
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
        return self.output.run_streamed(argv, as_user=as_user)

    # -- interaction (all honor dry-run / assume_yes) ------------------------
    def confirm(self, question: str, *, default: bool = False) -> bool:
        if self.dry_run:
            return False
        if self.assume_yes:
            return True
        try:
            ans = input(f"  {question} [y/N] ").strip().lower()
        except (EOFError, OSError):
            return default  # no readable stdin (piped / no tty) -> safe default
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


@dataclass
class TxItem:
    """One package in a would-run upgrade transaction.

    ``old is None`` marks a package that isn't installed yet (a dependency the
    upgrade pulls in). ``source`` groups the preview (``repo`` vs ``aur``);
    ``kind`` is ``upgrade`` | ``new-dep`` | ``remove``.
    """

    name: str
    new: str
    old: str | None = None
    source: str = "repo"
    kind: str = "upgrade"


@dataclass
class Transaction:
    """The full set a dry-run ``update`` would perform, plus any caveats.

    ``ok=False`` means the transaction could not be determined (query tool
    missing / errored) — distinct from ``ok=True`` with no items, which means
    genuinely nothing to install. ``notes`` are advisories to surface (stale
    repos, devel rebuilds not shown, fallbacks).
    """

    items: list[TxItem] = field(default_factory=list)
    ok: bool = True
    notes: list[str] = field(default_factory=list)


class PackageBackend(abc.ABC):
    """A distro's package/maintenance operations (one method per action)."""

    name: str = "base"
    supported: set[str] = set()

    def supports(self, action: str) -> bool:
        return action in self.supported

    def supply_chain_sources(self):
        """Package Supply Chain providers.

        The base set is **distro-agnostic**: flatpak, snap, containers and GNOME
        extensions install the same way on any distribution, so every backend gets
        them and each adds its own native provider on top. They used to be attached
        to the Debian backend alone, which meant an Arch box with flatpaks installed
        was audited as though it had none.

        Each provider still gates itself with ``is_present``, so an absent tool costs
        nothing beyond one ``which`` call.
        """
        from ..supplychain.container_source import ContainerSource
        from ..supplychain.flatpak_source import FlatpakSource
        from ..supplychain.gh_source import GhSource
        from ..supplychain.gnome_source import GnomeSource
        from ..supplychain.snap_source import SnapSource
        from ..supplychain.vscode_source import VSCodeSource
        return [FlatpakSource(), SnapSource(), ContainerSource(), GnomeSource(),
                VSCodeSource(), GhSource()]

    # -- actions (overridden per backend; NotImplementedError = not yet built) --
    # What the clean confirmation asks. Overridden where a family removes more than
    # caches: QA found every backend asking to remove "build dirs", which only the
    # Arch family has — so Debian and RHEL users were consenting to something that
    # could not happen, on a prompt whose safe default is No.
    clean_prompt = "remove downloaded package caches?"

    def cache_paths(self, ctx: Context) -> list[Path]:
        """Directories ``clean_caches`` reclaims, sized before and after by
        ``actions._clean`` so the summary can state what was actually freed.

        Returning ``[]`` means "not measurable here" and the summary stays silent
        about figures rather than inventing one.
        """
        return []

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

    def check_auto_updates(self, ctx: Context) -> Result:
        """Report whether the system is configured to update itself
        automatically (read-only, informational)."""
        raise NotImplementedError

    def manage_kernels(self, ctx: Context) -> Result:
        raise NotImplementedError

    def verify_integrity(self, scan) -> None:
        """sys-audit `packages` check — verify installed files against the package
        DB. Takes a ``secure.base.Scan`` and emits through it (the one distro-
        specific sys-audit check; see PLAN §3.7)."""
        raise NotImplementedError

    def map_files_to_packages(self, paths) -> dict[str, str]:
        """Map each installed file path to the package that owns it.

        Read-only and rootless; used by the hardening audit to attribute a
        binary's shortcomings to a package. Paths with no owner are omitted.
        Default is empty (a backend without a package DB can't attribute).
        """
        return {}

    def pending_upgrades(self, ctx: Context) -> list[tuple[str, str, str]]:
        """Packages that ``update`` would upgrade, as ``(name, old_ver, new_ver)``.

        Read-only (no root, no system change) — used by the Upgrade Checker.
        Empty list when up to date or the query tool is absent.
        """
        return []

    def refresh_metadata(self, ctx: Context) -> Result:
        """Safely refresh package metadata WITHOUT upgrading (for ``only-update``).

        Default is a no-op; backends refresh their repos and any managed
        flatpak/snap metadata. Must never leave the system in a partial-upgrade
        state (Arch previews from a private cache instead of ``pacman -Sy``).
        """
        return Result()

    def pending_transaction(self, ctx: Context, *, sync: bool = True) -> Transaction:
        """The full set ``update`` would install (upgrades + new deps), for
        ``-u --dry-run``. Read-only and rootless.

        Default derives from :meth:`pending_upgrades` (upgrades only, no new
        deps); backends override to resolve the real transaction. ``sync``
        requests fresh repo data (may hit the network) when the backend supports
        a rootless refresh.
        """
        items = [TxItem(name=n, new=new, old=old)
                 for n, old, new in self.pending_upgrades(ctx)]
        return Transaction(items=items, ok=True)

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

    # -- snap is distro-neutral too: snapd works everywhere -------------------
    def _prune_disabled_snaps(self, ctx: Context) -> None:
        """Offer to remove superseded (disabled) snap revisions left after a refresh.

        Distro-agnostic for the same reason as :meth:`supply_chain_sources`: snapd
        installs and refreshes identically on every distribution, so an Arch or RHEL
        box with snapd accumulates exactly the same reclaimable revisions a Debian one
        does. This used to hang off the Debian backend alone, so those revisions were
        never offered anywhere else. Self-gated on ``snap`` being present, so a box
        without snapd pays one ``which`` call.

        Each revision is confirmed individually — removing an installed snap
        revision is never done without asking (only ``--yes`` opts into all).
        """
        from .. import command

        if not command.which("snap"):
            return
        # `snap list --all` lists every revision; the Notes column marks the
        # superseded ones "disabled". Header row skipped.
        out = command.run(["snap", "list", "--all"], capture=True).stdout
        disabled = []  # (name, revision)
        for line in out.splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 6 and "disabled" in cols[5]:
                disabled.append((cols[0], cols[2]))
        if not disabled:
            return
        ctx.output.note("disabled (superseded) snap revisions:")
        labels = [f"{name} (rev {rev})" for name, rev in disabled]
        for label in labels:
            print(f"    {label}")
        by_label = dict(zip(labels, disabled))
        for label in ctx.select(labels, prompt="remove disabled snap revision"):
            name, rev = by_label[label]
            ctx.execute(["snap", "remove", name, f"--revision={rev}"],
                        quiet=True, msg=f"removed disabled snap {name} (rev {rev})")
