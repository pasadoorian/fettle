"""Arch / Manjaro backend (pacman + yay/pamac + AUR).

M2 implemented the update path; M3 adds the maintenance checks (orphans, rebuilds,
python-rebuild, config drift, kernels). ``firmware`` is inherited from the base
class (fwupd is distro-neutral).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .. import command, reports
from ..util import matches_any
from ..output import FAILED
from .base import (Context, PackageBackend, Result, Transaction, TxItem,
                   is_regenerated, sample_lines)

_PACMAN_CACHE = Path("/var/cache/pacman/pkg")
# Versions of each *installed* package kept in the cache by `clean`. Two means one
# working rollback target plus a spare; 0 keeps none. Overridable via [clean].
_DEFAULT_KEEP_VERSIONS = 2

_SYSTEM_UPDATERS = {"pacman", "pamac"}
_AUR_UPDATERS = {"yay", "pamac", "none"}

# Arch ships no official auto-updater (deliberate: partial-upgrade risk, the news
# needs reading first). "Auto-updates enabled" therefore means a user wired up a
# systemd timer. We match a curated list of known community updater units; a
# custom-named timer won't be detected (the documented tradeoff of name-matching).
# Keyring-sync / cache-clean timers are intentionally absent (not updaters).
KNOWN_UPDATE_TIMERS = (
    "arch-update.timer",          # Antiz96/arch-update
    "auto-update.timer",
    "autoupdate.timer",           # common guide name
    "pacman-auto-update.timer",   # cmuench/pacman-auto-update
    "pacupdate.timer",
    "system-update.timer",
    "topgrade.timer",             # topgrade scheduled run
    "yay-auto-update.timer",      # CoreSec-xyz/yay-auto-update
)

# `checkupdates` / `pacman -Qu` line: "pkgname oldver -> newver" (optional trailing
# "[ignored]"). Capture the three fields; ignore anything that doesn't match.
_ARROW_RE = re.compile(r"^(\S+)\s+(\S+)\s+->\s+(\S+)")

# Python interpreter package names (python, python3, python310, python312, ...).
# These OWN an old python3.X dir but are the interpreter itself, not a module that
# needs rebuilding — excluded from the Python-rebuild candidate list.
_PY_INTERP_RE = re.compile(r"^python3?\d*$")

# pacman's config leftovers, in the order pacdiff reports them. NOT interchangeable:
# a `.pacnew` leaves YOUR file in effect with a new default beside it, while a
# `.pacorig` means the package's version is in effect and yours was moved aside — a
# setting somebody made that silently stopped applying. `.pacsave` is your file kept
# after the package was removed. All four used to be reported as "pacnew files".
_DRIFT_KINDS = {
    ".pacnew": (False, "the package shipped a new default; YOUR file is still in "
                       "effect — review the .pacnew for options worth adopting"),
    ".pacorig": (True, "YOUR file was moved aside and the PACKAGE's version is now in "
                       "effect — settings you made are NOT active"),
    ".pacsave": (False, "your file, kept after the package was removed; nothing is "
                        "using it now — delete it once you have salvaged anything "
                        "worth keeping"),
}


def _parse_arrow_upgrades(text: str) -> list[tuple[str, str, str]]:
    out = []
    for line in text.splitlines():
        m = _ARROW_RE.match(line.strip())
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


def _parse_sup_lines(text: str) -> list[tuple[str, str]]:
    """Parse `pacman -Sup --print-format '%r/%n %v'`: 'repo/name version' per
    target. Returns [(name, version), ...]; the repo prefix is dropped."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        left, ver = line.split(" ", 1)
        name = left.split("/", 1)[1] if "/" in left else left
        out.append((name, ver.strip()))
    return out


def _paccheck_path(line: str) -> str:
    """The file path out of a paccheck line: ``<pkg>: '<path>' <what> mismatch``."""
    m = re.search(r"'([^']+)'", line)
    return m.group(1) if m else ""


class ArchBackend(PackageBackend):
    name = "arch"
    supported = {
        "clean", "orphans", "update", "only_update", "rebuild_check",
        "python_rebuild_check", "config_drift", "auto_updates", "firmware_check",
        "kernel", "aur_audit", "pkg_audit", "hardening_audit", "pkg_integrity",
        "container_update",
    }

    # Measured, not assumed: `checkrebuild` and `pacman -Qoq` both exit 0 as an
    # unprivileged user, and `refresh_metadata` here runs no command whatsoever.
    extra_no_root = {"only_update", "rebuild_check", "python_rebuild_check"}

    def supply_chain_sources(self):
        from ..supplychain.aur_source import AURSource
        return [AURSource(), *super().supply_chain_sources()]

    # -- sys-audit `packages` integrity (M10) --------------------------------
    def verify_integrity(self, scan) -> None:
        """sys-audit's ``packages`` check, following the RHEL implementation.

        Two things the naive version got wrong, both measured on the QA host:

        **"Could not read" is not "found a problem".** Unprivileged, paccheck emits
        ``warning: <pkg>: '<path>' read error (Permission denied)`` for every file it
        cannot open — 30-odd on a stock desktop. Those were printed under a single
        ``Package Integrity: Issues found`` error, so most of the "issues" were
        actually the scan admitting it could not look. That is the governing
        invariant inverted, and it cries wolf just as badly as the reverse.

        **A cap that says nothing is a lie about coverage.** The output was sliced to
        the first 50 lines with no indication that anything followed. The count now
        comes from the whole output and the sample is explicitly a sample.
        """
        scan.sub("Pacman Package Verification")
        if scan.which("paccheck"):
            scan.dim("Running paccheck --sha256sum (this may take a while)...")
            out = scan.run_text(["paccheck", "--sha256sum", "--quiet"])
            altered, unreadable, expected = [], [], []
            for line in out.splitlines():
                if not line.strip():
                    continue
                line = line.rstrip()
                if "read error" in line:
                    unreadable.append(line)
                elif is_regenerated(_paccheck_path(line)):
                    expected.append(line)
                else:
                    altered.append(line)
            if altered:
                scan.status("Package Integrity",
                            f"{len(altered)} file(s) differ from their package",
                            "error")
                scan.result(sample_lines(altered))
            else:
                scan.status("Package Integrity", "no unexplained differences", "ok")
            if expected:
                scan.status("Expected differences",
                            f"{len(expected)} file(s) regenerated after install "
                            "(depmod output, plugin caches, mirror lists)", "info")
                if scan.verbose:
                    scan.result(sample_lines(expected))
            if unreadable:
                scan.status("Not verified",
                            f"{len(unreadable)} file(s) could not be read — "
                            "re-run as root (`sudo fettle -V`) to verify them", "warn")
                if scan.verbose:
                    scan.result(sample_lines(unreadable))
        elif scan.which("pacman"):
            scan.dim("Running pacman -Qkk (checking file presence)...")
            altered = [ln for ln in scan.run_text(["pacman", "-Qkk"]).splitlines()
                       if ln.strip() and "0 altered files" not in ln]
            if not altered:
                scan.status("Package Files", "No alterations detected", "ok")
            else:
                scan.status("Package Files",
                            f"{len(altered)} package(s) with modified files", "warn")
                scan.result(sample_lines(altered))
        else:
            scan.status("pacman", "Not found", "error")

    # -- helpers -------------------------------------------------------------
    def _updaters(self, ctx: Context) -> tuple[str, str]:
        conf = {}
        if isinstance(ctx.config.updaters, dict):
            conf = ctx.config.updaters.get("arch", {}) or {}
        system = str(conf.get("system_updater", "pacman"))
        aur = str(conf.get("aur_updater", "yay"))
        if system not in _SYSTEM_UPDATERS:
            ctx.output.warn(f"invalid system_updater '{system}'; using pacman")
            system = "pacman"
        if aur not in _AUR_UPDATERS:
            ctx.output.warn(f"invalid aur_updater '{aur}'; using yay")
            aur = "yay"
        return system, aur

    @staticmethod
    def _query(cmd) -> str:
        """Run a read-only query and return stdout (runs even under dry-run)."""
        return command.run(cmd, capture=True).stdout

    def map_files_to_packages(self, paths) -> dict[str, str]:
        paths = list(paths)
        if not paths or not command.which("pacman"):
            return {}
        # `pacman -Qo <files...>` -> "<path> is owned by <pkg> <ver>" per owned
        # file (unowned ones go to stderr and are simply absent from stdout).
        out: dict[str, str] = {}
        for line in self._query(["pacman", "-Qo", *paths]).splitlines():
            m = re.match(r"^(.*) is owned by (\S+) ", line)
            if m:
                out[m.group(1)] = m.group(2)
        return out

    def _rebuild(self, pkgs: list[str], ctx: Context) -> None:
        """Rebuild via the configured AUR backend, so hooks/review still fire."""
        _, aur = self._updaters(ctx)
        if aur == "yay":
            ctx.execute(["yay", "-S", "--rebuild", "--answerdiff", "None", "--answeredit",
                         "None", "--diffmenu=true", "--editmenu=true", "--", *pkgs],
                        as_user=ctx.sudo_user)
        elif aur == "pamac":
            ctx.execute(["pamac", "build", *pkgs], as_user=ctx.sudo_user)
        else:
            ctx.output.err("cannot rebuild: aur_updater is 'none'. Set it to yay or pamac.")

    # -- update path (M2) ----------------------------------------------------
    def _keep_versions(self, ctx: Context) -> int:
        """``[clean] keep_versions`` — cached versions to keep per installed package."""
        raw = (getattr(ctx.config, "clean", None) or {}).get(
            "keep_versions", _DEFAULT_KEEP_VERSIONS)
        try:
            n = int(raw)
        except (TypeError, ValueError):
            ctx.output.warn(f"[clean] keep_versions: {raw!r} is not a whole number; "
                            f"using {_DEFAULT_KEEP_VERSIONS}.")
            return _DEFAULT_KEEP_VERSIONS
        if n < 0:
            ctx.output.warn(f"[clean] keep_versions: {n} is negative; "
                            f"using {_DEFAULT_KEEP_VERSIONS}.")
            return _DEFAULT_KEEP_VERSIONS
        return n

    def _mirror_refresh(self, ctx: Context) -> list[str] | None:
        """argv to regenerate the mirrorlist before upgrading, or ``None`` to skip.

        ``[updaters.arch] refresh_mirrors`` takes three shapes on purpose:

        * ``true`` (default) — ``pacman-mirrors -f``. **On by default because a stale
          mirrorlist breaks upgrades in practice**, not merely in theory: a mirror that
          has fallen behind serves an old database, and pacman then resolves against
          package versions that no longer exist on it.
        * ``false`` — skip it. The mirrorlist is system configuration, and rewriting it
          on every upgrade is a side effect some users would rather opt out of.
        * an integer ``N`` — ``pacman-mirrors -f N``, the fastest N mirrors.

        The integer form exists because bare ``-f`` is the *heaviest* variant, not a
        middling default: its argument is ``nargs="?", const=-1``, and the builder reads
        anything ``<= 0`` as "test the entire pool". Every upgrade therefore speed-tests
        every known mirror. ``refresh_mirrors = 5`` is the usual Manjaro advice.
        """
        conf = {}
        if isinstance(ctx.config.updaters, dict):
            conf = ctx.config.updaters.get("arch", {}) or {}
        raw = conf.get("refresh_mirrors", True)
        if raw is False:
            return None
        if raw is True:
            return ["pacman-mirrors", "-f"]
        try:
            n = int(raw)
        except (TypeError, ValueError):
            ctx.output.warn(f"[updaters.arch] refresh_mirrors: {raw!r} is not true, "
                            "false or a whole number; refreshing all mirrors.")
            return ["pacman-mirrors", "-f"]
        # 0 or negative means "no limit" to pacman-mirrors itself, so pass bare -f.
        return ["pacman-mirrors", "-f"] if n <= 0 else ["pacman-mirrors", "-f", str(n)]

    def _clean_pacman_cache(self, ctx: Context) -> None:
        """Reclaim the package cache without destroying offline rollback.

        **Why not ``pacman -Scc --noconfirm``** (what this used to run): ``--noconfirm``
        makes pacman take the *default* answer to its own prompts, and ``-Scc`` defaults
        to **No** precisely because it is destructive. Measured on a lab guest: 194
        cached packages before, 194 after, exit 0. It had never removed anything on any
        Arch or Manjaro system, while reporting that it had.

        Simply answering "yes" would have been the wrong repair. ``-Scc`` also deletes
        the cached copy of every *currently installed* package, and that cache is the
        primary way to roll back a bad upgrade on Arch without a network. So the
        replacement splits the job by rollback value:

        1. packages no longer installed at all — no rollback value, always removed;
        2. superseded versions of installed packages — keep ``[clean] keep_versions``.

        ``paccache`` ships in ``pacman-contrib``. Without it, fall back to ``pacman -Sc
        --noconfirm``, whose prompt defaults to **Yes** and which keeps installed
        versions — less thorough, but correct and dependency-free.
        """
        keep = self._keep_versions(ctx)
        if command.which("paccache"):
            ctx.execute(["paccache", "-r", "-u", "-k0"], quiet=True,
                        msg="dropped cached packages that are no longer installed")
            ctx.execute(["paccache", "-r", f"-k{keep}"], quiet=True,
                        msg=f"trimmed old versions (keeping {keep} per package)")
        else:
            ctx.output.note("paccache not found (install pacman-contrib for version "
                            "retention); falling back to pacman -Sc.")
            ctx.execute(["pacman", "-Sc", "--noconfirm"], quiet=True,
                        msg="removed cached packages that are no longer installed")

    # The Arch family is the one that really does remove build directories — AUR
    # helpers leave whole source trees behind — so the prompt says so here and
    # nowhere else.
    clean_prompt = "remove downloaded package caches and AUR build directories?"

    def cache_paths(self, ctx: Context) -> list[Path]:
        return [_PACMAN_CACHE, *self._user_cache_dirs(ctx)]

    @staticmethod
    def _user_cache_dirs(ctx: Context) -> list[Path]:
        dirs = [ctx.user_home / ".cache/pamac",
                ctx.user_home / ".cache/yay",
                ctx.user_home / ".cache/paru"]
        if ctx.sudo_user:
            dirs.append(Path(f"/var/tmp/pamac-build-{ctx.sudo_user}"))
        return dirs

    def clean_caches(self, ctx: Context) -> Result:
        ctx.execute(["rm", "-f", "/var/lib/pacman/db.lck"],
                    quiet=True, msg="removed stale pacman db lock")
        self._clean_pacman_cache(ctx)
        if ctx.sudo_user and command.which("pamac"):
            ctx.execute(["pamac", "clean", "--no-confirm"], as_user=ctx.sudo_user,
                        quiet=True, msg="pamac cache cleared")
        for d in self._user_cache_dirs(ctx):
            ctx.execute(["rm", "-rf", str(d)], quiet=True, msg=f"removed {d}")
        # snapd is available on Arch too (AUR `snapd`), and leaves the same superseded
        # revisions behind. Base class; self-gated on `snap`. There is no
        # `[updaters.arch] snap_updater` key to consult — every revision is confirmed
        # individually regardless, so nothing is removed unasked.
        self._prune_disabled_snaps(ctx)
        # The summary lives in actions._clean, which sizes cache_paths() around this
        # call — one truthful account for every family instead of three.
        return Result(summary="caches cleaned")

    def update_system(self, ctx: Context) -> Result:
        out = ctx.output
        system, aur = self._updaters(ctx)
        # `pacman-mirrors` is Manjaro-only; vanilla Arch / EndeavourOS map to this
        # backend and don't have it, so guard rather than fail the whole update.
        argv = self._mirror_refresh(ctx)
        if command.which("pacman-mirrors"):
            if argv is None:
                out.note("skipping mirror refresh "
                         "([updaters.arch] refresh_mirrors = false).")
            else:
                if not ctx.dry_run:
                    # Announce BEFORE probing. This step runs quiet, so it used to
                    # print only a tick once finished — and with a bare `-f` it probes
                    # every known mirror, so the user watched a silent terminal for as
                    # long as that took and reasonably read it as a hang. Every other
                    # step of the upgrade says what it is about to do.
                    out.note("regenerating the mirror list (probing mirrors — this "
                             "can take a while)...")
                ctx.execute(argv, quiet=True,
                            msg="mirror list regenerated (/etc/pacman.d/mirrorlist)")
        elif argv is not None:
            # Asked for, but there is nothing here to do it with. Say so rather than
            # skipping in silence — the setting is on and the user expects an effect.
            out.note("mirror refresh requested, but `pacman-mirrors` is Manjaro-only "
                     "and is not installed; leaving /etc/pacman.d/mirrorlist alone "
                     "(on Arch, `reflector` is the usual tool).")
        if aur == "pamac":
            if system != "pamac":
                out.note("AUR updater is pamac, which manages repos too — using pamac for both.")
            out.note("updating repos + AUR via pamac...")
            pamac_cmd = ["pamac", "update", "-a", "--enable-downgrade", "--force-refresh"]
            if ctx.assume_yes:
                pamac_cmd.append("--no-confirm")
            ctx.execute(pamac_cmd, as_user=ctx.sudo_user)
            return Result(summary="pamac: repos + AUR")
        if system == "pacman":
            out.note("updating official repos (pacman)...")
            # Ask before upgrading by default — pacman shows the plan and prompts;
            # --yes (assume_yes) skips it.
            pacman_cmd = ["pacman", "-Syuu"]
            if ctx.assume_yes:
                pacman_cmd.append("--noconfirm")
            ctx.execute(pacman_cmd)
        else:  # pamac (repos only)
            out.note("updating official repos (pamac)...")
            pamac_cmd = ["pamac", "update", "--enable-downgrade", "--force-refresh"]
            if ctx.assume_yes:
                pamac_cmd.append("--no-confirm")
            ctx.execute(pamac_cmd, as_user=ctx.sudo_user)
        return Result()

    def update_extras(self, ctx: Context) -> Result:
        out = ctx.output
        system, aur = self._updaters(ctx)
        if aur == "pamac":
            return Result()  # already handled in update_system
        if aur == "none":
            out.note("skipping AUR (aur_updater: none).")
            return Result(summary=f"repos only, via {system}")
        if not command.which("yay"):
            out.err("yay not found (aur_updater=yay). Install it, or set aur_updater to pamac/none.")
            return Result(ok=False)
        if not self._aur_precheck_gate(ctx):
            out.warn("AUR update skipped by the pre-check gate.")
            return Result(summary="AUR SKIPPED by the pre-check gate")
        yay_cmd = ["yay", "-Sua", "--devel", "--cleanafter",
                   "--answerdiff", "None", "--answeredit", "None"]
        if ctx.assume_yes:
            # Unattended: no prompts and no diff/edit menus — this SKIPS PKGBUILD
            # review (the documented --yes tradeoff).
            out.note("updating AUR packages (yay, UNATTENDED — PKGBUILD review skipped)...")
            yay_cmd += ["--noconfirm", "--diffmenu=false", "--editmenu=false"]
        else:
            out.note("updating AUR packages (yay, with PKGBUILD review)...")
            yay_cmd += ["--diffmenu=true", "--editmenu=true"]
        ctx.execute(yay_cmd, as_user=ctx.sudo_user)
        out.next_step("check AUR packages before the next build: fettle -A -P")
        return Result()

    # -- pending upgrades (UC1) ----------------------------------------------
    def pending_upgrades(self, ctx: Context) -> list[tuple[str, str, str]]:
        # `checkupdates` (pacman-contrib) syncs a private temp DB, so it's safe and
        # rootless — unlike `pacman -Sy`. Fall back to `pacman -Qu` against the
        # existing sync DB when it's absent (may be stale if never synced).
        if command.which("checkupdates"):
            out = self._query(["checkupdates"])
        elif command.which("pacman"):
            out = self._query(["pacman", "-Qu"])
        else:
            return []
        return _parse_arrow_upgrades(out)

    def refresh_metadata(self, ctx: Context) -> Result:
        # Deliberately NO `pacman -Sy`: syncing the system DB without a full
        # upgrade is the partial-upgrade footgun. The upgradable report is derived
        # from a private temp DB (see pending_transaction), so it is both fresh and
        # safe — the system database is left untouched.
        ctx.output.note("official repos: previewed from a fresh private cache; "
                        "system database left untouched (no partial-upgrade risk).")
        return Result()

    def pending_transaction(self, ctx: Context, *, sync: bool = True) -> Transaction:
        # Resolve the full transaction the real `pacman -Syuu` would perform —
        # upgrades *and* the new dependencies they drag in — without touching the
        # system or needing root. `-Sup --print-format` is authoritative (honors
        # IgnorePkg); `-Qu` supplies old->new to annotate the upgrades. When
        # `sync`, run the query against a fresh private temp DB (checkupdates'
        # trick); otherwise use the existing sync DB (fast, possibly stale).
        if not command.which("pacman"):
            return Transaction(ok=False, notes=["pacman not found"])

        notes: list[str] = []
        dbargs: list[str] = []
        if sync:
            tmp, why = self._temp_synced_db()
            if tmp is not None:
                dbargs = ["--dbpath", str(tmp)]
            else:
                notes.append(f"could not refresh repos — {why}. The preview below "
                             "reflects the last sync and MAY BE STALE.")

        upgrades = {n: (old, new)
                    for n, old, new in _parse_arrow_upgrades(
                        self._query(["pacman", "-Qu", *dbargs]))}
        items: list[TxItem] = []
        for name, ver in _parse_sup_lines(
                self._query(["pacman", "-Sup", "--print-format", "%r/%n %v", *dbargs])):
            if name in upgrades:
                old, new = upgrades[name]
                items.append(TxItem(name=name, new=new, old=old, kind="upgrade"))
            else:
                items.append(TxItem(name=name, new=ver, old=None, kind="new-dep"))

        aur_items, aur_note = self._aur_transaction(ctx)
        items += aur_items
        if aur_note:
            notes.append(aur_note)
        return Transaction(items=items, ok=True, notes=notes)

    def _aur_upgrade_names(self, ctx: Context) -> list[str]:
        """Names of AUR packages `yay -Sua` would upgrade (from `yay -Qua`) — the
        set the pre-upgrade IoC gate checks. `--devel`/-git rebuilds that don't
        bump a version aren't listed here (covered by the yay hook + post-scan)."""
        if not command.which("yay"):
            return []
        out = command.run(["yay", "-Qua"], as_user=ctx.sudo_user, capture=True).stdout
        return [n for n, _o, _new in _parse_arrow_upgrades(out)]

    def _aur_precheck_gate(self, ctx: Context) -> bool:
        """Pre-check the AUR packages `yay -Sua` would build against the IoC feeds
        (RPC health + known-compromise), before it builds them. Returns True to
        proceed, False if the user aborts. On by default; ``aur_precheck_on_update
        = false`` disables it."""
        from ..aur import precheck

        out = ctx.output
        if not getattr(ctx.config, "aur_precheck_on_update", True):
            return True
        names = self._aur_upgrade_names(ctx)
        if not names:
            return True  # nothing to build -> nothing to gate
        out.note(f"pre-checking {len(names)} AUR package(s) against IoC feeds...")
        crit, warn = precheck.scan(names, home=ctx.user_home, owner=ctx.sudo_user)
        if not crit and not warn:
            out.ok(f"AUR pre-check: {len(names)} package(s), no indicators.")
            return True

        for c in crit:
            out.alert(f"AUR: {c}")
        for w in warn:
            out.warn(f"AUR: {w}")
        if ctx.dry_run:  # informational preview only; the real gate runs live
            out.note("(dry-run: pre-check is informational; the gate would prompt here)")
            return True
        # A CRIT under --yes never installs unattended — an explicit --force-aur
        # is required. WARN-only under --yes proceeds (assume_yes -> confirm True).
        if crit and ctx.assume_yes and not getattr(ctx, "force_aur", False):
            out.alert(f"refusing to install unattended: {len(crit)} CRITICAL AUR "
                      "indicator(s). Re-run with --force-aur to override.")
            return False
        label = "CRITICAL" if crit else "advisory"
        if ctx.confirm(f"{label} AUR indicator(s) found — build/install anyway?",
                       default=False):
            return True
        return False

    def _aur_transaction(self, ctx: Context) -> tuple[list[TxItem], str]:
        """AUR upgrades via `yay -Qua` (run as the invoking user). Returns items
        plus a caveat, since `--devel` git rebuilds may not report a version bump
        until yay fetches their sources."""
        _, aur = self._updaters(ctx)
        if aur != "yay" or not command.which("yay"):
            return [], ""
        out = command.run(["yay", "-Qua"], as_user=ctx.sudo_user, capture=True).stdout
        items = [TxItem(name=n, new=new, old=old, source="aur", kind="upgrade")
                 for n, old, new in _parse_arrow_upgrades(out)]
        return items, "AUR: --devel/-git rebuilds may not show until sources are fetched"

    def _real_dbpath(self) -> Path:
        if command.which("pacman-conf"):
            out = command.run(["pacman-conf", "DBPath"], capture=True).stdout.strip()
            if out:
                return Path(out)
        return Path("/var/lib/pacman")

    def _temp_synced_db(self) -> tuple[Path | None, str]:
        """checkupdates' technique: a private DB in TMPDIR with the real `local`
        symlinked in, sync'd fresh via `fakeroot pacman -Sy` (no root, no change
        to the system DB).

        Returns ``(path, "")`` on success, or ``(None, reason)``. The reason matters:
        this can fail three unrelated ways, and the caller used to report the first one
        unconditionally — telling users to install `fakeroot` and `pacman-contrib` when
        both were present and the mirror was simply unreachable.
        """
        if not command.which("fakeroot"):
            return None, "fakeroot not found (install pacman-contrib)"
        db = Path(os.environ.get("TMPDIR", "/tmp")) / f"fettle-checkdb-{os.getuid()}"
        try:
            (db / "sync").mkdir(parents=True, exist_ok=True)
            local = db / "local"
            if not local.is_symlink():
                local.symlink_to(self._real_dbpath() / "local")
        except OSError as exc:
            return None, f"could not prepare the temporary database ({exc.strerror})"
        # `--disable-sandbox-filesystem`: pacman 7's download step drops to the
        # `alpm` user and applies a Landlock ruleset, which fakeroot (fake uid,
        # no real privilege) can't do — the sync fails without this. checkupdates
        # passes the same flag. Older pacman lacks it and rejects the arg, so we
        # just fall back to the system DB (staleness note) — graceful either way.
        proc = command.run(
            ["fakeroot", "--", "pacman", "-Sy", "--disable-sandbox-filesystem",
             "--dbpath", str(db), "--logfile", "/dev/null"], capture=True)
        if proc.ok:
            return db, ""
        # Most often an unreachable mirror; on pre-7 pacman, the sandbox flag being
        # rejected. Quote pacman rather than guessing, so the user sees the real cause.
        why = (proc.stderr or proc.stdout or "").strip().splitlines()
        detail = why[-1][:120] if why else f"pacman -Sy exited {proc.returncode}"
        return None, f"repo sync failed: {detail}"

    # -- maintenance checks (M3) ---------------------------------------------
    def installed_packages(self, ctx: Context) -> set[str]:
        return set(self._query(["pacman", "-Qq"]).split())

    def check_foreign_orphans(self, ctx: Context) -> Result:
        out, cfg = ctx.output, ctx.config
        # `-Qm` (name + version) mirrors update.sh's alien-pkgs.txt content; filter
        # on the package name (first field) but keep the version column in the file.
        foreign = [ln for ln in self._query(["pacman", "-Qm"]).splitlines() if ln.strip()]
        kept = [ln for ln in foreign if not matches_any(ln.split()[0], cfg.exclude_foreign)]
        if not ctx.dry_run:
            try:
                data = {"packages": [{"name": p.split()[0],
                                      "version": (p.split() + [""])[1]}
                                     for p in kept]}
                alien = reports.write_report("alien-pkgs", "\n".join(kept), ctx,
                                             data=data)
                out.note(f"foreign (AUR/manual) packages saved to {alien} "
                         "for review (vet with -A / -P)")
            except OSError as exc:
                out.warn(f"could not write alien-pkgs report: {exc}")
        suppressed = len(foreign) - len(kept)
        if suppressed:
            out.note(f"{suppressed} foreign package(s) suppressed by exclude_foreign")

        orphans = self._query(["pacman", "-Qtdq"]).split()
        if not orphans:
            out.ok("no orphaned packages found.")
            return Result()
        protected = [o for o in orphans if matches_any(o, cfg.keep_orphans)]
        removable = [o for o in orphans if o not in protected]
        if protected:
            out.note(f"protected orphans (keep_orphans): {' '.join(protected)}")
        if not removable:
            out.ok("no removable orphans after keep_orphans.")
            return Result()
        out.note("orphaned packages eligible for removal:")
        for o in removable:
            print(f"    {o}")
        to_remove = ctx.select(removable, prompt="remove orphan")
        if not to_remove:
            out.ok("no orphans removed.")
            return Result()

        out.note(f"removing: {' '.join(to_remove)}")
        # `-Rs` also removes dependencies the chosen packages were the last thing
        # needing, so the real transaction can be larger than what was consented to —
        # measured: choosing `nmap` also removed `lua54`. pacman prints that set, but
        # `--noconfirm` answered its own question, so the user saw the extra package
        # and had no way to refuse it. Under `--yes` there is nothing to ask.
        argv = ["pacman", "-Rsn", *(["--noconfirm"] if ctx.assume_yes else []), *to_remove]
        before = self.installed_packages(ctx)
        ctx.execute(argv)
        gone = before - self.installed_packages(ctx) if before else set()
        if gone:
            extra = sorted(gone - set(to_remove))
            detail = f" (including {len(extra)} unused dependency(ies): " \
                     f"{', '.join(extra)})" if extra else ""
            out.summary_add(f"{len(gone)} package(s) removed{detail}")
        else:
            # pacman printed its plan and the user declined it, or the removal failed;
            # either way nothing went, and claiming a count would be wrong.
            out.ok("nothing was removed.")
        return Result()

    @staticmethod
    def _running_kernel_modules_gone(ctx: Context) -> tuple[bool, str]:
        """Whether the running kernel's module tree has been removed by an upgrade.

        The canonical Arch symptom, and it is worse than "a reboot is pending": the
        `linux` package owns ``/usr/lib/modules/<release>`` and an upgrade *replaces* that
        directory, so the running kernel can no longer load any module it has not already
        loaded. Plugging in a USB device or mounting an unusual filesystem fails until
        the machine reboots.

        Compares ``uname -r`` against the directories on disk rather than parsing version
        strings — the package version (``7.1.5.arch1-2``) and the kernel release
        (``7.1.5-arch1-2``) are punctuated differently, and matching them textually is a
        trap. Measured on a guest running 7.1.3 with 7.1.5 installed: the 7.1.3 tree was
        gone and nothing in fettle said so.
        """
        running = os.uname().release
        base = ctx.root / "usr/lib/modules"
        try:
            present = sorted(p.name for p in base.iterdir() if p.is_dir())
        except OSError:
            return False, ""          # no module tree to reason about (container?)
        if not present or running in present:
            return False, ""
        return True, f"running {running}, installed {', '.join(present)}"

    def check_rebuilds(self, ctx: Context) -> Result:
        out = ctx.output
        # Kernel first — `checkrebuild` only looks at libraries, so a machine whose
        # running kernel was replaced underneath it reported "no packages need
        # rebuilding" and nothing else. RHEL has always reported this; Arch did not.
        stale_kernel, detail = self._running_kernel_modules_gone(ctx)
        if stale_kernel:
            out.warn(f"REBOOT REQUIRED — the running kernel's modules are gone "
                     f"({detail}); it can no longer load any module it has not "
                     "already loaded.")
            out.summary_add("reboot required (running kernel replaced)")
            out.next_step("reboot to start running the kernel you have installed")
        if not command.which("checkrebuild"):
            # Not a silent skip: the summary would otherwise be empty, which reads
            # exactly like "nothing needs rebuilding" to anyone not watching closely.
            out.warn("checkrebuild not found (install rebuild-detector) — whether any "
                     "package needs rebuilding was NOT checked.")
            return Result(ok=False)
        proc = command.run(["checkrebuild"], capture=True)
        if not proc.ok and not (proc.stdout or "").strip():
            out.warn(f"checkrebuild failed (exit {proc.returncode}) — whether any "
                     "package needs rebuilding was NOT determined.")
            return Result(ok=False)
        lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
        if not lines:
            out.ok("no packages need rebuilding.")
            return Result()
        out.note("packages that may require a rebuild:")
        for ln in lines:
            print(f"    {ln}")
        # checkrebuild prints "<pkgbase> <pkgname>"; older builds print just the name.
        # Taking field 2 unconditionally silently dropped every single-field line, so
        # `-R` could report N candidates and rebuild none of them.
        pkgs = [p[1] if len(p := ln.split()) >= 2 else p[0] for ln in lines]
        if ctx.auto_rebuild and pkgs:
            if ctx.confirm(f"rebuild {len(pkgs)} package(s)?"):
                failed_before = len(ctx.failed_commands)
                self._rebuild(pkgs, ctx)
                if len(ctx.failed_commands) > failed_before:
                    out.summary_fail(f"rebuild of {len(pkgs)} package(s) did NOT "
                                     "complete — see the errors above.", kind=FAILED)
                else:
                    out.summary_add(f"{len(pkgs)} package(s) rebuilt")
        else:
            out.summary_add(f"{len(lines)} package(s) may need rebuilding")
            out.next_step("rebuild them: fettle -r -R")
        return Result()

    def check_python_rebuilds(self, ctx: Context) -> Result:
        out = ctx.output
        current = self._query(
            ["python3", "-c", "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')"]
        ).strip()
        if not current:
            # Without the current version every python3.* directory looks "old", and
            # every package owning one would be reported as stranded. Refusing to guess
            # beats inventing a sentinel version that matches nothing.
            out.warn("could not determine the running Python version — packages "
                     "stranded on an old Python were NOT checked.")
            return Result(ok=False)
        out.note(f"current Python version: {current}")
        libdir = ctx.root / "usr/lib"
        old_dirs = sorted(
            p for p in libdir.glob("python3.*")
            if p.is_dir() and p.name != f"python{current}"
        )
        if not old_dirs:
            out.ok("no old Python directories found; nothing to rebuild.")
            return Result()

        pkgs: set[str] = set()
        interpreters: set[str] = set()
        orphaned: list[Path] = []
        for d in old_dirs:
            owners = [x for x in self._query(["pacman", "-Qoq", str(d)]).split() if x]
            if not owners:
                orphaned.append(d)  # no owning package -> leftover cruft
                continue
            pkgs.update(owners)
            # The interpreter for this dir owns its stdlib — probe a sentinel file
            # (os.py exists in every CPython) for the non-recursive dir owner. That
            # package IS Python, not a module stranded on it, so it's not a rebuild
            # target (e.g. the foreign `python312` package owning /usr/lib/python3.12).
            interpreters.update(self._query(["pacman", "-Qoq", str(d / "os.py")]).split())
        interpreters |= {p for p in pkgs if _PY_INTERP_RE.match(p)}  # name fallback

        if orphaned:
            out.note("orphaned old-Python directories (no owning package — "
                     "leftover, removable):")
            for d in orphaned:
                print(f"    {d}")
        if interpreters:
            out.note(f"skipped {len(interpreters)} installed Python interpreter "
                     f"package(s), not rebuild targets: {', '.join(sorted(interpreters))}")

        ordered = sorted(pkgs - interpreters)
        if not ordered:
            out.ok("no packages need rebuilding for the new Python version.")
            return Result()
        out.note("packages stranded on an old Python (need rebuilding):")
        for pk in ordered:
            print(f"    {pk}")
        if ctx.auto_rebuild:
            if ctx.confirm(f"rebuild {len(ordered)} package(s) for Python {current}?"):
                failed_before = len(ctx.failed_commands)
                self._rebuild(ordered, ctx)
                if len(ctx.failed_commands) > failed_before:
                    out.summary_fail(f"rebuild for Python {current} did NOT complete — "
                                     "see the errors above.", kind=FAILED)
                else:
                    out.summary_add(f"{len(ordered)} package(s) rebuilt for "
                                    f"Python {current}")
        else:
            # Without this the digest said nothing at all, so a `fettle -a` run with
            # stranded packages looked identical to one with none — in the action whose
            # whole purpose is surfacing them.
            out.summary_add(f"{len(ordered)} package(s) stranded on an old Python")
            out.next_step(f"rebuild for Python {current}: fettle -y -R")
        return Result()

    def check_config_drift(self, ctx: Context) -> Result:
        """Pending config merges under ``/etc``.

        **Walks the directory rather than asking ``pacdiff``**, which is a *merge* tool:
        measured, ``pacdiff -o`` lists only leftovers whose base file still exists,
        because with nothing to merge against there is nothing for it to do. A
        ``.pacsave`` is created when a package is *removed*, so its base file is gone by
        definition — every one of them was invisible here, while the Debian and RHEL
        backends find their equivalents with exactly this walk.

        Scanning ``/etc`` only, matching the other two backends: pacman can leave these
        elsewhere, but configuration is what a human needs to reconcile.
        """
        out = ctx.output
        etc = ctx.root / "etc"
        found = {suffix: sorted(str(p) for p in etc.rglob(f"*{suffix}"))
                 for suffix in _DRIFT_KINDS} if etc.is_dir() else {}
        total = sum(len(v) for v in found.values())

        if not total:
            out.ok("no pending config-file merges.")
            return Result()

        for suffix, (displaced, advice) in _DRIFT_KINDS.items():
            files = found.get(suffix) or []
            if not files:
                continue
            # `.pacorig` means a setting silently stopped applying — worse than an
            # unmerged default, so it warns rather than notes.
            emit = out.warn if displaced else out.note
            emit(f"{len(files)} {suffix} file(s): {advice}")
            for path in files:
                print(f"    {path}")

        displaced_n = sum(len(found.get(s) or [])
                          for s, (d, _) in _DRIFT_KINDS.items() if d)
        out.summary_add(f"{total} config file(s) to review"
                        + (f" — {displaced_n} where YOUR version is no longer in effect"
                           if displaced_n else ""))
        if command.which("pacdiff"):
            out.next_step("merge them: pacdiff")
        else:
            out.next_step("merge them by hand, or install pacman-contrib and run: pacdiff")
        return Result()

    def check_auto_updates(self, ctx: Context) -> Result:
        """Report whether an automatic-update systemd timer is enabled.

        Matches the curated KNOWN_UPDATE_TIMERS list (Arch has no official
        auto-updater). Read-only and rootless; informational only.
        """
        out = ctx.output
        if not command.which("systemctl"):
            out.note("systemctl not found; cannot determine auto-update state.")
            return Result()
        enabled = [t for t in KNOWN_UPDATE_TIMERS
                   if self._query(["systemctl", "is-enabled", t]).strip() == "enabled"]
        if enabled:
            out.note("automatic-update timer(s) enabled: " + ", ".join(enabled) + ".")
            out.summary_add("auto-updates: ON (" + ", ".join(enabled) + ")")
            self.report_timer_health(ctx, enabled)
        else:
            out.note("automatic updates: none detected "
                     "(manual updates — the Arch default).")
            out.summary_add("auto-updates: OFF")
        return Result()

    def manage_kernels(self, ctx: Context) -> Result:
        """Manjaro drives this through `mhwd-kernel`; plain Arch gets a report.

        `mhwd-kernel` is Manjaro-only, so on Arch this action used to print "skipping"
        and do nothing at all — an action that appears to exist and then declines at
        runtime, which is worse than one that is honestly absent.

        **Arch reports rather than removes, deliberately.** Manjaro's kernels are
        whole-series packages (`linux612`, `linux71`) that its own tool understands;
        Arch's are ordinary packages (`linux`, `linux-lts`, `linux-zen`) with no series
        concept, and removing one is a plain `pacman -R` the user is better placed to
        decide on. This is the same choice the RHEL backend makes and for the same
        reason: kernel removal is the most consequential thing this tool can do, and an
        inventory is genuinely useful where an auto-selected removal is a liability.
        """
        if not command.which("mhwd-kernel"):
            return self._report_kernels_pacman(ctx)
        out = ctx.output
        out.note("installed kernels:")
        print(self._query(["mhwd-kernel", "-li"]).rstrip())
        out.note("available kernels:")
        print(self._query(["mhwd-kernel", "-l"]).rstrip())
        if ctx.dry_run:
            out.note("would prompt to install/remove kernels via mhwd-kernel")
            return Result()
        if ctx.confirm("install a new kernel?"):
            ver = ctx.ask("kernel version (e.g. 612 for linux612): ")
            if ver:
                ctx.execute(["mhwd-kernel", "-i", f"linux{ver}"])
        # Audited against the Debian "purge the newer kernel before reboot" bug
        # (Phase 7): Manjaro kernels are whole-series packages (linux612, linux71)
        # updated in place, not ABI-bump siblings, and removal is DRIVEN BY THE
        # USER typing an explicit version — fettle never auto-selects one. The
        # running series is refused outright. So the auto-rollback bug can't occur
        # here; the only removal is a deliberate, named one.
        if ctx.confirm("remove an old kernel?"):
            ver = ctx.ask("kernel version to remove (e.g. 66 for linux66): ")
            if ver and ver == self._running_kernel_digits():
                out.warn(f"refusing to remove the running kernel (linux{ver}); reboot into another first.")
            elif ver:
                ctx.execute(["mhwd-kernel", "-r", f"linux{ver}"])
        return Result()

    def _report_kernels_pacman(self, ctx: Context) -> Result:
        """Inventory the installed kernels on plain Arch, from pacman rather than names.

        Which package owns the running kernel is asked of pacman (who owns this modules
        directory), never built by pasting `uname -r` into a package name. That exact
        shortcut is the Debian bug this project already recorded once: a kernel named
        anything unexpected stops matching, and the *running* kernel then looks like
        just another removable entry.
        """
        out = ctx.output
        running = os.uname().release
        base = ctx.root / "usr/lib/modules"
        try:
            dirs = sorted(p for p in base.iterdir() if p.is_dir())
        except OSError:
            out.warn("could not read /usr/lib/modules — installed kernels were NOT "
                     "determined")
            out.summary_warn("kernel: could not determine which kernels are installed")
            return Result()

        rows = []
        for d in dirs:
            owner = self._query(["pacman", "-Qoq", str(d / "vmlinuz")]).strip()
            rows.append((d.name, owner.splitlines()[0] if owner else "",
                         d.name == running))
        if not rows:
            out.note("no kernel module trees found under /usr/lib/modules.")
            out.summary_add("kernel: no installed kernels found")
            return Result()

        out.note("installed kernels:")
        for release, pkg, is_running in rows:
            tag = "  <- running" if is_running else ""
            owner = pkg or "(no package owns this tree — left behind by an upgrade?)"
            print(f"  {release:<28} {owner}{tag}")

        if not any(r[2] for r in rows):
            # rebuild-check owns the reboot advice; do not duplicate it, but do not stay
            # quiet either — this is the state where module loading is already broken.
            out.warn(f"the running kernel ({running}) has no module tree on disk — it "
                     "was replaced by an upgrade. Reboot; see rebuild-check (-r).")
        orphaned = [r[0] for r in rows if not r[1]]
        if orphaned:
            out.warn(f"{len(orphaned)} module tree(s) owned by no package: "
                     f"{', '.join(orphaned)} — leftovers from a removed or upgraded "
                     "kernel, safe to delete once you are sure nothing boots from them.")

        out.note("fettle does not remove kernels on Arch: they are ordinary packages "
                 "with no series concept, so removal is a deliberate "
                 "`sudo pacman -R <package>`. Never remove the one marked running.")
        installed = sum(1 for r in rows if r[1])
        summary = f"kernel: {installed} installed, running {running}"
        if orphaned or not any(r[2] for r in rows):
            out.summary_warn(summary + f"; {len(orphaned)} unowned module tree(s)"
                             if orphaned else summary + "; running kernel's modules are gone")
        else:
            out.summary_add(summary)
        return Result()

    def _running_kernel_digits(self) -> str:
        """The running kernel's major.minor with the dot dropped (6.12.x -> '612').

        Mirrors update.sh: ``uname -r | sed 's/\\([0-9]*\\.[0-9]*\\).*/\\1/' | tr -d '.'``,
        so a remove-version like ``612`` is compared exactly (not as a substring).
        """
        m = re.match(r"(\d+)\.(\d+)", self._query(["uname", "-r"]).strip())
        return (m.group(1) + m.group(2)) if m else ""
