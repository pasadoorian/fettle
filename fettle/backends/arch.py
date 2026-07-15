"""Arch / Manjaro backend (pacman + yay/pamac + AUR).

M2 implemented the update path; M3 adds the maintenance checks (orphans, rebuilds,
python-rebuild, config drift, kernels). ``firmware`` is inherited from the base
class (fwupd is distro-neutral).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .. import command
from ..util import chown_to_user, matches_any
from .base import Context, PackageBackend, Result, Transaction, TxItem

_SYSTEM_UPDATERS = {"pacman", "pamac"}
_AUR_UPDATERS = {"yay", "pamac", "none"}

# `checkupdates` / `pacman -Qu` line: "pkgname oldver -> newver" (optional trailing
# "[ignored]"). Capture the three fields; ignore anything that doesn't match.
_ARROW_RE = re.compile(r"^(\S+)\s+(\S+)\s+->\s+(\S+)")

# Python interpreter package names (python, python3, python310, python312, ...).
# These OWN an old python3.X dir but are the interpreter itself, not a module that
# needs rebuilding — excluded from the Python-rebuild candidate list.
_PY_INTERP_RE = re.compile(r"^python3?\d*$")


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


class ArchBackend(PackageBackend):
    name = "arch"
    supported = {
        "clean", "orphans", "update", "only_update", "rebuild_check",
        "python_rebuild_check", "config_drift", "firmware_check", "kernel",
        "aur_audit", "aur_ioc_scan", "pkg_audit",
    }

    def supply_chain_sources(self):
        from ..supplychain.aur_source import AURSource
        return [AURSource()]

    # -- sys-audit `packages` integrity (M10) --------------------------------
    def verify_integrity(self, scan) -> None:
        scan.sub("Pacman Package Verification")
        if scan.which("paccheck"):
            scan.dim("Running paccheck --sha256sum (this may take a while)...")
            issues = scan.run_text(["paccheck", "--sha256sum", "--quiet"]).splitlines()[:50]
            if not any(ln.strip() for ln in issues):
                scan.status("Package Integrity", "All packages verified", "ok")
            else:
                scan.status("Package Integrity", "Issues found", "error")
                scan.result("\n".join(issues))
        elif scan.which("pacman"):
            scan.dim("Running pacman -Qkk (checking file presence)...")
            altered = [ln for ln in scan.run_text(["pacman", "-Qkk"]).splitlines()
                       if "0 altered files" not in ln][:20]
            if not altered:
                scan.status("Package Files", "No alterations detected", "ok")
            else:
                scan.status("Package Files", "Modified files found", "warn")
                scan.result("\n".join(altered))
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
    def clean_caches(self, ctx: Context) -> Result:
        out = ctx.output
        ctx.execute(["rm", "-f", "/var/lib/pacman/db.lck"],
                    quiet=True, msg="removed stale pacman db lock")
        ctx.execute(["pacman", "-Scc", "--noconfirm"],
                    quiet=True, msg="pacman cache cleared")
        if ctx.sudo_user and command.which("pamac"):
            ctx.execute(["pamac", "clean", "--no-confirm"], as_user=ctx.sudo_user,
                        quiet=True, msg="pamac cache cleared")
        cache_dirs = [
            ctx.user_home / ".cache/pamac",
            ctx.user_home / ".cache/yay",
            ctx.user_home / ".cache/paru",
        ]
        if ctx.sudo_user:
            cache_dirs.append(Path(f"/var/tmp/pamac-build-{ctx.sudo_user}"))
        for d in cache_dirs:
            ctx.execute(["rm", "-rf", str(d)], quiet=True, msg=f"removed {d}")
        out.summary_add("caches cleaned")
        return Result(summary="caches cleaned")

    def update_system(self, ctx: Context) -> Result:
        out = ctx.output
        system, aur = self._updaters(ctx)
        # `pacman-mirrors` is Manjaro-only; vanilla Arch / EndeavourOS map to this
        # backend and don't have it, so guard rather than fail the whole update.
        if command.which("pacman-mirrors"):
            ctx.execute(["pacman-mirrors", "-f"], quiet=True, msg="mirrors refreshed")
        if aur == "pamac":
            if system != "pamac":
                out.note("AUR updater is pamac, which manages repos too — using pamac for both.")
            out.note("updating repos + AUR via pamac...")
            pamac_cmd = ["pamac", "update", "-a", "--enable-downgrade", "--force-refresh"]
            if ctx.assume_yes:
                pamac_cmd.append("--no-confirm")
            ctx.execute(pamac_cmd, as_user=ctx.sudo_user)
            out.summary_add("packages updated (pamac: repos + AUR)")
            return Result()
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
            out.summary_add(f"packages updated (repos only, via {system})")
            return Result()
        if not command.which("yay"):
            out.err("yay not found (aur_updater=yay). Install it, or set aur_updater to pamac/none.")
            return Result(ok=False)
        if not self._aur_precheck_gate(ctx):
            out.warn("AUR update skipped by the pre-check gate.")
            out.summary_add("AUR update SKIPPED (pre-check gate)")
            return Result()
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
        out.summary_add(f"packages updated (repos: {system}, AUR: yay)")
        out.next_step("check AUR packages before the next build: fettle -A -I")
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
            tmp = self._temp_synced_db()
            if tmp is not None:
                dbargs = ["--dbpath", str(tmp)]
            else:
                notes.append("could not refresh repos (needs fakeroot + pacman-contrib);"
                             " preview reflects the last sync and may be stale")

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

    def _temp_synced_db(self) -> Path | None:
        """checkupdates' technique: a private DB in TMPDIR with the real `local`
        symlinked in, sync'd fresh via `fakeroot pacman -Sy` (no root, no change
        to the system DB). Returns the path, or None if it can't be prepared."""
        if not command.which("fakeroot"):
            return None
        db = Path(os.environ.get("TMPDIR", "/tmp")) / f"fettle-checkdb-{os.getuid()}"
        try:
            (db / "sync").mkdir(parents=True, exist_ok=True)
            local = db / "local"
            if not local.is_symlink():
                local.symlink_to(self._real_dbpath() / "local")
        except OSError:
            return None
        # `--disable-sandbox-filesystem`: pacman 7's download step drops to the
        # `alpm` user and applies a Landlock ruleset, which fakeroot (fake uid,
        # no real privilege) can't do — the sync fails without this. checkupdates
        # passes the same flag. Older pacman lacks it and rejects the arg, so we
        # just fall back to the system DB (staleness note) — graceful either way.
        proc = command.run(
            ["fakeroot", "--", "pacman", "-Sy", "--disable-sandbox-filesystem",
             "--dbpath", str(db), "--logfile", "/dev/null"], capture=True)
        return db if proc.ok else None

    # -- maintenance checks (M3) ---------------------------------------------
    def check_foreign_orphans(self, ctx: Context) -> Result:
        out, cfg = ctx.output, ctx.config
        # `-Qm` (name + version) mirrors update.sh's alien-pkgs.txt content; filter
        # on the package name (first field) but keep the version column in the file.
        foreign = [ln for ln in self._query(["pacman", "-Qm"]).splitlines() if ln.strip()]
        kept = [ln for ln in foreign if not matches_any(ln.split()[0], cfg.exclude_foreign)]
        alien = ctx.user_home / "alien-pkgs.txt"
        if not ctx.dry_run:
            try:
                alien.write_text("".join(f"{ln}\n" for ln in kept))
                chown_to_user(alien, ctx.sudo_user)
            except OSError as exc:
                out.warn(f"could not write {alien}: {exc}")
        out.note(f"foreign (AUR/manual) packages saved to {alien} for review (vet with -A/-I)")
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
        if to_remove:
            out.note(f"removing: {' '.join(to_remove)}")
            ctx.execute(["pacman", "-Rsn", "--noconfirm", *to_remove])
            out.summary_add(f"{len(to_remove)} orphan(s) removed")
        else:
            out.ok("no orphans removed.")
        return Result()

    def check_rebuilds(self, ctx: Context) -> Result:
        out = ctx.output
        if not command.which("checkrebuild"):
            out.note("checkrebuild not found (install rebuild-detector); skipping.")
            return Result()
        lines = [ln for ln in self._query(["checkrebuild"]).splitlines() if ln.strip()]
        if not lines:
            out.ok("no packages need rebuilding.")
            return Result()
        out.note("packages that may require a rebuild:")
        for ln in lines:
            print(f"    {ln}")
        pkgs = [parts[1] for ln in lines if len(parts := ln.split()) >= 2]
        if ctx.auto_rebuild and pkgs:
            if ctx.confirm(f"rebuild {len(pkgs)} package(s)?"):
                self._rebuild(pkgs, ctx)
                out.summary_add("rebuilt packages with outdated deps")
        else:
            out.summary_add(f"{len(lines)} package(s) may need rebuilding")
            out.next_step("rebuild them: fettle -r -R")
        return Result()

    def check_python_rebuilds(self, ctx: Context) -> Result:
        out = ctx.output
        current = self._query(
            ["python3", "-c", "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}')"]
        ).strip() or "unknown"
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
                self._rebuild(ordered, ctx)
                out.summary_add(f"rebuilt packages for Python {current}")
        else:
            out.next_step(f"rebuild for Python {current}: fettle -y -R")
        return Result()

    def check_config_drift(self, ctx: Context) -> Result:
        out = ctx.output
        if not command.which("pacdiff"):
            out.note("pacdiff not found (install pacman-contrib); skipping.")
            return Result()
        files = [ln for ln in self._query(["pacdiff", "-o"]).splitlines() if ln.strip()]
        if not files:
            out.ok("no .pacnew files to merge.")
            return Result()
        out.note("pacnew files needing attention:")
        for f in files:
            print(f"    {f}")
        out.summary_add(f"{len(files)} .pacnew file(s) to merge")
        out.next_step("merge them: pacdiff")
        return Result()

    def manage_kernels(self, ctx: Context) -> Result:
        out = ctx.output
        if not command.which("mhwd-kernel"):
            out.note("mhwd-kernel not found (Manjaro-only); skipping kernel management.")
            return Result()
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

    def _running_kernel_digits(self) -> str:
        """The running kernel's major.minor with the dot dropped (6.12.x -> '612').

        Mirrors update.sh: ``uname -r | sed 's/\\([0-9]*\\.[0-9]*\\).*/\\1/' | tr -d '.'``,
        so a remove-version like ``612`` is compared exactly (not as a substring).
        """
        m = re.match(r"(\d+)\.(\d+)", self._query(["uname", "-r"]).strip())
        return (m.group(1) + m.group(2)) if m else ""
