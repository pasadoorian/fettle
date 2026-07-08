"""Arch / Manjaro backend (pacman + yay/pamac + AUR).

M2 implemented the update path; M3 adds the maintenance checks (orphans, rebuilds,
python-rebuild, config drift, kernels). ``firmware`` is inherited from the base
class (fwupd is distro-neutral).
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import command
from ..util import chown_to_user, matches_any
from .base import Context, PackageBackend, Result

_SYSTEM_UPDATERS = {"pacman", "pamac"}
_AUR_UPDATERS = {"yay", "pamac", "none"}


class ArchBackend(PackageBackend):
    name = "arch"
    supported = {
        "clean", "orphans", "update", "rebuilds", "python_rebuild",
        "config_drift", "firmware", "kernels", "aur_audit", "aur_ioc_scan",
        "pkg_audit", "integrity",
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
            ctx.execute(["pacman", "-Syuu", "--noconfirm"])
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
        out.next_step("check AUR packages before the next build: fettle -A -S")
        return Result()

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
        out.note(f"foreign (AUR/manual) packages saved to {alien} for review (vet with -A/-S)")
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
        out.note("found old Python directories:")
        for d in old_dirs:
            print(f"    {d}")
        pkgs: set[str] = set()
        for d in old_dirs:
            pkgs.update(x for x in self._query(["pacman", "-Qoq", str(d)]).split() if x)
        ordered = sorted(pkgs)
        if not ordered:
            out.ok("no packages need rebuilding for the new Python version.")
            return Result()
        out.note("packages owning files under an old Python dir:")
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
