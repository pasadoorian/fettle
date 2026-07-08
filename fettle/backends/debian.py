"""Debian / Ubuntu backend (apt + flatpak + snap).

Implements the maintenance actions against a curated command allowlist (per the
PLAN's anti-topgrade rule: config tunes *behavior*, never *discovers* commands).
``firmware_updates`` is inherited from the base class (fwupd is distro-neutral);
``python_rebuild`` is intentionally absent (apt handles interpreter transitions);
the supply-chain providers (``pkg-audit``) and ``verify_integrity`` land in M8/M10.

Updater knobs live under ``[updaters.debian]`` in the config:
``system_updater`` (apt | nala | none), ``flatpak_updater`` (flatpak | none),
``snap_updater`` (snap | none).
"""

from __future__ import annotations

import re

from .. import command
from ..util import chown_to_user, matches_any
from .base import Context, PackageBackend, Result

_SYSTEM_UPDATERS = {"apt", "nala", "none"}
_FLATPAK_UPDATERS = {"flatpak", "none"}
_SNAP_UPDATERS = {"snap", "none"}


class DebianBackend(PackageBackend):
    name = "debian"
    supported = {
        "clean", "orphans", "update", "rebuilds", "config_drift", "firmware", "kernels",
        "pkg_audit",
        # M10 adds integrity. No python_rebuild / aur_* (Arch-only).
    }

    def supply_chain_sources(self):
        from ..supplychain.apt_source import AptSource
        from ..supplychain.flatpak_source import FlatpakSource
        from ..supplychain.snap_source import SnapSource
        return [AptSource(), FlatpakSource(), SnapSource()]

    # -- sys-audit `packages` integrity (M10) --------------------------------
    def verify_integrity(self, scan) -> None:
        scan.sub("Dpkg Package Verification")
        if scan.which("debsums"):
            scan.dim("Running debsums (this may take a while)...")
            issues = [ln for ln in scan.run_text(["debsums"]).splitlines()
                      if not ln.rstrip().endswith("OK")][:50]
            if not issues:
                scan.status("Package Integrity", "All packages verified", "ok")
            else:
                scan.status("Package Integrity", "Issues found", "warn")
                scan.result("\n".join(issues))
        else:
            scan.status("debsums", "Not installed (apt install debsums)", "warn")
            scan.dim("Running dpkg --verify...")
            out = scan.run_text(["dpkg", "--verify"]).splitlines()[:30]
            if not any(ln.strip() for ln in out):
                scan.status("Package Files", "No issues detected", "ok")
            else:
                scan.result("\n".join(out))

    # -- helpers -------------------------------------------------------------
    def _updaters(self, ctx: Context) -> tuple[str, str, str]:
        conf = {}
        if isinstance(ctx.config.updaters, dict):
            conf = ctx.config.updaters.get("debian", {}) or {}
        system = str(conf.get("system_updater", "apt"))
        flatpak = str(conf.get("flatpak_updater", "flatpak"))
        snap = str(conf.get("snap_updater", "snap"))
        if system not in _SYSTEM_UPDATERS:
            ctx.output.warn(f"invalid system_updater '{system}'; using apt")
            system = "apt"
        if flatpak not in _FLATPAK_UPDATERS:
            ctx.output.warn(f"invalid flatpak_updater '{flatpak}'; using flatpak")
            flatpak = "flatpak"
        if snap not in _SNAP_UPDATERS:
            ctx.output.warn(f"invalid snap_updater '{snap}'; using snap")
            snap = "snap"
        return system, flatpak, snap

    @staticmethod
    def _query(cmd) -> str:
        """Run a read-only query and return stdout (runs even under dry-run)."""
        return command.run(cmd, capture=True).stdout

    # -- clean ---------------------------------------------------------------
    def clean_caches(self, ctx: Context) -> Result:
        out = ctx.output
        _, flatpak, snap = self._updaters(ctx)
        ctx.execute(["apt-get", "clean"], quiet=True, msg="apt cache cleared")
        ctx.execute(["apt-get", "autoclean", "-y"], quiet=True, msg="apt autoclean done")
        if flatpak != "none" and command.which("flatpak"):
            ctx.execute(["flatpak", "uninstall", "--unused", "-y"],
                        quiet=True, msg="unused flatpaks removed")
        if snap != "none" and command.which("snap"):
            self._prune_disabled_snaps(ctx)
        out.summary_add("caches cleaned")
        return Result(summary="caches cleaned")

    def _prune_disabled_snaps(self, ctx: Context) -> None:
        """Offer to remove superseded (disabled) snap revisions left after a refresh.

        Each revision is confirmed individually — removing an installed snap
        revision is never done without asking (only ``--yes`` opts into all).
        """
        disabled = []  # (name, revision)
        for line in self._query(["snap", "list", "--all"]).splitlines()[1:]:
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

    # -- update --------------------------------------------------------------
    def update_system(self, ctx: Context) -> Result:
        out = ctx.output
        system, _, _ = self._updaters(ctx)
        if system == "none":
            out.note("skipping repo update (system_updater: none).")
            return Result()
        tool = "nala" if system == "nala" and command.which("nala") else "apt-get"
        out.note(f"updating package lists ({tool})...")
        ctx.execute([tool, "update"])
        out.note("applying upgrades...")
        if tool == "nala":
            ctx.execute(["nala", "upgrade", "-y"])
        else:
            ctx.execute(["apt-get", "full-upgrade", "-y"])
        return Result()

    def update_extras(self, ctx: Context) -> Result:
        out = ctx.output
        _, flatpak, snap = self._updaters(ctx)
        did = ["apt"]
        if flatpak != "none" and command.which("flatpak"):
            out.note("updating flatpaks...")
            ctx.execute(["flatpak", "update", "-y"])
            did.append("flatpak")
        if snap != "none" and command.which("snap"):
            out.note("refreshing snaps...")
            ctx.execute(["snap", "refresh"])
            did.append("snap")
        out.summary_add(f"packages updated ({', '.join(did)})")
        return Result()

    # -- orphans / obsolete --------------------------------------------------
    def check_foreign_orphans(self, ctx: Context) -> Result:
        out, cfg = ctx.output, ctx.config

        # Obsolete packages (installed, no longer in any archive) -> review file
        # (the Debian analogue of Arch's alien-pkgs.txt).
        obsolete = self._obsolete_packages(ctx)
        review = ctx.user_home / "obsolete-pkgs.txt"
        if not ctx.dry_run:
            try:
                review.write_text("".join(f"{p}\n" for p in obsolete))
                chown_to_user(review, ctx.sudo_user)
            except OSError as exc:
                out.warn(f"could not write {review}: {exc}")
        out.note(f"obsolete/foreign packages saved to {review} for review "
                 f"({len(obsolete)} found)")

        # Orphaned libraries via deborphan -> offer purge.
        if command.which("deborphan"):
            orphans = [o for o in self._query(["deborphan"]).split()
                       if not matches_any(o, cfg.keep_orphans)]
            if orphans:
                out.note("orphaned libraries eligible for removal:")
                for o in orphans:
                    print(f"    {o}")
                chosen = ctx.select(orphans, prompt="purge orphan")
                if chosen:
                    ctx.execute(["apt-get", "purge", "-y", *chosen])
                    out.summary_add(f"{len(chosen)} orphaned lib(s) purged")
            else:
                out.ok("no orphaned libraries (deborphan).")
        else:
            out.note("deborphan not found (install it to detect orphaned libraries); skipping.")

        # Unused dependencies.
        if ctx.confirm("run apt-get autoremove to drop unused dependencies?"):
            ctx.execute(["apt-get", "autoremove", "-y"])
            out.summary_add("autoremove completed")
        return Result()

    def _obsolete_packages(self, ctx: Context) -> list[str]:
        if command.which("apt-show-versions"):
            names = []
            for line in self._query(["apt-show-versions"]).splitlines():
                if "No available version" in line:
                    names.append(line.split(":")[0].split("/")[0].strip())
            return names
        if command.which("aptitude"):
            return self._query(["aptitude", "search", "~o", "-F", "%p"]).split()
        ctx.output.note("neither apt-show-versions nor aptitude found; "
                        "skipping obsolete-package scan.")
        return []

    # -- rebuilds (service restarts after library upgrades) ------------------
    def check_rebuilds(self, ctx: Context) -> Result:
        out = ctx.output
        if command.which("needrestart"):
            svc = [ln.split(":", 1)[1].strip()
                   for ln in self._query(["needrestart", "-b", "-r", "l"]).splitlines()
                   if ln.startswith("NEEDRESTART-SVC:")]
            if not svc:
                out.ok("no services need restarting.")
                return Result()
            out.note("services needing a restart after library upgrades:")
            for s in svc:
                print(f"    {s}")
            out.summary_add(f"{len(svc)} service(s) need restarting")
            out.next_step("restart them: sudo needrestart")
            return Result()
        if command.which("checkrestart"):
            text = self._query(["checkrestart"]).strip()
            if text:
                print(text)
                out.summary_add("services need restarting (checkrestart)")
            else:
                out.ok("no services need restarting.")
            return Result()
        out.note("needrestart/checkrestart not found (install needrestart); skipping.")
        return Result()

    # -- config drift --------------------------------------------------------
    def check_config_drift(self, ctx: Context) -> Result:
        out = ctx.output
        etc = ctx.root / "etc"
        files: list[str] = []
        if etc.is_dir():
            for pat in ("*.dpkg-dist", "*.dpkg-new", "*.ucf-dist"):
                files.extend(str(p) for p in etc.rglob(pat))
        files.sort()
        if files:
            out.note("config files needing review (new maintainer versions):")
            for f in files:
                print(f"    {f}")
            out.summary_add(f"{len(files)} config file(s) to merge")
            out.next_step("review and merge the .dpkg-dist / .ucf-dist files")
        else:
            out.ok("no pending config-file merges.")
        # dpkg --audit surfaces half-configured / broken packages.
        if command.which("dpkg"):
            audit = self._query(["dpkg", "--audit"]).strip()
            if audit:
                out.warn("dpkg --audit reports problems:")
                print(audit)
                out.summary_add("dpkg --audit found package problems")
        return Result()

    # -- kernels -------------------------------------------------------------
    def manage_kernels(self, ctx: Context) -> Result:
        out = ctx.output
        if not command.which("dpkg"):
            out.note("dpkg not found; skipping kernel management.")
            return Result()
        installed = self._installed_kernel_images()
        running = "linux-image-" + self._query(["uname", "-r"]).strip()
        removable = [p for p in installed if p != running]
        out.note("installed kernel images:")
        for p in installed:
            print(f"    {p}{'  (running)' if p == running else ''}")
        if not removable:
            out.ok("no removable kernel images (only the running one is installed).")
            return Result()
        if ctx.dry_run:
            out.note("would prompt to purge old kernel images via apt-get")
            return Result()
        out.note("old kernel images eligible for removal (the running one is protected):")
        for p in removable:
            print(f"    {p}")
        chosen = ctx.select(removable, prompt="purge kernel")
        if chosen:
            ctx.execute(["apt-get", "purge", "-y", *chosen])
            out.summary_add(f"{len(chosen)} old kernel image(s) purged")
        return Result()

    def _installed_kernel_images(self) -> list[str]:
        """Versioned linux-image packages from ``dpkg -l`` (meta-packages skipped)."""
        imgs = []
        for line in self._query(["dpkg", "-l", "linux-image-*"]).splitlines():
            cols = line.split()
            # Installed rows start with "ii"; keep only versioned images (linux-image-<digit>...).
            if len(cols) >= 2 and cols[0] == "ii" and re.match(r"linux-image-\d", cols[1]):
                imgs.append(cols[1])
        return imgs
