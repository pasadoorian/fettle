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

from .. import command, reports
from ..util import matches_any
from .base import Context, PackageBackend, Result, Transaction, TxItem

_SYSTEM_UPDATERS = {"apt", "nala", "none"}
_FLATPAK_UPDATERS = {"flatpak", "none"}
_SNAP_UPDATERS = {"snap", "none"}

# `apt-get -s dist-upgrade` simulation lines:
#   Inst name [oldver] (newver origin [arch])   -> upgrade  ([old] present)
#   Inst name (newver origin [arch])            -> new dependency (no [old])
#   Remv name [ver] ...                         -> removal
# (Conf lines are the post-install configure phase — ignored.)
_APT_INST_RE = re.compile(r"^Inst\s+(\S+)\s+(?:\[([^\]]+)\]\s+)?\((\S+)")
_APT_REMV_RE = re.compile(r"^Remv\s+(\S+)\s+\[([^\]]+)\]")


def _kernel_version_key(name: str) -> tuple[int, ...]:
    """Numeric sort key for a `linux-image-<ver>-<flavor>` package name, so
    6.8.0-124 sorts above 6.8.0-99 (a plain string sort gets this wrong)."""
    return tuple(int(n) for n in re.findall(r"\d+", name))


def _parse_apt_sim(text: str) -> list[TxItem]:
    items = []
    for raw in text.splitlines():
        line = raw.strip()
        m = _APT_INST_RE.match(line)
        if m:
            name, old, new = m.group(1), m.group(2), m.group(3)
            items.append(TxItem(name=name, new=new, old=old,
                                kind="upgrade" if old else "new-dep"))
            continue
        r = _APT_REMV_RE.match(line)
        if r:
            items.append(TxItem(name=r.group(1), new="", old=r.group(2), kind="remove"))
    return items


class DebianBackend(PackageBackend):
    name = "debian"
    supported = {
        "clean", "orphans", "update", "only_update", "rebuild_check",
        "config_drift", "auto_updates", "firmware_check", "kernel", "pkg_audit",
        "hardening_audit",
        # No python_rebuild_check / aur_* (Arch-only). Integrity lives in sys-audit.
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

    def map_files_to_packages(self, paths) -> dict[str, str]:
        paths = list(paths)
        if not paths or not command.which("dpkg-query"):
            return {}
        # `dpkg-query -S <files...>` -> "<pkg>[, <pkg>...]: <path>" per owned file.
        out: dict[str, str] = {}
        for line in self._query(["dpkg-query", "-S", *paths]).splitlines():
            pkgs, sep, path = line.partition(": ")
            if sep and path:
                out[path.strip()] = pkgs.split(",")[0].split(":")[0].strip()
        return out

    # -- pending upgrades (UC1) ----------------------------------------------
    def pending_upgrades(self, ctx: Context) -> list[tuple[str, str, str]]:
        if not command.which("apt"):
            return []
        # `apt list --upgradable` reads the current lists (no root, no fetch). Lines:
        #   pkg/suite newver arch [upgradable from: oldver]
        out = []
        for line in self._query(["apt", "list", "--upgradable"]).splitlines():
            m = re.match(r"^(\S+?)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:\s*([^\]]+)\]",
                         line.strip())
            if m:
                out.append((m.group(1), m.group(3).strip(), m.group(2)))
        return out

    def refresh_metadata(self, ctx: Context) -> Result:
        # apt update is safe (no partial-upgrade concept like Arch) and needs root.
        system, flatpak, _snap = self._updaters(ctx)
        if system != "none":
            tool = "nala" if system == "nala" and command.which("nala") else "apt-get"
            ctx.execute([tool, "update"], quiet=True, msg="apt package lists refreshed")
        if flatpak != "none" and command.which("flatpak"):
            ctx.execute(["flatpak", "update", "--appstream"], quiet=True,
                        msg="flatpak metadata refreshed")
        # snap has no safe metadata-only refresh (snapd refreshes itself) — skipped.
        return Result()

    def pending_transaction(self, ctx: Context, *, sync: bool = True) -> Transaction:
        # apt simulates the *full* resolver as a normal user (`-s`), so unlike the
        # Arch backend there's no temp-DB/fakeroot trick — `dist-upgrade` gives the
        # upgrades AND the new dependencies (and any removals) in one shot. We match
        # the real update verb (full-upgrade == dist-upgrade). apt can't refresh the
        # lists rootlessly, so we simulate against the current lists and warn if
        # they look stale (`sync` requests that freshness check).
        apt = ("apt-get" if command.which("apt-get")
               else "apt" if command.which("apt") else None)
        if apt is None:
            return Transaction(ok=False, notes=["apt-get not found"])
        items = _parse_apt_sim(self._query([apt, "-s", "dist-upgrade"]))
        notes: list[str] = []
        if sync:
            age = self._apt_lists_age_days(ctx)
            if age is not None and age >= 7:
                notes.append(f"apt lists are ~{int(age)} days old — run "
                             "`sudo apt update` for an accurate preview")
        return Transaction(items=items, ok=True, notes=notes)

    @staticmethod
    def _apt_lists_age_days(ctx: Context) -> float | None:
        """Days since the apt package lists were last refreshed (dir mtime), or
        None if the path is missing. Rootless read; ctx.root keeps it testable."""
        import time

        try:
            mtime = (ctx.root / "var/lib/apt/lists").stat().st_mtime
        except OSError:
            return None
        return max(0.0, (time.time() - mtime) / 86400)

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
        if ctx.assume_yes:
            # Unattended: auto-confirm, keep old conffiles (no dpkg prompt; the kept
            # file surfaces later via config-drift as .dpkg-dist), non-interactive
            # frontend so nothing can stall an SSH run.
            env = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"]
            if tool == "nala":
                upgrade = [*env, "nala", "upgrade", "-y"]
            else:
                upgrade = [*env, "apt-get",
                           "-o", "Dpkg::Options::=--force-confold",
                           "-o", "Dpkg::Options::=--force-confdef", "full-upgrade", "-y"]
        else:
            # Ask before upgrading by default — apt/nala show the plan and prompt.
            # Force plain-text debconf + non-interactive needrestart so neither pops a
            # full-screen ncurses dialog (which corrupts the tty, esp. over `ssh -t`).
            # apt still asks its own [Y/n]; needrestart just *lists* (see restart step).
            env = ["env", "DEBIAN_FRONTEND=readline", "NEEDRESTART_MODE=l"]
            upgrade = [*env, "nala", "upgrade"] if tool == "nala" else [*env, "apt-get", "full-upgrade"]
        ctx.execute(upgrade)
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
        if not ctx.dry_run:
            try:
                data = {"packages": list(obsolete)}
                review = reports.write_report("obsolete-pkgs", "\n".join(obsolete),
                                              ctx, data=data)
                out.note(f"obsolete/foreign packages saved to {review} for review "
                         f"({len(obsolete)} found)")
            except OSError as exc:
                out.warn(f"could not write obsolete-pkgs report: {exc}")
        else:
            out.note(f"{len(obsolete)} obsolete/foreign package(s) would be saved for review")

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

        # Unused dependencies — show exactly what autoremove would drop, THEN ask.
        removable = self._autoremove_preview(ctx)
        if not removable:
            out.ok("no unused dependencies to autoremove.")
        else:
            out.note(f"{len(removable)} unused dependency(ies) would be removed:")
            for p in removable:
                print(f"    {p}")
            if ctx.dry_run:
                out.note("would run: apt-get autoremove -y")
            elif ctx.confirm("remove these now (apt-get autoremove)?"):
                ctx.execute(["apt-get", "autoremove", "-y"])
                out.summary_add(f"{len(removable)} unused dependency(ies) autoremoved")
        return Result()

    def _autoremove_preview(self, ctx: Context) -> list[str]:
        """Packages `apt-get autoremove` would remove — simulated, rootless."""
        removed = []
        for line in self._query(["apt-get", "autoremove", "--dry-run"]).splitlines():
            m = _APT_REMV_RE.match(line.strip())
            if m:
                removed.append(m.group(1))
        return removed

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

    # -- automatic-update posture (Phase 13) ---------------------------------
    def check_auto_updates(self, ctx: Context) -> Result:
        """Report whether unattended (automatic) upgrades are configured.

        Read-only and rootless; informational only. `apt-config dump` is the
        authoritative source — it honors the full `apt.conf.d/` layering, so it
        beats reading `20auto-upgrades` directly. Auto-*install* requires the
        `Unattended-Upgrade` periodic knob on, the `unattended-upgrades` package
        installed, and `apt-daily-upgrade.timer` enabled.
        """
        out = ctx.output
        if not command.which("apt-config"):
            out.note("apt-config not found; cannot determine auto-update state.")
            return Result()
        periodic: dict[str, str] = {}
        for line in self._query(["apt-config", "dump"]).splitlines():
            m = re.match(r'APT::Periodic::(\S+)\s+"([^"]*)"\s*;', line.strip())
            if m:
                periodic[m.group(1)] = m.group(2)
        upgrade = periodic.get("Unattended-Upgrade", "0")
        lists = periodic.get("Update-Package-Lists", "0")
        installed = "install ok installed" in self._query(
            ["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
        timer = self._query(["systemctl", "is-enabled", "apt-daily-upgrade.timer"]).strip()
        timer_on = timer == "enabled"
        if upgrade != "0" and installed and timer_on:
            out.note("automatic updates: ENABLED — unattended-upgrades installs "
                     f"upgrades (Unattended-Upgrade={upgrade}, "
                     "apt-daily-upgrade.timer enabled).")
            out.summary_add("auto-updates: ON (unattended-upgrades)")
        else:
            reasons = []
            if not installed:
                reasons.append("unattended-upgrades not installed")
            if upgrade == "0":
                reasons.append("Unattended-Upgrade=0")
            if not timer_on:
                reasons.append(f"apt-daily-upgrade.timer {timer or 'not-enabled'}")
            out.note("automatic updates: DISABLED (" + "; ".join(reasons) + ").")
            out.summary_add("auto-updates: OFF")
        if lists != "0":
            out.note(f"package lists auto-refresh is on (Update-Package-Lists={lists}).")
        return Result()

    # -- kernels -------------------------------------------------------------
    def manage_kernels(self, ctx: Context) -> Result:
        out = ctx.output
        if not command.which("dpkg"):
            out.note("dpkg not found; skipping kernel management.")
            return Result()
        installed = self._installed_kernel_images()
        running = "linux-image-" + self._query(["uname", "-r"]).strip()

        # Protect the running kernel AND the newest installed one(s). After a
        # kernel upgrade before reboot, the RUNNING kernel is the OLD one and the
        # freshly installed newer kernel is the next-boot target — protecting only
        # `running` would offer to purge that newer kernel (a rollback). Compare
        # versions numerically: string sort ranks 6.8.0-99 above 6.8.0-124.
        newest_key = max((_kernel_version_key(p) for p in installed), default=())
        protected = {p for p in installed if _kernel_version_key(p) == newest_key}
        protected.add(running)
        removable = [p for p in installed if p not in protected]

        out.note("installed kernel images:")
        for p in installed:
            tags = []
            if p == running:
                tags.append("running")
            if _kernel_version_key(p) == newest_key and p != running:
                tags.append("newest — boots next")
            print(f"    {p}{'  (' + ', '.join(tags) + ')' if tags else ''}")

        # Reboot-pending nudge: you're running an older kernel than the newest
        # installed one. Explains why the newer kernel isn't offered for removal.
        running_key = _kernel_version_key(running)
        if running_key and running_key < newest_key:
            out.warn("a newer kernel is installed but not running — reboot to "
                     "activate it (it stays protected from removal until then).")
            out.next_step("reboot to switch to the newest kernel")

        if not removable:
            out.ok("no kernel images to remove (running + newest are protected).")
            return Result()
        if ctx.dry_run:
            out.note("would prompt to purge old kernel images via apt-get")
            return Result()
        out.note("old kernel images eligible for removal "
                 "(running + newest kernels are protected):")
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
