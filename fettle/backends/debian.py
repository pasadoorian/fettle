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

import json
import re

from pathlib import Path

from .. import command, reports
from ..util import matches_any
from .base import (Context, PackageBackend, Result, Transaction, TxItem,
                   is_regenerated, sample_lines)

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

# dpkg/ucf config leftovers. NOT interchangeable, and the difference is the point:
# with a `.dpkg-dist` your file is still in effect and the new default sits unmerged
# beside it, whereas with a `.dpkg-old` **your file is no longer in effect** — dpkg moved
# it aside and installed the package's version. The second case is a setting somebody
# deliberately made that has silently stopped applying.
#
# `.dpkg-old` and `.ucf-old` were not looked for at all before v0.59.0, so that case was
# invisible here while the RHEL backend had always warned about its equivalent.
_DRIFT_KINDS = {
    ".dpkg-dist": (False, "the package shipped a new default; YOUR file is still in "
                          "effect — review the .dpkg-dist for options worth adopting"),
    ".ucf-dist": (False, "same, via ucf: YOUR file is still in effect"),
    ".dpkg-new": (False, "an unpacked-but-unapplied package file; usually transient, "
                         "but a leftover can mean an interrupted install"),
    ".dpkg-old": (True, "YOUR file was moved aside and the PACKAGE's version is now in "
                        "effect — settings you made are NOT active"),
    ".ucf-old": (True, "same, via ucf: YOUR version is NOT active"),
}


def _kernel_version_key(name: str) -> tuple[int, ...]:
    """Numeric sort key for a `linux-image-<ver>-<flavor>` package name, so
    6.8.0-124 sorts above 6.8.0-99 (a plain string sort gets this wrong)."""
    return tuple(int(n) for n in re.findall(r"\d+", name))


# A dependency field entry: "libfoo1 (>= 1.2) | libbar2", possibly with :arch.
_DEP_NAME_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9+.\-]*)")


def orphaned_libraries(status_text: str) -> list[str]:
    """Installed library packages that nothing installed depends on.

    `deborphan`'s core question, answered from dpkg's own status file, because
    deborphan itself no longer exists in Debian 13 or Ubuntu 26.04 and the check had
    become a permanent skip on the two most widely deployed server distros in the lab.

    Deliberately narrow, in the direction that matters. Only packages whose name looks
    like a library are considered, and **every** dependency-ish field of **every**
    installed package counts as a reference — Depends, Pre-Depends, Recommends,
    Suggests, Enhances, and the Provides graph, so a package satisfying a virtual name
    protects whatever depends on that name. Alternatives (``a | b``) protect both sides.

    Suggests is included even though it is the weakest relationship. It costs a few
    false negatives — a library stays listed as needed when only a Suggests mentions it
    — and buys the opposite of a false positive. **This list feeds a removal prompt**,
    so an over-eager entry is far worse than a missing one; the whole point of the
    per-package confirm and apt's own transaction is that this list is a suggestion, not
    a verdict.

    Essential and Required packages are never listed whatever the graph says.
    """
    packages, referenced = [], set()
    for block in status_text.split("\n\n"):
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        key = ""
        for line in block.splitlines():
            if line[:1] in (" ", "\t") and key:
                fields[key] += " " + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                fields[key] = val.strip()
        name = fields.get("package", "")
        if not name or not fields.get("status", "").endswith("installed"):
            continue          # deinstalled/config-files entries are not installed
        packages.append((name, fields))
        for field in ("depends", "pre-depends", "recommends", "suggests", "enhances"):
            for alt in fields.get(field, "").split(","):
                for part in alt.split("|"):
                    m = _DEP_NAME_RE.search(part.strip())
                    if m:
                        referenced.add(m.group(1))

    out = []
    for name, fields in packages:
        if not (name.startswith("lib") and not name.startswith("libreoffice")):
            continue
        if fields.get("essential", "") == "yes" or fields.get("priority", "") in (
                "required", "important"):
            continue
        # A package is needed if its own name is depended on, OR if it Provides a
        # virtual name that something depends on. Marking the virtual name itself as
        # "referenced" protects nothing — virtual names are not packages — and the
        # package actually supplying it would be offered for removal. Caught by a
        # positive control against a real dpkg status file.
        provided = {m.group(1)
                    for prov in fields.get("provides", "").split(",")
                    for m in [_DEP_NAME_RE.search(prov.strip())] if m}
        if name in referenced or (provided & referenced):
            continue
        out.append(name)
    return sorted(out)


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
        "hardening_audit", "container_update", "pkg_integrity",
        # No python_rebuild_check / aur_* (Arch-only). Integrity lives in sys-audit.
    }

    def supply_chain_sources(self):
        from ..supplychain.apt_source import AptSource
        return [AptSource(), *super().supply_chain_sources()]

    # -- sys-audit `packages` integrity (M10) --------------------------------
    def verify_integrity(self, scan) -> None:
        """sys-audit's ``packages`` check — see the RHEL implementation for the shape.

        ``debsums`` writes ``<path> OK`` / ``<path> FAILED`` to stdout but
        ``debsums: no md5sums for <pkg>`` to **stderr**, which ``run_text`` merges in.
        Filtering on "does not end in OK" therefore counted every package that ships
        no checksums — a normal and common thing — as an integrity issue. Those are a
        gap in coverage, not a finding, and the two are now reported separately.
        """
        scan.sub("Dpkg Package Verification")
        if scan.which("debsums"):
            scan.dim("Running debsums (this may take a while)...")
            altered, unverifiable, expected = [], [], []
            for line in scan.run_text(["debsums"]).splitlines():
                line = line.rstrip()
                if not line.strip() or line.endswith("OK"):
                    continue
                if "no md5sums" in line:
                    unverifiable.append(line)
                elif is_regenerated(line.split()[0] if line.split() else ""):
                    expected.append(line)
                else:
                    altered.append(line)
            if altered:
                scan.status("Package Integrity",
                            f"{len(altered)} file(s) differ from their package", "warn")
                scan.result(sample_lines(altered))
            else:
                scan.status("Package Integrity", "no unexplained differences", "ok")
            if expected:
                scan.status("Expected differences",
                            f"{len(expected)} file(s) regenerated after install "
                            "(depmod output, plugin caches)", "info")
                if scan.verbose:
                    scan.result(sample_lines(expected))
            if unverifiable:
                scan.status("Not verified",
                            f"{len(unverifiable)} package(s) ship no checksums, so "
                            "their files could not be verified (not a root problem — "
                            "dpkg has nothing to compare against)", "warn")
                if scan.verbose:
                    scan.result(sample_lines(unverifiable))
        else:
            scan.status("debsums", "Not installed (apt install debsums)", "warn")
            scan.dim("Running dpkg --verify...")
            out = [ln for ln in scan.run_text(["dpkg", "--verify"]).splitlines()
                   if ln.strip()]
            if not out:
                scan.status("Package Files", "No issues detected", "ok")
            else:
                scan.status("Package Files", f"{len(out)} discrepancy line(s)", "warn")
                scan.result(sample_lines(out))

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

    @staticmethod
    def _apt_has_error_on() -> bool:
        """Whether this apt understands ``--error-on=any`` (apt 2.1+, 2020).

        Probed rather than assumed: an older apt rejects the option with exit 100 and
        "not understood", which would look exactly like the failed refresh the flag
        exists to detect. When the version cannot be read, assume not — a missed
        failure signal degrades to today's behaviour, while a refresh that always
        errors would break the action outright.
        """
        out = command.run(["apt-get", "--version"], capture=True).stdout
        m = re.search(r"\bapt\s+(\d+)\.(\d+)", out)
        return bool(m) and (int(m.group(1)), int(m.group(2))) >= (2, 1)

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


    # -- Ubuntu Pro / ESM ----------------------------------------------------
    @staticmethod
    def _pro_security_status() -> dict | None:
        """``pro security-status --format json``, or ``None`` when unavailable.

        Ubuntu-only, and gated on the **binary** rather than the distro ID, so Debian and
        Mint simply skip it. The JSON form is the one ``pro`` itself asks for: its human
        output opens with a warning that the text is "subject to change" and that scripts
        should prefer the machine-readable data.

        Read-only and rootless — verified on a live Ubuntu 24.04 host.
        """
        if not command.which("pro"):
            return None
        proc = command.run(["pro", "security-status", "--format", "json"], capture=True)
        if proc.returncode != 0:
            return None
        try:
            data = json.loads(proc.stdout or "")
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _esm_hidden_updates(data: dict) -> tuple[int, int]:
        """``(esm_infra, esm_apps)`` security updates apt cannot currently see.

        Zero when the host is attached, because the ESM pockets are then real apt
        sources and the ordinary upgrade paths already count them.
        """
        summary = data.get("summary") or {}
        if (summary.get("ua") or {}).get("attached"):
            return (0, 0)

        def _n(key):
            try:
                return max(0, int(summary.get(key) or 0))
            except (TypeError, ValueError):
                return 0

        return (_n("num_esm_infra_updates"), _n("num_esm_apps_updates"))

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
            argv = [tool, "update"]
            if tool == "apt-get" and self._apt_has_error_on():
                # `apt-get update` exits **0 even when it could not reach a single
                # repository** — measured on Ubuntu 26.04 with DNS broken. Without this
                # flag fettle cannot tell a refresh from a failure, and reports the
                # green "lists refreshed" line for a refresh that never happened.
                # `--error-on=any` makes it exit 100 instead (measured).
                argv.append("--error-on=any")
            ctx.execute(argv, quiet=True, msg="apt package lists refreshed")
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
        # Security updates that exist but are invisible to apt on an unattached host.
        # Reporting the smaller number without saying so understates the exposure.
        pro = self._pro_security_status()
        if pro:
            infra, apps = self._esm_hidden_updates(pro)
            if infra or apps:
                notes.append(
                    f"{infra + apps} further security update(s) are NOT shown above: this "
                    f"host is not attached to Ubuntu Pro, so apt cannot see the esm-infra "
                    f"({infra}) and esm-apps ({apps}) pockets")
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
    def cache_paths(self, ctx: Context) -> list[Path]:
        return [ctx.root / "var/cache/apt/archives"]

    def clean_caches(self, ctx: Context) -> Result:
        _, flatpak, snap = self._updaters(ctx)
        # `apt-get clean` empties the archive directory outright. `autoclean` — which
        # ran here too — removes only packages that can no longer be downloaded, so
        # after `clean` it has nothing left to consider. QA measured it succeeding
        # against an empty directory and printing its own tick, which read as two
        # operations where one had happened.
        ctx.execute(["apt-get", "clean"], quiet=True, msg="apt package cache cleared")
        if flatpak != "none" and command.which("flatpak"):
            ctx.execute(["flatpak", "uninstall", "--unused", "-y"],
                        quiet=True, msg="unused flatpaks removed")
        if snap != "none":
            self._prune_disabled_snaps(ctx)  # base class; self-gated on `snap`
        return Result(summary="caches cleaned")

    # -- update --------------------------------------------------------------
    def update_system(self, ctx: Context) -> Result:
        out = ctx.output
        system, _, _ = self._updaters(ctx)
        if system == "none":
            out.note("skipping repo update (system_updater: none).")
            return Result()
        tool = "nala" if system == "nala" and command.which("nala") else "apt-get"
        out.note(f"updating package lists ({tool})...")
        refresh = [tool, "update"]
        if tool == "apt-get" and self._apt_has_error_on():
            # Same reason as `refresh_metadata`: `apt-get update` exits 0 even when it
            # could not reach a single repository, so without this the upgrade below
            # runs against whatever is already on disk and reports success. Measured on
            # Debian 12 with every repo unreachable: bare exits 0, this exits 100.
            # `nala update` exits 1 unaided (measured, nala 0.12.2) and needs no flag.
            refresh.append("--error-on=any")
        if ctx.execute(refresh).returncode != 0:
            # Upgrading from lists that could not be refreshed is how a machine ends up
            # believing it is current: apt has nothing newer to install, so it exits 0
            # with "0 upgraded" and the run signs off green. Stop instead, and say which
            # half failed — the package lists, not the packages.
            return Result(ok=False, summary=(
                f"upgrade SKIPPED — the package lists could not be refreshed, and "
                f"upgrading from stale lists would report success while installing "
                f"nothing (run `sudo {tool} update` to see which repository failed)"))
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
        # No summary_add here: `actions._update` owns the summary, because only it
        # knows whether this was a dry run or whether a command failed.
        return Result(summary=", ".join(did))

    # -- orphans / obsolete --------------------------------------------------
    def installed_packages(self, ctx: Context) -> set[str]:
        """Only packages actually installed — status ``ii``.

        `dpkg-query -W` alone also lists **`rc`** packages: removed, but with their
        config files kept. A plain `apt-get remove` leaves a package in exactly that
        state, so it would appear in a before *and* an after snapshot and the diff would
        count it as still present. Measured on Ubuntu, where two of ten autoremoved
        packages left config behind.
        """
        out = self._query(["dpkg-query", "-W", "-f",
                           "${db:Status-Abbrev} ${binary:Package}\n"])
        return {line.split()[1].split(":")[0]
                for line in out.splitlines()
                if line.startswith("ii") and len(line.split()) > 1}

    def _orphan_candidates(self, ctx: Context):
        """``(source, [package, ...])`` or ``None`` if nothing could answer.

        **`deborphan` no longer exists in Debian 13 or Ubuntu 26.04**, so on the two
        most widely deployed server distros in the matrix this check had become a
        permanent skip — honest, but the capability was missing exactly where it matters
        most.

        **`apt-get autoremove` is not the answer**, though it looks like it: this action
        already runs an autoremove preview further down, and autoremove only ever
        considers packages apt marked *auto-installed*. A library you installed by hand
        and no longer need is invisible to it forever. That case — deborphan's whole
        purpose — is what actually went missing.

        So the fallback reimplements deborphan's core question directly from dpkg's own
        status file: **which installed library packages does nothing installed depend
        on?** One file read, no new dependency, and no per-package `apt-cache rdepends`
        storm.

        Whichever source answers, it is used **only as a list**. The removal stays the
        existing explicit per-package purge, so the safety that flow already has — no
        blanket ``-y``, apt's own transaction shown, the installed set diffed around the
        command — is untouched. An orphan list that is wrong in the *removal* direction
        is the most dangerous output this tool produces, which is why the caller also
        prints which source produced it.
        """
        if command.which("deborphan"):
            return "deborphan", self._query(["deborphan"]).split()
        try:
            status = (ctx.root / "var/lib/dpkg/status").read_text(errors="replace")
        except OSError:
            return None
        return "dpkg reverse-deps", orphaned_libraries(status)

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

        # Orphaned packages -> offer purge. Two sources, and they are NOT the same
        # question, so the output names which one answered.
        found = self._orphan_candidates(ctx)
        if found is not None:
            source, candidates = found
            orphans = [o for o in candidates if not matches_any(o, cfg.keep_orphans)]
            if orphans:
                out.note(f"orphaned packages eligible for removal ({source}):")
                for o in orphans:
                    print(f"    {o}")
                # `--yes` answers questions; it does not override a safety judgement.
                # That is already how the AUR gate behaves — a CRITICAL finding needs
                # `--force-aur` on top of `--yes` — and the same reasoning applies here.
                # When the list came from fettle's own INFERENCE rather than a dedicated
                # tool, an unattended run would purge every package a heuristic guessed
                # at, with apt's own confirmation suppressed too. deborphan's verdict is
                # a tool's; the dpkg reverse-dependency scan is ours.
                if ctx.assume_yes and source != "deborphan":
                    out.warn(f"{len(orphans)} orphan(s) found by {source}, NOT removed: "
                             "--yes will not auto-purge a list fettle inferred rather "
                             "than one a tool reported. Re-run without --yes to review "
                             "them, or install deborphan.")
                    out.summary_warn(f"{len(orphans)} orphaned package(s) found but not "
                                     "removed (unattended run, inferred list)")
                    chosen = []
                else:
                    chosen = ctx.select(orphans, prompt="purge orphan")
                if chosen:
                    # No blanket `-y`: purging can pull in dependents, and apt's own
                    # transaction is the only place that set is shown. Under `--yes`
                    # there is no one to ask.
                    argv = ["apt-get", "purge", *(["-y"] if ctx.assume_yes else []),
                            *chosen]
                    before = self.installed_packages(ctx)
                    ctx.execute(argv)
                    gone = before - self.installed_packages(ctx) if before else set()
                    if gone:
                        extra = sorted(gone - set(chosen))
                        detail = (f" (including {len(extra)} dependent(s): "
                                  f"{', '.join(extra)})" if extra else "")
                        out.summary_add(f"{len(gone)} orphaned package(s) purged{detail}")
                    else:
                        out.ok("nothing was purged.")
            else:
                out.ok(f"no orphaned packages ({source}).")
        else:
            out.warn("no way to detect orphaned packages on this system: `deborphan` is "
                     "not installed (and no longer exists in Debian 13 / Ubuntu 26.04), "
                     "checked.")

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
                before = self.installed_packages(ctx)
                ctx.execute(["apt-get", "autoremove", "-y"])
                gone = before - self.installed_packages(ctx) if before else set()
                # The preview is normally exact here — autoremove removes what it said
                # it would — but reporting the measured set keeps every removal path
                # answering the same question: what actually went?
                out.summary_add(f"{len(gone) or len(removable)} unused "
                                "dependency(ies) autoremoved")
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
    # needrestart's kernel verdict (`NEEDRESTART-KSTA`), from its own documentation.
    # Only 1 means "the running kernel is the one you have installed".
    _KSTA = {
        "0": (True, "could not determine whether the running kernel is current"),
        "1": (False, ""),
        "2": (True, "a newer kernel is installed with a compatible ABI — the running "
                    "one is still the old build"),
        "3": (True, "a newer kernel is installed; the running one is OLD"),
    }

    def check_rebuilds(self, ctx: Context) -> Result:
        out = ctx.output
        if command.which("needrestart"):
            text = self._query(["needrestart", "-b", "-r", "l"])
            if not text.strip():
                # An empty answer is not "nothing to do" — needrestart always prints its
                # header. Saying "no services need restarting" here would be inventing a
                # clean result out of a check that did not run.
                out.warn("needrestart produced no output — whether anything needs "
                         "restarting was NOT determined.")
                return Result(ok=False)
            fields = {}
            for ln in text.splitlines():
                key, _, val = ln.partition(":")
                fields.setdefault(key.strip(), []).append(val.strip())

            # The kernel first: fettle read only the service lines, so a box running an
            # OLD kernel after its own upgrade was told to restart three services —
            # advice that cannot help, because the running kernel is the unpatched one.
            # RHEL has always reported this; Debian silently did not.
            ksta = (fields.get("NEEDRESTART-KSTA") or ["0"])[0]
            reboot, why = self._KSTA.get(ksta, self._KSTA["0"])
            if reboot:
                cur = (fields.get("NEEDRESTART-KCUR") or [""])[0]
                exp = (fields.get("NEEDRESTART-KEXP") or [""])[0]
                detail = f" (running {cur}, installed {exp})" if cur and exp else ""
                out.warn(f"REBOOT REQUIRED — {why}{detail}.")
                out.summary_warn("reboot required (kernel)")
                out.next_step("reboot to start running the kernel you have installed")

            svc = fields.get("NEEDRESTART-SVC", [])
            if not svc:
                out.ok("no services need restarting.")
                return Result()
            out.note("services needing a restart after library upgrades:")
            for s in svc:
                print(f"    {s}")
            out.summary_warn(f"{len(svc)} service(s) need restarting")
            out.next_step("restart them: sudo needrestart")
            return Result()
        if command.which("checkrestart"):
            text = self._query(["checkrestart"]).strip()
            if text:
                print(text)
                out.summary_warn("services need restarting (checkrestart)")
            else:
                out.ok("no services need restarting.")
            return Result()
        out.note("needrestart/checkrestart not found (install needrestart); skipping.")
        return Result()

    # -- config drift --------------------------------------------------------
    def check_config_drift(self, ctx: Context) -> Result:
        out = ctx.output
        etc = ctx.root / "etc"
        found = {suffix: sorted(str(p) for p in etc.rglob(f"*{suffix}"))
                 for suffix in _DRIFT_KINDS} if etc.is_dir() else {}
        total = sum(len(v) for v in found.values())

        if not total:
            out.ok("no pending config-file merges.")
        else:
            for suffix, (displaced, advice) in _DRIFT_KINDS.items():
                files = found.get(suffix) or []
                if not files:
                    continue
                # `.dpkg-old`/`.ucf-old` mean a setting silently stopped applying, which
                # is worse than an unmerged default — so they warn rather than note.
                emit = out.warn if displaced else out.note
                emit(f"{len(files)} {suffix} file(s): {advice}")
                for f in files:
                    print(f"    {f}")
            displaced_n = sum(len(found.get(s) or [])
                              for s, (d, _) in _DRIFT_KINDS.items() if d)
            out.summary_warn(f"{total} config file(s) to review"
                            + (f" — {displaced_n} where YOUR version is no longer in "
                               "effect" if displaced_n else ""))
            out.next_step("review and merge them (see the paths above)")
        # dpkg --audit surfaces half-configured / broken packages.
        if command.which("dpkg"):
            audit = self._query(["dpkg", "--audit"]).strip()
            if audit:
                out.warn("dpkg --audit reports problems:")
                print(audit)
                out.summary_warn("dpkg --audit found package problems")
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
            out.summary_add("ON (unattended-upgrades)")
            self.report_timer_health(ctx, ["apt-daily-upgrade.timer"])
        else:
            reasons = []
            if not installed:
                reasons.append("unattended-upgrades not installed")
            if upgrade == "0":
                reasons.append("Unattended-Upgrade=0")
            if not timer_on:
                reasons.append(f"apt-daily-upgrade.timer {timer or 'not-enabled'}")
            out.note("automatic updates: DISABLED (" + "; ".join(reasons) + ").")
            out.summary_add("OFF")
        if lists != "0":
            out.note(f"package lists auto-refresh is on (Update-Package-Lists={lists}).")
        self._report_pro_coverage(ctx)
        return Result()

    def _report_pro_coverage(self, ctx: Context) -> None:
        """Which of this host's packages are actually receiving security updates.

        "Automatic updates are on" is only half the posture on Ubuntu: unattended-upgrades
        can be working perfectly while a whole class of packages quietly receives no
        security updates at all. Universe/Multiverse packages are covered by `esm-apps`,
        and after an LTS leaves its main window Main/Restricted moves to `esm-infra` —
        both only with an Ubuntu Pro subscription. Measured on a live Ubuntu 24.04 host:
        18 of its 854 packages sit in that gap today.
        """
        out = ctx.output
        data = self._pro_security_status()
        if not data:
            return                      # not Ubuntu, or `pro` absent — nothing to say
        summary = data.get("summary") or {}
        ua = summary.get("ua") or {}

        def _n(key):
            try:
                return max(0, int(summary.get(key) or 0))
            except (TypeError, ValueError):
                return 0

        if ua.get("attached"):
            services = ", ".join(ua.get("enabled_services") or []) or "none enabled"
            out.note(f"Ubuntu Pro: attached ({services}).")
            return
        infra, apps = self._esm_hidden_updates(data)
        if infra or apps:
            out.warn(f"Ubuntu Pro: not attached — {infra + apps} security update(s) are "
                     f"unavailable to this host (esm-infra {infra}, esm-apps {apps}).")
            out.summary_warn(f"{infra + apps} security update(s) need Ubuntu Pro")
            out.next_step("attach a subscription: sudo pro attach")
            return
        uncovered = _n("num_universe_packages") + _n("num_multiverse_packages")
        if uncovered:
            out.note(f"Ubuntu Pro: not attached — {uncovered} installed package(s) come "
                     "from Universe/Multiverse and receive security updates only with "
                     "Pro (esm-apps). None are outstanding right now.")

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
        if not chosen:
            return Result()
        # No blanket `-y`. Purging a kernel image can take the **meta-package** with it —
        # measured on Debian 13, removing one image also purged `linux-image-cloud-amd64`,
        # which is what pulls in future kernel upgrades. So consenting to drop one old
        # kernel would silently stop the machine receiving new ones, and apt's own
        # transaction is the only place that is shown. `orphans` was fixed this way in
        # v0.56.0; this, the more dangerous action, was missed.
        argv = ["apt-get", "purge", *(["-y"] if ctx.assume_yes else []), *chosen]
        before = self.installed_packages(ctx)
        ctx.execute(argv)
        gone = before - self.installed_packages(ctx) if before else set()
        if not gone:
            out.ok("no kernels were removed.")
            return Result()
        extra = sorted(gone - set(chosen))
        detail = (f" (including {len(extra)} other package(s): {', '.join(extra)})"
                  if extra else "")
        out.summary_add(f"{len(gone)} package(s) purged{detail}")
        if any("linux-image" in p and not re.match(r"linux-image-\d", p) for p in extra):
            # Losing the meta-package is not a cleanup, it is a policy change.
            out.warn("a kernel META-package was removed as well — this host will no "
                     "longer pull in new kernel versions automatically. Reinstall it "
                     "(e.g. apt-get install linux-image-<flavour>) if that was not "
                     "intended.")
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
