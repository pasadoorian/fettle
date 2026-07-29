"""RHEL / CentOS Stream / Rocky / AlmaLinux / Oracle Linux backend (dnf + rpm).

This backend landed audit-first — the cross-ecosystem package audit, the binary
hardening audit, container updates and RPM integrity — and is now growing the
maintenance half. Actions still absent from ``supported`` are reported as unsupported
by ``actions.run`` rather than faked, which works because
:class:`~fettle.backends.base.PackageBackend` declares no abstract methods: capability
is advertised through ``supported``, and any method left unimplemented raises
``NotImplementedError`` for the action runner to degrade into a note.

Registering the backend is worth more than it looks: the base class already returns the
distro-agnostic supply-chain providers (flatpak, snap, containers, GNOME extensions,
VS Code extensions, gh extensions), so ``fettle -P`` starts working here with no
RPM-specific code at all. **podman** is RHEL's default container runtime and the
container provider already prefers docker then podman.

**One code path for dnf4 and dnf5.** The advisory provider needed a version gate
because ``updateinfo`` and ``advisory`` emit unrelated formats. The *maintenance* verbs
do not: ``upgrade``, ``check-update``, ``makecache``, ``clean`` and ``autoremove`` were
measured to behave identically on dnf 4.20 (RHEL 10) and dnf5 5.4.2 (Fedora), so
nothing here branches on the dnf version. The only measured divergence is cosmetic and
handled in :func:`_parse_check_update`.

Updater knobs live under ``[updaters.rhel]``: ``system_updater`` (dnf | none),
``flatpak_updater`` (flatpak | none), ``snap_updater`` (snap | none).

Fedora is deliberately *not* claimed as a distro. It shares dnf, but its advisories come
from Bodhi as ``FEDORA-*`` rather than Red Hat's ``RHSA-*``, so a provider tuned for
RHSA data would be honest here and approximate there.
"""

from __future__ import annotations

import os
import re

from .. import command
from .base import Context, PackageBackend, Result, Transaction, TxItem

_SYSTEM_UPDATERS = {"dnf", "none"}
_FLATPAK_UPDATERS = {"flatpak", "none"}
_SNAP_UPDATERS = {"snap", "none"}

# One `dnf check-update` row — exactly three fields, the first of them `name.arch`:
#   NetworkManager.x86_64        1:1.58~rc1-1.el10   centos-stream-baseos
#
# Insisting on *exactly* three fields is what rejects everything else dnf writes to
# stdout, without maintaining a list of things to ignore: the rootless "Not root,
# Subscription Management repositories not updated" notice, "Last metadata expiration
# check: ...", dnf5's bare "Upgrades" section header and blank lines all have a
# different field count. Anchoring at column 0 rejects dnf4's *indented* rows.
_CU_ROW = re.compile(r"^(\S+\.\S+)[ \t]+(\S+)[ \t]+(\S+)[ \t]*$")

# rpm queryformat for "the version string dnf would print". The epoch conditional is
# load-bearing: dnf renders an epoch-bearing package as `1:1.54.0-1.el10`, while a bare
# `%{EVR}` omits the epoch — so old and new would be formatted differently and every
# such package would appear to be changing epoch.
_RPM_QF = r"%{NAME}.%{ARCH} %|EPOCH?{%{EPOCH}:}|%{VERSION}-%{RELEASE}\n"


# Transaction-table section headers -> TxItem kind. Wording measured on dnf 4.20 and
# dnf5 5.4.2, which agree on all of these.
_TX_SECTIONS = {
    "upgrading": "upgrade",
    "installing": "new-dep",
    "installing dependencies": "new-dep",
    "installing weak dependencies": "new-dep",
    "obsoleting": "new-dep",
    "removing": "remove",
    "removing dependent packages": "remove",
    "removing unused dependencies": "remove",
}

# One row of the transaction table: exactly ONE leading space, then
# `name arch version repo [size...]`.
#
# The single-space anchor is load-bearing. dnf5 follows each upgrade with a
# `replacing <pkg>` sub-row indented by three spaces, carrying the version being
# *removed*; accepting those would double every upgrade and list the outgoing version
# as if it were incoming. dnf4 indents its obsoleted packages the same way.
_TX_ROW = re.compile(r"^ (\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s|$)")


def _have_root() -> bool:
    """Whether this process can run ``dnf upgrade``, which refuses to run otherwise."""
    return os.geteuid() == 0


def _image_based(ctx: Context) -> bool:
    """Whether this host booted from an ostree image (rpm-ostree, Fedora Silverblue,
    RHEL Image Mode / bootc) rather than from packages.

    ``/run/ostree-booted`` is the marker to use because it exists only when the running
    system *actually booted* from an ostree deployment — bootc images are ostree-based,
    so it covers both. Testing for an ``rpm-ostree`` or ``bootc`` **binary** instead
    would be wrong: either can be installed on an ordinary RHEL box, and refusing to
    upgrade a perfectly normal machine is a worse failure than the one being guarded
    against.
    """
    return (ctx.root / "run/ostree-booted").exists()


def _image_update_command() -> str:
    """The command that actually updates an image-based host.

    Named from what is installed rather than assumed. ``rpm-ostree`` notably does *not*
    want sudo — it authenticates through polkit over D-Bus — whereas ``bootc`` does.
    """
    if command.which("bootc"):
        return "sudo bootc upgrade"
    if command.which("rpm-ostree"):
        return "rpm-ostree upgrade   (no sudo — it uses polkit)"
    return "bootc upgrade / rpm-ostree upgrade"


def _norm_evr(ver: str) -> str:
    """Drop a zero epoch.

    dnf5's transaction table writes ``0:9.10-4.fc44`` where ``check-update`` and rpm
    write ``9.10-4.fc44``. Left alone, every package on a dnf5 host would appear to be
    gaining an epoch.
    """
    return ver[2:] if ver.startswith("0:") else ver


def _parse_tx_table(text: str) -> tuple[list[tuple[str, str, str]], list[str]]:
    """``([(kind, name.arch, version)], [unrecognised section names])``.

    Parsing stops at "Transaction Summary" — dnf5 writes that with a trailing colon,
    which would otherwise read as a section header.

    Unrecognised sections are *returned*, not skipped: ``Downgrading:`` and
    ``Reinstalling:`` have no equivalent in :class:`~fettle.backends.base.TxItem`'s
    vocabulary, and a section this parser does not understand must be reported rather
    than quietly dropped from a preview the user is about to act on.
    """
    rows: list[tuple[str, str, str]] = []
    unknown: list[str] = []
    kind = ""
    for raw in text.splitlines():
        if raw.startswith("Transaction Summary"):
            break
        stripped = raw.strip()
        if raw[:1] not in (" ", "\t") and stripped.endswith(":"):
            label = stripped[:-1].strip().lower()
            kind = _TX_SECTIONS.get(label, "")
            if not kind and label not in unknown:
                unknown.append(label)
            continue
        m = _TX_ROW.match(raw.rstrip())
        if m and kind:
            name, arch, ver = m.group(1), m.group(2), m.group(3)
            rows.append((kind, f"{name}.{arch}", _norm_evr(ver)))
    return rows, unknown


def _is_obsoletes_header(line: str) -> bool:
    """Whether ``line`` opens the obsoletes block that dnf appends after the upgrades.

    dnf4 writes "Obsoleting Packages" and dnf5 "Obsoleting packages" — both strings
    read out of the shipped binaries, not guessed. Matching a case-insensitive *prefix*
    at column 0 accepts either, and keeps working if a future dnf drops or rewords the
    second word. One predicate, so the parser and the obsoletes count can never
    disagree about where the block starts.
    """
    return line[:1] not in (" ", "\t") and line.strip().lower().startswith("obsoleting")


def _parse_check_update(text: str) -> list[tuple[str, str]]:
    """``(name.arch, new_version)`` for each upgradable package.

    Stops at the obsoletes block. That matters because dnf lists the *obsoleting*
    package there a second time — measured on RHEL 10, ``fwupd`` appears both in the
    main list and again under the header — so reading past it double-counts.

    Packages appearing *only* in that block are not returned: they replace a
    differently-named package, so there is no ``(name, old, new)`` for them. The count
    is surfaced as a note by :meth:`RhelBackend.pending_transaction` rather than being
    silently dropped.
    """
    rows: list[tuple[str, str]] = []
    for raw in text.splitlines():
        if _is_obsoletes_header(raw):
            break
        m = _CU_ROW.match(raw.rstrip())
        if m:
            rows.append((m.group(1), m.group(2)))
    return rows


def _count_obsoletes(text: str) -> int:
    """How many packages the obsoletes block lists (0 when there is no block)."""
    lines = text.splitlines()
    for i, raw in enumerate(lines):
        if _is_obsoletes_header(raw):
            return sum(1 for ln in lines[i + 1:] if _CU_ROW.match(ln.rstrip()))
    return 0

# `rpm -Va` rows, e.g.
#   missing     /boot
#   .....UG..  g /proc
#   S.5....T.  c /etc/dnf/dnf.conf
#   S.5....T.    /usr/bin/gzip
# Anchoring the path on a leading `/` rather than splitting on whitespace keeps
# paths containing spaces intact, and makes the optional file-type marker
# unambiguous.
_VA_RE = re.compile(r"^(\S+)\s+(?:([cdglr])\s+)?(/.*)$")

# Markers whose files are EXPECTED to differ from the package: config files you
# edited, ghost files created at runtime, documentation. A modification here is
# normal operation, not tampering. A row with no marker is a packaged file —
# a binary or library — and that is the row worth alarming about.
_EXPECTED_DRIFT = {"c": "config", "g": "ghost (runtime-created)",
                   "d": "documentation", "l": "license", "r": "readme"}


class RhelBackend(PackageBackend):
    name = "rhel"
    # Only what is actually implemented. Everything else is absent on purpose — see
    # the module docstring; a later phase adds the maintenance actions.
    supported = {
        "pkg_audit",         # via the distro-agnostic providers on the base class
        "hardening_audit",   # checksec-driven; distro-neutral apart from the baseline
        "container_update",  # podman/docker, backend-independent
        "only_update",       # dnf makecache + report upgradable (no upgrade)
    }
    # NOTE: `verify_integrity` below is NOT listed here. `supported` names *pipeline
    # actions*; sys-audit's `packages` category calls the backend method directly
    # (secure/audit.py), so adding it would name an action that does not exist —
    # which is exactly what the action-registry cross-check flagged.

    def supply_chain_sources(self):
        from ..supplychain.dnf_source import DnfSource
        return [DnfSource(), *super().supply_chain_sources()]

    # -- helpers -------------------------------------------------------------
    def _updaters(self, ctx: Context) -> tuple[str, str, str]:
        conf = {}
        if isinstance(ctx.config.updaters, dict):
            conf = ctx.config.updaters.get("rhel", {}) or {}
        system = str(conf.get("system_updater", "dnf"))
        flatpak = str(conf.get("flatpak_updater", "flatpak"))
        snap = str(conf.get("snap_updater", "snap"))
        if system not in _SYSTEM_UPDATERS:
            ctx.output.warn(f"invalid system_updater '{system}'; using dnf")
            system = "dnf"
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
    def _installed_versions() -> dict[str, str]:
        """``name.arch -> installed version``, formatted as dnf would print it.

        One ``rpm -qa`` rather than a query per package: ``check-update`` reports only
        the *new* version, so the old side has to come from the rpm database.
        """
        out: dict[str, str] = {}
        for line in RhelBackend._query(["rpm", "-qa", "--qf", _RPM_QF]).splitlines():
            label, _, ver = line.partition(" ")
            if label and ver:
                out[label] = _norm_evr(ver)
        return out

    # -- pending upgrades ----------------------------------------------------
    def pending_upgrades(self, ctx: Context) -> list[tuple[str, str, str]]:
        """Upgradable packages as ``(name.arch, old, new)``.

        Keyed on ``name.arch`` rather than the bare name because multilib is real: the
        i686 and x86_64 builds of one package are two independent upgrades, and
        collapsing them would report one and hide the other.

        ``dnf check-update`` is rootless — unlike ``dnf upgrade``, which refuses to run
        as a normal user — and **exits 100 when upgrades exist**. 100 is success here;
        0 means nothing to do and anything else is a real failure.
        """
        if not command.which("dnf"):
            return []
        proc = command.run(["dnf", "check-update"], capture=True)
        if proc.returncode not in (0, 100):
            return []
        installed = self._installed_versions()
        return [(label, installed.get(label, ""), new)
                for label, new in _parse_check_update(proc.stdout or "")]

    def refresh_metadata(self, ctx: Context) -> Result:
        # `dnf makecache` downloads repo metadata and upgrades nothing. RPM systems have
        # no partial-upgrade hazard (no rolling-release ABI coupling like Arch), so this
        # is safe to run on its own. It writes /var/cache/dnf, hence root — `only_update`
        # is deliberately outside cli.NO_ROOT_ACTIONS.
        system, flatpak, _snap = self._updaters(ctx)
        if system != "none":
            ctx.execute(["dnf", "makecache"], quiet=True, msg="dnf metadata refreshed")
        if flatpak != "none" and command.which("flatpak"):
            ctx.execute(["flatpak", "update", "--appstream"], quiet=True,
                        msg="flatpak metadata refreshed")
        # snap has no safe metadata-only refresh (snapd refreshes itself) — skipped.
        return Result()

    def pending_transaction(self, ctx: Context, *, sync: bool = True) -> Transaction:
        """The transaction ``update`` would perform.

        **dnf has no rootless equivalent of ``apt-get -s``.** ``dnf upgrade --assumeno``
        resolves the real thing — new dependencies, obsoletes, removals — but refuses to
        run without root. So the branch is on privilege, not on a flag: as root (which
        ``-O`` already is, and which ``--dry-run --full-preview`` opts into) the full
        resolver runs; otherwise the preview lists upgrades only and *says* it is
        partial, because a partial answer must never render identically to a complete
        one.
        """
        if not command.which("dnf"):
            return Transaction(ok=False, notes=["dnf not found"])
        if _image_based(ctx):
            # dnf can still *list* upgrades here, and that list is a lie: applying it
            # writes into a deployment the next boot discards. ok=False so the runner
            # reports "could not determine" instead of an actionable-looking preview.
            return Transaction(ok=False, notes=[
                "this host booted from an ostree image, so dnf cannot upgrade it — "
                "changes would not survive a reboot",
                f"update the image instead: {_image_update_command()}"])
        if _have_root():
            return self._full_transaction(ctx, sync=sync)
        return self._partial_transaction(ctx)

    def _full_transaction(self, ctx: Context, *, sync: bool) -> Transaction:
        """Resolve the complete transaction with ``dnf upgrade --assumeno`` (needs root).

        ``--assumeno`` answers dnf's own confirmation prompt with "no", so nothing is
        installed; it is safe under ``--dry-run`` and is therefore *not* routed through
        ``ctx.execute``, which would suppress it. It can still refresh the metadata cache
        on the way, so ``--no-sync`` adds ``-C`` for a purely cached answer.
        """
        argv = ["dnf", "upgrade", "--assumeno"] if sync else \
               ["dnf", "-C", "upgrade", "--assumeno"]
        proc = command.run(argv, capture=True)
        text = proc.stdout or ""
        rows, unknown = _parse_tx_table(text)

        # Exit codes, measured: 0 with "Nothing to do." when there is nothing to
        # upgrade; 1 when --assumeno declines at the prompt; and *also* 1 for a genuine
        # error ("Error: No packages marked for upgrade."). 1 is therefore ambiguous, so
        # the resolved table is the discriminator rather than a localisable message.
        resolved = bool(rows) or "Nothing to do" in text
        if proc.returncode > 1 or (proc.returncode == 1 and not resolved):
            err = [ln for ln in (proc.stderr or "").strip().splitlines()
                   if ln.strip() and "Operation aborted" not in ln]
            return Transaction(ok=False, notes=[
                f"dnf upgrade --assumeno failed (exit {proc.returncode})", *err[:3]])

        installed = self._installed_versions()
        items = []
        for kind, label, ver in rows:
            old = installed.get(label)
            if kind == "remove":
                items.append(TxItem(name=label, new="", old=old or "", kind="remove"))
            elif kind == "upgrade":
                items.append(TxItem(name=label, new=ver, old=old, kind="upgrade"))
            else:
                items.append(TxItem(name=label, new=ver, old=None, kind="new-dep"))

        notes = []
        if not sync:
            notes.append("preview built from cached metadata (--no-sync) — it may miss "
                         "upgrades published since the last refresh")
        if unknown:
            # e.g. Downgrading: / Reinstalling:, which TxItem cannot express.
            notes.append("this preview does not itemise dnf's "
                         f"{', '.join(unknown)} section(s) — inspect with "
                         "`dnf upgrade --assumeno` before applying")
        return Transaction(items=items, ok=True, notes=notes)

    def _partial_transaction(self, ctx: Context) -> Transaction:
        """Upgrades only, from the rootless ``dnf check-update``, with the gap stated."""
        proc = command.run(["dnf", "check-update"], capture=True)
        if proc.returncode not in (0, 100):
            err = (proc.stderr or "").strip().splitlines()
            return Transaction(ok=False, notes=[f"dnf check-update failed "
                                                f"(exit {proc.returncode})",
                                                *err[:3]])
        text = proc.stdout or ""
        installed = self._installed_versions()
        items = [TxItem(name=label, new=new, old=installed.get(label) or None,
                        kind="upgrade" if installed.get(label) else "new-dep")
                 for label, new in _parse_check_update(text)]

        gap = "new dependencies and removals are not shown — dnf cannot resolve a full "
        if getattr(ctx, "full_preview", False):
            # Asked for the full preview and still landed here: elevation did not
            # happen. Say that, rather than advising a flag they already passed.
            notes = [gap + "transaction without root, and this process is not root "
                           "despite --full-preview"]
        else:
            notes = [gap + "transaction without root; add --full-preview to elevate "
                           "and resolve the complete set"]
        obsoletes = _count_obsoletes(text)
        if obsoletes:
            notes.append(f"{obsoletes} package(s) additionally replace obsoleted "
                         "packages (see --full-preview)")
        if "Not root, Subscription Management repositories not updated" in text:
            notes.append("subscription-manager repositories were not refreshed for this "
                         "rootless query — a subscribed RHEL host may have more updates "
                         "than shown")
        return Transaction(items=items, ok=True, notes=notes)

    def verify_integrity(self, scan) -> None:
        """sys-audit's ``packages`` check — the RPM analogue of debsums/paccheck.

        ``rpm -Va`` compares every installed file against the package metadata. Two
        things about it drive this implementation:

        **Its exit code cannot detect failure.** ``rpm -Va`` exits 1 when it merely
        *finds* discrepancies, and — measured — exits **0 with no output** when the
        database is unreadable, which is byte-identical to a clean system. So the
        database is proven readable first; without that, "could not look" and "all
        verified" are the same result.

        **Most rows are expected.** Config files you edited, ghost files created at
        runtime and documentation all legitimately differ, and on a stock system they
        are the bulk of the output. Rows with no file-type marker are packaged files —
        binaries and libraries — and those are the ones worth alarming about.
        """
        scan.sub("RPM Package Verification")
        if not scan.which("rpm"):
            scan.status("rpm", "Not installed", "error")
            return

        probe, probe_rc = scan.run_text_rc(["rpm", "-q", "rpm"])
        if probe_rc != 0 or not probe.strip():
            scan.status("Package Integrity",
                        "UNKNOWN — the rpm database could not be queried; packages "
                        "were NOT verified", "error")
            return

        scan.dim("Running rpm -Va (this may take a while)...")
        # rc 0 (clean) and rc 1 (discrepancies found) are both successful runs.
        out, rc = scan.run_text_rc(["rpm", "-Va"])
        if rc > 1:
            scan.status("Package Integrity",
                        f"UNKNOWN — rpm -Va failed (exit {rc}); packages were NOT "
                        "verified", "error")
            return

        altered, expected = [], []
        for line in out.splitlines():
            m = _VA_RE.match(line.rstrip())
            if not m:
                continue
            (altered if m.group(2) is None else expected).append(line.rstrip())

        if altered:
            scan.status("Package Integrity",
                        f"{len(altered)} packaged file(s) differ from their package",
                        "error")
            scan.result("\n".join(altered[:50]))
        else:
            scan.status("Package Integrity",
                        "No packaged files altered", "ok")
        if expected:
            # Reported, not hidden — but as context, so it cannot drown the signal.
            scan.status("Expected differences",
                        f"{len(expected)} config/ghost/doc file(s) differ "
                        "(normal: you edited them, or they are created at runtime)",
                        "info")
            if scan.verbose:
                scan.result("\n".join(expected[:50]))
