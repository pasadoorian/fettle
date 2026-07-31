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

from pathlib import Path

from .. import command, reports
from ..util import matches_any
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

# `dnf repoquery` output format. One `name.arch` per line — see `_repoquery` for the two
# quirks this has to survive.
_REPOQUERY_QF = r"%{name}.%{arch}\n"

# Defence in depth behind the `--installonly` query: a name that starts with one of
# these is never offered for removal even if dnf does not report it as installonly.
# Removing a running kernel leaves an unbootable machine, so over-protecting (a package
# like `kernelshark` is spared needlessly) is the right direction to err in.
_NEVER_REMOVE_PREFIXES = ("kernel",)

# rpm's config leftovers. These are NOT interchangeable, and the difference is the whole
# point: with a `.rpmnew` your file is still in effect and a new default sits unmerged
# beside it, whereas with a `.rpmsave` or `.rpmorig` **your file is no longer in effect**
# — rpm moved it aside and installed the package's version. Lumping them together (as the
# Debian backend does for its own three suffixes) would hide the case where a machine
# quietly stopped honouring settings someone deliberately made.
_DRIFT_KINDS = {
    ".rpmnew": (False, "the package shipped a new default; YOUR file is still in effect "
                       "— review the .rpmnew for options worth adopting"),
    ".rpmsave": (True, "YOUR file was moved aside and the PACKAGE's version is now in "
                       "effect — settings you made are NOT active"),
    ".rpmorig": (True, "the file present before the package owned it was moved aside; "
                       "the package's version is now in effect"),
}


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


# Informational lines dnf writes to **stdout** rather than stderr. They contaminate any
# "did this command produce output?" test, and doing exactly that made `dnf check` report
# package problems on a clean box: an unregistered RHEL host emits three of these and
# exits 0. All measured on the live RHEL 10.1 machine, rootless and as root.
_DNF_STDOUT_NOTICES = (
    "Not root,",
    "Last metadata expiration check",
    "Updating Subscription Management repositories",
    "Unable to read consumer identity",
    "This system is not registered",
)


def _kernel_key(version: str) -> tuple[int, ...]:
    """Numeric sort key for an rpm kernel version, so `6.12.0-218.el10` sorts above
    `6.12.0-124.8.1.el10_1` — a plain string sort gets that backwards.

    A digit-run comparison, not a real rpm vercmp (RHEL ships no guaranteed vercmp CLI).
    Good enough because this report never *removes* anything: the worst a mis-sort can do
    is mislabel which kernel boots next, not delete the wrong one.
    """
    return tuple(int(n) for n in re.findall(r"\d+", version))


def _strip_dnf_notices(text: str) -> str:
    """Drop dnf's informational stdout lines, leaving only real output.

    The other parsers here are immune to these by construction — they require a specific
    row shape (three fields, or a whitespace-free ``name.arch``) that no notice matches.
    Anything that merely asks "was there output?" needs this.
    """
    return "\n".join(ln for ln in text.splitlines()
                     if ln.strip() and not ln.startswith(_DNF_STDOUT_NOTICES)).strip()


# dnf-automatic's timers, and whether the *unit* forces a behaviour that overrides
# `automatic.conf`. Read out of the shipped .service files rather than guessed:
#   dnf-automatic.service            --timer
#   dnf-automatic-install.service    --timer --installupdates
#   dnf-automatic-download.service   --timer --downloadupdates --no-installupdates
#   dnf-automatic-notifyonly.service --timer --no-installupdates --no-downloadupdates
#
# So `-install` applies updates even with `apply_updates = no`, and `-download` /
# `-notifyonly` never apply them even with `apply_updates = yes`. Reading the config alone
# — or only the plain `dnf-automatic.timer` — reports "auto-updates OFF" on a machine that
# upgrades itself every night. True/False force it; None defers to the config file.
_AUTO_TIMERS = {
    "dnf-automatic-install.timer": True,
    "dnf-automatic-download.timer": False,
    "dnf-automatic-notifyonly.timer": False,
    "dnf-automatic.timer": None,
    "dnf5-automatic.timer": None,     # dnf5 ships its own unit under a second name
}

# Checked in order, first one that exists wins. On dnf5 both `/etc` entries are rpm
# **ghost** files that are never written to disk, so the shipped defaults under
# `/usr/share` are what actually applies unless an admin created one of the others.
_AUTO_CONF_PATHS = (
    "etc/dnf/dnf5-plugins/automatic.conf",
    "etc/dnf/automatic.conf",
    "usr/share/dnf5/dnf5-plugins/automatic.conf",
)

# `systemctl is-enabled` states that mean the unit will actually be started. Everything
# else — disabled, static, indirect, masked, generated, not-found — will not.
_UNIT_ON = ("enabled", "enabled-runtime")


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
        "update",            # dnf upgrade --refresh (+ flatpak/snap when present)
        "clean",             # dnf clean packages (NOT clean all) + unused flatpaks
        "orphans",           # repoquery --unneeded/--extras; kernels never offered
        "config_drift",      # .rpmnew/.rpmsave/.rpmorig + dnf check
        "firmware_check",    # fwupd; the base-class impl, nothing RPM-specific
        "auto_updates",      # dnf-automatic: four timers, and they override the config
        "rebuild_check",     # needs-restarting: standalone on dnf4, a subcommand on dnf5
        "kernel",            # informational: dnf enforces installonly_limit itself
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

    # -- config drift --------------------------------------------------------
    # -- file -> package attribution (for the hardening audit) ---------------
    def map_files_to_packages(self, paths) -> dict[str, str]:
        """Map each installed file to the rpm that owns it.

        **Only paths that exist are queried**, because rpm handles its two failure modes
        differently and only one of them keeps the output aligned with the input:

        * a **missing** file → ``error: file …: No such file or directory`` on *stderr*
          and the line is **skipped**, so every later result shifts up by one and gets
          attributed to the wrong file;
        * a file that exists but is **unowned** → ``file X is not owned by any package``
          inline on *stdout*, which preserves the 1:1 mapping.

        Filtering to existing paths turns the dangerous case into the safe one, and the
        length check below refuses to guess if alignment is somehow still lost — an empty
        map degrades the hardening report to "no package named", whereas a shifted map
        would confidently blame the wrong package.
        """
        from pathlib import Path

        wanted = [str(p) for p in paths]
        if not wanted or not command.which("rpm"):
            return {}
        existing = [p for p in wanted if Path(p).exists()]
        if not existing:
            return {}
        proc = command.run(["rpm", "-qf", "--qf", r"%{NAME}\n", *existing], capture=True)
        lines = (proc.stdout or "").splitlines()
        if len(lines) != len(existing):
            return {}
        return {path: name.strip() for path, name in zip(existing, lines)
                if name.strip() and "not owned by any package" not in name}

    # -- kernels -------------------------------------------------------------
    def manage_kernels(self, ctx: Context) -> Result:
        """Report installed kernels. Informational, because dnf prunes them itself.

        Unlike apt, dnf enforces ``installonly_limit`` (3 by default) — installing a
        fourth kernel removes the oldest automatically. So there is no routine cleanup to
        offer, and the most dangerous operation in the tool is simply not performed here.
        What is worth reporting is which kernel is running, whether a newer one is waiting
        for a reboot, and how many of the limit's slots are used.

        **``kernel-core`` is queried, not ``kernel``.** Measured on the RHEL 10.1 VM:
        ``rpm -q kernel`` reported *one* version while ``kernel-core`` reported *two*,
        including the running one. On RHEL 8+ ``kernel-core`` is the package that actually
        carries the kernel, so querying ``kernel`` can hide the kernel you booted.
        """
        out = ctx.output
        if not command.which("rpm"):
            out.note("rpm not found; skipping the kernel report.")
            return Result()
        proc = command.run(["rpm", "-q", "kernel-core", "--qf",
                            r"%{VERSION}-%{RELEASE}.%{ARCH}\n"], capture=True)
        # rpm writes "package kernel-core is not installed" to *stdout*, not stderr.
        installed = sorted((ln.strip() for ln in (proc.stdout or "").splitlines()
                            if ln.strip() and "is not installed" not in ln),
                           key=_kernel_key)
        if not installed:
            out.note("no kernel-core package is installed — normal in a container, and "
                     "expected on an image-based host.")
            return Result()

        running = command.run(["uname", "-r"], capture=True).stdout.strip()
        newest = installed[-1]
        out.note(f"{len(installed)} kernel(s) installed:")
        for ver in installed:
            tags = []
            if ver == running:
                tags.append("running")
            if ver == newest and ver != running:
                tags.append("newest — boots next")
            print(f"    {ver}{'  (' + ', '.join(tags) + ')' if tags else ''}")

        if running and running != newest and _kernel_key(running) < _kernel_key(newest):
            out.warn("a newer kernel is installed but not running — reboot to activate "
                     f"it ({newest}).")
            out.next_step("reboot to switch to the newest kernel")
        elif running and running not in installed:
            # Running a kernel rpm has no record of: a hand-built one, or the package was
            # removed underneath it. Either way, not something to quietly ignore.
            out.warn(f"the running kernel ({running}) is not owned by any installed "
                     "kernel-core package.")

        limit = self._installonly_limit(ctx)
        out.note(f"dnf keeps at most {limit} kernel(s) (installonly_limit) and removes "
                 f"the oldest itself — {len(installed)} of {limit} slots used, so no "
                 "removal is offered here.")
        if len(installed) > limit:
            out.note("there are more kernels than the limit; dnf prunes on the next "
                     "kernel install, or clear them now with: "
                     "sudo dnf remove --oldinstallonly")
        return Result()

    @staticmethod
    def _installonly_limit(ctx: Context) -> int:
        """``installonly_limit`` from dnf.conf; dnf's own default is 3."""
        conf = ctx.root / "etc/dnf/dnf.conf"
        try:
            for line in conf.read_text(errors="replace").splitlines():
                key, sep, val = line.partition("=")
                if sep and key.strip() == "installonly_limit":
                    return max(1, int(val.strip()))
        except (OSError, ValueError):
            pass
        return 3

    # -- rebuilds / restarts after an upgrade --------------------------------
    def check_rebuilds(self, ctx: Context) -> Result:
        """Whether a reboot or a service restart is owed after upgrading.

        **Two invocations, one meaning.** dnf4 ships a standalone ``needs-restarting``
        (from ``yum-utils``) where ``-r`` is the reboot hint. dnf5 ships **no such
        binary** — the hint is bare ``dnf needs-restarting``, and its own ``-r`` is
        documented as *"Has no effect, kept for compatibility with DNF 4"*. Keyed on which
        of the two exists rather than on a version string.

        **Exit codes, measured on both: 0 = no reboot needed, 1 = reboot required.** 1 is
        also dnf's generic error code, so as everywhere else in this backend the output is
        the discriminator — and the *safe* direction is asymmetric here. Wrongly saying
        "reboot required" costs a needless reboot; wrongly saying "no reboot required"
        leaves a machine running the old libraries it just patched. So only exit 0 is
        allowed to mean "no reboot"; anything else is either the hint or an admission that
        it could not be determined. Printing the body verbatim also keeps this working on
        a localised system, where matching an English phrase would not.
        """
        out = ctx.output
        standalone = command.which("needs-restarting")
        if not standalone and not command.which("dnf"):
            out.note("needs-restarting not found (dnf4: `dnf install yum-utils`; "
                     "dnf5: `dnf install dnf5-plugin-needs-restarting`); skipping.")
            return Result()

        hint = ["needs-restarting", "-r"] if standalone else ["dnf", "needs-restarting"]
        proc = command.run(hint, capture=True)
        body = _strip_dnf_notices(proc.stdout or "")
        if proc.returncode == 0:
            out.ok("no reboot required.")
        elif body:
            out.warn("a reboot is required — core libraries or services were updated "
                     "since this host booted:")
            print(body)
            out.summary_add("reboot required")
            out.next_step("reboot to finish applying those updates")
        else:
            err = _strip_dnf_notices(proc.stderr or "").splitlines()
            out.warn(f"could not determine whether a reboot is required (exit "
                     f"{proc.returncode}) — NOT assessed."
                     + (f" {err[0]}" if err else ""))

        self._restartable_services(ctx, standalone=bool(standalone))
        return Result()

    @staticmethod
    def _restartable_services(ctx: Context, *, standalone: bool) -> None:
        """Services started before their dependencies were updated (``-s``).

        Needs root, and **silently returns nothing without it** — measured on the RHEL VM,
        where rootless ``-s`` printed no services at all while root printed the real
        (empty) answer. So an unprivileged run has to say it could not look rather than
        report a clean list. ``rebuild_check`` is outside ``cli.NO_ROOT_ACTIONS``, so a
        normal run is already elevated; this guard is for ``--dry-run``.
        """
        out = ctx.output
        if not _have_root():
            out.note("not root, so the list of services needing a restart was not "
                     "collected (it reads other users' processes).")
            return
        argv = ["needs-restarting", "-s"] if standalone \
            else ["dnf", "needs-restarting", "-s"]
        proc = command.run(argv, capture=True)
        if proc.returncode not in (0, 1):
            out.warn(f"could not list services needing a restart (exit "
                     f"{proc.returncode}).")
            return
        services = [ln.strip() for ln in
                    _strip_dnf_notices(proc.stdout or "").splitlines() if ln.strip()]
        if not services:
            out.ok("no services need restarting.")
            return
        out.note("services started before their dependencies were updated:")
        for svc in services[:40]:
            print(f"    {svc}")
        out.summary_add(f"{len(services)} service(s) need restarting")
        out.next_step("restart them: sudo systemctl restart " + " ".join(services[:5])
                      + (" …" if len(services) > 5 else ""))

    # -- automatic-update posture --------------------------------------------
    @staticmethod
    def _unit_state(unit: str) -> str:
        """``systemctl is-enabled`` for one unit, as its *text*.

        Keyed on the text and not the exit code deliberately: `not-found` came back
        rc=1 on the RHEL VM and rc=4 in a container, so the code cannot be compared
        against a fixed value. The text is stable across both.
        """
        proc = command.run(["systemctl", "is-enabled", unit], capture=True)
        # `not-found` arrives on stderr in some systemd versions and stdout in others.
        text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        return text.splitlines()[0].strip() if text else ""

    def _automatic_conf(self, ctx: Context) -> tuple[dict, str]:
        """``([commands] as a dict, path used)`` from dnf-automatic's config.

        Returns ``({}, "")`` when no config exists anywhere, which is a real state on
        dnf5: its ``/etc`` entries are rpm ghost files. Both generations default
        ``apply_updates`` to ``no``, so an absent file is not permissive — but the
        shipped ``/usr/share`` copy is read rather than that assumption hardcoded.
        """
        import configparser

        for rel in _AUTO_CONF_PATHS:
            path = ctx.root / rel
            if not path.is_file():
                continue
            # interpolation off: `reboot_command` carries quotes and shell text.
            cp = configparser.ConfigParser(strict=False, interpolation=None)
            try:
                cp.read_string(path.read_text(errors="replace"))
            except (OSError, configparser.Error):
                continue
            return (dict(cp["commands"]) if cp.has_section("commands") else {}), str(path)
        return {}, ""

    def check_auto_updates(self, ctx: Context) -> Result:
        """Report whether this host installs updates by itself (read-only).

        The subtle part is that **the timer overrides the config**. `dnf-automatic` ships
        four timers; `-install` passes `--installupdates` and so applies updates even when
        `automatic.conf` says ``apply_updates = no``, while `-download` and `-notifyonly`
        pass `--no-installupdates` and never apply them however the file is set. A check
        that reads only the config, or only the plain timer, gets both cases backwards.
        """
        out = ctx.output
        if not command.which("systemctl"):
            out.note("systemctl not found; cannot determine the automatic-update state.")
            return Result()

        states = {unit: self._unit_state(unit) for unit in _AUTO_TIMERS}
        if all(s == "not-found" for s in states.values()):
            out.note("automatic updates: DISABLED (dnf-automatic is not installed — none "
                     "of its timers exist).")
            out.summary_add("auto-updates: OFF")
            out.next_step("to enable: dnf install dnf-automatic, set apply_updates=yes "
                          "in /etc/dnf/automatic.conf, then enable dnf-automatic.timer")
            return Result()

        enabled = [u for u, s in states.items() if s in _UNIT_ON]
        forced_on = [u for u in enabled if _AUTO_TIMERS[u] is True]
        forced_off = [u for u in enabled if _AUTO_TIMERS[u] is False]
        by_config = [u for u in enabled if _AUTO_TIMERS[u] is None]
        commands, conf_path = self._automatic_conf(ctx)
        apply_updates = str(commands.get("apply_updates", "no")).strip().lower() \
            in ("yes", "true", "1")

        if forced_on:
            out.note(f"automatic updates: ENABLED — {', '.join(forced_on)} installs "
                     "upgrades. That unit passes --installupdates, so it applies them "
                     f"regardless of apply_updates in {conf_path or 'automatic.conf'}.")
            out.summary_add("auto-updates: ON (dnf-automatic)")
        elif by_config and apply_updates:
            out.note(f"automatic updates: ENABLED — {', '.join(by_config)} with "
                     f"apply_updates=yes in {conf_path}.")
            out.summary_add("auto-updates: ON (dnf-automatic)")
        else:
            reasons = []
            if not enabled:
                installed = [u for u, s in states.items() if s != "not-found"]
                reasons.append("dnf-automatic is installed but none of its timers are "
                               f"enabled ({', '.join(sorted(installed))})")
            if by_config and not apply_updates:
                where = conf_path or "no automatic.conf found; dnf's default is off"
                reasons.append(f"apply_updates is not set ({where})")
            if forced_off:
                # Not the same as "off": updates are fetched, so a later manual upgrade
                # is fast, and nothing is applied. Worth stating rather than collapsing.
                reasons.append(f"{', '.join(forced_off)} only downloads or notifies — it "
                               "passes --no-installupdates, so nothing is applied even "
                               "with apply_updates=yes")
            out.note("automatic updates: DISABLED (" + "; ".join(reasons) + ").")
            out.summary_add("auto-updates: OFF")

        reboot = str(commands.get("reboot", "never")).strip().lower()
        if reboot != "never" and (forced_on or (by_config and apply_updates)):
            # A server rebooting itself is a bigger operational fact than the updates.
            out.warn(f"this host is configured to REBOOT ITSELF after applying updates "
                     f"(reboot = {reboot} in {conf_path}).")
            out.summary_add("auto-updates: host reboots itself")

        if self._unit_state("dnf-makecache.timer") in _UNIT_ON:
            out.note("repo metadata refreshes on a timer (dnf-makecache.timer).")

        # Unit files are readable without systemd running, so "enabled" can be true on
        # disk while nothing will ever start it — true inside a container.
        running = command.run(["systemctl", "is-system-running"], capture=True)
        if "offline" in ((running.stdout or "") + (running.stderr or "")).lower():
            out.warn("systemd is not running as init here, so the timer state above was "
                     "read from unit files and nothing will actually fire.")
        return Result()

    def check_config_drift(self, ctx: Context) -> Result:
        """Pending config merges, plus a package-database sanity check.

        Scans ``/etc`` only, matching the Debian backend. rpm can drop these leftovers
        elsewhere, but configuration is what a human needs to reconcile, and walking the
        whole filesystem to find a stray ``.rpmnew`` under ``/usr/share`` is not worth
        the cost.
        """
        out = ctx.output
        etc = ctx.root / "etc"
        found = {suffix: sorted(str(p) for p in etc.rglob(f"*{suffix}"))
                 for suffix in _DRIFT_KINDS} if etc.is_dir() else {}
        total = sum(len(v) for v in found.values())

        if not total:
            out.ok("no pending config-file merges.")
        else:
            for suffix, (lost, advice) in _DRIFT_KINDS.items():
                files = found.get(suffix) or []
                if not files:
                    continue
                # `.rpmsave`/`.rpmorig` mean a setting silently stopped applying, which
                # is worse than an unmerged default — so they warn rather than note.
                emit = out.warn if lost else out.note
                emit(f"{len(files)} {suffix} file(s): {advice}")
                for path in files:
                    print(f"    {path}")
            out.summary_add(f"{total} config file(s) to review")
            if command.which("rpmconf"):
                out.next_step("reconcile them interactively: sudo rpmconf -a")
            else:
                out.next_step("merge them by hand, or install rpmconf "
                              "(dnf install rpmconf) and run: sudo rpmconf -a")
        self._dnf_check(ctx)
        return Result()

    @staticmethod
    def _dnf_check(ctx: Context) -> None:
        """``dnf check`` — the analogue of Debian's ``dpkg --audit``.

        **Exit 1 means "problems were found", not "the check failed"** — the same trap as
        ``rpm -Va`` and ``dnf check-update``. But a genuinely broken dnf *also* exits 1:
        measured, removing libxml2 breaks dnf's own Python bindings and it exits 1 with a
        traceback. The code alone cannot separate the two, so the presence of output on
        stdout is the discriminator, and a non-zero exit with nothing on stdout is
        reported as "not assessed" rather than as a clean bill of health.

        The problem list is shown verbatim rather than parsed, because the two
        generations disagree about its shape: dnf4 writes one line per problem
        (``pkg has missing requires of dep``), dnf5 writes the package on one line with an
        indented ``missing require "dep"`` beneath it. Only the count is extracted, from
        the summary line both write to *stderr*.
        """
        if not command.which("dnf"):
            return
        proc = command.run(["dnf", "check"], capture=True)
        # Notices must go before the emptiness test, not after: an unregistered RHEL box
        # writes three of them to stdout and exits 0, which read as "problems found".
        body = _strip_dnf_notices(proc.stdout or "")
        if proc.returncode == 0 and not body:
            ctx.output.ok("dnf check: no package problems.")
            return
        if not body:
            ctx.output.warn(f"dnf check could not run (exit {proc.returncode}) — "
                            "package problems were NOT assessed.")
            return
        match = re.search(r"(\d+)\s+problem", proc.stderr or "")
        count = f"{match.group(1)} " if match else ""
        ctx.output.warn(f"dnf check found {count}package problem(s):")
        print("\n".join(body.splitlines()[:40]))
        ctx.output.summary_add("dnf check found package problems")

    # -- orphans / foreign packages ------------------------------------------
    @staticmethod
    def _repoquery(*flags: str) -> tuple[list[str], bool]:
        """``(name.arch list, query_succeeded)`` from ``dnf repoquery``.

        The success flag is not decoration. One caller is the kernel-protection set, and
        a failed query returns an empty list that is byte-identical to "no kernels are
        installed" — which would quietly offer a running kernel for removal. It nearly
        happened: **dnf5 rejects ``--installonly --installed`` as mutually exclusive**
        (dnf4 accepts the pair), and the complaint goes to *stderr*, so the pair looked
        like a clean empty answer. ``--installonly`` alone means "installed installonly
        packages" on both, and is what is used.

        Two output quirks, both measured:

        * **dnf4 already terminates each record with a newline**, so the ``\\n`` that
          dnf5 *requires* — without it dnf5 runs every record together on one line —
          makes dnf4 emit a blank line between entries.
        * dnf writes its rootless "Not root, Subscription Management repositories not
          updated" notice to **stdout**, mixed in with the results.

        Keeping only whitespace-free tokens containing a dot handles both.
        """
        proc = command.run(["dnf", "repoquery", *flags,
                            "--queryformat", _REPOQUERY_QF], capture=True)
        if proc.returncode != 0:
            return [], False
        found = {ln.strip() for ln in (proc.stdout or "").splitlines()}
        return sorted(n for n in found
                      if n and "." in n and not any(c.isspace() for c in n)), True

    def _report_foreign(self, ctx: Context) -> None:
        """Installed packages that no enabled repository offers — the RPM analogue of
        Debian's obsolete-package report, written to the same report name so
        ``fettle report`` picks it up either way."""
        out = ctx.output
        extras, ok = self._repoquery("--extras")
        if not ok:
            out.warn("could not list packages absent from every repository "
                     "(dnf repoquery --extras failed); skipping that report.")
            return
        if not extras:
            out.ok("every installed package comes from an enabled repository.")
            return
        if ctx.dry_run:
            out.note(f"{len(extras)} package(s) from no enabled repository would be "
                     "saved for review")
            return
        try:
            review = reports.write_report("obsolete-pkgs", "\n".join(extras), ctx,
                                         data={"packages": list(extras)})
            out.note(f"packages from no enabled repository saved to {review} for review "
                     f"({len(extras)} found)")
        except OSError as exc:
            out.warn(f"could not write obsolete-pkgs report: {exc}")

    def check_foreign_orphans(self, ctx: Context) -> Result:
        out, cfg = ctx.output, ctx.config
        self._report_foreign(ctx)

        unneeded, ok = self._repoquery("--unneeded")
        if not ok:
            out.warn("could not list unused dependencies (dnf repoquery --unneeded "
                     "failed); nothing is offered for removal.")
            return Result()
        if not unneeded:
            out.ok("no unused dependencies.")
            return Result()

        # Fail SAFE: without a trustworthy installonly set there is no way to know which
        # of these is a kernel, and offering one is not a mistake that can be undone
        # from a shell that no longer boots.
        installonly, ok = self._repoquery("--installonly")
        if not ok:
            out.warn("could not determine which packages dnf keeps multiple versions "
                     "of (kernels), so nothing is offered for removal — removing a "
                     "running kernel leaves an unbootable system.")
            return Result()

        protected = {p for p in unneeded
                     if p in installonly
                     or p.split(".")[0].startswith(_NEVER_REMOVE_PREFIXES)}
        kept = {p for p in unneeded if matches_any(p, cfg.keep_orphans)}
        candidates = [p for p in unneeded if p not in protected and p not in kept]

        if protected:
            # Named, not hidden: dnf's autoremove has been known to propose removing
            # kernels when the `dnf mark` reason data is incomplete, and a user who sees
            # nothing cannot tell that anything was held back.
            out.note(f"{len(protected)} unused package(s) held back as installonly "
                     "(kernels are never offered): " + ", ".join(sorted(protected)))
        if kept:
            out.note(f"{len(kept)} skipped by keep_orphans: " + ", ".join(sorted(kept)))
        if not candidates:
            out.ok("no unused dependencies eligible for removal.")
            return Result()

        out.note(f"{len(candidates)} unused dependency(ies) eligible for removal:")
        for pkg in candidates:
            print(f"    {pkg}")
        if ctx.dry_run:
            out.note("would ask about each, then run: dnf remove <chosen>")
            return Result()
        chosen = ctx.select(candidates, prompt="remove unused dependency")
        if not chosen:
            return Result()
        # `dnf remove` on the chosen list, NOT `dnf autoremove`: the selection is
        # per-package, and autoremove is all-or-nothing by construction. Without --yes
        # dnf then shows its own transaction and confirms, so a removal that cascades
        # into dependents cannot happen unseen.
        argv = ["dnf", "remove", *chosen]
        if ctx.assume_yes:
            argv.append("-y")
        ctx.execute(argv)
        out.summary_add(f"{len(chosen)} unused dependency(ies) removed")
        return Result()

    # -- clean ---------------------------------------------------------------
    def cache_paths(self, ctx: Context) -> list[Path]:
        """Both dnf generations' cache roots.

        dnf5 caches under ``/var/cache/libdnf5`` and leaves an **empty**
        ``/var/cache/dnf`` behind — measuring only the latter on Fedora reports a clean
        cache that was never looked at. Listing both means the size is right whichever
        generation is installed, and the absent one contributes zero.
        """
        return [ctx.root / "var/cache/dnf", ctx.root / "var/cache/libdnf5"]

    def clean_caches(self, ctx: Context) -> Result:
        """Reclaim disk from downloaded packages, keeping the repo metadata.

        **``clean packages``, deliberately not ``clean all``.** The two are very
        differently priced: measured on the RHEL 10.1 box, ``/var/cache/dnf`` held 796M
        of which 736M was ``.rpm`` files and 60M was metadata. ``clean packages`` frees
        the 736M; ``clean all`` would also throw away the metadata, so the very next dnf
        command re-downloads it — a slow, network-dependent surprise in exchange for a
        rounding error of disk.

        Worth knowing: RHEL ships ``keepcache=0``, so packages are normally removed
        after a successful install. A large ``.rpm`` cache therefore usually means an
        *interrupted* transaction, which is exactly the case where reclaiming it helps.

        The one confirmation for the whole action already lives in ``actions._clean``.
        """
        _, flatpak, snap = self._updaters(ctx)
        ctx.execute(["dnf", "clean", "packages"], quiet=True,
                    msg="dnf package cache cleared")
        if flatpak != "none" and command.which("flatpak"):
            ctx.execute(["flatpak", "uninstall", "--unused", "-y"], quiet=True,
                        msg="unused flatpaks removed")
        if snap != "none":
            self._prune_disabled_snaps(ctx)  # base class; self-gated on `snap`
        return Result(summary="caches cleaned")

    # -- update --------------------------------------------------------------
    def _unsigned_repos(self, ctx: Context) -> list[str]:
        """Enabled repositories that install packages without checking signatures.

        Reuses the pkg-audit provider instead of re-parsing ``/etc/yum.repos.d``, so the
        gate and the audit can never disagree — and the provider already resolves an
        *absent* ``gpgcheck`` against ``[main]`` in ``dnf.conf``, which is the part that
        is easy to get wrong (treating absence as disabled flags every repo on every
        box). ``Severity.WARN`` is what marks a finding as an *enabled* repo; the
        provider reports disabled ones at LOW, and those install nothing today.
        """
        try:
            from ..supplychain.base import INSECURE_TRANSPORT, Severity
            from ..supplychain.dnf_source import DnfSource
            src = DnfSource()
            if not src.is_present(ctx):
                return []
            return sorted({f.package for f in src.findings(ctx)
                           if f.question == INSECURE_TRANSPORT
                           and "gpgcheck=0" in f.detail
                           and f.severity == Severity.WARN})
        except Exception:      # never let the audit path break a routine upgrade
            return []

    def _signature_gate(self, ctx: Context) -> bool:
        """Ask before installing packages whose signatures nobody checked.

        Returns ``False`` only to abort. Note the deliberate asymmetry with
        :func:`~fettle.advisories.check.security_gate`, which fails *open*: an unpatched
        CVE is a pre-existing condition that blocking does not fix — refusing to upgrade
        leaves you unpatched, which is worse. ``gpgcheck=0`` is the opposite: the
        upgrade itself is the delivery mechanism, so an unreadable stdin defaults to
        *not* installing unverified packages.
        """
        repos = self._unsigned_repos(ctx)
        if not repos:
            return True
        out = ctx.output
        out.warn(f"{len(repos)} enabled repositor{'y' if len(repos) == 1 else 'ies'} "
                 "install packages WITHOUT verifying their signature (gpgcheck=0):")
        for repo in repos:
            print(f"    {repo}")
        if ctx.dry_run:
            # Nothing is installed in a dry run, so warning is right and blocking would
            # only hide the command the user asked to preview.
            out.note("a real upgrade would ask for confirmation before using these.")
            return True
        if ctx.assume_yes:
            # Never silently block automation — and never let it pass unremarked.
            out.warn("proceeding anyway (--yes): these packages are unverified.")
            out.summary_add(f"upgraded from {len(repos)} unsigned repo(s)")
            return True
        return ctx.confirm("upgrade from these unverified repositories anyway?",
                           default=False)

    def update_system(self, ctx: Context) -> Result:
        out = ctx.output
        if _image_based(ctx):
            out.warn("this host booted from an ostree image — dnf cannot upgrade it; "
                     "the changes would not survive a reboot.")
            out.next_step(f"update the image instead: {_image_update_command()}")
            out.summary_add("update skipped: image-based host")
            return Result(ok=False, summary="image-based host")
        system, _, _ = self._updaters(ctx)
        if system == "none":
            out.note("skipping repo update (system_updater: none).")
            return Result()
        if not self._signature_gate(ctx):
            out.warn("upgrade skipped — set gpgcheck=1 on the repositories above "
                     "(or import their keys) first.")
            return Result(ok=False, summary="upgrade skipped (unsigned repos)")
        out.note("applying upgrades (dnf)...")
        # `--refresh` expires the metadata cache first, making this the equivalent of
        # Debian's `apt-get update && apt-get full-upgrade` in one command. Without -y,
        # dnf shows its own transaction table and prompts — the same deal apt gets.
        argv = ["dnf", "upgrade", "--refresh"]
        if ctx.assume_yes:
            argv.append("-y")
        ctx.execute(argv)
        return Result()

    def update_extras(self, ctx: Context) -> Result:
        out = ctx.output
        _, flatpak, snap = self._updaters(ctx)
        did = ["dnf"]
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
