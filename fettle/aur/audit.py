"""AUR audit (`-A`) — the update.sh-style health/metrics table.

Reproduces ``update.sh``'s ``aur_audit``: a per-package metrics table (age,
votes, out-of-date, orphan, recently-changed), a not-found-in-AUR list, and the
maintainer-change (re-adoption) section — printed and saved to ``~/aur-audit.txt``.
Provenance/health only; malicious/IOC cross-references live in ``pkg-audit``
(they were ``aur-ioc-scan``'s until it was retired in v0.73.0).
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime

from .. import command, reports
from ..util import chown_to_user
from . import common as aur_common
from . import meta as aur_meta

# Per-action maintainer baseline. It used to be ONE file shared with pkg-audit's AUR
# provider, and both read *and rewrote* it — so a maintainer takeover, the signal that
# matters most here, was reported exactly once by whichever action ran first and was
# invisible to the other. `fettle -P` then `fettle -A` and the second said "none".
_SNAPSHOT = ".cache/fettle/aur-maintainers-audit.json"
# Read-only fallback, so upgrading does not discard a change that is already pending.
_LEGACY_SNAPSHOT = ".cache/fettle/aur-maintainers.json"
_HEADER = f'{"PACKAGE":<34} {"MAINTAINER":<16} {"AGE(d)":>7} {"OOD":<8} {"VOTES":>6}  FLAGS'
_RULE = "-" * 90

# A package "ships a public shared library" if it owns a /usr/lib/<name>.so* file
# (one level — excludes app-private bundles under /usr/lib/<app>/…).
_PUBLIC_LIB_RE = re.compile(r"^/usr/lib/[^/]+\.so")


def run(ctx) -> None:
    out = ctx.output
    foreign = aur_common.foreign_packages(ctx)
    if not foreign:
        out.ok("no foreign (AUR) packages installed.")
        return

    results = aur_meta.fetch_info(foreign)  # None => RPC unreachable
    if not results:
        out.err("AUR RPC returned no data (offline, or none resolve in the AUR).")
        # Not silent in the digest: an audit that could not run was indistinguishable
        # from one that found nothing wrong.
        out.summary_warn(f"AUR audit did NOT run — the RPC returned no data for "
                         f"{len(foreign)} foreign package(s)")
        return
    by_name = {r.get("Name"): r for r in results if r.get("Name")}

    # Reverse-dependency analysis over ALL foreign packages: the AUR RPC can't tell
    # you nothing on the system needs a package (a healthy-but-leftover clone).
    deps = _dependents(foreign)          # {name: (required_by, optional_for)}
    libs = _library_packages(foreign)    # {name, ...} that ship a public .so

    now = time.time()
    recent = ctx.config.aur_recent_days
    rows = []
    for name, r in by_name.items():
        maint = r.get("Maintainer")
        last = r.get("LastModified")
        age = int((now - last) // 86400) if isinstance(last, (int, float)) else -1
        votes = r.get("NumVotes") or 0
        flags = []
        if not maint:
            flags.append("ORPHAN")
        if r.get("OutOfDate"):
            flags.append("OUT-OF-DATE")
        if 0 <= age <= recent:
            flags.append("RECENTLY-CHANGED")
        _append_dep_flags(flags, name, deps, libs)
        rows.append((age, name, (maint or "ORPHAN"),
                     "FLAGGED" if r.get("OutOfDate") else "-", votes, " ".join(flags)))
    rows.sort(key=lambda x: -x[0])  # oldest (worst) first

    lines = [
        f"AUR audit  -  {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Installed foreign packages: {len(foreign)}",
        "",
        _HEADER,
        _RULE,
    ]
    lines += [f"{name:<34} {maint[:16]:<16} {age:>7} {ood:<8} {votes:>6}  {flags}"
              for age, name, maint, ood, votes, flags in rows]

    changes, first_run, seen_before = _maintainer_changes(by_name, ctx, foreign)

    # "Absent from the AUR" is two very different situations wearing one label, and
    # lumping them made the finding useless: on a real 79-package host it stood at 9
    # every single run, most of them work packages built in-house that were never in the
    # AUR at all. A list that is permanently 9 long is a list nobody reads.
    #
    # The event worth alarming on is *disappearance*: it was there when fettle last
    # looked, and now it is not. That is what deletion for malware looks like. The rest
    # is provenance trivia — installed from somewhere else, or gone before fettle ever
    # saw it — and fettle cannot tell those two apart, so it does not pretend to.
    missing = [p for p in foreign if p not in by_name]
    vanished = [p for p in missing if p in seen_before]
    unseen = [p for p in missing if p not in seen_before]
    if vanished:
        lines += ["", "VANISHED FROM THE AUR SINCE THE LAST RUN (investigate): "
                  + " ".join(vanished)]
    if unseen:
        lines += ["", "Not in the AUR, and never seen there by fettle (installed from "
                  "elsewhere, or removed before the first run): " + " ".join(unseen)]

    removal = _removal_candidates(foreign, deps, libs)
    if removal:
        # The command was repeated under every single candidate — 59 of them on a real
        # host, so the list was twice as long as the information in it. Said once.
        lines += ["", "=== Candidates for removal (no packaged dependents) ===",
                  "  Review these packages and decide if you need to keep them;",
                  "  remove with: sudo pacman -Rns <package name>", ""]
        for c in removal:
            tag = "  [shared library]" if c["is_library"] else ""
            lines.append(f"  {c['name']}{tag}")
        lines += ["  (pacman only tracks PACKAGED dependents; unpackaged software —",
                  "   AppImage, /opt, manually built, dlopen — could still use these.",
                  "   Verify before removing.)"]

    lines += ["", "=== Maintainer changes since last run ==="]
    # "none (or first run)" made the run that matters most — the first — indistinguishable
    # from a run where genuinely nothing moved.
    lines += ([f"  [REVIEW BEFORE UPGRADE] {c}" for c in changes]
              or ["  first run - baseline saved; changes will be reported from now on"
                  if first_run else "  none"])

    for ln in lines:
        print(ln)

    report = None                     # stays None on --dry-run and on a write failure
    if not ctx.dry_run:
        try:
            data = {
                "packages": [{"age_days": age, "name": name, "maintainer": maint,
                              "out_of_date": ood, "votes": votes, "flags": flags,
                              "description": (by_name.get(name, {}).get("Description") or ""),
                              "homepage": (by_name.get(name, {}).get("URL") or ""),
                              "required_by": deps.get(name, ([], []))[0],
                              "optional_for": deps.get(name, ([], []))[1],
                              "is_library": name in libs}
                             for age, name, maint, ood, votes, flags in rows],
                "not_found_in_aur": list(missing),
                "vanished_from_aur": list(vanished),
                "never_seen_in_aur": list(unseen),
                "removal_candidates": removal,
                "maintainer_changes": list(changes),
            }
            report = reports.write_report("aur-audit", "\n".join(lines), ctx, data=data)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write aur-audit report: {exc}")
    # Say what was FOUND, not merely that the audit ran. Measured on a real 77-package
    # host: 9 absent from the AUR and 4 flagged out-of-date, all summarised as
    # "AUR audit of 77 package(s)" — and "no longer exists upstream" is exactly what a
    # package deleted for malware looks like from here.
    orphaned = sum(1 for r in rows if "ORPHAN" in r[5])
    ood = sum(1 for r in rows if r[3] == "FLAGGED")
    notes = []
    if vanished:
        notes.append(f"{len(vanished)} VANISHED from the AUR since the last run")
    if unseen:
        notes.append(f"{len(unseen)} not in the AUR (never seen there)")
    if ood:
        notes.append(f"{ood} flagged out-of-date")
    if orphaned:
        notes.append(f"{orphaned} orphaned")
    if changes:
        notes.append(f"{len(changes)} maintainer change(s)")
    summary = f"AUR audit of {len(foreign)} package(s)"
    if notes:
        summary += " — " + ", ".join(notes)
    if report:
        summary += f"; written to {report}"
    # The text was fixed to say what was found; the MARK was not, so the summary read
    # `✓ AUR audit of 79 package(s) — 9 no longer in the AUR` and exited 0. A green tick
    # whose own words report findings is the shape this QA pass exists to remove, and it
    # sat on the highest-signal supply-chain indicator there is.
    #
    # Only the two EVENT-shaped signals raise the mark. A package that vanished upstream
    # or changed hands is something that *happened* and wants looking at. Out-of-date and
    # orphaned are standing states — on a real 79-package host, 7 are flagged out-of-date
    # more or less permanently, and warning on those every single run is how a warning
    # stops being read. They stay in the text, counted.
    if vanished or changes:
        out.summary_warn(summary)
    else:
        out.summary_add(summary)
    if vanished:
        out.warn(f"{len(vanished)} installed package(s) VANISHED from the AUR since the "
                 "last run — they were there when fettle last looked. A package deleted "
                 f"for malware looks exactly like this: {', '.join(vanished)}")
    if unseen:
        out.note(f"{len(unseen)} installed package(s) are not in the AUR and never were "
                 "as far as fettle has seen — most likely built in-house or installed "
                 f"from elsewhere: {', '.join(unseen)}")
    if changes:
        out.warn(f"{len(changes)} AUR package(s) changed maintainer since the last run "
                 "— review before upgrading them.")


def _append_dep_flags(flags: list[str], name, deps: dict, libs: set) -> None:
    """Add the reverse-dependency flags for ``name`` (nothing if the query gave no
    data for it). NO-DEPENDENTS = nothing requires OR optionally-needs it (strong);
    NO-HARD-DEPS = nothing requires it but something lists it as an optdep (weaker);
    +LIB when it ships a public shared library (an unused *library* is the tell)."""
    if name not in deps:
        return
    required_by, optional_for = deps[name]
    if required_by:
        return
    flags.append("NO-DEPENDENTS" if not optional_for else "NO-HARD-DEPS")
    if name in libs:
        flags.append("LIB")


def _removal_candidates(foreign, deps: dict, libs: set) -> list[dict]:
    """Foreign packages with NO packaged dependents at all (Required By AND Optional
    For both empty) — the strong 'candidate leftover' set, libraries first. Covers
    every foreign package, including ones not found in the AUR."""
    out = []
    for name in foreign:
        if name not in deps:
            continue
        required_by, optional_for = deps[name]
        if not required_by and not optional_for:
            out.append({"name": name, "is_library": name in libs})
    out.sort(key=lambda c: (not c["is_library"], c["name"]))
    return out


def _dependents(names) -> dict:
    """``{name: (required_by, optional_for)}`` from ``pacman -Qi`` (LC_ALL=C so the
    field labels are English). Empty dict on any failure — never breaks the audit."""
    if not names:
        return {}
    proc = command.run(["env", "LC_ALL=C", "pacman", "-Qi", "--", *names], capture=True)
    if proc.returncode != 0 or not proc.stdout:
        return {}
    out: dict = {}
    for block in proc.stdout.split("\n\n"):
        fields: dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if not line.strip():
                continue
            if " : " in line and not line[:1].isspace():
                label, _, val = line.partition(" : ")
                key = label.strip()
                fields[key] = val.strip()
            elif key and line[:1].isspace():      # wrapped continuation of a value
                fields[key] += " " + line.strip()
        name = fields.get("Name")
        if name:
            out[name] = (_val_list(fields.get("Required By", "")),
                         _val_list(fields.get("Optional For", "")))
    return out


def _val_list(value: str) -> list[str]:
    v = value.strip()
    return [] if v in ("", "None") else v.split()


def _library_packages(names) -> set:
    """The subset of ``names`` that own a public ``/usr/lib/*.so*`` file (via
    ``pacman -Ql``). Empty set on failure."""
    if not names:
        return set()
    proc = command.run(["env", "LC_ALL=C", "pacman", "-Ql", "--", *names], capture=True)
    if proc.returncode != 0 or not proc.stdout:
        return set()
    libs: set[str] = set()
    for line in proc.stdout.splitlines():
        pkg, _, path = line.partition(" ")
        if pkg and pkg not in libs and _PUBLIC_LIB_RE.match(path):
            libs.add(pkg)
    return libs


def _maintainer_changes(by_name, ctx, foreign=()) -> tuple[list[str], bool, set]:
    """``(changes, first_run, seen_before)`` — maintainers that moved since the snapshot,
    whether there was a snapshot at all, and which installed packages this file has ever
    recorded as being in the AUR.

    ``seen_before`` is what makes "it disappeared" separable from "it was never there".

    The re-adoption tell. ``first_run`` is returned because "nothing changed" and "there
    was nothing to compare against" were reported with one sentence, so on the run where
    it matters most the user could not tell which they were looking at.
    Shares the snapshot file with pkg-audit's AUR provider.
    """
    snap_path = ctx.user_home / _SNAPSHOT
    if not snap_path.is_file():
        legacy = ctx.user_home / _LEGACY_SNAPSHOT      # read-only migration path
        if legacy.is_file():
            snap_path = legacy
    current = {n: (r.get("Maintainer") or "ORPHAN") for n, r in by_name.items()}
    previous: dict[str, str] = {}
    had_snapshot = snap_path.is_file()
    if had_snapshot:
        # OSError too: a prior elevated run may have left this root-owned.
        try:
            previous = json.loads(snap_path.read_text())
        except (OSError, ValueError):
            previous = {}
            had_snapshot = False
    changes = [f"{n}: {previous[n]} -> {m}"
               for n, m in current.items()
               if n in previous and previous[n] != m]
    seen_before = {n for n in (foreign or ()) if n in previous}
    # A package that has vanished from the AUR is absent from `current`, so writing
    # `current` alone would forget it immediately and the disappearance would be
    # reported exactly once — on a run the user may never read — and then silently
    # downgrade to "never seen there" forever after. Its last known entry is kept for
    # as long as the package is still installed, so the finding persists until it is
    # dealt with. Uninstalled packages drop out, so this cannot grow without bound.
    retained = {n: previous[n] for n in (foreign or ())
                if n not in current and n in previous}
    if not ctx.dry_run:
        try:
            write_to = ctx.user_home / _SNAPSHOT       # always our own file
            write_to.parent.mkdir(parents=True, exist_ok=True)
            write_to.write_text(json.dumps({**current, **retained}))
            chown_to_user(write_to.parent, ctx.sudo_user)  # don't leave root-owned
            chown_to_user(write_to, ctx.sudo_user)
        except OSError:
            pass
    return changes, not had_snapshot, seen_before
