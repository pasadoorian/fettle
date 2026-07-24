"""AUR audit (`-A`) — the update.sh-style health/metrics table.

Reproduces ``update.sh``'s ``aur_audit``: a per-package metrics table (age,
votes, out-of-date, orphan, recently-changed), a not-found-in-AUR list, and the
maintainer-change (re-adoption) section — printed and saved to ``~/aur-audit.txt``.
Provenance/health only; malicious/IOC cross-references live in ``aur-ioc-scan``.
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

_SNAPSHOT = ".cache/fettle/aur-maintainers.json"
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

    missing = [p for p in foreign if p not in by_name]
    if missing:
        lines += ["", f"NOT FOUND IN AUR (deleted/renamed - investigate): {' '.join(missing)}"]

    removal = _removal_candidates(foreign, deps, libs)
    if removal:
        lines += ["", "=== Candidates for removal (no packaged dependents) ==="]
        for c in removal:
            tag = "  [shared library]" if c["is_library"] else ""
            lines.append(f"  {c['name']}{tag}")
            lines.append(f"    review, then: sudo pacman -Rns {c['name']}")
        lines += ["  (pacman only tracks PACKAGED dependents; unpackaged software —",
                  "   AppImage, /opt, manually built, dlopen — could still use these.",
                  "   Verify before removing.)"]

    lines += ["", "=== Maintainer changes since last run ==="]
    changes = _maintainer_changes(by_name, ctx)
    lines += ([f"  [REVIEW BEFORE UPGRADE] {c}" for c in changes]
              or ["  none (or first run - baseline saved)"])

    for ln in lines:
        print(ln)

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
                "removal_candidates": removal,
                "maintainer_changes": list(changes),
            }
            report = reports.write_report("aur-audit", "\n".join(lines), ctx, data=data)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write aur-audit report: {exc}")
    out.summary_add(f"AUR audit of {len(foreign)} package(s) written to {report}")


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


def _maintainer_changes(by_name, ctx) -> list[str]:
    """Diff current maintainers against the snapshot (the re-adoption tell), then
    refresh it. Shares the snapshot file with pkg-audit's AUR provider."""
    snap_path = ctx.user_home / _SNAPSHOT
    current = {n: (r.get("Maintainer") or "ORPHAN") for n, r in by_name.items()}
    previous: dict[str, str] = {}
    if snap_path.is_file():
        # OSError too: a prior elevated run may have left this root-owned.
        try:
            previous = json.loads(snap_path.read_text())
        except (OSError, ValueError):
            previous = {}
    changes = [f"{n}: {previous[n]} -> {m}"
               for n, m in current.items()
               if n in previous and previous[n] != m]
    if not ctx.dry_run:
        try:
            snap_path.parent.mkdir(parents=True, exist_ok=True)
            snap_path.write_text(json.dumps(current))
            chown_to_user(snap_path.parent, ctx.sudo_user)  # don't leave root-owned
            chown_to_user(snap_path, ctx.sudo_user)
        except OSError:
            pass
    return changes
