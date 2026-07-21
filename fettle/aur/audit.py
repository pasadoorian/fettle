"""AUR audit (`-A`) — the update.sh-style health/metrics table.

Reproduces ``update.sh``'s ``aur_audit``: a per-package metrics table (age,
votes, out-of-date, orphan, recently-changed), a not-found-in-AUR list, and the
maintainer-change (re-adoption) section — printed and saved to ``~/aur-audit.txt``.
Provenance/health only; malicious/IOC cross-references live in ``aur-ioc-scan``.
"""

from __future__ import annotations

import json
import time
from datetime import datetime

from .. import reports
from ..util import chown_to_user
from . import common as aur_common
from . import meta as aur_meta

_SNAPSHOT = ".cache/fettle/aur-maintainers.json"
_HEADER = f'{"PACKAGE":<34} {"MAINTAINER":<16} {"AGE(d)":>7} {"OOD":<8} {"VOTES":>6}  FLAGS'
_RULE = "-" * 90


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
                              "out_of_date": ood, "votes": votes, "flags": flags}
                             for age, name, maint, ood, votes, flags in rows],
                "not_found_in_aur": list(missing),
                "maintainer_changes": list(changes),
            }
            report = reports.write_report("aur-audit", "\n".join(lines), ctx, data=data)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write aur-audit report: {exc}")
    out.summary_add(f"AUR audit of {len(foreign)} package(s) written to {report}")


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
