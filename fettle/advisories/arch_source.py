"""Arch/Manjaro advisory provider (PLAN.md §19.5 M1).

Bulk-fetches the full AVG feed from ``security.archlinux.org/json`` into the shared
SQLite cache, then classifies each installed package against it. Version comparison
is delegated to ``vercmp`` (ships with pacman) — fettle never hand-rolls Arch version
ordering (§19.3.1). Manjaro's normal sync lag is handled by the caller's tone, not by
special-casing here (§19.3.2).
"""

from __future__ import annotations

import json
import urllib.request

from .. import command
from . import base, db

_FEED = "https://security.archlinux.org/json"
_TRACKER = "https://security.archlinux.org/"


class ArchAdvisorySource(base.AdvisoryProvider):
    source = "arch"

    def is_present(self, ctx) -> bool:
        return bool(command.which("pacman") and command.which("vercmp"))

    # -- fetch ---------------------------------------------------------------
    def refresh(self, conn) -> int:
        try:
            req = urllib.request.Request(_FEED, headers={"User-Agent": "fettle"})
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (fixed https)
                data = json.load(resp)
        except (OSError, ValueError):
            return -1
        rows = []
        for avg in data:
            name = avg.get("name")
            advs = avg.get("advisories") or []
            status = avg.get("status") or "Unknown"
            rows.extend(
                (self.source, name, pkg, status,
                 avg.get("severity") or "Unknown", avg.get("affected") or "",
                 avg.get("fixed") or None, json.dumps(avg.get("issues") or []),
                 (advs[0] if advs else None),
                 _TRACKER + str(name) if name else _TRACKER, status)  # dclass = raw status
                for pkg in (avg.get("packages") or []))
        db.replace_source(conn, self.source, rows)
        return len(rows)

    # -- classify ------------------------------------------------------------
    def findings(self, ctx, conn) -> list[base.AdvisoryFinding]:
        installed = self._installed()
        if not installed:
            return []
        out: list[base.AdvisoryFinding] = []
        for (group_id, pkg, status, severity, _affected, fixed, cves_json,
             advisory_id, url, dclass) in db.all_rows(conn, self.source):
            iv = installed.get(pkg)
            if iv is None:
                continue
            norm, fx = self._classify(iv, status, fixed)
            if norm is None:                       # patched / not affected -> skip
                continue
            out.append(base.AdvisoryFinding(
                source=self.source, package=pkg, installed_version=iv, status=norm,
                severity=severity, cves=json.loads(cves_json) if cves_json else [],
                fixed_version=fx, group_id=group_id, advisory_id=advisory_id,
                distro_class=dclass, url=url))
        return out

    def _classify(self, installed: str, status: str, fixed):
        """(normalized_status, fixed_version) for an installed version, or
        (None, None) to skip (patched or not affected)."""
        if status == "Not affected":
            return None, None
        if status == "Vulnerable":                 # no fix released yet -> the tell
            return base.PENDING_FIX, None
        if status in ("Fixed", "Testing") and fixed:
            cmp = self._vercmp(installed, fixed)
            if cmp is None:
                return base.UNKNOWN, fixed
            return (base.FIXED_AVAILABLE, fixed) if cmp < 0 else (None, None)
        if status == "Unknown" and fixed and (self._vercmp(installed, fixed) or 0) < 0:
            return base.FIXED_AVAILABLE, fixed
        return None, None

    # -- helpers -------------------------------------------------------------
    def _installed(self) -> dict[str, str]:
        proc = command.run(["pacman", "-Q"], capture=True)
        out = {}
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                out[parts[0]] = parts[1]
        return out

    def _vercmp(self, a: str, b: str):
        """<0 / 0 / >0 per ``vercmp a b``, or None if it can't be determined."""
        proc = command.run(["vercmp", a, b], capture=True)
        try:
            return int(proc.stdout.strip())
        except (ValueError, AttributeError):
            return None

    def uncovered(self, ctx) -> list[str]:
        # the tracker covers official-repo packages only; foreign = AUR/manual.
        return command.run(["pacman", "-Qmq"], capture=True).stdout.split()
