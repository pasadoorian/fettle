"""Debian advisory provider (PLAN.md §19.5 M2).

Bulk-fetches ``security-tracker.debian.org``'s full JSON, filters it to the running
release, and stores it in the shared SQLite cache; classifies installed SOURCE
packages against it. Version comparison via ``dpkg --compare-versions``, source
mapping via ``dpkg-query`` (§19.3.1/19.3.3). Debian only — Ubuntu tracks its own
fix state independently (Milestone 3), even though both use apt/dpkg.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

from .. import command
from ..distro import parse_os_release
from . import base, db

_FEED = "https://security-tracker.debian.org/tracker/data/json"
_CVE_URL = "https://security-tracker.debian.org/tracker/"

# Debian per-release urgency -> our severity band (Debian assigns no "critical").
_URGENCY = {"high": "High", "medium": "Medium", "low": "Low",
            "unimportant": "Low", "end-of-life": "Low"}


class DebianAdvisorySource(base.AdvisoryProvider):
    source = "debian"

    def _osrel(self, ctx=None) -> dict:
        root = (getattr(ctx, "root", None) if ctx else None) or "/"
        try:
            return parse_os_release(Path(root))
        except Exception:
            return {}

    def _suite(self, ctx=None) -> str:
        return self._osrel(ctx).get("VERSION_CODENAME", "") or ""

    def is_present(self, ctx) -> bool:
        # Debian proper only — Ubuntu (ID_LIKE=debian) uses the Ubuntu provider (M3).
        return self._osrel(ctx).get("ID") == "debian" and bool(command.which("dpkg"))

    # -- fetch (filtered to the running release) -----------------------------
    def refresh(self, conn) -> int:
        suite = self._suite()
        if not suite:
            return -1
        try:
            req = urllib.request.Request(_FEED, headers={"User-Agent": "fettle"})
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310 (fixed https)
                data = json.load(resp)
        except (OSError, ValueError):
            return -1
        rows = []
        for srcpkg, cves in data.items():
            for cve, info in (cves or {}).items():
                rel = (info.get("releases") or {}).get(suite)
                if not rel:
                    continue
                classified = self._classify_release(rel)
                if classified is None:
                    continue
                stored, fixed, dclass = classified
                sev = _URGENCY.get(rel.get("urgency") or "", "Unknown")
                rows.append((self.source, cve, srcpkg, stored, sev, "", fixed,
                             json.dumps([cve]), None, _CVE_URL + cve, dclass))
        db.replace_source(conn, self.source, rows)
        return len(rows)

    def _classify_release(self, rel: dict):
        """(stored_status, fixed_version|None, dclass) for a per-release entry, or
        None to skip. stored_status is 'pending' (findings emit directly) or
        'fixable' (findings compares installed vs fixed)."""
        status = rel.get("status")
        fixed = rel.get("fixed_version")
        nodsa = "nodsa" in rel
        dclass = "nodsa" if nodsa else (rel.get("urgency") or "unknown")
        if status == "open":
            return ("pending", None, dclass)
        if status == "resolved":
            if fixed and fixed != "0":
                return ("fixable", fixed, dclass)
            if nodsa:                              # vulnerable, won't be fixed here
                return ("pending", None, "nodsa")
            return None                            # not affected / fixed pre-release
        return None                                # undetermined -> skip

    # -- classify installed --------------------------------------------------
    def findings(self, ctx, conn) -> list[base.AdvisoryFinding]:
        installed = self._installed()
        if not installed:
            return []
        out: list[base.AdvisoryFinding] = []
        for (group_id, pkg, status, severity, _affected, fixed, cves_json,
             _advisory_id, url, dclass) in db.all_rows(conn, self.source):
            iv = installed.get(pkg)
            if iv is None:
                continue
            if status == "pending":
                norm, fx = base.PENDING_FIX, None
            elif status == "fixable" and fixed and self._behind(iv, fixed):
                norm, fx = base.FIXED_AVAILABLE, fixed
            else:
                continue                           # patched / not applicable
            out.append(base.AdvisoryFinding(
                source=self.source, package=pkg, installed_version=iv, status=norm,
                severity=severity, cves=json.loads(cves_json) if cves_json else [],
                fixed_version=fx, group_id=group_id, distro_class=dclass, url=url))
        return out

    def _installed(self) -> dict[str, str]:
        proc = command.run(["dpkg-query", "-W", "-f=${source:Package} ${Version}\n"],
                           capture=True)
        out = {}
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] not in out:
                out[parts[0]] = parts[1]
        return out

    def _behind(self, installed: str, fixed: str) -> bool:
        """True if ``installed`` < ``fixed`` per ``dpkg --compare-versions``."""
        return command.run(
            ["dpkg", "--compare-versions", installed, "lt", fixed]).returncode == 0

    def uncovered(self, ctx) -> list[str]:
        # Debian coverage is by source package from the tracker; reliably flagging
        # third-party/local .debs is a known limitation (noted in the report). []
        return []
