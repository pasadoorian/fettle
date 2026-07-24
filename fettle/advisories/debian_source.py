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

from .. import command
from . import db
from .apt_base import AptAdvisorySource

_FEED = "https://security-tracker.debian.org/tracker/data/json"
_CVE_URL = "https://security-tracker.debian.org/tracker/"

# Debian per-release urgency -> our severity band (Debian assigns no "critical").
_URGENCY = {"high": "High", "medium": "Medium", "low": "Low",
            "unimportant": "Low", "end-of-life": "Low"}


class DebianAdvisorySource(AptAdvisorySource):
    source = "debian"

    def _suite(self, ctx=None) -> str:
        return self._codename(ctx)

    def is_present(self, ctx) -> bool:
        # Debian proper only — Ubuntu (ID_LIKE=debian) uses the Ubuntu provider (M3).
        return self._osrel(ctx).get("ID") == "debian" and bool(command.which("dpkg"))

    # -- fetch (filtered to the running release) -----------------------------
    def refresh(self, conn, ctx=None) -> int:
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

    # findings / _installed / _behind / uncovered are inherited from AptAdvisorySource.
