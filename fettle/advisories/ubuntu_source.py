"""Ubuntu advisory provider (PLAN.md §19.5 M3).

Bulk-fetches Ubuntu's per-release **OVAL** (``security-metadata.canonical.com``),
which carries fix-available data — each CVE + affected source package + the fixed
version — with Canonical's ``priority`` (incl. ``critical``, unlike Debian). Installed
source packages are classified via dpkg (shared :class:`AptAdvisorySource`).

NOTE: the ``pkg`` OVAL contains only *fixed* CVEs, so Ubuntu's "vulnerable, no fix
yet" (pending) findings aren't surfaced here — that data lives in Canonical's CVE
JSON API (``ubuntu.com/security/cves.json``), which was returning HTTP 503 when M3
landed. The report says so; pending will light up when that API is reachable.
"""

from __future__ import annotations

import bz2
import json
import re
import urllib.request

from .. import command
from . import db, osv
from .apt_base import AptAdvisorySource

_OVAL = "https://security-metadata.canonical.com/oval/com.ubuntu.{}.pkg.oval.xml.bz2"
_CVE_URL = "https://ubuntu.com/security/"
_PRIO = {"critical": "Critical", "high": "High", "medium": "Medium",
         "low": "Low", "negligible": "Low"}

# <cve ... priority="X" ...>CVE-YYYY-N</cve>
_CVE_PRIO = re.compile(r'<cve[^>]*\bpriority="([^"]+)"[^>]*>(CVE-\d{4}-\d+)</cve>')
# comment="(CVE-YYYY-N) <pkg> package in <rel> was vulnerable but has been fixed (note: 'VER')."
_FIXED = re.compile(
    r'''comment="\((CVE-\d{4}-\d+)\)\s+(\S+)\s+package in \S+ was vulnerable '''
    r'''but has been fixed \(note: '([^']+)'\)''')


class UbuntuAdvisorySource(AptAdvisorySource):
    source = "ubuntu"

    def is_present(self, ctx) -> bool:
        return self._osrel(ctx).get("ID") == "ubuntu" and bool(command.which("dpkg"))

    def refresh(self, conn) -> int:
        codename = self._codename()
        if not codename:
            return -1
        try:
            req = urllib.request.Request(_OVAL.format(codename),
                                         headers={"User-Agent": "fettle"})
            with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 (fixed https)
                txt = bz2.decompress(resp.read()).decode("utf-8", "replace")
        except (OSError, ValueError):
            return -1
        prio = {cve: p for (p, cve) in _CVE_PRIO.findall(txt)}
        rows = []
        for cve, pkg, ver in _FIXED.findall(txt):
            p = prio.get(cve, "")
            rows.append((self.source, cve, pkg, "fixable", _PRIO.get(p, "Unknown"),
                         "", ver, json.dumps([cve]), None, _CVE_URL + cve, p or "unknown"))
        # OVAL is fixed-only. `_osv_pending()` (below) can fill "vulnerable, no fix
        # yet" via OSV, but it's NOT wired in by default: on a real box OSV returns
        # ~1315 pending Ubuntu CVEs (mostly negligible/won't-fix) — too slow to fetch
        # and too noisy to show unfiltered. Needs a severity floor + opt-in first
        # (PLAN.md §19.10). The engine is built + tested, ready to enable.
        db.replace_source(conn, self.source, rows)
        return len(rows)

    def _osv_ecosystem(self, ctx=None) -> str:
        rel = self._osrel(ctx)
        vid = rel.get("VERSION_ID", "")
        if not vid:
            return ""
        return f"Ubuntu:{vid}:LTS" if "LTS" in (rel.get("VERSION", "") or "") \
            else f"Ubuntu:{vid}"

    def _osv_pending(self, conn) -> list:
        """OSV pending findings for the running release — packages *affected with no
        fix event* (OVAL already covers the fixed ones, so we keep only `pending`)."""
        eco = self._osv_ecosystem()
        installed = self._installed()
        if not eco or not installed:
            return []
        queries = [{"package": {"ecosystem": eco, "name": n}, "version": v}
                   for n, v in installed.items()]
        try:
            batches = osv.querybatch(queries)
        except (OSError, ValueError):
            return []
        rows = []
        for name, vulns in zip(list(installed), batches):
            for vln in vulns:
                rec = osv.record(conn, vln.get("id"), vln.get("modified"))
                cl = osv.classify(rec, eco, installed[name]) if rec else None
                if cl is None or cl[0] != "pending":     # OVAL owns the fixed ones
                    continue
                band, cvss = osv.severity(rec)
                cves = osv.cve_ids(rec)
                rows.append((self.source, vln.get("id"), name, "pending", band, "",
                             None, json.dumps(cves), None,
                             _CVE_URL + (cves[0] if cves else ""), band, cvss))
        conn.commit()                                    # persist cached osv records
        return rows
