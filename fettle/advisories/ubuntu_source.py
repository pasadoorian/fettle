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
from . import db
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
        db.replace_source(conn, self.source, rows)
        return len(rows)
