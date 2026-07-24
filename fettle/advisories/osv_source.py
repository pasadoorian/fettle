"""OSV language-ecosystem provider (PLAN.md §19.10).

Flags vulnerable **Python (PyPI)** and **Node (npm)** packages installed system-wide —
CVEs the OS trackers can't see. Enumerates installed language packages, queries
OSV.dev (via the shared ``osv`` client + SQLite record cache), and classifies each
against its ecosystem's fix state. Cross-platform (runs on any distro).
"""

from __future__ import annotations

import json
import re

from .. import command
from . import base, db, osv


def _pypi_norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dedup(rows):
    """OSV surfaces the same CVE from several databases (GHSA + PYSEC …). Collapse to
    one row per (package, CVE set), keeping the best-rated (and CVSS-carrying) copy."""
    best: dict = {}
    for r in rows:
        key = (r[2], r[7])                        # package, cves json
        cur = best.get(key)
        if cur is None or base.severity_rank(r[4]) > base.severity_rank(cur[4]) \
                or (base.severity_rank(r[4]) == base.severity_rank(cur[4]) and r[11] and not cur[11]):
            best[key] = r
    return list(best.values())


class OsvLanguageSource(base.AdvisoryProvider):
    source = "osv"

    def is_present(self, ctx) -> bool:
        return True                              # queries OSV.dev; enumerates what's installed

    # -- fetch/classify (querybatch installed pkgs -> classified rows) --------
    def refresh(self, conn) -> int:
        meta, queries = [], []                   # meta[i] = (ecosystem, name, version)
        for eco, name, ver in self._installed():
            meta.append((eco, name, ver))
            queries.append({"package": {"ecosystem": eco, "name": name}, "version": ver})
        if not queries:
            db.replace_source(conn, self.source, [])
            return 0
        try:
            batches = osv.querybatch(queries)
        except (OSError, ValueError):
            return -1
        rows = []
        for (eco, name, ver), vulns in zip(meta, batches):
            for v in vulns:
                rec = osv.record(conn, v.get("id"), v.get("modified"))
                cl = osv.classify(rec, eco, ver) if rec else None
                if cl is None:
                    continue
                status, fixed = cl
                band, cvss = osv.severity(rec)
                rows.append((self.source, v.get("id"), name, status, band, ver, fixed,
                             json.dumps(osv.cve_ids(rec)), None,
                             f"https://osv.dev/vulnerability/{v.get('id')}", eco, cvss))
        db.replace_source(conn, self.source, _dedup(rows))
        conn.commit()                            # persist osv_vulns cached during record()
        return len(rows)

    def findings(self, ctx, conn) -> list[base.AdvisoryFinding]:
        out = []
        for (gid, pkg, status, sev, installed, fixed, cves_json, _adv, url,
             dclass, cvss) in db.all_rows(conn, self.source):
            out.append(base.AdvisoryFinding(
                source=self.source, package=pkg, installed_version=installed,
                status=(base.PENDING_FIX if status == "pending" else base.FIXED_AVAILABLE),
                severity=sev, cves=json.loads(cves_json) if cves_json else [],
                fixed_version=fixed or None, group_id=gid, distro_class=dclass,
                url=url, cvss=cvss))
        return out

    def uncovered(self, ctx) -> list[str]:
        return []

    # -- installed language packages (system-wide) ---------------------------
    def _installed(self):
        return self._pip() + self._npm()

    def _pip(self):
        try:
            from importlib.metadata import distributions
        except Exception:
            return []
        seen: dict[str, tuple] = {}
        for dist in distributions():
            name, ver = getattr(dist, "name", None), getattr(dist, "version", None)
            if name and ver:
                seen.setdefault(_pypi_norm(name), ("PyPI", _pypi_norm(name), ver))
        return list(seen.values())

    def _npm(self):
        if not command.which("npm"):
            return []
        proc = command.run(["npm", "ls", "-g", "--depth=0", "--json"], capture=True)
        try:
            data = json.loads(proc.stdout or "{}")
        except ValueError:
            return []
        return [("npm", name, info["version"])
                for name, info in (data.get("dependencies") or {}).items()
                if isinstance(info, dict) and info.get("version")]
