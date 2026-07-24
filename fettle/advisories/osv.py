"""OSV.dev client — the shared engine for the language-ecosystem provider and (later)
Ubuntu pending (PLAN.md §19.10).

``querybatch`` the installed packages (cheap — returns vuln IDs + ``modified`` only),
then fetch each vuln's full record, cached in SQLite and synced incrementally off
``modified`` (first run heavier, steady-state re-fetches only the changed few). A
returned vuln means the version is *affected*; the record's per-ecosystem range then
says fixed-available (a ``fixed`` event) vs pending (none). Pure stdlib.
"""

from __future__ import annotations

import json
import urllib.request

_BATCH = "https://api.osv.dev/v1/querybatch"
_VULN = "https://api.osv.dev/v1/vulns/"

_SEV_WORD = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium",
             "MEDIUM": "Medium", "LOW": "Low", "NEGLIGIBLE": "Low"}


def _post(url, payload, timeout=60):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"User-Agent": "fettle", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https)
        return json.load(r)


def querybatch(queries, *, chunk=1000) -> list[list[dict]]:
    """``queries``: list of ``{"package":{"ecosystem","name"}, "version"}``. Returns a
    list parallel to ``queries``; each element is that package's vulns as
    ``[{"id","modified"}, ...]`` (empty if clean). Raises on transport failure."""
    out: list[list[dict]] = []
    for i in range(0, len(queries), chunk):
        resp = _post(_BATCH, {"queries": queries[i:i + chunk]})
        out.extend((res.get("vulns") or []) for res in resp.get("results", []))
    return out


def record(conn, vuln_id: str, modified) -> dict | None:
    """Full OSV record for ``vuln_id`` — from the SQLite cache when its ``modified``
    matches, else fetched and cached. Falls back to any stale cache on a fetch error;
    returns None only if uncached and unfetchable."""
    from . import db
    hit = db.osv_cached(conn, vuln_id, modified)
    if hit is not None:
        return json.loads(hit)
    try:
        with urllib.request.urlopen(  # noqa: S310 (fixed https)
                urllib.request.Request(_VULN + vuln_id, headers={"User-Agent": "fettle"}),
                timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
    except (OSError, ValueError):
        stale = conn.execute("SELECT record FROM osv_vulns WHERE id=?",
                             (vuln_id,)).fetchone()
        return json.loads(stale[0]) if stale and stale[0] else None
    db.osv_store(conn, vuln_id, modified, raw)
    return json.loads(raw)


def classify(rec: dict, ecosystem: str, version: str):
    """(status, fixed_version) for an already-affected package, or None to skip.
    status is 'fixable' (a fix exists) or 'pending' (affected, no fix event)."""
    for aff in rec.get("affected", []):
        if (aff.get("package") or {}).get("ecosystem") != ecosystem:
            continue
        events = [e for rg in aff.get("ranges", []) for e in rg.get("events", [])]
        fixed = next((e["fixed"] for e in events if "fixed" in e), None)
        return ("fixable", fixed) if fixed else ("pending", None)
    return None


def severity(rec: dict) -> tuple[str, str]:
    """(band, cvss_vector) — the two perspectives. ``band`` is the native rating
    (Ubuntu's ``{type:"Ubuntu", score:"medium"}`` / GHSA's ``database_specific.
    severity`` word); ``cvss_vector`` is the raw CVSS string. Either may be empty."""
    native, cvss = "", ""
    for s in rec.get("severity") or []:
        score = str(s.get("score", ""))
        if "CVSS" in str(s.get("type", "")).upper():
            cvss = cvss or score
        elif score:
            native = native or score             # e.g. Ubuntu "medium"
    if not native:
        native = str((rec.get("database_specific") or {}).get("severity", ""))  # GHSA
    return _SEV_WORD.get(native.upper(), "Unknown"), cvss


def dedup_rows(rows):
    """OSV surfaces the same CVE from several databases (GHSA/PYSEC/UBUNTU-CVE …).
    Collapse to one row per (package, CVE set), keeping the best-rated + CVSS-carrying
    copy. Rows are the advisories-table tuples (severity at [4], cves at [7], cvss at
    [11])."""
    from .base import severity_rank
    best: dict = {}
    for r in rows:
        key = (r[2], r[7])
        cur = best.get(key)
        if cur is None or severity_rank(r[4]) > severity_rank(cur[4]) \
                or (severity_rank(r[4]) == severity_rank(cur[4]) and r[11] and not cur[11]):
            best[key] = r
    return list(best.values())


def cve_ids(rec: dict) -> list[str]:
    """The CVE aliases of a record (falling back to its OSV id)."""
    cves = [a for a in (rec.get("aliases") or []) if str(a).startswith("CVE-")]
    return cves or [rec.get("id", "")]
