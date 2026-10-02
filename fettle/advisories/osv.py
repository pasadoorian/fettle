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
        batch = queries[i:i + chunk]
        collected = [[] for _ in batch]
        pending = list(enumerate(batch))
        seen = set()
        while pending:
            resp = _post(_BATCH, {"queries": [q for _, q in pending]})
            results = resp.get("results") if isinstance(resp, dict) else None
            if not isinstance(results, list) or len(results) != len(pending):
                raise ValueError("incomplete OSV batch response")
            next_queries = []
            for (index, query), result in zip(pending, results):
                if not isinstance(result, dict) or "error" in result:
                    raise ValueError("invalid OSV query response")
                vulns = result.get("vulns", [])
                if not isinstance(vulns, list) or any(not isinstance(v, dict) or not v.get("id") for v in vulns):
                    raise ValueError("invalid OSV vulnerability list")
                collected[index].extend(vulns)
                token = result.get("next_page_token")
                if token:
                    if not isinstance(token, str) or (index, token) in seen:
                        raise ValueError("invalid OSV pagination token")
                    seen.add((index, token))
                    next_queries.append((index, {**query, "page_token": token}))
            pending = next_queries
        out.extend(collected)
    return out


def record(conn, vuln_id: str, modified) -> dict | None:
    """Full OSV record for ``vuln_id`` — from the SQLite cache when its ``modified``
    matches, else fetched and cached. A fetch failure returns None so callers retain
    the prior source data without falsely stamping stale records as current."""
    from . import db
    hit = db.osv_cached(conn, vuln_id, modified)
    if hit is not None:
        try:
            data = json.loads(hit)
            if isinstance(data, dict) and isinstance(data.get("affected"), list):
                return data
        except ValueError:
            pass
    try:
        with urllib.request.urlopen(  # noqa: S310 (fixed https)
                urllib.request.Request(_VULN + vuln_id, headers={"User-Agent": "fettle"}),
                timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
        data = json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("affected"), list):
            return None
    except (OSError, ValueError):
        # A stale record must not be stamped current after a failed refresh.
        return None
    db.osv_store(conn, vuln_id, modified, raw)
    return data


def classify(rec: dict, ecosystem: str, version: str, name: str | None = None):
    """(status, fixed_version) for an already-affected package, or None to skip.
    status is 'fixable' (a fix exists) or 'pending' (affected, no fix event)."""
    if rec.get("withdrawn"):
        return None
    for aff in rec.get("affected", []):
        if (aff.get("package") or {}).get("ecosystem") != ecosystem:
            continue
        if name is not None and (aff.get("package") or {}).get("name") != name:
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
    copy. Rows are advisories-table tuples (severity at [4], cves at [7], optional
    cvss at [11] — short rows from the bulk providers have no cvss yet)."""
    from .base import severity_rank

    def _cvss(r):
        return r[11] if len(r) > 11 else ""

    best: dict = {}
    for r in rows:
        key = (r[2], r[7])
        cur = best.get(key)
        if cur is None or severity_rank(r[4]) > severity_rank(cur[4]) \
                or (severity_rank(r[4]) == severity_rank(cur[4]) and _cvss(r) and not _cvss(cur)):
            best[key] = r
    return list(best.values())


def cve_ids(rec: dict) -> list[str]:
    """The CVE aliases of a record (falling back to its OSV id)."""
    cves = [a for a in (rec.get("aliases") or []) if str(a).startswith("CVE-")]
    return cves or [rec.get("id", "")]
