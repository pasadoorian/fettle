"""`fettle advisory-check` / `fettle advisory-update` (PLAN.md §19.5/19.8).

advisory-check: refresh the cache if stale (best-effort), classify installed
packages, and report — a **Pending fixes** callout (vulnerable, no fix released yet)
above a hardening-style severity table of fix-available findings, plus the packages
the tracker doesn't cover. advisory-update: force a refresh only. Read-only, opt-in.
"""

from __future__ import annotations

import time
from datetime import datetime

from .. import reports
from ..distro import parse_os_release
from ..util import matches_any
from . import base, db
from .arch_source import ArchAdvisorySource
from .debian_source import DebianAdvisorySource


def _providers():
    # Ubuntu provider joins here in Milestone 3.
    return [ArchAdvisorySource(), DebianAdvisorySource()]


def _cfg(ctx) -> dict:
    a = getattr(ctx.config, "advisories", None) or {}
    return {
        "cache_ttl": int(a.get("cache_ttl", 21600)),
        "severity_threshold": str(a.get("severity_threshold", "") or ""),
        "exclude_packages": a.get("exclude_packages", []) or [],
        "exclude_classes": [str(c) for c in (a.get("exclude_classes", []) or [])],
        "warn_gate": bool(a.get("warn_gate", True)),
    }


def _is_manjaro(ctx) -> bool:
    root = getattr(ctx, "root", None) or "/"
    try:
        rel = parse_os_release(__import__("pathlib").Path(root))
    except Exception:
        rel = {}
    idlike = (rel.get("ID", "") + " " + rel.get("ID_LIKE", "")).lower()
    return "manjaro" in idlike


# -- refresh (best-effort) ---------------------------------------------------
def _ensure_fresh(conn, provider, ttl, out, *, force=False) -> None:
    last = db.last_updated(conn, provider.source)
    if not force and last is not None and (time.time() - last) <= ttl:
        return
    if out:
        out.note(f"refreshing {provider.source} advisory data…")
    n = provider.refresh(conn)
    if n < 0 and out:
        out.warn(f"could not fetch {provider.source} advisory data"
                 + ("; using the cached copy." if last is not None
                    else " (offline?) and none is cached."))


# -- filters (§19.8) ---------------------------------------------------------
def _apply_filters(findings, cfg):
    thresh = base.severity_rank(cfg["severity_threshold"]) if cfg["severity_threshold"] else 0
    out = []
    for f in findings:
        if thresh and base.severity_rank(f.severity) < thresh:
            continue
        if cfg["exclude_packages"] and matches_any(f.package, cfg["exclude_packages"]):
            continue
        if f.distro_class in cfg["exclude_classes"]:
            continue
        out.append(f)
    return out


def _sev_key(f):
    return (-base.severity_rank(f.severity), f.package)


def _line(f) -> str:
    ver = f.installed_version + (f" -> {f.fixed_version}" if f.fixed_version else "")
    cves = " ".join(f.cves[:4]) + (" …" if len(f.cves) > 4 else "")
    return f"  [{f.severity:<8}] {f.package} {ver}   {cves}   {f.url}"


def _render(findings, uncovered, manjaro, sources):
    pending = sorted((f for f in findings if f.status == base.PENDING_FIX), key=_sev_key)
    fixable = sorted((f for f in findings if f.status != base.PENDING_FIX), key=_sev_key)

    lines = [f"Security advisories  -  {datetime.now():%Y-%m-%d %H:%M:%S}", ""]

    lines.append(f"=== Pending fixes — vulnerable, NO fix released yet ({len(pending)}) ===")
    lines += [_line(f) for f in pending] or ["  none"]

    hi = [f for f in fixable if base.severity_rank(f.severity) >= 3]  # Critical/High
    lo = [f for f in fixable if base.severity_rank(f.severity) < 3]
    lines += ["", f"=== Fix available — installed trails a security fix ({len(fixable)}) ==="]
    lines += [_line(f) for f in hi] or (["  none at Critical/High"] if lo else ["  none"])
    if lo:
        tally = {}
        for f in lo:
            tally[f.severity] = tally.get(f.severity, 0) + 1
        lines.append("  " + ", ".join(f"{k}: {v}" for k, v in tally.items())
                     + "  (Medium/Low/Unknown — see the full report)")

    for src in sources:
        unc = uncovered.get(src, [])
        if unc:
            lines += ["", f"NOT covered by the {src} tracker (AUR/manual/foreign): "
                      f"{len(unc)} package(s)", "  " + " ".join(sorted(unc)),
                      "  (their CVEs aren't tracked here — vet via `fettle -A`/`-P`/`-I`)"]
    if "debian" in sources:
        lines += ["", "Note: Debian coverage is by source package from the tracker; "
                  "third-party/local .debs aren't separately flagged yet."]

    if manjaro and fixable:
        lines += ["", "Note: on Manjaro, 'fix available' can reflect the normal 1–2 week",
                  "sync lag behind Arch, not special exposure — the fix is likely en route."]

    data = {
        "sources": sources,
        "findings": [base.advisory_to_dict(f) for f in findings],
        "counts": {"pending": len(pending), "fixed_available": len(fixable)},
        "uncovered": uncovered,
        "manjaro": manjaro,
    }
    return lines, data


# -- entry points ------------------------------------------------------------
def run(ctx) -> None:
    out = ctx.output
    provs = [p for p in _providers() if p.is_present(ctx)]
    if not provs:
        out.warn("no advisory provider for this system yet "
                 "(Arch/Manjaro supported; Debian/Ubuntu planned).")
        return
    cfg = _cfg(ctx)
    conn = db.connect(db.db_path(ctx))
    findings, uncovered = [], {}
    try:
        for p in provs:
            _ensure_fresh(conn, p, cfg["cache_ttl"], out)
            findings += p.findings(ctx, conn)
            uncovered[p.source] = p.uncovered(ctx)
    finally:
        conn.close()

    findings = _apply_filters(findings, cfg)
    lines, data = _render(findings, uncovered, _is_manjaro(ctx), [p.source for p in provs])
    for ln in lines:
        print(ln)

    report = None
    if not ctx.dry_run:
        try:
            report = reports.write_report("advisory-check", "\n".join(lines), ctx, data=data)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write advisory-check report: {exc}")
    out.summary_add(
        f"advisories: {data['counts']['pending']} pending, "
        f"{data['counts']['fixed_available']} fix-available")


def update(ctx) -> None:
    out = ctx.output
    provs = [p for p in _providers() if p.is_present(ctx)]
    if not provs:
        out.warn("no advisory provider for this system yet.")
        return
    conn = db.connect(db.db_path(ctx))
    try:
        for p in provs:
            out.note(f"fetching {p.source} advisory data…")
            n = p.refresh(conn)
            if n < 0:
                out.err(f"failed to fetch {p.source} advisory data.")
            else:
                out.ok(f"{p.source}: cached {n} advisory rows.")
    finally:
        conn.close()


def security_gate(ctx) -> bool:
    """Best-effort pre-update advisory gate (§19.8). Uses ONLY the cached DB — it
    never fetches, and MUST never block or fail a routine update on missing/stale/
    offline data. Prints a short security summary; if ``warn_gate`` is on and Critical
    CVEs are unpatched, asks one extra confirm. Returns ``False`` only to ABORT the
    update. Never raises."""
    out = getattr(ctx, "output", None)
    try:
        path = db.db_path(ctx)
        if not path.exists():
            return True                              # no cached data -> proceed
        cfg = _cfg(ctx)
        conn = db.connect(path)
        try:
            findings = [f for p in _providers() if p.is_present(ctx)
                        for f in p.findings(ctx, conn)]
        finally:
            conn.close()
        findings = _apply_filters(findings, cfg)
        if not findings:
            return True
        crit = sorted({f.package for f in findings if f.severity == "Critical"})
        if out:
            out.note(f"security: {len(findings)} advisory finding(s) affect installed "
                     f"packages, {len(crit)} Critical — see `fettle advisory-check`")
        if not (cfg["warn_gate"] and crit):
            return True
        if getattr(ctx, "assume_yes", False):
            if out:
                out.warn("proceeding despite unpatched Critical CVEs (--yes): "
                         + ", ".join(crit))
            return True
        if out:
            out.warn("unpatched Critical CVEs: " + ", ".join(crit))
        return ctx.confirm("Continue with the update despite unpatched Critical CVEs?",
                           default=True)
    except Exception:                                # never let advisory logic break an update
        return True
