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
from .osv_source import OsvLanguageSource
from .rhel_source import RhelAdvisorySource
from .ubuntu_source import UbuntuAdvisorySource


def _providers():
    return [ArchAdvisorySource(), DebianAdvisorySource(), UbuntuAdvisorySource(),
            RhelAdvisorySource(), OsvLanguageSource()]


_RETIRED_KEYS = {
    "warn_gate": ("the pre-update confirm was removed in v0.75.0 — an update installs "
                  "available fixes, so nothing about CVE state blocks it now"),
}


def _cfg(ctx) -> dict:
    a = getattr(ctx.config, "advisories", None) or {}
    return {
        "cache_ttl": int(a.get("cache_ttl", 21600)),
        "severity_threshold": str(a.get("severity_threshold", "") or ""),
        "exclude_packages": a.get("exclude_packages", []) or [],
        "exclude_classes": [str(c) for c in (a.get("exclude_classes", []) or [])],
    }


def _warn_retired_keys(ctx) -> None:
    """A config key that no longer does anything must say so. Left silent, someone
    keeps believing `warn_gate = true` is guarding their updates."""
    a = getattr(getattr(ctx, "config", None), "advisories", None) or {}
    out = getattr(ctx, "output", None)
    for key, why in _RETIRED_KEYS.items():
        if key in a and out:
            out.warn(f"[advisories] {key} no longer has any effect — {why}.")


def _is_manjaro(ctx) -> bool:
    root = getattr(ctx, "root", None) or "/"
    try:
        rel = parse_os_release(__import__("pathlib").Path(root))
    except Exception:
        rel = {}
    idlike = (rel.get("ID", "") + " " + rel.get("ID_LIKE", "")).lower()
    return "manjaro" in idlike


# -- refresh (best-effort) ---------------------------------------------------
def _ensure_fresh(conn, provider, ttl, out, ctx=None, *, force=False) -> str:
    """``""`` when the data is current, else why it isn't.

    The caller needs the answer, not just the log line: a CVE check running on a
    stale or absent feed is the "could not look" case, and it used to warn inline
    and then contribute a clean-looking summary anyway.
    """
    last = db.last_updated(conn, provider.source)
    if not force and last is not None and (time.time() - last) <= ttl:
        return ""
    if out:
        out.note(f"refreshing {provider.source} advisory data…")
    n = provider.refresh(conn, ctx)
    if n >= 0:
        return ""
    why = ("using a cached copy" if last is not None else "and NONE is cached")
    if out:
        out.warn(f"could not fetch {provider.source} advisory data — {why}.")
    return f"{provider.source} ({why})"


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


def _sev_key(item):
    f = item[0] if isinstance(item, tuple) else item
    return (-base.severity_rank(f.severity), f.package)


# How many environment names to spell out before summarizing (the full list always
# reaches the JSON sibling, so nothing is lost — this only keeps the text readable).
_ENVS_SHOWN = 10


def _group(findings):
    """Collapse findings that describe **the same fix**.

    The unmanaged-language scan reports per environment, so one vulnerable package
    copied into many virtualenvs arrives as many findings. On a real box that was
    594 occurrences for 28 packages. That noise is replication, not severity — a
    severity floor barely touches it (209 of 212 were rated High) — so reporting
    groups instead.

    Keyed on the **remediation** (package + fix version + CVEs), deliberately *not*
    on the installed version: "upgrade pip to 26.1.2" is one action whether a given
    virtualenv sits on 24.0 or 25.2, and keying on installed version fragmented that
    single action into 34 lines. Measured on real data: 594 occurrences → 323 groups
    keyed with the installed version, → 132 keyed on the fix. Each environment keeps
    its own version in the returned pairs so nothing is lost.

    Returns ``[(representative_finding, [(environment, installed_version), …]), …]``.
    """
    groups: dict[tuple, list] = {}
    for f in findings:
        key = (f.source, f.package, f.fixed_version, f.status, f.severity,
               tuple(f.cves))
        groups.setdefault(key, []).append(f)
    out = []
    for fs in groups.values():
        envs = sorted({(f.environment, f.installed_version) for f in fs if f.environment})
        out.append((fs[0], envs))
    return out


def _installed_summary(f, envs) -> str:
    """The installed side of the version arrow: one version, or a span when the
    environments disagree (the fix target is the same either way)."""
    versions = sorted({v for _e, v in envs}) if envs else [f.installed_version]
    if len(versions) == 1:
        return versions[0]
    return f"{versions[0]}…{versions[-1]} ({len(versions)} versions)"


def _lines_for(f, envs=(), labels=None) -> list[str]:
    ver = _installed_summary(f, envs)
    ver += f" -> {f.fixed_version}" if f.fixed_version else ""
    cves = " ".join(f.cves[:4]) + (" …" if len(f.cves) > 4 else "")
    cvss = f"  ({f.cvss})" if f.cvss else ""
    out = [f"  [{f.severity:<8}] {f.source}/{f.package} {ver}   {cves}   {f.url}{cvss}"]
    if envs:
        lab = labels or {}
        shown = ", ".join(f"{lab.get(e, e)} ({v})" for e, v in envs[:_ENVS_SHOWN])
        more = f" (+{len(envs) - _ENVS_SHOWN} more)" if len(envs) > _ENVS_SHOWN else ""
        where = (f"in {len(envs)} environments: " if len(envs) > 1 else "in ")
        out.append(f"             {where}{shown}{more}")
    return out


def _count_note(groups, raw_total) -> str:
    """Say so when grouping collapsed occurrences, so a smaller number than last
    release doesn't read as findings having gone missing."""
    if raw_total <= len(groups):
        return ""
    envs = len({e for _f, env_list in groups for e, _v in env_list})
    return (f"  ({raw_total} occurrences across {envs} environment(s), "
            f"grouped by package+CVE)")


def _render(findings, uncovered, manjaro, sources, scopes=()):
    # Environments are identified by absolute path; the terminal shows a short label
    # and the key at the end resolves it. QA: the report said `jetkvm (25.3.0)` and
    # never said where jetkvm was, so acting on a finding began with a `find`.
    from .osv_source import env_labels
    env_paths = sorted({e for f in findings for e in ([f.environment] if f.environment
                                                      else [])})
    labels = env_labels(env_paths) if env_paths else {}

    pending_f = [f for f in findings if f.status == base.PENDING_FIX]
    fixable_f = [f for f in findings if f.status != base.PENDING_FIX]
    pending = sorted(_group(pending_f), key=_sev_key)
    fixable = sorted(_group(fixable_f), key=_sev_key)

    lines = [f"Security advisories  -  {datetime.now():%Y-%m-%d %H:%M:%S}", ""]

    # Say what was looked at before saying what was found. Two very different things
    # are being reported — the distro's package database, and a walk of your home
    # directory — and the only signal used to be an `arch/` vs `osv/` row prefix.
    if scopes:
        lines.append("What was checked:")
        lines += [f"  {src:<6} {text}" for src, text in scopes if text]
        lines.append("")

    lines.append(f"=== Pending fixes — vulnerable, NO fix released yet ({len(pending)}) ==="
                 + _count_note(pending, len(pending_f)))
    lines += [ln for f, envs in pending for ln in _lines_for(f, envs, labels)] \
        or ["  none"]

    hi = [(f, e) for f, e in fixable if base.severity_rank(f.severity) >= 3]
    lo = [(f, e) for f, e in fixable if base.severity_rank(f.severity) < 3]
    lines += ["", f"=== Fix available — installed trails a security fix ({len(fixable)}) ==="
              + _count_note(fixable, len(fixable_f))]
    lines += [ln for f, envs in hi for ln in _lines_for(f, envs, labels)] \
        or (["  none at Critical/High"] if lo else ["  none"])
    if lo:
        tally = {}
        for f, _e in lo:
            tally[f.severity] = tally.get(f.severity, 0) + 1
        lines.append("  " + ", ".join(f"{k}: {v}" for k, v in tally.items())
                     + "  (Medium/Low/Unknown — see the full report)")

    for src in sources:
        unc = uncovered.get(src, [])
        if unc:
            lines += ["", f"NOT covered by the {src} tracker (AUR/manual/foreign): "
                      f"{len(unc)} package(s)", "  " + " ".join(sorted(unc)),
                      "  (their CVEs aren't tracked here — vet via `fettle -P` / `-A`)"]
    if "debian" in sources:
        lines += ["", "Note: Debian coverage is by source package from the tracker; "
                  "third-party/local .debs aren't separately flagged yet."]
    if "rhel" in sources:
        lines += ["", "Note: RHEL-family findings come from the repositories' own "
                  "updateinfo metadata, so coverage depends on your repo mix — "
                  "CentOS Stream publishes no security errata. Only advisories that "
                  "HAVE a fix are knowable this way; 'vulnerable, no fix yet' would "
                  "need Red Hat's CSAF/VEX feed."]
    if "ubuntu" in sources:
        lines += ["", "Note: Ubuntu fix-available findings come from the OVAL feed. "
                  "'Vulnerable, no fix yet' (pending) is opt-in via [advisories] "
                  "ubuntu_pending + ubuntu_pending_severity (OSV-sourced)."]

    if labels:
        lines += ["", f"Environments ({len(labels)}) — the short names above, in full:"]
        width = max(len(v) for v in labels.values())
        lines += [f"  {labels[pth]:<{width}}  {pth}" for pth in env_paths]

    if manjaro and fixable:
        lines += ["", "Note: on Manjaro, 'fix available' can reflect the normal 1–2 week",
                  "sync lag behind Arch, not special exposure — the fix is likely en route."]

    data = {
        "sources": sources,
        "findings": [base.advisory_to_dict(f) for f in findings],
        # Grouped counts are the headline (distinct problems); occurrence counts keep
        # the pre-grouping totals so consumers can tell the two apart.
        "counts": {"pending": len(pending), "fixed_available": len(fixable),
                   "pending_occurrences": len(pending_f),
                   "fixed_available_occurrences": len(fixable_f)},
        "uncovered": uncovered,
        "manjaro": manjaro,
        # label -> absolute path, so a consumer of the JSON can act on a finding
        # without re-deriving where the environment lives.
        "environments": {labels[p]: p for p in env_paths},
        "scopes": dict(scopes),
    }
    return lines, data


# -- entry points ------------------------------------------------------------
def run(ctx) -> None:
    out = ctx.output
    provs = [p for p in _providers() if p.is_present(ctx)]
    if not provs:
        out.warn("no advisory provider for this system "
                 "(Arch/Manjaro, Debian/Ubuntu and the RHEL family are supported).")
        return
    _warn_retired_keys(ctx)
    cfg = _cfg(ctx)
    conn = db.connect(db.db_path(ctx))
    findings, uncovered, degraded = [], {}, []
    try:
        for p in provs:
            stale = _ensure_fresh(conn, p, cfg["cache_ttl"], out, ctx)
            if stale:
                degraded.append(stale)
            findings += p.findings(ctx, conn)
            uncovered[p.source] = p.uncovered(ctx)
    finally:
        conn.close()

    findings = _apply_filters(findings, cfg)
    scopes = [(p.source, p.scope(ctx)) for p in provs]
    lines, data = _render(findings, uncovered, _is_manjaro(ctx),
                          [p.source for p in provs], scopes)
    for ln in lines:
        print(ln)

    report = None
    if not ctx.dry_run:
        try:
            report = reports.write_report("advisory-check", "\n".join(lines), ctx, data=data)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write advisory-check report: {exc}")
    counts = data["counts"]
    line = (f"advisories: {counts['pending']} pending, "
            f"{counts['fixed_available']} fix-available")
    crit = [f for f in findings
            if f.status != base.PENDING_FIX and base.severity_rank(f.severity) >= 4]
    if degraded:
        # A CVE check is only worth its answer. Stale or missing feed data means the
        # answer covers less than it appears to, so it must not read as a clean pass.
        out.summary_warn(f"{line} — but advisory data is NOT current: "
                         + ", ".join(degraded))
    elif crit:
        # A Critical with a fix already released is the one case that should stop an
        # automated run; `security_gate` already treats it that way before -u/-a.
        out.summary_fail(f"{line} — {len(crit)} CRITICAL with a fix available")
    elif counts["pending"] or counts["fixed_available"]:
        # Unpatched CVEs are open items, not an accomplishment.
        out.summary_warn(line)
    else:
        out.summary_add("advisories: nothing known-vulnerable")


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
            n = p.refresh(conn, ctx)
            if n < 0:
                out.err(f"failed to fetch {p.source} advisory data.")
            else:
                out.ok(f"{p.source}: cached {n} advisory rows.")
    finally:
        conn.close()


def security_note(ctx) -> None:
    """Print the security posture before a real upgrade. **Never blocks it.**

    This was a *gate*: on an unpatched Critical it asked "Continue with the update
    despite unpatched Critical CVEs?" and returned False to abort. QA found that
    argues for the harmful answer. On the machine it was measured on, 732 of 770
    findings had a fix already released — so the update it offered to abort was
    precisely the thing that installs those fixes, and answering "no" left the box
    both unpatched *and* vulnerable. For a Critical with no fix released, aborting
    does not help either: the update is unrelated to it.

    So it informs and gets out of the way. An update is the remedy; nothing about CVE
    state should stand in front of it.

    Reads ONLY the cached DB — never fetches, so a network problem cannot delay an
    upgrade — and never raises. Best-effort by design: on any error it says nothing
    and the update proceeds.
    """
    out = getattr(ctx, "output", None)
    if out is None:
        return
    try:
        path = db.db_path(ctx)
        if not path.exists():
            return                                   # no cached data -> nothing to say
        cfg = _cfg(ctx)
        conn = db.connect(path)
        try:
            findings = [f for p in _providers() if p.is_present(ctx)
                        for f in p.findings(ctx, conn)]
        finally:
            conn.close()
        findings = _apply_filters(findings, cfg)
        if not findings:
            return
        # Count what `fettle advisory-check` shows. Counting raw findings here said
        # "770 advisory finding(s) ... see `fettle advisory-check`", and running that
        # showed 176 — the note contradicted the document it sent you to.
        groups = _group(findings)
        crit = [f for f, _envs in groups if base.severity_rank(f.severity) >= 4]
        fixable = [f for f in crit if f.status != base.PENDING_FIX]
        pending = [f for f in crit if f.status == base.PENDING_FIX]

        out.note(f"security: {len(groups)} known-vulnerable package(s) on this system, "
                 f"{len(crit)} Critical — detail in `fettle advisory-check`")
        if fixable:
            names = ", ".join(sorted({f.package for f in fixable})[:6])
            out.note(f"  {len(fixable)} Critical with a fix released — this update "
                     f"should install them: {names}")
        if pending:
            # The one thing an upgrade genuinely cannot fix, so it is the one thing
            # worth raising a warning about here.
            names = ", ".join(sorted({f.package for f in pending})[:6])
            out.warn(f"{len(pending)} Critical with NO fix released — the update will "
                     f"not address these: {names}")
    except Exception:            # never let advisory logic disturb an update
        return
