"""AUR IoC scan (`-S` / ``aur-ioc-scan``) — check installed AUR packages for
indicators of compromise.

Cross-references the installed foreign set against the lenucksi IOC feeds:
known-malicious **package names**, known-malicious **maintainer accounts**, and
malicious **JS-dependency traces** in the user's package-manager caches. Findings
are printed and saved to ``~/aur-ioc-scan.txt``. Threat-focused; the health
metrics table lives in ``aur-audit`` (-A).
"""

from __future__ import annotations

from .. import reports
from ..supplychain.base import KNOWN_BAD, Finding, Severity
from . import common as aur_common
from . import meta as aur_meta


def run(ctx) -> None:
    out = ctx.output
    foreign = aur_common.foreign_packages(ctx)
    if not foreign:
        out.ok("no foreign (AUR) packages installed.")
        return

    ioc = aur_common.ioc_feed(ctx)
    findings: list[Finding] = []

    # 1) Installed package names vs the known-malicious package list.
    bad_pkgs = ioc.bad_packages()
    if not bad_pkgs:
        out.warn("could not load malicious-package lists (offline?); coverage degraded.")
    findings += [Finding(Severity.CRIT, "aur", name, KNOWN_BAD,
                         "on a known-malicious package list — REMOVE/INVESTIGATE")
                 for name in foreign if name in bad_pkgs]

    # 2) Maintainer accounts vs the known-malicious accounts list (one batched RPC).
    bad_accounts = ioc.bad_accounts()
    for r in aur_meta.query_info(foreign):
        name, maint = r.get("Name"), r.get("Maintainer")
        if name and maint and maint in bad_accounts:
            findings.append(Finding(Severity.CRIT, "aur", name, KNOWN_BAD,
                                    f"maintained by a known-malicious account ({maint})"))

    # 3) Malicious JS-dependency traces in package-manager caches.
    findings += [Finding(Severity.CRIT, "aur", name, KNOWN_BAD,
                         f"malicious JS package trace under {path}")
                 for name, path in aur_common.js_cache_hits(ioc.bad_npm(), ctx.user_home)]

    _report(ctx, foreign, findings)


def _report(ctx, foreign, findings) -> None:
    out = ctx.output
    findings.sort(key=lambda f: (f.package, f.detail))
    if not findings:
        out.ok(f"scan complete: no indicators matched across {len(foreign)} package(s).")
        out.note("(a clean result is not a guarantee — lists cover known campaigns only.)")
    else:
        for f in findings:
            out.alert(f"[{f.source}] {f.package}: {f.detail}")
        out.summary_add(f"{len(findings)} IoC indicator(s) flagged — INVESTIGATE")

    if not ctx.dry_run:
        try:
            lines = ["aur-ioc-scan report", ""]
            lines += ([f"[{f.severity.name}] [{f.source}] {f.package}: {f.detail}"
                       for f in findings] or ["no indicators matched"])
            report = reports.write_report("aur-ioc-scan", "\n".join(lines), ctx)
            out.note(f"report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write aur-ioc-scan report: {exc}")
