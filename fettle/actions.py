"""Distro-agnostic orchestration: run the requested actions against a backend.

Section titles and the step counter live here; the backend methods only emit
status. Actions not yet implemented print a note (they raise NotImplementedError
in the ABC) so a half-built backend degrades gracefully.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .backends.base import Context, PackageBackend

# Human-facing section titles (mirrors update.sh's headers).
TITLES = {
    "clean": "Cleaning caches",
    "orphans": "Foreign & orphaned packages",
    "update": "Updating packages",
    "rebuilds": "Rebuild check",
    "python_rebuild": "Python rebuild check",
    "config_drift": "Config file drift",
    "firmware": "Firmware",
    "kernels": "Kernel management",
    "aur_audit": "Package supply-chain audit",
    "aur_scan": "Package supply-chain scan",
    "pkg_audit": "Package supply-chain audit",
    "integrity": "Package integrity",
    "source_audit": "Package supply-chain audit",
}


def _update(backend: "PackageBackend", ctx: "Context") -> None:
    backend.update_system(ctx)
    backend.update_extras(ctx)


def _emit(out, finding) -> None:
    from .supplychain.base import Severity
    line = f"[{finding.source}] {finding.package}: {finding.detail}"
    if finding.severity >= Severity.CRIT:
        out.alert(line)
    elif finding.severity == Severity.WARN:
        out.warn(line)
    else:
        out.note(line)


def pkg_audit(backend: "PackageBackend", ctx: "Context") -> None:
    """Run every present Package Supply Chain provider and report normalized findings."""
    from .util import chown_to_user
    from .supplychain.base import Severity

    out = ctx.output
    providers = [p for p in backend.supply_chain_sources() if p.is_present(ctx)]
    if not providers:
        out.ok("no package sources present for a supply-chain audit.")
        return

    findings = []
    for p in providers:
        out.note(f"[{p.source}] coverage: {p.coverage}")
        findings.extend(p.findings(ctx))
    findings.sort(key=lambda f: (-int(f.severity), f.source, f.package))

    if not findings:
        out.ok("no supply-chain findings.")
    else:
        for f in findings:
            _emit(out, f)
        crit = sum(1 for f in findings if f.severity >= Severity.CRIT)
        msg = f"{len(findings)} supply-chain finding(s)"
        if crit:
            msg += f", {crit} CRITICAL — INVESTIGATE"
        out.summary_add(msg)

    # Persist a plain-text report (parity with update.sh's ~/aur-audit.txt).
    if not ctx.dry_run:
        report = ctx.user_home / "pkg-audit.txt"
        try:
            lines = ["pkg-audit report", ""]
            lines += [f"[{f.severity.name}] [{f.source}] {f.package}: {f.detail}"
                      for f in findings] or ["no findings"]
            report.write_text("\n".join(lines) + "\n")
            chown_to_user(report, ctx.sudo_user)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write {report}: {exc}")


# action name -> callable(backend, ctx). Only implemented actions appear here.
HANDLERS = {
    "clean": lambda b, c: b.clean_caches(c),
    "update": _update,
    "orphans": lambda b, c: b.check_foreign_orphans(c),
    "rebuilds": lambda b, c: b.check_rebuilds(c),
    "python_rebuild": lambda b, c: b.check_python_rebuilds(c),
    "config_drift": lambda b, c: b.check_config_drift(c),
    "firmware": lambda b, c: b.firmware_updates(c),
    "kernels": lambda b, c: b.manage_kernels(c),
    "pkg_audit": pkg_audit,
    "aur_audit": pkg_audit,   # -A is an Arch alias into pkg-audit
    "aur_scan": pkg_audit,    # -S is an Arch alias into pkg-audit
}


def run(actions: list[str], backend: "PackageBackend", ctx: "Context") -> None:
    out = ctx.output
    out.step_total = len(actions)
    for name in actions:
        out.section(TITLES.get(name, name))
        handler = HANDLERS.get(name)
        if handler is None:
            out.note(f"'{name}' not yet implemented — coming in a later milestone")
            continue
        try:
            handler(backend, ctx)
        except NotImplementedError:
            out.note(f"'{name}' not yet implemented for the {backend.name} backend")
    out.print_summary()
