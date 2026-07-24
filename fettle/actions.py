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
    "only_update": "Refreshing metadata",
    "rebuild_check": "Rebuild check",
    "python_rebuild_check": "Python rebuild check",
    "config_drift": "Config file drift",
    "auto_updates": "Automatic updates",
    "firmware_check": "Firmware",
    "kernel": "Kernel management",
    "aur_audit": "AUR audit",
    "aur_ioc_scan": "AUR IoC scan",
    "pkg_audit": "Package supply-chain audit",
    "hardening_audit": "Binary hardening audit",
}


def _clean(backend: "PackageBackend", ctx: "Context") -> None:
    # One confirmation for the whole clean (it deletes cache files). --yes and
    # non-interactive both proceed; a dry-run shows what would run without asking.
    if not ctx.dry_run and not ctx.confirm(
            "remove package-manager caches and build dirs?", default=False):
        ctx.output.note("skipped cache cleaning.")
        return
    backend.clean_caches(ctx)


def _update(backend: "PackageBackend", ctx: "Context") -> None:
    if ctx.dry_run:
        _preview_transaction(backend, ctx)
    else:
        # Best-effort security gate (Phase 19): warn (and, if enabled, confirm) on
        # unpatched Critical CVEs before a real upgrade. Never blocks on missing data.
        from .advisories.check import security_gate
        if not security_gate(ctx):
            ctx.output.warn("update skipped — review with `fettle advisory-check`.")
            return
    backend.update_system(ctx)
    backend.update_extras(ctx)


def _only_update(backend: "PackageBackend", ctx: "Context") -> None:
    """Refresh package metadata (no upgrade) and report what's now upgradable."""
    ctx.output.note("refreshing package metadata (no packages will be upgraded)...")
    backend.refresh_metadata(ctx)
    _preview_transaction(backend, ctx)


# Order within a group: upgrades, then new dependencies, then removals.
_KIND_ORDER = {"upgrade": 0, "new-dep": 1, "remove": 2}
_SOURCE_LABELS = {"repo": "official repos", "aur": "AUR"}


def _fmt_txitem(it) -> str:
    if it.kind == "remove":
        return f"- {it.name}  {it.old}  (remove)"
    if it.old is None or it.kind == "new-dep":
        return f"+ {it.name}  {it.new}  (new dependency)"
    return f"  {it.name}  {it.old} -> {it.new}"


def _preview_transaction(backend: "PackageBackend", ctx: "Context") -> None:
    """Print the full set the upgrade would install (upgrades + new deps + any
    removals), grouped by source, before the `would run:` command lines."""
    out = ctx.output
    tx = backend.pending_transaction(ctx, sync=ctx.sync)
    if not tx.ok:
        detail = f" ({'; '.join(tx.notes)})" if tx.notes else " (query tool unavailable)"
        out.warn(f"could not determine the package transaction{detail}")
        return
    for note in tx.notes:
        out.note(note)
    if not tx.items:
        out.ok("nothing to install — system is up to date.")
        return

    out.note(f"{len(tx.items)} package(s) would be installed/changed:")
    groups: dict[str, list] = {}
    for it in tx.items:
        groups.setdefault(it.source, []).append(it)
    # Known sources first (repo, aur), then any others deterministically.
    for source in list(_SOURCE_LABELS) + [s for s in groups if s not in _SOURCE_LABELS]:
        group = groups.get(source)
        if not group:
            continue
        group.sort(key=lambda i: (_KIND_ORDER.get(i.kind, 9), i.name))
        print(f"    {_SOURCE_LABELS.get(source, source)} ({len(group)}):")
        for it in group:
            print(f"    {_fmt_txitem(it)}")


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
    from . import reports
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

    # Persist a plain-text report under ~/.fettle/reports/<host>/.
    if not ctx.dry_run:
        try:
            lines = ["pkg-audit report", ""]
            lines += [f"[{f.severity.name}] [{f.source}] {f.package}: {f.detail}"
                      for f in findings] or ["no findings"]
            from .supplychain.base import finding_to_dict
            data = {"findings": [finding_to_dict(f) for f in findings]}
            report = reports.write_report("pkg-audit", "\n".join(lines), ctx, data=data)
            out.note(f"full report saved to {report}")
        except OSError as exc:
            out.warn(f"could not write pkg-audit report: {exc}")


# action name -> callable(backend, ctx). Only implemented actions appear here.
HANDLERS = {
    "clean": _clean,
    "only_update": _only_update,
    "update": _update,
    "orphans": lambda b, c: b.check_foreign_orphans(c),
    "rebuild_check": lambda b, c: b.check_rebuilds(c),
    "python_rebuild_check": lambda b, c: b.check_python_rebuilds(c),
    "config_drift": lambda b, c: b.check_config_drift(c),
    "auto_updates": lambda b, c: b.check_auto_updates(c),
    "firmware_check": lambda b, c: b.firmware_updates(c),
    "kernel": lambda b, c: b.manage_kernels(c),
    "pkg_audit": pkg_audit,
    # -A and -S are distinct AUR-specific commands (not pkg-audit aliases):
    # -A is the health/metrics table; -S is the installed-package IoC scan.
    "aur_audit": lambda b, c: _aur_audit(c),
    "aur_ioc_scan": lambda b, c: _aur_ioc_scan(c),
    "hardening_audit": lambda b, c: _hardening_audit(b, c),
}


def _hardening_audit(backend: "PackageBackend", ctx: "Context") -> None:
    from .hardening import audit
    audit.run(backend, ctx)


def _aur_audit(ctx: "Context") -> None:
    from .aur import audit
    audit.run(ctx)


def _aur_ioc_scan(ctx: "Context") -> None:
    from .aur import ioc_scan
    ioc_scan.run(ctx)


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
