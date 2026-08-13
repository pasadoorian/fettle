"""Distro-agnostic orchestration: run the requested actions against a backend.

Section titles and the step counter live here; the backend methods only emit
status. Actions not yet implemented print a note (they raise NotImplementedError
in the ABC) so a half-built backend degrades gracefully.
"""

from __future__ import annotations
from .output import BLIND, FAILED, FOUND

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
    "pkg_audit": "Package supply-chain audit",
    "hardening_audit": "System hardening audit",
    "pkg_integrity": "Package file integrity",
    "container_update": "Container images",
    "sys_audit": "System & firmware security audit",
    "advisory_check": "Security advisories (CVEs)",
    "compromise_check": "Compromise indicators",
}


def _clean(backend: "PackageBackend", ctx: "Context") -> None:
    """Confirm, clean, and report what was *actually* reclaimed.

    The measuring and the summary live here rather than in each backend so all three
    families tell the truth the same way. QA found the old arrangement reporting
    ``✓ caches cleaned`` in three situations that are not the same thing: a run that
    freed 41 MB, a run against an already-empty cache, and a ``--dry-run`` that deleted
    nothing at all. Sizing the cache directories before and after distinguishes them
    without trusting any package manager's own account of itself — which is the point,
    since ``pacman -Scc --noconfirm`` reported success while removing nothing.
    """
    from .backends.base import dir_bytes, human_bytes

    # One confirmation for the whole clean (it deletes cache files). --yes and
    # non-interactive both proceed; a dry-run shows what would run without asking.
    if not ctx.dry_run and not ctx.confirm(backend.clean_prompt, default=False):
        ctx.output.note("skipped cache cleaning.")
        return

    paths = backend.cache_paths(ctx)
    before = sum(dir_bytes(p) for p in paths)
    failed_before = len(ctx.failed_commands)
    result = backend.clean_caches(ctx)
    freed = max(0, before - sum(dir_bytes(p) for p in paths))
    failed = ctx.failed_commands[failed_before:]

    # A backend may decline rather than fail — the Arch clean refuses while a package
    # transaction holds pacman's lock. Nothing ran and nothing was freed, so without
    # this the branches below would reach "caches already clean — nothing to reclaim",
    # which describes a clean that did not happen.
    if result is not None and result.ok is False:
        ctx.output.summary_fail(result.summary or "clean did NOT run", kind=FAILED)
        return

    if ctx.dry_run:
        ctx.output.summary_add("would clean caches")
        return
    if failed:
        # A clean that could not run is NOT a clean cache. Reporting the byte delta
        # alone collapses "nothing to free" and "could not free" into one sentence,
        # and the second one leaves files on disk while the summary reads green.
        tools = ", ".join(sorted(set(failed)))
        detail = f"{human_bytes(freed)} reclaimed before it stopped" if freed \
            else "nothing was reclaimed"
        ctx.output.summary_fail(
            f"clean did NOT complete — {tools} failed ({detail}). "
            "The cache is not necessarily empty; see the errors above.", kind=FAILED)
        return
    if not paths:
        # Backend declared nothing measurable — say what happened, claim no figure.
        ctx.output.summary_add("caches cleaned")
    elif freed:
        ctx.output.summary_add(f"caches cleaned — {human_bytes(freed)} reclaimed")
    else:
        ctx.output.summary_add("caches already clean — nothing to reclaim")


def _update(backend: "PackageBackend", ctx: "Context") -> None:
    """Upgrade, and claim it only if it happened.

    The backends describe *what they did* (``Result.summary`` — "repos: pacman, AUR:
    yay"); this decides whether that description has been earned. They used to call
    ``summary_add("packages updated (…)")`` themselves, unconditionally, so a
    ``--dry-run`` that installed nothing signed off `✓ packages updated` — on an
    up-to-date system, directly under `✓ no updates pending`.
    """
    out = ctx.output
    if ctx.dry_run:
        _preview_transaction(backend, ctx)
    else:
        # Best-effort security posture before a real upgrade (Phase 19). Informational
        # only: it never blocks, because the update is what installs available fixes.
        from .advisories.check import security_note
        security_note(ctx)

    failed_before = len(ctx.failed_commands)
    # **Sequenced deliberately, not evaluated as one list.** These used to be
    # `[backend.update_system(ctx), backend.update_extras(ctx)]`, so both ran before
    # anything looked at whether the first had worked: a failed pacman transaction was
    # followed straight away by `yay -Sua`, rebuilding AUR packages against a
    # half-upgraded system, and Debian and RHEL went on to flatpak and snap the same
    # way. Extras are the step most likely to compile against whatever the system
    # upgrade just left behind, which makes them the worst thing to run next.
    #
    # A decline stops it too. Without `--yes` a non-zero exit means the user answered
    # "no" — and someone who declined the system upgrade did not ask for their flatpaks
    # to be updated regardless.
    system = backend.update_system(ctx)
    results = [system]
    system_failed = bool(ctx.failed_commands[failed_before:]) or (
        system is not None and system.ok is False)
    if system_failed:
        out.summary_warn("extras (AUR/flatpak/snap) were NOT updated — the system "
                         "upgrade did not complete, and rebuilding on top of a "
                         "half-upgraded system is how a bad upgrade gets worse")
    else:
        results.append(backend.update_extras(ctx))
    failed = sorted(set(ctx.failed_commands[failed_before:]))
    # Tolerant of a backend that returns None or a stub: the summary is a nicety,
    # and it must not be able to break an upgrade that already happened.
    what = ", ".join(r.summary for r in results
                     if isinstance(getattr(r, "summary", None), str) and r.summary)

    if ctx.dry_run:
        out.summary_add("would update packages" + (f" ({what})" if what else ""))
        return
    if failed:
        # Upgrades end early for two very different reasons, and the package managers
        # do not distinguish them: pacman, apt and dnf all exit non-zero both when the
        # user answers "no" at their prompt and when they genuinely fail. `--yes` is
        # the one reliable discriminator — with it there was no prompt to decline, so
        # a non-zero exit is a real failure.
        tools = ", ".join(failed)
        if ctx.assume_yes:
            out.summary_fail(f"update did NOT complete — {tools} failed. Some packages "
                             "may be upgraded and others not; re-run to finish, and "
                             "see the errors above.", kind=FAILED)
        else:
            out.summary_warn(f"update did not complete — {tools} stopped without "
                             "finishing. If you declined its prompt, nothing was "
                             "changed; otherwise see the errors above.")
        return
    if any(r is not None and r.ok is False for r in results):
        out.summary_fail("update did not fully complete — see the errors above.",
                         kind=FAILED)
        return
    out.summary_add(f"packages updated ({what})" if what else "packages updated")


def _only_update(backend: "PackageBackend", ctx: "Context") -> None:
    """Refresh package metadata (no upgrade) and report what's now upgradable.

    The refresh is allowed to fail — mirrors go away, keys expire, laptops are on a
    train. What is *not* allowed is answering the user's question anyway as though the
    data were current. QA measured every non-Arch family doing exactly that: with the
    network broken, `-O` printed a confident list of pending packages, no caveat, exit 0.
    """
    out = ctx.output
    if ctx.dry_run:
        out.note("would refresh package metadata (nothing is refreshed in a dry run).")
    else:
        out.note("refreshing package metadata (no packages will be upgraded)...")
    failed_before = len(ctx.failed_commands)
    backend.refresh_metadata(ctx)
    stale = sorted(set(ctx.failed_commands[failed_before:]))
    if stale:
        out.warn(f"metadata refresh FAILED ({', '.join(stale)}) — the list below "
                 "reflects the LAST SUCCESSFUL refresh and may be out of date. "
                 "Newly published updates, including security fixes, will not appear.")
    _preview_transaction(backend, ctx, stale=bool(stale))
    if stale:
                # BLIND: the refresh is what failed, so what is pending is unknown. The list
        # printed above is from stale data and may be missing everything that matters.
        out.summary_fail("could not refresh package metadata — the pending list above "
                         "is from stale data and may be incomplete.", kind=BLIND)


# Order within a group: upgrades, then new dependencies, then removals.
_KIND_ORDER = {"upgrade": 0, "new-dep": 1, "remove": 2}
_SOURCE_LABELS = {"repo": "official repos", "aur": "AUR"}


def _fmt_txitem(it) -> str:
    if it.kind == "remove":
        return f"- {it.name}  {it.old}  (remove)"
    if it.old is None or it.kind == "new-dep":
        return f"+ {it.name}  {it.new}  (new dependency)"
    return f"  {it.name}  {it.old} -> {it.new}"


def _preview_transaction(backend: "PackageBackend", ctx: "Context", *,
                         stale: bool = False) -> None:
    """Print the full set the upgrade would install (upgrades + new deps + any
    removals), grouped by source, before the `would run:` command lines.

    ``stale`` marks a preview built on metadata that could not be refreshed, so the
    summary says so rather than presenting a possibly-incomplete list as the answer.
    """
    out = ctx.output
    tx = backend.pending_transaction(ctx, sync=ctx.sync)
    if not tx.ok:
        detail = f" ({'; '.join(tx.notes)})" if tx.notes else " (query tool unavailable)"
        out.warn(f"could not determine the package transaction{detail}")
        # BLIND, not FAILED: nothing was attempted, so nothing broke — but the
        # pending list is unknown, and "no updates" would be a lie.
        out.summary_fail("could not determine what is pending — see the warning above.",
                         kind=BLIND)
        return
    for note in tx.notes:
        out.note(note)
    # The whole point of this action is the count, and the summary used to omit it
    # entirely — a run with 179 packages waiting signed off "nothing to report".
    qualifier = " (from stale metadata)" if stale else ""
    if not tx.items:
        out.ok("nothing to install — system is up to date.")
        if not stale:
            out.summary_add("no updates pending")
        return
    out.summary_add(f"{len(tx.items)} package(s) pending{qualifier}")

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
    if finding.severity >= Severity.CRITICAL:
        out.alert(line)
    elif finding.severity == Severity.MEDIUM:
        out.warn(line)
    else:
        out.note(line)


def _skipped_sources(ctx: "Context") -> set[str]:
    """Provider names whose "not present" notice is suppressed.

    ``[supplychain] skip_sources`` applies wherever the config is read. A
    ``[supplychain.hosts.<hostname>]`` table overrides it for one machine, for people
    who sync a single config around — note that ``fettle remote`` runs the zipapp on
    the *remote*, which reads the *remote's* config, so host tables only matter for
    configs you deliberately share.
    """
    import socket

    sc = getattr(getattr(ctx, "config", None), "supplychain", None) or {}
    hosts = sc.get("hosts") or {}
    entry = hosts.get(socket.gethostname()) if isinstance(hosts, dict) else None
    chosen = entry if isinstance(entry, dict) and "skip_sources" in entry else sc
    return {str(s) for s in (chosen.get("skip_sources") or [])}


def pkg_audit(backend: "PackageBackend", ctx: "Context") -> None:
    """Run every present Package Supply Chain provider and report normalized findings."""
    from . import reports
    from .supplychain.base import Severity

    out = ctx.output
    # `skip_sources` means "never check this here" — the provider is not run and its
    # absence is not reported, so an ecosystem you don't use costs you no output at
    # all (a tool can be installed but empty, which is why silencing only the absence
    # notice would not have helped).
    skip = _skipped_sources(ctx)
    sources = [p for p in backend.supply_chain_sources() if p.source not in skip]
    providers = [p for p in sources if p.is_present(ctx)]

    # Say what was NOT audited. Every provider is offered on every distro now, so a
    # silent omission would leave you unable to tell "flatpak is clean" from "flatpak
    # was never looked at".
    for p in sources:
        if p not in providers:
            out.note(f"[{p.source}] not present on this system — nothing to audit "
                     f"(silence it with [supplychain] skip_sources)")

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
        crit = sum(1 for f in findings if f.severity >= Severity.CRITICAL)
        msg = f"{len(findings)} supply-chain finding(s)"
        if crit:
            # A known-malicious package is not a to-do item. This is the one read-only
            # audit whose result should stop an automated run.
                        # FOUND: pkg-audit looked and found compromised packages. The audit worked.
            out.summary_fail(f"{msg}, {crit} CRITICAL — INVESTIGATE", kind=FOUND)
        else:
            # Findings are open items, not an accomplishment — a green tick over 46 of
            # them reads as "all good" at a glance, which is the opposite of the point.
            out.summary_warn(msg)

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
    "hardening_audit": lambda b, c: _hardening_audit(b, c),
    "pkg_integrity": lambda b, c: _pkg_integrity(b, c),
    "container_update": lambda b, c: _container_update(c),
    "sys_audit": lambda b, c: _sys_audit(c),
    "advisory_check": lambda b, c: _advisory_check(c),
    "compromise_check": lambda b, c: _compromise_check(b, c),
}


def _sys_audit(ctx: "Context") -> None:
    """Run every sys-audit category into the SHARED output.

    Honours ``--dry-run`` by not writing its report, which the standalone
    `fettle sys-audit` never had to think about — it has no --dry-run flag. As a
    pipeline action it is reachable through `--everything --dry-run`, where writing a
    report would be a change made by a command that promised none.

    `fettle sys-audit` builds its own `Output` and prints its own summary, which is
    right for a standalone run and wrong inside a pipeline — the digest would be
    printed twice and the exit code computed from only one of them. Here the same
    checks write into `ctx.output`, so their findings land in the one summary with
    everything else.

    `sys_audit.run()` sets `step_total` to its own category count and then numbers each
    category, so nesting it inside a pipeline that is already counting produced
    ``[3/9] … [10/9]`` — a running number against someone else's total, ending past it.
    Both halves of the counter are therefore saved and restored, and zeroed for the
    duration so the nested categories number themselves 1..n.
    """
    from .secure import audit as sysaudit
    from .secure.base import Scan

    out = ctx.output
    total, cur = out.step_total, out._step_cur
    scan = Scan(output=out, root=ctx.root,
                verbose=bool(getattr(out, "verbose", False)), config=ctx.config)
    try:
        out._step_cur = 0
        sysaudit.run(list(sysaudit.CATEGORIES), scan, summarize=False)
        if ctx.dry_run:
            out.note("report would be saved to ~/.fettle/reports/")
        else:
            sysaudit._write_report(scan, out)
    finally:
        out.step_total, out._step_cur = total, cur


def _advisory_check(ctx: "Context") -> None:
    """CVE tracking into the shared output.

    `Context` already carries everything `check.run` wants — config, user_home,
    sudo_user, output, dry_run, root — which is why the standalone entry point builds a
    SimpleNamespace with exactly those fields.
    """
    from .advisories import check
    check.run(ctx)


def _container_update(ctx: "Context") -> None:
    from . import containers
    containers.run(ctx)


def _hardening_audit(backend: "PackageBackend", ctx: "Context") -> None:
    from .hardening import audit
    audit.run(backend, ctx)


def _pkg_integrity(backend: "PackageBackend", ctx: "Context") -> None:
    from . import integrity
    integrity.run(backend, ctx)


def _aur_audit(ctx: "Context") -> None:
    from .aur import audit
    audit.run(ctx)


def _compromise_check(backend: "PackageBackend", ctx: "Context") -> None:
    from .compromise import audit
    audit.run(backend, ctx)


def run(actions: list[str], backend: "PackageBackend", ctx: "Context") -> None:
    out = ctx.output
    out.step_total = len(actions)
    for name in actions:
        out.section(TITLES.get(name, name))
        # Tag every summary line this handler produces with the command that produced
        # it — the name you would type to re-run just this one.
        out.current_action = name.replace("_", "-")
        handler = HANDLERS.get(name)
        if handler is None:
            out.note(f"'{name}' not yet implemented — coming in a later milestone")
            out.summary_warn("did NOT run — not implemented")
            out.current_action = ""
            continue
        before = out.summary_size()
        try:
            handler(backend, ctx)
        except NotImplementedError:
            out.note(f"'{name}' not yet implemented for the {backend.name} backend")
            out.summary_warn(f"did NOT run — the {backend.name} backend does not "
                             "implement it")
        finally:
            # Every action gets a line, so a fourteen-action sweep can be read as a
            # checklist. Without this, an action that found nothing said nothing, and a
            # summary of two lines gave no way to tell "twelve checks were clean" from
            # "twelve never ran" — which is the same question the `Not checked` block
            # answers for coverage, asked about the actions themselves.
            if out.summary_size() == before:
                out.summary_add("nothing to report")
            out.current_action = ""
    out.print_summary()
