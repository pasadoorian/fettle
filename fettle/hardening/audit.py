"""The `hardening-audit` action: scan → attribute → exclude → report.

Read-only and rootless. Reports a *long* list by default (every real deviation
from the distro's declared build baseline); the user prunes via ``[hardening]``
exclude lists in the config.
"""

from __future__ import annotations

from .. import command
from ..backends.base import Context, PackageBackend, Result
from .. import reports as freports
from . import baseline as bl
from . import engine, report, score


def run(backend: PackageBackend, ctx: Context) -> Result:
    out = ctx.output
    if not command.which("checksec"):
        # A note with an empty summary is how "not audited" comes to look like
        # "nothing wrong" — the exact confusion the analysed-zero guard below exists
        # to prevent, left unhandled in the easier case.
        # Distro-appropriate, because a wrong install hint wastes the reader's time:
        # on the RHEL family checksec is not in the base repositories at all, it comes
        # from EPEL. Measured on Rocky 9 — absent by default, present and working
        # (v2.5.0, 147 deviations) after `dnf install epel-release checksec`.
        hint = {"arch": "pacman -S checksec",
                "debian": "apt install checksec",
                "rhel": "dnf install epel-release && dnf install checksec"}.get(
                    backend.name, "install checksec")
        out.warn(f"checksec not found — binary hardening was NOT audited. "
                 f"Install it: {hint}")
        out.summary_warn("hardening audit did NOT run — checksec is not installed")
        return Result(ok=False)

    base = bl.resolve(backend.name, root=ctx.root)
    for note in base.notes:
        out.note(note)

    targets = engine.default_targets(ctx.root)
    if not targets:
        out.warn("no ELF binaries were found to scan — binary hardening was NOT "
                 "audited (an unexpected filesystem layout, or a container).")
        out.summary_warn("hardening audit did NOT run — no binaries found")
        return Result(ok=False)
    out.note(f"scanning {len(targets)} ELF binaries with checksec...")
    deviations, scan_stats = engine.scan(targets, baseline=base, root=ctx.root)

    pkgmap = backend.map_files_to_packages({d.path for d in deviations})
    excl = report.exclusions(ctx.config)
    scorer = score.Scorer.from_config(ctx.config)
    reports, filt_stats = report.apply(deviations, pkgmap, excl, scorer)

    if scan_stats.get("analyzed", 0) == 0:
        # The load-bearing guard. checksec producing nothing usable is
        # indistinguishable from a perfectly hardened system unless it is said out
        # loud — and that is not hypothetical: Fedora ships checksec **2.7.1**, whose
        # invocation and JSON schema differ from the 3.x this was written against, so
        # every binary silently fell out and the audit announced a clean bill of health
        # after examining nothing.
        out.warn(f"checksec analysed NONE of the {len(targets)} binaries found — the "
                 "hardening audit did NOT run. Its output could not be parsed "
                 "(version too old, or an unexpected format).")
        out.summary_warn("hardening audit did NOT run (checksec output unusable)")
        out.next_step("check `checksec --version`; fettle expects the 2.x or 3.x "
                      "interfaces")
    elif not reports:
        out.ok(f"no hardening deviations from the distro baseline "
               f"({scan_stats['analyzed']} binaries analysed).")
    else:
        for line in report.render_screen(reports):
            print(f"  {line}")
        # Deviations are open items, not an accomplishment. A green tick over
        # "1 Critical, 7 High, …" reads as a pass at a glance.
        #
        # Deliberately a warning and not a failure, unlike pkg-audit's CRITICAL: there
        # a critical finding means a known-malicious package is installed — rare and
        # actionable. Here "Critical" is the worst band of a scoring scheme, and every
        # real desktop has some, so failing the run would make `-H` exit non-zero
        # forever and teach people to ignore it.
        out.summary_warn(report.band_summary(reports))
        dropped = (filt_stats["excluded_check"] + filt_stats["excluded_package"]
                   + filt_stats["excluded_path"])
        if dropped:
            out.note(f"{dropped} deviation(s) hidden by your [hardening] exclude lists.")
        elif excl.is_empty():
            out.note("tip: prune this list via [hardening] exclude_checks/"
                     "exclude_packages/exclude_paths in your config.")

    if not ctx.dry_run:
        try:
            body = report.render(reports, filt_stats, base, scan_stats)
            data = report.to_dict(reports, filt_stats, base, scan_stats)
            path = freports.write_report("hardening-audit", "\n".join(body), ctx,
                                         data=data)
            out.note(f"full per-criterion matrix saved to {path}")
        except OSError as exc:
            out.warn(f"could not write hardening-audit report: {exc}")
    return Result()
