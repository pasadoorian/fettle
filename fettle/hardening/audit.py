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
        out.note("checksec not found (install it: pacman -S checksec / "
                 "apt install checksec); skipping hardening audit.")
        return Result()

    base = bl.resolve(backend.name, root=ctx.root)
    for note in base.notes:
        out.note(note)

    targets = engine.default_targets(ctx.root)
    if not targets:
        out.note("no ELF binaries found to scan.")
        return Result()
    out.note(f"scanning {len(targets)} ELF binaries with checksec...")
    deviations, scan_stats = engine.scan(targets, baseline=base, root=ctx.root)

    pkgmap = backend.map_files_to_packages({d.path for d in deviations})
    excl = report.exclusions(ctx.config)
    scorer = score.Scorer.from_config(ctx.config)
    reports, filt_stats = report.apply(deviations, pkgmap, excl, scorer)

    if not reports:
        out.ok("no hardening deviations from the distro baseline.")
    else:
        for line in report.render_screen(reports):
            print(f"  {line}")
        out.summary_add(report.band_summary(reports))
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
            path = freports.write_report("hardening-audit", "\n".join(body), ctx)
            out.note(f"full per-criterion matrix saved to {path}")
        except OSError as exc:
            out.warn(f"could not write hardening-audit report: {exc}")
    return Result()
