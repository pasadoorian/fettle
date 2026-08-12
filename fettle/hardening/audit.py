"""The `hardening-audit` action — is this system hardened, along several axes?

Read-only, and rootless wherever it can be. The oldest and largest axis is the
**binary** one (scan → attribute → exclude → report against the distro's declared
build baseline); the rest live in :mod:`fettle.hardening.axes` and each answers one
independent question about the running system.

Axes are independent on purpose. This action used to be the binary scan and nothing
else, which meant a missing checksec returned ``Result(ok=False)`` and the user got
*no* hardening answer rather than the four-fifths that needed no external tool at all.
Now a missing checksec costs one axis and says so, and the others still run.

Reports a *long* list by default; the user prunes via ``[hardening]`` exclude lists.
Nothing here sets a non-zero exit status — see the band-summary comment below.
"""

from __future__ import annotations

from .. import command
from ..backends.base import Context, PackageBackend, Result
from .. import reports as freports
from . import axes
from .axes import render as arender
from . import baseline as bl
from . import engine, report, score


class _Binary:
    """The binary axis's results, or the reason there are none."""

    def __init__(self, reports=None, filt_stats=None, base=None, scan_stats=None):
        self.reports = reports
        self.filt_stats = filt_stats
        self.base = base
        self.scan_stats = scan_stats

    @property
    def ran(self) -> bool:
        return self.scan_stats is not None


def _binary_axis(backend: PackageBackend, ctx: Context) -> _Binary:
    """checksec every ELF on the box and score what is missing its build hardening."""
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
        out.not_checked("binary hardening (checksec)",
                        f"checksec is not installed — install it: {hint}")
        return _Binary()

    base = bl.resolve(backend.name, root=ctx.root)
    for note in base.notes:
        out.note(note)

    targets = engine.default_targets(ctx.root)
    if not targets:
        out.not_checked("binary hardening (checksec)",
                        "no ELF binaries were found to scan — an unexpected "
                        "filesystem layout, or a container")
        return _Binary()
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
        out.not_checked("binary hardening (checksec)",
                        f"checksec analysed NONE of the {len(targets)} binaries found "
                        f"— its output could not be parsed (version too old, or an "
                        f"unexpected format)")
        out.next_step("check `checksec --version`; fettle expects the 2.x or 3.x "
                      "interfaces")
        return _Binary()

    if not reports:
        out.ok(f"no hardening deviations from the distro baseline "
               f"({scan_stats['analyzed']} binaries analysed).")
    else:
        # Through `out.detail`, not `print`: the axes table below already honours
        # `--quiet`, and one half of an action's output obeying the flag while the
        # other ignores it is worse than neither doing so.
        out.detail(f"Binary hardening: {report.band_summary(reports)}")
        for line in report.render_screen(reports):
            out.detail(f"  {line}")
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
    return _Binary(reports, filt_stats, base, scan_stats)


def run(backend: PackageBackend, ctx: Context) -> Result:
    out = ctx.output

    # A name that matches no axis disables nothing, and a security check that silently
    # stayed on when the user asked for it off is the same class of surprise as one
    # that silently stayed off.
    for name in axes.unknown_disabled(ctx.config):
        out.warn(f"[hardening] disable_axes: {name!r} is not an axis "
                 f"(known: {', '.join(axes.ALL_AXIS_NAMES)}) — nothing was disabled")

    off = axes.disabled(ctx.config)
    binary = _Binary() if "binary" in off else _binary_axis(backend, ctx)

    results = axes.run_all(backend, ctx)
    excl = report.exclusions(ctx.config)
    hidden = axes.apply_excludes(results, excl.checks, excl.paths)
    for line in arender.screen(results):
        out.detail(line)
    for res in results:
        for what, why, package in res.blind:
            out.not_checked(what, why, package)
    if hidden:
        out.note(f"{hidden} finding(s) hidden by your [hardening] exclude lists.")

    total = {}
    for res in results:
        for sev, n in res.tally().items():
            total[sev] = total.get(sev, 0) + n
    if any(total.values()):
        named = ", ".join(r.name for r in results if r.findings)
        parts = [f"{total[s]} {s}" for s in axes.SEVERITY_ORDER if total.get(s)]
        # Leads with the axis names because the summary already carries the action
        # name, and "hardening-audit: system hardening: …" says it twice. Naming the
        # axes also keeps this line distinguishable from the binary axis's band line
        # directly above it, which otherwise opens with counts in the same shape.
        # Warning, not failure — the same reasoning as the binary bands above, and the
        # answer Paul gave when asked directly: -H must stay usable in automation.
        out.summary_warn(f"{named} — {', '.join(parts)}")

    if not ctx.dry_run:
        try:
            body = (report.render(binary.reports, binary.filt_stats, binary.base,
                                  binary.scan_stats)
                    if binary.ran else ["BINARY HARDENING", "----------------",
                                        "not checked — see the run output for why"])
            body = list(body) + arender.report_body(results)
            data = (report.to_dict(binary.reports, binary.filt_stats, binary.base,
                                   binary.scan_stats)
                    if binary.ran else {"scan": {}, "packages": []})
            data["axes"] = arender.to_dict(results)
            path = freports.write_report("hardening-audit", "\n".join(body), ctx,
                                         data=data)
            out.note(f"full per-criterion matrix saved to {path}")
        except OSError as exc:
            out.warn(f"could not write hardening-audit report: {exc}")
    return Result()
