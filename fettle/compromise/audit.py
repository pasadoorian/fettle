"""The `compromise-check` action — is there evidence something is already here?

Read-only, and **read-only is not the same as rootless**: most of what this action
wants to read is root-only, which is the distinction `cli._READ_ONLY_BUT_NEEDS_ROOT`
exists to carry. It is classified there alongside `sys-audit` and `pkg-integrity`, so
the pipeline elevates once up front rather than prompting partway through.

Unprivileged it still runs and still answers — the system-scope persistence checks
read `/etc/systemd/system` and the package database, both of which an ordinary user
can read — and it says, in its own words, which half of the question it could not
reach. That sentence is the whole point of the action degrading rather than refusing:
*"user-scope persistence for 3 accounts was not checked"* is a different statement
from *"nothing found"*, and a reader must never have to guess which one they got.
"""

from __future__ import annotations

import os

from ..backends.base import Context, PackageBackend, Result
from ..output import BLIND, FOUND
from .. import reports as freports
from ..hardening.axes import render as arender
# The package is imported as a module rather than `from . import GROUP_NAMES`, which
# would bind the tuple at import time: the registry grows one entry per milestone, and
# a stale binding would leave this module describing a set of groups that differs from
# the one `run_all` actually iterates — a coverage statement that disagrees with the
# coverage, which is the one kind of bug this action cannot afford.
from . import CRITICAL, HIGH
from .. import compromise as _pkg
from .users import real_users


def _is_root() -> bool:
    # Local rather than imported from `cli`: importing it would close a cycle
    # (cli -> actions -> here -> cli), and `secure.base`, `backends.rhel` and
    # `hardening.engine` each already ask the question this way.
    return os.geteuid() == 0


def _scope(ctx: Context) -> None:
    """Say how many accounts are in scope, before saying what was found.

    Ordered first deliberately. A coverage statement that arrives after the findings
    reads as a footnote to a verdict; arriving before them it is part of the verdict.

    **It no longer announces what root would add**, and that removal is the point. The
    first version printed a blanket "user-scope persistence, at jobs and the eBPF
    surface need root" on every unprivileged run — which was true when nothing was
    implemented and became a lie the moment the persistence group landed, because those
    checks now run and mostly succeed without root. Each check reports its own
    blindness, naming the directory it could not open; a second, coarser claim
    alongside them could only ever disagree with the first.
    """
    out = ctx.output
    scan = real_users(ctx.root, readable_only=not _is_root())
    note = scan.note()
    if note:
        out.note(note)


def run(backend: PackageBackend, ctx: Context) -> Result:
    out = ctx.output

    # A name matching no group disables nothing. Silently ignoring the typo would
    # leave a user believing they had switched a check off — and, worse here than in
    # `-H`, believing a *rootkit* check was off when it was running, or on when it was
    # not. Either direction is a lie about coverage.
    known = ", ".join(_pkg.GROUP_NAMES) or "none yet"
    for name in _pkg.unknown_disabled(ctx.config):
        out.warn(f"[compromise] disable_checks: {name!r} is not a check group "
                 f"(known: {known}) — nothing was disabled")

    _scope(ctx)

    results = _pkg.run_all(backend, ctx)

    # No groups built yet (M1.1 ships the action; the checks land in M1.2 onward).
    # This branch must never print an "all clear": an action that examined nothing and
    # rendered like a clean run is the exact failure this project's QA pass was about,
    # and it would be at its most dangerous in the action whose subject is a rootkit.
    if not results:
        off = bool(_pkg.GROUP_NAMES) and \
            set(_pkg.GROUP_NAMES) <= _pkg.disabled(ctx.config)
        why = ("every check group is disabled by [compromise] disable_checks" if off
               else "no check groups are implemented yet — this release ships the "
                    "action and its plumbing, not its checks")
        out.not_checked("compromise indicators", why)
        # A warning rather than a failure, matching how the pipeline already reports an
        # action with no handler ("did NOT run — not implemented"). The state describes
        # fettle, not the machine, and failing the run would make `--everything` red for
        # a reason that has nothing to do with the host it just swept. The summary line
        # has to stand alone, because the summary is the part people read.
        out.summary_warn(f"nothing was examined — {why.split(' — ')[0]}")
        return Result()

    for line in arender.screen(results):
        print(f"  {line}")
    for res in results:
        for what, why, package in res.blind:
            out.not_checked(what, why, package)

    total: dict[str, int] = {}
    for res in results:
        for sev, n in res.tally().items():
            total[sev] = total.get(sev, 0) + n

    # Coverage travels with the verdict, always. `actions.run` fills an empty summary
    # with "nothing to report", so a run where most checks were blind and one trivial
    # one succeeded would summarise as clean — the screen says "plus N not checked" and
    # the summary would not. The summary is what a fifteen-action sweep is read from, so
    # it is the line that has to carry both halves.
    blind_count = sum(len(r.blind) for r in results)
    unable = ", ".join(r.name for r in results if not r.ran)
    coverage = f"; {blind_count} check(s) could not look" if blind_count else ""

    if any(total.values()):
        named = ", ".join(r.name for r in results if r.findings)
        parts = [f"{total[s]} {s}" for s in arender.SEVERITY_ORDER if total.get(s)]
        line = f"{named} — {', '.join(parts)}{coverage}"
        # **The exit status turns on severity, not on the existence of findings.**
        #
        # Every real machine has some. The reference desktop has four — two unowned
        # vendor units, an unowned cron entry timeshift wrote itself, and a self-updating
        # AppImage — and none is worth failing a run over. Exiting non-zero on any
        # finding would make `-M` red forever and teach people to ignore it, which is the
        # mistake `-H` deliberately avoids for the same reason.
        #
        # High and Critical are different: those are the two bands that also print the
        # preservation banner, so the exit status and the banner agree about what "stop
        # and look at this" means. `kind=FOUND` follows `advisory-check`, which does the
        # same for a Critical CVE with a fix available — the check worked, and the thing
        # it found is what needs attention.
        if total.get(CRITICAL) or total.get(HIGH):
            out.summary_fail(line, kind=FOUND)
        else:
            out.summary_warn(line)
        _preserve_banner(out, total)
    elif not any(r.ran for r in results):
        # Nothing examined at all. The strongest form of the invariant — and a genuine
        # failure of the run rather than a finding, so it fails as BLIND: the summary
        # must never let "could not look" pass for "looked and was happy".
        out.summary_fail(f"nothing was examined — {unable or 'every check'} could not "
                         f"look, see above", kind=BLIND)
    elif blind_count:
        # Something ran and found nothing, but not everything could look. "Nothing to
        # report" alone would claim coverage this run did not have.
        out.summary_warn(f"nothing found, but {blind_count} check(s) could not look — "
                         f"see above")

    if not ctx.dry_run:
        try:
            body = ["COMPROMISE INDICATORS", "=" * 21, "",
                    "Anomalies, not verdicts. Each finding below names what is unusual "
                    "and what the ordinary explanation would be. Investigate before "
                    "changing anything: rebooting, deleting the artifact or "
                    "reinstalling the package destroys the evidence.", ""]
            body += arender.report_body(results)
            path = freports.write_report(
                "compromise-check", "\n".join(body), ctx,
                data={"groups": arender.to_dict(results)})
            out.note(f"full findings saved to {path}")
        except OSError as exc:
            out.warn(f"could not write compromise-check report: {exc}")
    return Result()


def _preserve_banner(out, total: dict[str, int]) -> None:
    """Printed once, above High or Critical findings only.

    Deliberately not shown for Medium and Low. Every real machine has some unowned
    units — wopr's two runZero agent services are the working example — and a
    preservation warning over an explicable finding is how a genuine one gets ignored.
    """
    if not (total.get(CRITICAL) or total.get(HIGH)):
        return
    out.warn("Before you change anything: do not reboot, do not delete the artifact, "
             "and do not reinstall the package. Timestamps, open file descriptors and "
             "unlinked inodes are the evidence, and each of those destroys them. If "
             "you want a full collection first, UAC's `ir_triage` profile is built "
             "for this (github.com/tclahr/uac).")
