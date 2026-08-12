"""The `compromise-check` skeleton — M1.1.

Two things are being pinned here, and neither is about finding rootkits yet.

**The action must never render like a clean run when it examined nothing.** That is the
governing invariant applied to the action where getting it wrong would be worst: a
rootkit check that prints an all-clear over an unasked question is the single most
harmful output this project could produce. The skeleton has no check groups, so every
run is currently that case, which makes it exactly the right time to nail it down.

**Privilege classification.** `compromise-check` is read-only *and* needs root — the
same pair as `sys-audit` and `pkg-integrity`. Getting that wrong has happened once in
each direction already (`-D` prompting for a password to read a CVE cache; `sys-audit`
sitting outside the read-only set while being read-only), so both memberships are
asserted rather than assumed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fettle import compromise
from fettle.backends.base import Context
from fettle.compromise import audit as caudit
from fettle.compromise.users import real_users
from fettle.config import Config
from fettle.output import Output


class _Backend:
    name = "arch"
    supported: set[str] = set()

    def supports(self, action):
        return True


def _ctx(tmp_path: Path, **cfg) -> Context:
    return Context(output=Output(color=False), config=Config(**cfg), root=tmp_path,
                   user_home=tmp_path, dry_run=True)


# --------------------------------------------------------------------------- wiring


def test_registered_everywhere_it_has_to_be():
    from fettle.actions import HANDLERS, TITLES
    from fettle.backends.base import PackageBackend
    from fettle.cli import ACTION_NAMES

    assert "compromise_check" in ACTION_NAMES
    assert "compromise_check" in HANDLERS
    assert "compromise_check" in TITLES
    # Distro-agnostic like sys_audit: it reads systemd, /proc and the package database
    # through each backend's existing mapper, so a backend that forgot to opt in would
    # silently drop the action rather than fail.
    assert "compromise_check" in PackageBackend.UNIVERSAL_ACTIONS


def test_runs_last_under_everything():
    """An update removes a vulnerable package; it does not remove an implant.

    Running it before `update` would describe the system the user booted rather than
    the one they are being left with — the same reason `advisory-check` is last today.
    """
    from fettle.cli import EVERYTHING_ACTIONS

    assert EVERYTHING_ACTIONS[-1] == "compromise_check"
    assert EVERYTHING_ACTIONS.index("advisory_check") < \
        EVERYTHING_ACTIONS.index("compromise_check")


def test_read_only_and_needs_root():
    from fettle.cli import NO_ROOT_ACTIONS, READ_ONLY_ACTIONS

    assert "compromise_check" in READ_ONLY_ACTIONS      # it changes nothing
    assert "compromise_check" not in NO_ROOT_ACTIONS    # ...and still needs root


def test_not_in_the_default_set():
    """Opt-in, or reachable through `--everything` — never a surprise in `fettle`."""
    from fettle.cli import DEFAULT_ACTIONS

    assert "compromise_check" not in DEFAULT_ACTIONS


# ------------------------------------------------------------------- the invariant


def test_examining_nothing_never_reads_as_clean(tmp_path, capsys):
    """The invariant, in the action where breaking it would be worst.

    An empty root gives every group nothing to read, so all of them come back blind.
    The run must say so on screen *and* in the summary, and must use none of the
    wording fettle uses elsewhere for a genuine all-clear.

    This caught a real bug when the first check group landed: `actions.run` fills an
    empty summary with "nothing to report", so a fully-blind compromise-check
    summarised itself as clean while the screen above it said "not checked".
    """
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    ctx.output.print_summary()
    text = capsys.readouterr().out

    assert "could not look" in text
    assert "not checked" in text
    lowered = text.lower()
    assert "no compromise" not in lowered
    assert "clean" not in lowered
    # A per-group "nothing to report" tally line is fine and true; what must never
    # appear is the *summary* claiming it, since that is the line a sweep is read from.
    summary = text.split("▸ Summary", 1)[1]
    assert "nothing to report" not in summary.lower()


def test_summary_line_stands_alone(tmp_path):
    """The summary is the part people read, so it cannot need the block above it."""
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    warnings = ctx.output._warnings
    assert warnings, "a run that could not look must warn"
    assert any("could not look" in w for w in warnings)


def test_a_group_that_found_nothing_is_allowed_to_say_so(tmp_path, monkeypatch):
    """The mirror of the test above, and just as necessary.

    "Could not look" must not render as "found nothing" — but "looked and found
    nothing" must not be dressed up as blindness either. A group that genuinely ran
    and was clean adds no warning, and the pipeline's own "nothing to report" is then
    the correct summary.
    """
    from fettle.compromise import CheckResult

    class _Clean:
        @staticmethod
        def run(backend, ctx):
            return CheckResult(name="persistence", title="Boot persistence", checked=482)

    monkeypatch.setattr(compromise, "_module", lambda name: _Clean)
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    assert ctx.output._warnings == []


def test_a_group_that_raises_is_blind_not_clean(tmp_path, monkeypatch):
    """A crashed check must never be indistinguishable from a check that passed."""
    class _Boom:
        @staticmethod
        def run(backend, ctx):
            raise RuntimeError("chkproc fell over")

    monkeypatch.setattr(compromise, "GROUP_NAMES", ("persistence",))
    monkeypatch.setattr(compromise, "_module", lambda name: _Boom)

    results = compromise.run_all(_Backend(), _ctx(tmp_path))
    assert len(results) == 1
    assert results[0].findings == []
    assert results[0].blind, "a raising group must report blindness"
    assert "chkproc fell over" in results[0].blind[0][1]
    assert not results[0].ran


# ------------------------------------------------------------------------- config


def test_disable_checks_typo_is_reported_not_swallowed(tmp_path, monkeypatch, capsys):
    """Believing a rootkit check is off when it is on is as bad as the reverse."""
    monkeypatch.setattr(compromise, "GROUP_NAMES", ("persistence",))
    ctx = _ctx(tmp_path, compromise={"disable_checks": ["persistance"]})
    assert compromise.unknown_disabled(ctx.config) == ["persistance"]

    caudit.run(_Backend(), ctx)
    text = capsys.readouterr().err          # warnings go to stderr
    assert "persistance" in text and "nothing was disabled" in text
    assert "persistence" in text, "the warning should name the groups that DO exist"


def test_disable_checks_normalises_and_ignores_junk(tmp_path):
    ctx = _ctx(tmp_path, compromise={"disable_checks": ["  Kernel_Loader ", ""]})
    assert compromise.disabled(ctx.config) == {"kernel-loader"}
    assert compromise.disabled(Config()) == set()
    assert compromise.disabled(Config(compromise={"disable_checks": "nope"})) == set()


# -------------------------------------------------------------------------- users


def test_real_users_skips_accounts_that_cannot_log_in(tmp_path, monkeypatch):
    """wopr has 32 `nixbld*` accounts pointing at /var/empty.

    Walking all of them to examine one real user is not merely wasteful — it makes the
    coverage count a lie, which is the same failure as a clean result nobody can audit.
    """
    import pwd

    home = tmp_path / "home" / "real"
    home.mkdir(parents=True)
    entries = [
        pwd.struct_passwd(("root", "x", 0, 0, "", "/root", "/bin/bash")),
        pwd.struct_passwd(("daemon", "x", 2, 2, "", "/", "/usr/sbin/nologin")),
        pwd.struct_passwd(("real", "x", 1000, 1000, "", "/home/real", "/bin/bash")),
        pwd.struct_passwd(("gone", "x", 1001, 1001, "", "/home/gone", "/bin/bash")),
        *[pwd.struct_passwd((f"nixbld{i}", "x", 1100 + i, 1100 + i, "",
                             "/var/empty", "/usr/sbin/nologin")) for i in range(32)],
    ]
    monkeypatch.setattr(pwd, "getpwall", lambda: entries)

    scan = real_users(tmp_path)
    assert [u.name for u in scan.users] == ["real"]
    # root is handled by the system-scope checks; `daemon` is below the UID floor and
    # is not a "skip" at all. The 32 nixbld accounts and the missing home are.
    assert scan.skipped == {"cannot log in": 32, "no home directory": 1}
    assert "32 cannot log in" in scan.note()
    assert "1 user account(s) examined" in scan.note()


def test_user_scan_note_is_empty_when_nothing_was_skipped(tmp_path, monkeypatch):
    import pwd

    home = tmp_path / "home" / "only"
    home.mkdir(parents=True)
    monkeypatch.setattr(pwd, "getpwall", lambda: [
        pwd.struct_passwd(("only", "x", 1000, 1000, "", "/home/only", "/bin/bash"))])
    assert real_users(tmp_path).note() == ""


@pytest.mark.skipif(os.geteuid() == 0, reason="chmod 000 does not apply to root")
def test_blindness_is_named_by_the_check_that_hit_it(tmp_path, monkeypatch, capsys):
    """"Could not look" and "found nothing" are different sentences, always.

    The first version of this printed a blanket "user-scope persistence, at jobs and the
    eBPF surface need root" on every unprivileged run. That was true while nothing was
    implemented and became false the moment a real check landed — those checks run, and
    mostly succeed, without root. Each check now names the directory *it* could not
    open, which is both more useful and incapable of disagreeing with the run.
    """
    monkeypatch.setattr(caudit, "_is_root", lambda: False)
    spool = tmp_path / "var/spool/cron"
    spool.mkdir(parents=True)
    (spool / "root").write_text("0 3 * * * /usr/bin/thing\n")
    spool.chmod(0o000)
    try:
        ctx = _ctx(tmp_path)
        caudit.run(_Backend(), ctx)
        ctx.output.print_summary()
        text = capsys.readouterr().out
    finally:
        spool.chmod(0o755)

    assert "var/spool/cron" in text, "the specific directory is named"
    assert "could not be read" in text
    # The advice must match what fettle actually does: `-M` elevates itself, so the
    # only way to be reading this line is a --dry-run, and telling the reader to
    # "re-run with sudo" sends them to solve a problem they do not have.
    assert "fettle elevates for you" in text
    assert "sudo" not in text
    # And no blanket claim about things that were checked successfully.
    assert "user-scope persistence, at jobs" not in text


def test_root_run_does_not_claim_a_privilege_gap(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(caudit, "_is_root", lambda: True)
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    ctx.output.print_summary()
    assert "need root" not in capsys.readouterr().out


# ------------------------------------------------------------------------ reports


def test_dry_run_writes_no_report(tmp_path, monkeypatch):
    """`--dry-run` promises no changes, and a report file is a change."""
    monkeypatch.setattr(compromise, "GROUP_NAMES", ("persistence",))
    written = []
    monkeypatch.setattr("fettle.reports.write_report",
                        lambda *a, **k: written.append(a) or Path("x"))
    ctx = _ctx(tmp_path)      # dry_run=True
    caudit.run(_Backend(), ctx)
    assert written == []


@pytest.mark.parametrize("severity,banner", [("Low", False), ("Medium", False),
                                             ("High", True), ("Critical", True)])
def test_preservation_banner_only_above_medium(severity, banner, capsys):
    """Every real machine has some unowned units — wopr has two, and they are fine.

    A do-not-touch-anything warning over an explicable Medium is how the warning that
    matters gets ignored.
    """
    caudit._preserve_banner(Output(color=False), {severity: 1})
    printed = capsys.readouterr().err
    assert ("do not reboot" in printed) is banner
    if banner:
        # The escalation is named, not implied: someone who wants a full collection
        # before touching the box should not have to go and find the tool.
        assert "ir_triage" in printed


# ------------------------------------------------------------ dashboard (M4.2)


def _compromise_report(base, host, ts, groups):
    import json
    d = base / ".fettle/reports" / host
    d.mkdir(parents=True, exist_ok=True)
    (d / f"compromise-check-{ts}.json").write_text(json.dumps(
        {"schema": "fettle.report/1", "tool": "compromise-check", "host": host,
         "timestamp": ts, "fettle_version": "1.5.0", "data": {"groups": groups}}))


def _group(name, findings=(), not_checked=()):
    return {"axis": name, "title": name.capitalize(), "checked": 10,
            "not_applicable": "", "tally": {}, "findings": list(findings),
            "not_checked": [{"what": w, "why": "", "package": ""} for w in not_checked],
            "notes": []}


def _finding(severity, subject="thing", summary="something"):
    return {"check": "x", "subject": subject, "severity": severity,
            "summary": summary, "detail": summary, "fix": "look at it"}


def test_the_dashboard_reads_the_groups_key(tmp_path):
    """`hardening-audit` stores `axes` and `compromise-check` stores `groups`.

    The payload is the same shape — both come from `axes.render.to_dict` — so the
    dashboard reads either. Renaming one would make every report already on disk
    unreadable, and stored reports are forever.
    """
    from fettle import htmlreport

    data = {"groups": [_group("persistence", [_finding("High", "evil.service")])]}
    assert len(htmlreport._axis_findings(data)) == 1
    assert "evil.service" in htmlreport._render_axes(data)


def test_a_critical_compromise_finding_dominates_the_host_verdict(tmp_path):
    """Not capped at Medium, unlike the hardening bands.

    That cap exists because every desktop has Critical-band packages. This is the
    opposite kind of thing: a host running something nobody installed must not sit on a
    fleet page looking like a host with a stale package.
    """
    from fettle import htmlreport

    _compromise_report(tmp_path, "h1", "20260812-010101",
                       [_group("kernel", [_finding("Critical", "pid 31337",
                                                   "running from memory")])])
    host = htmlreport.collect(tmp_path / ".fettle")["h1"]
    problems = htmlreport._host_problems(host, stale_days=99999)
    assert problems, "a Critical compromise finding must reach the card"
    assert problems[0][0] == 4, "and outrank everything else on it"
    assert "compromise indicator" in problems[0][1]


def test_a_blind_compromise_run_is_not_silence_on_the_fleet_page(tmp_path):
    """A host whose rootkit checks could not run is not a host with nothing to report.

    At fleet scale that is exactly the difference nobody notices.
    """
    from fettle import htmlreport

    _compromise_report(tmp_path, "h2", "20260812-010101",
                       [_group("kernel", not_checked=["pinned eBPF objects"])])
    host = htmlreport.collect(tmp_path / ".fettle")["h2"]
    problems = htmlreport._host_problems(host, stale_days=99999)
    assert any("could not look" in p for _, p in problems)


def test_a_blind_compromise_report_is_not_dropped_as_empty(tmp_path):
    """Dropping it would turn "I could not see" into silence — the same lie the
    action refuses to tell on the command line."""
    from fettle import htmlreport

    entry = {"tool": "compromise-check",
             "data": {"groups": [_group("kernel", not_checked=["/sys/fs/bpf"])]}}
    assert not htmlreport._is_empty(entry)


def test_a_compromise_report_with_nothing_at_all_is_empty(tmp_path):
    from fettle import htmlreport

    entry = {"tool": "compromise-check", "data": {"groups": [_group("kernel")]}}
    assert htmlreport._is_empty(entry)


# --------------------------------------------------------------- exit status (M4.1)


def test_high_findings_fail_the_run_and_medium_ones_do_not(tmp_path, monkeypatch):
    """The exit status turns on severity, not on the existence of findings.

    The reference machine has four findings and none is worth failing over — exiting
    non-zero on any of them would make `-M` red forever and teach people to ignore it,
    which is the mistake `-H` deliberately avoids. High and Critical are the two bands
    that also print the preservation banner, so the status and the banner agree.
    """
    from fettle.compromise import CheckResult, Finding

    def _with(severity):
        class _G:
            @staticmethod
            def run(backend, ctx):
                res = CheckResult(name="persistence", title="P", checked=5)
                res.findings.append(Finding(check="x", subject="s",
                                            detail="d — why", severity=severity))
                return res
        monkeypatch.setattr(compromise, "_module", lambda name: _G)
        ctx = _ctx(tmp_path)
        caudit.run(_Backend(), ctx)
        return ctx.output

    assert not _with("Medium").had_failures, "an inventory is not a failure"
    assert not _with("Low").had_failures
    assert _with("High").had_failures, "High is where the banner fires, and the status"
    assert _with("Critical").had_failures


def test_a_wholly_blind_run_fails_as_blind_not_as_a_finding(tmp_path, monkeypatch):
    """The three kinds of bad news stay distinguishable for automation.

    A run that examined *nothing* is a failed run, and it is recorded as BLIND rather
    than FOUND — so a script can tell "could not read /sys/fs/bpf" from "found a
    rootkit" even though fettle's documented convention exits 1 for both.
    """
    from fettle.compromise import CheckResult
    from fettle.output import BLIND, FOUND

    class _Blind:
        @staticmethod
        def run(backend, ctx):
            return CheckResult(name="kernel", title="K",
                               blind=[("everything", "no privilege", "")])

    monkeypatch.setattr(compromise, "_module", lambda name: _Blind)
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    assert ctx.output.had_failures
    assert ctx.output.failures_of(BLIND), "recorded as could-not-look"
    assert not ctx.output.failures_of(FOUND), "and not as a finding"


def test_partial_blindness_warns_rather_than_failing(tmp_path, monkeypatch):
    """`bpftool` being absent is a permanent state on most machines.

    Failing on it would make `-M` red forever for a reason the user may never intend to
    change — the "red forever" trap `-H` avoids. Every other action treats `not_checked`
    the same way: it is reported loudly and does not set the exit status. Only a run
    that examined *nothing* fails.
    """
    from fettle.compromise import CheckResult

    class _Partial:
        @staticmethod
        def run(backend, ctx):
            return CheckResult(name="kernel", title="K", checked=40,
                               blind=[("pinned eBPF objects", "needs root", "")])

    monkeypatch.setattr(compromise, "_module", lambda name: _Partial)
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    assert not ctx.output.had_failures
    assert any("could not look" in w for w in ctx.output._warnings), "but it is said"
