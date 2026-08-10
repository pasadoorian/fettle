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
    """The whole point of the skeleton milestone.

    With no groups built, the action must say so in three places — the not-checked
    block, the summary line, and by the absence of any success wording. A reader who
    sees only the summary must still know that nothing was examined.
    """
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    ctx.output.print_summary()
    text = capsys.readouterr().out

    assert "nothing was examined" in text
    assert "no check groups are implemented yet" in text
    # No wording that could be read as a pass. "clean" and "nothing to report" are the
    # two phrases the rest of fettle uses for a genuine all-clear.
    lowered = text.lower()
    assert "nothing to report" not in lowered
    assert "no compromise" not in lowered
    assert "clean" not in lowered


def test_summary_line_stands_alone(tmp_path):
    """The summary is the part people read, so it cannot need the block above it."""
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    warnings = ctx.output._warnings
    assert warnings, "an examined-nothing run must warn"
    assert any("nothing was examined" in w and "implemented" in w for w in warnings)


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


def test_unprivileged_run_names_what_it_could_not_reach(tmp_path, monkeypatch, capsys):
    """"Could not look" and "found nothing" are different sentences, always."""
    monkeypatch.setattr(caudit, "_is_root", lambda: False)
    ctx = _ctx(tmp_path)
    caudit.run(_Backend(), ctx)
    ctx.output.print_summary()
    text = capsys.readouterr().out
    assert "user-scope persistence" in text
    assert "need root" in text


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
