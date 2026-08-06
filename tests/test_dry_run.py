"""`--dry-run` promises to change nothing. This is the row that checks it means it.

The dangerous failures here are not cosmetic: a dry run that mutates has broken the one
guarantee that makes it safe to type on a production box.
"""

from unittest.mock import patch

import pytest

from fettle import runlog
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


def _ctx(**kw):
    return Context(output=Output(color=False), config=Config(), **kw)


# -- the run-log was deleting real history -------------------------------------
def test_dry_run_is_never_recorded():
    """Measured on a real tree: writing a run-log rotates the directory to `keep`, so a
    dry run DELETED older real run-logs — eleven went to nine after one invocation. The
    command whose whole promise is "change nothing" was destroying history."""
    assert runlog._skip(["-d", "--dry-run"])
    assert runlog._skip(["--dry-run"])
    assert runlog._skip(["remote", "host", "-a", "--dry-run"])


def test_a_real_run_is_still_recorded(monkeypatch):
    """The other half — the guard must not switch logging off altogether.

    FETTLE_TEST is set for the suite and short-circuits `_skip`, so it has to come out
    of the environment or this asserts nothing.
    """
    monkeypatch.delenv("FETTLE_TEST", raising=False)
    with patch.object(runlog, "is_active", return_value=False):
        assert not runlog._skip(["-d"])
        assert not runlog._skip(["-a"])
        assert runlog._skip(["-d", "--dry-run"])   # and the guard still holds


# -- the execution gate --------------------------------------------------------
def test_execute_runs_nothing_and_says_what_it_would_have(capsys):
    ctx = _ctx(dry_run=True)
    proc = ctx.execute(["pacman", "-Scc"])
    assert proc.returncode == 0
    out = "".join(capsys.readouterr())
    assert "would run: pacman -Scc" in out


def test_confirm_never_prompts_under_dry_run():
    """A prompt in a preview is both wrong and a hang risk in automation."""
    ctx = _ctx(dry_run=True)
    with patch("builtins.input", side_effect=AssertionError("prompted under --dry-run")):
        assert ctx.confirm("remove everything?") is False


def test_select_returns_nothing_under_dry_run():
    ctx = _ctx(dry_run=True)
    with patch("builtins.input", side_effect=AssertionError("prompted under --dry-run")):
        assert ctx.select(["a", "b"], prompt="purge") == []


@pytest.mark.parametrize("as_user", [None, "paulda"])
def test_the_gate_holds_for_dropped_privileges_too(as_user, capsys):
    ctx = _ctx(dry_run=True)
    with patch("fettle.command.run", side_effect=AssertionError("ran under --dry-run")):
        ctx.execute(["rm", "-rf", "/tmp/x"], as_user=as_user)
    assert "would run" in "".join(capsys.readouterr())


def test_a_failed_command_list_stays_empty_under_dry_run():
    """Nothing ran, so nothing can have failed — and the exit code keys off this."""
    ctx = _ctx(dry_run=True)
    ctx.execute(["false"])
    assert ctx.failed_commands == []


# -- a report is a change too --------------------------------------------------
def test_pkg_integrity_writes_no_report_under_dry_run(tmp_path, capsys):
    """Measured: `-V --dry-run` wrote two files while `-P` and `-A` wrote none, so this
    one was the outlier rather than the convention."""
    from fettle import integrity

    written = []

    class FakeBackend:
        name = "fake"

        def verify_integrity(self, scan):
            scan.records.append({"category": "c", "sub": "s", "label": "l",
                                 "value": "v", "level": "ok", "blind": False})

    ctx = _ctx(dry_run=True)
    ctx.user_home = tmp_path
    with patch("fettle.reports.write_report",
               side_effect=lambda *a, **k: written.append(a) or tmp_path / "x.txt"):
        integrity.run(FakeBackend(), ctx)
    assert written == [], "wrote a report under --dry-run"
    assert "would be saved" in "".join(capsys.readouterr())


def test_pkg_integrity_does_write_a_report_on_a_real_run(tmp_path):
    """The guard must not switch reporting off altogether."""
    from fettle import integrity

    written = []

    class FakeBackend:
        name = "fake"

        def verify_integrity(self, scan):
            scan.records.append({"category": "c", "sub": "s", "label": "l",
                                 "value": "v", "level": "ok", "blind": False})

    ctx = _ctx(dry_run=False)
    ctx.user_home = tmp_path
    with patch("fettle.reports.write_report",
               side_effect=lambda *a, **k: written.append(a) or tmp_path / "x.txt"):
        integrity.run(FakeBackend(), ctx)
    assert written, "a real run must still write its report"


def test_sys_audit_writes_no_report_under_dry_run(capsys):
    """It has no --dry-run flag of its own, but as a pipeline action it is reachable
    through `--everything --dry-run`."""
    from fettle import actions as A

    ctx = _ctx(dry_run=True)
    with patch("fettle.secure.audit.run"), \
         patch("fettle.secure.audit._write_report") as wr:
        A._sys_audit(ctx)
    assert not wr.called
    assert "would be saved" in "".join(capsys.readouterr())
