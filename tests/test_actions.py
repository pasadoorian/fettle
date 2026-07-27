import time
from unittest.mock import patch

import pytest

from fettle import actions
from fettle.backends.arch import ArchBackend
from fettle.backends.base import Context
from fettle.command import Proc
from fettle.config import Config
from fettle.output import Output
from fettle.cli import READ_ONLY_ACTIONS


def _ctx(**kw):
    return Context(output=Output(color=False), config=Config(), dry_run=True, **kw)


def test_implemented_action_shows_title_and_would_run(capsys):
    actions.run(["clean"], ArchBackend(), _ctx())
    out = capsys.readouterr().out
    assert "Cleaning caches" in out
    assert "would run:" in out


def test_unimplemented_action_notes_gracefully(capsys):
    # Defensive path: an action with no handler degrades gracefully. Every real
    # action does have one (guaranteed by test_action_registry); this exercises
    # the fallback with a synthetic name.
    actions.run(["future_action"], ArchBackend(), _ctx())
    out = capsys.readouterr().out
    assert "not yet implemented" in out


def test_step_counter_reflects_action_count(capsys):
    actions.run(["clean", "future_action"], ArchBackend(), _ctx())
    out = capsys.readouterr().out
    assert "[1/2]" in out and "[2/2]" in out


class _CleanSpy:
    def __init__(self):
        self.ran = 0

    def clean_caches(self, ctx):
        self.ran += 1


def test_clean_asks_and_skips_when_declined(capsys):
    # dry_run=False + assume_yes=False + no stdin -> confirm returns default (No).
    ctx = Context(output=Output(color=False), config=Config())
    spy = _CleanSpy()
    actions.run(["clean"], spy, ctx)
    assert spy.ran == 0
    assert "skipped cache cleaning" in capsys.readouterr().out


def test_clean_runs_without_prompt_when_assume_yes():
    ctx = Context(output=Output(color=False), config=Config(), assume_yes=True)
    spy = _CleanSpy()
    actions.run(["clean"], spy, ctx)
    assert spy.ran == 1


def test_clean_dry_run_shows_would_run_without_prompt(capsys):
    actions.run(["clean"], ArchBackend(), _ctx())  # _ctx is dry_run=True
    assert "would run:" in capsys.readouterr().out


def test_only_update_refreshes_then_reports(capsys):
    from fettle.backends.base import Result, Transaction, TxItem

    class _B:
        def __init__(self):
            self.refreshed = 0

        def refresh_metadata(self, ctx):
            self.refreshed += 1
            return Result()

        def pending_transaction(self, ctx, *, sync=True):
            return Transaction(items=[TxItem(name="bash", new="5.3-1", old="5.2-1")])

    b = _B()
    actions.run(["only_update"], b, _ctx())
    out = capsys.readouterr().out
    assert b.refreshed == 1                      # refreshed before reporting
    assert "Refreshing metadata" in out          # section title
    assert "bash  5.2-1 -> 5.3-1" in out          # upgradable report


# -- read-only actions under --dry-run ---------------------------------------
# Regression guard for the whole class: `fettle -A --dry-run` crashed with
# UnboundLocalError because a report path bound inside `if not ctx.dry_run:`
# was read outside it. --dry-run is supported for every READ_ONLY_ACTION, so
# each one must survive a dry run rather than only the one that broke.
@pytest.mark.parametrize("action", sorted(READ_ONLY_ACTIONS))
def test_read_only_actions_survive_dry_run(action, tmp_path):
    """Each read-only action completes under --dry-run without raising.

    The stubs must return *data*, not empties: with an empty AUR result the audit
    bails at "RPC returned no data" and never reaches the report/summary code that
    actually crashed, so the guard would pass while the bug was present.
    """
    info = [{"Name": "somepkg", "Maintainer": "bob", "LastModified": time.time(),
             "NumVotes": 5}]
    with patch("fettle.command.run", return_value=Proc(0, stdout="somepkg")), \
         patch("fettle.aur.meta.fetch_info", return_value=info), \
         patch("fettle.aur.ioc._fetch", return_value=""):
        ctx = Context(output=Output(color=False), config=Config(), dry_run=True,
                      sudo_user="paul", user_home=tmp_path)
        actions.run([action], ArchBackend(), ctx)   # must not raise


def test_aur_audit_dry_run_summary_omits_report_path(tmp_path, capsys):
    """The dry-run summary reports the audit without claiming a written report."""
    info = [{"Name": "somepkg", "Maintainer": "bob", "LastModified": time.time(),
             "NumVotes": 5}]
    with patch("fettle.command.run", return_value=Proc(0, stdout="somepkg")), \
         patch("fettle.aur.meta.fetch_info", return_value=info):
        ctx = Context(output=Output(color=False), config=Config(), dry_run=True,
                      sudo_user="paul", user_home=tmp_path)
        actions.run(["aur_audit"], ArchBackend(), ctx)
    out = capsys.readouterr().out
    assert "AUR audit of 1 package(s)" in out
    assert "written to" not in out                  # nothing was written
    assert "None" not in out                        # and no stringified None
