from fettle import actions
from fettle.backends.arch import ArchBackend
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


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
