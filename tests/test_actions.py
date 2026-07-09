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
    actions.run(["clean", "integrity"], ArchBackend(), _ctx())
    out = capsys.readouterr().out
    assert "[1/2]" in out and "[2/2]" in out
