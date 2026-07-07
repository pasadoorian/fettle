from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


def _ctx(**kw):
    return Context(output=Output(color=False), config=Config(), **kw)


def test_confirm_assume_yes_is_true():
    assert _ctx(assume_yes=True).confirm("go?") is True


def test_confirm_dry_run_is_false():
    assert _ctx(dry_run=True).confirm("go?") is False


def test_confirm_reads_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    assert _ctx().confirm("go?") is True


def test_confirm_reads_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "")
    assert _ctx().confirm("go?") is False


def test_select_assume_yes_takes_all():
    assert _ctx(assume_yes=True).select(["a", "b"], prompt="x") == ["a", "b"]


def test_select_dry_run_takes_none():
    assert _ctx(dry_run=True).select(["a", "b"], prompt="x") == []


def test_select_interactive_y_n_q(monkeypatch):
    answers = iter(["y", "n", "q"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    # a=yes, b=no, c=quit -> only 'a'
    assert _ctx().select(["a", "b", "c", "d"], prompt="p") == ["a"]


def test_select_interactive_all(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "a")
    assert _ctx().select(["a", "b", "c"], prompt="p") == ["a", "b", "c"]
