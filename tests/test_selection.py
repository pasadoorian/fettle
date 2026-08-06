"""The default action set, and `--only` / `--skip`.

Low-stakes rows — neither can damage a machine — but both decide what actually runs, and
a selection that silently resolves to nothing is a run that reports success for work it
never did.
"""

import pytest

from fettle.cli import EVERYTHING_ACTIONS, build_parser
from fettle.config import DEFAULT_ACTIONS


def _actions_for(argv):
    from fettle.cli import _requested_actions
    from fettle.config import Config
    return _requested_actions(build_parser().parse_args(argv), Config())


# -- the default set -----------------------------------------------------------
def test_the_default_set_updates_before_it_inspects_the_result():
    """It ran `orphans` before `update`, so it described the machine you booted rather
    than the one you now have. Same reasoning as --everything: the rebuild checks catch
    what the update made stale, and orphans and config-drift are things an upgrade
    CREATES."""
    for later in ("rebuild_check", "python_rebuild_check", "orphans", "config_drift"):
        assert DEFAULT_ACTIONS.index("update") < DEFAULT_ACTIONS.index(later), later


def test_the_default_set_cleans_before_updating():
    assert DEFAULT_ACTIONS.index("clean") < DEFAULT_ACTIONS.index("update")


def test_the_two_orders_agree_where_they_overlap():
    """`-a` and `--everything` share nine actions. Two different orders for the same
    work is the kind of inconsistency nobody notices until the output disagrees."""
    shared = [a for a in EVERYTHING_ACTIONS if a in DEFAULT_ACTIONS]
    assert shared == [a for a in DEFAULT_ACTIONS if a in EVERYTHING_ACTIONS]


# -- --only / --skip -----------------------------------------------------------
def test_only_rejects_an_unknown_action():
    """`--only hardening-audi` selected nothing, ran nothing and exited 0 — a typo in a
    cron line reporting success for work that never happened."""
    with pytest.raises(SystemExit) as e:
        _actions_for(["--only", "hardening-audi"])
    assert "unknown action" in str(e.value)


def test_skip_rejects_an_unknown_action():
    with pytest.raises(SystemExit) as e:
        _actions_for(["--skip", "no-such-thing"])
    assert "unknown action" in str(e.value)


def test_only_and_skip_accept_the_word_aliases():
    """`upgrade` is a synonym for `update` everywhere else; it must be here too."""
    assert _actions_for(["--everything", "--only", "upgrade"]) == ["update"]
    assert "update" not in _actions_for(["--everything", "--skip", "upgrade"])


def test_only_accepts_both_spellings_of_a_name():
    assert _actions_for(["-a", "--only", "config-drift"]) == ["config_drift"]
    assert _actions_for(["-a", "--only", "config_drift"]) == ["config_drift"]


def test_skip_removes_only_what_was_named():
    got = _actions_for(["-a", "--skip", "clean"])
    assert "clean" not in got and "update" in got
