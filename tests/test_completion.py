"""Shell-completion candidates (`fettle --complete`).

Two of these tests are doing real work rather than restating the implementation:

* :func:`test_a_tab_press_must_not_write_a_run_log` guards a data-loss path. Writing a
  run-log rotates the directory to ``keep`` entries, and completion shells out to fettle
  on every tab press — so without the guard, tab-completing would evict real run history
  a few keystrokes at a time. The identical bug was measured and fixed for ``--dry-run``.
* :func:`test_every_routed_subcommand_is_listed` reads `cli.py`'s own source, because
  ``SUBCOMMANDS`` is a second place a subcommand name has to appear and nothing else
  would notice if the two came apart.

The option-coverage tests are weaker on purpose, and it is worth being clear about why:
the candidates are *derived* from the real parser, so "every option is offered" is close
to tautological today. The derivation is the anti-drift mechanism; these tests exist to
fail if someone later swaps it for a hand-written list, which is the realistic regression.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from fettle import cli, completion, runlog


def _top(*before: str) -> list[str]:
    """Candidates with ``before`` already typed, at the next position."""
    words = ["fettle", *before, ""]
    return completion.candidates(words, len(words) - 1)


# -- the two guards ----------------------------------------------------------

def test_a_tab_press_must_not_write_a_run_log(monkeypatch):
    """The data-loss guard. Both recording paths gate on `_skip`, so one entry covers
    the PTY case and the non-tty case (completion is always the latter).

    The two env vars are cleared because the suite sets ``FETTLE_TEST=1``, which makes
    `_skip` return True for *everything* — so without clearing them this test would pass
    just as happily with the guard removed, which is the least useful kind of green.
    """
    monkeypatch.delenv("FETTLE_TEST", raising=False)
    monkeypatch.delenv(runlog.GUARD, raising=False)

    assert runlog._skip(["--complete", "2", "--", "fettle", "-c"]) is True
    # ...and it is the name that does it, not a blanket skip: a normal run is recorded.
    assert runlog._skip(["-c"]) is False


def test_every_routed_subcommand_is_listed():
    """`SUBCOMMANDS` is a second copy of the routing table; this fails if they diverge."""
    src = Path(cli.__file__).read_text()
    routed = set(re.findall(r'argv\[0\] == "([^"]+)"', src))
    for group in re.findall(r'argv\[0\] in \(([^)]+)\)', src):
        routed |= set(re.findall(r'"([^"]+)"', group))
    flags = {name for name in routed if name.startswith("-")}
    routed = routed - flags

    assert routed, "the routing regex matched nothing — it has drifted from the source"
    assert routed <= set(cli.SUBCOMMANDS), f"routed but not listed: {routed - set(cli.SUBCOMMANDS)}"
    assert set(cli.SUBCOMMANDS) <= routed, f"listed but not routed: {set(cli.SUBCOMMANDS) - routed}"
    # The same contract for the hidden flags routed the same way. `HIDDEN_FLAGS` is what
    # tells the stale-flag sweep these spellings are real, so a flag routed but unlisted
    # would make that sweep report fettle's own docs as stale.
    assert flags == set(cli.HIDDEN_FLAGS), f"routed {flags}, listed {set(cli.HIDDEN_FLAGS)}"


# -- what is offered ---------------------------------------------------------

def test_every_parser_option_is_offered():
    parser = cli.build_parser()
    options = {opt for a in parser._actions for opt in a.option_strings}
    assert options <= set(_top())


def test_nothing_phantom_is_offered():
    """The other direction: a candidate that is not a real option, action or subcommand
    is worse than a missing one — it teaches a CLI that does not exist."""
    parser = cli.build_parser()
    legal = ({opt for a in parser._actions for opt in a.option_strings}
             | {n.replace("_", "-") for n in cli.ACTION_NAMES}
             | set(cli.WORD_ALIASES) | set(cli.SUBCOMMANDS) | set(cli.DISPATCH_SHORTCUTS))
    assert set(_top()) <= legal


def test_actions_are_offered_as_hyphenated_words_and_as_flags():
    """All three interchangeable forms reach the user: `-r`, `--rebuild-check`,
    `rebuild-check`. The underscore spelling the parser also accepts is deliberately
    not offered — it is not what the help documents or what people type."""
    cands = set(_top())
    assert {"-r", "--rebuild-check", "rebuild-check"} <= cands
    assert "rebuild_check" not in cands


def test_word_aliases_are_offered():
    """`upgrade` comes from WORD_ALIASES, so a future alias is offered without anyone
    remembering to add it here."""
    assert "upgrade" in _top()
    assert "update" in _top()


def test_subcommands_and_dispatch_shortcuts_are_offered():
    cands = set(_top())
    assert {"report", "remote", "sys-audit", "advisory-update"} <= cands
    assert {"-S", "-U", "-p"} <= cands


def test_an_option_already_given_is_not_offered_again():
    assert "--dry-run" in _top()
    assert "--dry-run" not in _top("--dry-run")
    # ...but a repeatable one is still a flag, so this is about noise, not correctness:
    # actions stay available because you can name several.
    assert "clean" in _top("--dry-run")


# -- context -----------------------------------------------------------------

@pytest.mark.parametrize("before,want", [
    ([], None),
    (["--dry-run"], None),
    (["report"], "report"),
    (["--dry-run", "remote"], "remote"),
    (["-S"], "sys-audit"),                 # a dispatch shortcut is its subcommand
    (["--upgrade-check"], "upgrade-check"),
])
def test_context_detection(before, want):
    assert completion.context(before) == want


def test_inside_a_subcommand_nothing_is_offered_yet():
    """M1 is top level only. Offering the top-level options here would be worse than
    offering nothing — `fettle report --dry-run` is not a thing."""
    assert _top("report") == []
    assert _top("-S") == []


# -- robustness: a broken completion must not break the shell -----------------

@pytest.mark.parametrize("argv", [
    [],                                    # no args at all
    ["notanumber", "--", "fettle"],        # cword is not an int
    ["-1", "--", "fettle"],                # negative cword
    ["999", "--", "fettle"],               # cword past the end
    ["1"],                                 # no `--` separator
    ["--"],                                # separator, no words
    ["2", "--", "fettle", "nonsense-sub"],  # unknown subcommand
])
def test_garbage_input_exits_zero_and_says_nothing(argv, capsys):
    assert completion.main(argv) == 0
    assert capsys.readouterr().err == ""


def test_a_word_index_of_zero_offers_nothing():
    """cword 0 is the program name; the shell completes that from PATH."""
    assert completion.candidates(["fettle"], 0) == []


def test_an_internal_error_is_silent_rather_than_a_traceback(monkeypatch, capsys):
    """The rule that matters most in practice: a user's prompt is not ours to break."""
    monkeypatch.setattr(completion, "candidates",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert completion.main(["1", "--", "fettle"]) == 0
    out = capsys.readouterr()
    assert out.out == "" and out.err == ""


def test_the_helper_is_routed_before_the_parser(capsys):
    """It must not reach argparse: the words are half-typed input, and the pipeline
    parser would exit 2 with a usage error on most of them."""
    assert cli._main(["--complete", "1", "--", "fettle"]) == 0
    assert "usage:" not in capsys.readouterr().err
