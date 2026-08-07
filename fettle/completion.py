"""Candidate lists for shell completion.

The shell script that drives this is deliberately tiny (see ``contrib/fettle.bash``) —
it knows nothing about fettle's options and just asks::

    fettle --complete <cword> -- <words...>

where ``cword`` is bash's ``COMP_CWORD`` and ``words`` is ``COMP_WORDS`` verbatim,
program name included. Every candidate valid at that position is printed one per line
and the shell does its own prefix filtering with ``compgen -W``.

**Why the logic lives here and not in the shell script.** fettle's CLI is oddly shaped:
every action has three interchangeable forms (``-c`` == ``--clean`` == ``clean``),
``-S``/``-U``/``-p`` are intercepted before argparse and cannot be combined with action
flags, and each subcommand has a parser of its own. Encoding that a second time in bash
is how the two drift apart, and this project has already spent a QA pass on bugs of
exactly that class. So the candidates are **derived from the real parser** — that
derivation, not the test suite, is the actual anti-drift mechanism; the tests guard
against someone later replacing it with a hand-written list.

**Two hard rules**, both because a completion function runs on every keystroke-ish and
a user's shell is not ours to break:

* :func:`main` never raises and never exits non-zero. On any internal error it prints
  nothing, which degrades to "no suggestions" rather than to a stack trace over the
  prompt.
* It must stay off every side-effecting path. It is routed before argparse, and
  ``--complete`` is in :data:`fettle.runlog._NO_RECORD` — without that entry a run-log
  would be written *per tab press*, and writing one rotates the directory, so tab
  completion would quietly evict real run history. That is not hypothetical: the same
  bug was measured and fixed for ``--dry-run`` (eleven real logs down to nine after a
  single preview).
"""

from __future__ import annotations


def _toplevel_candidates() -> list[str]:
    """Everything valid as the first meaningful word: options, actions, subcommands.

    Action words are offered **hyphenated** (``rebuild-check``), which is what the help
    documents and what a person types; the parser accepts either spelling. ``upgrade``
    comes from ``WORD_ALIASES`` rather than being spelled out here, so an alias added
    later is offered without anyone remembering to.
    """
    from . import cli

    parser = cli.build_parser()
    out = {opt for action in parser._actions for opt in action.option_strings}
    out |= {name.replace("_", "-") for name in cli.ACTION_NAMES}
    out |= set(cli.WORD_ALIASES)
    out |= set(cli.SUBCOMMANDS)
    out |= set(cli.DISPATCH_SHORTCUTS)
    return sorted(out)


def context(before: list[str]) -> str | None:
    """Which subcommand the cursor is inside, or ``None`` for the top level.

    ``before`` is the words already typed, excluding the program name and the partial
    word under the cursor. A dispatch shortcut counts: ``fettle -S <TAB>`` is inside
    ``sys-audit``, because that is what it will actually run.
    """
    from . import cli

    for word in before:
        if word in cli.SUBCOMMANDS:
            return word
        if word in cli.DISPATCH_SHORTCUTS:
            return cli.DISPATCH_SHORTCUTS[word]
    return None


def candidates(words: list[str], cword: int) -> list[str]:
    """Candidates for the word at ``cword``. Empty is a valid answer, never an error."""
    if cword < 1:
        # cword 0 is the program name itself — the shell completes that from PATH.
        return []
    before = [w for w in words[1:cword] if w]

    if context(before) is not None:
        # Subcommand contexts arrive in the next milestone. Offering the top-level
        # options here would be worse than offering nothing: `fettle report --dry-run`
        # is not a thing, and suggesting it teaches the wrong CLI.
        return []

    given = {w for w in before if w.startswith("-")}
    return [c for c in _toplevel_candidates() if c not in given]


def main(argv: list[str]) -> int:
    """Handle ``--complete <cword> -- <words...>``. Always returns 0, always silent
    on error — see the module docstring."""
    try:
        if "--" in argv:
            sep = argv.index("--")
            head, words = argv[:sep], argv[sep + 1:]
        else:
            head, words = argv[:1], argv[1:]
        cword = int(head[0]) if head else len(words)
        for line in candidates(words, cword):
            print(line)
    except Exception:                    # noqa: BLE001 — a broken completion must not
        pass                             # break the user's shell. See the docstring.
    return 0
