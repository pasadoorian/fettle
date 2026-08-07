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


def options(parser) -> set[str]:
    """Every option string a parser accepts, minus the ones hidden from ``--help``.

    A suppressed option is a machine interface rather than something to suggest to a
    person — ``upgrade-check --collect`` is how the remote transport asks for a JSON
    snapshot, and offering it invites someone to type it and get output they cannot use.
    The same reasoning keeps ``--complete`` itself out of the list.
    """
    import argparse

    return {opt for a in parser._actions if a.help is not argparse.SUPPRESS
            for opt in a.option_strings}


def repeatable() -> set[str]:
    """Options that may legitimately be given more than once.

    Seeing ``--only`` on the line is no reason to stop offering it — naming two actions
    takes two of them. Derived from every parser rather than listed, so an ``append``
    option added anywhere keeps working; ``--ssh-arg`` is named because ``fettle
    remote`` is hand-parsed and has no parser to read.
    """
    from . import cli
    from .secure import audit

    repeating = ("_AppendAction", "_AppendConstAction", "_CountAction", "_ExtendAction")
    out = {"--ssh-arg"}
    for parser in (cli.build_parser(), cli.report_parser(), cli.web_parser(),
                   cli.upgrade_check_parser(), cli.advisory_parser("advisory-check"),
                   audit.parser(), audit.remote_parser()):
        out |= {opt for a in parser._actions
                if a.__class__.__name__ in repeating for opt in a.option_strings}
    return out


def _toplevel_candidates() -> list[str]:
    """Everything valid as the first meaningful word: options, actions, subcommands.

    Action words are offered **hyphenated** (``rebuild-check``), which is what the help
    documents and what a person types; the parser accepts either spelling. ``upgrade``
    comes from ``WORD_ALIASES`` rather than being spelled out here, so an alias added
    later is offered without anyone remembering to.
    """
    from . import cli

    out = options(cli.build_parser())
    out |= {name.replace("_", "-") for name in cli.ACTION_NAMES}
    out |= set(cli.WORD_ALIASES)
    out |= set(cli.SUBCOMMANDS)
    out |= set(cli.DISPATCH_SHORTCUTS)
    return sorted(out)


def _action_words() -> set[str]:
    from . import cli

    return {n.replace("_", "-") for n in cli.ACTION_NAMES} | set(cli.WORD_ALIASES)


def _sys_audit_candidates(before: list[str]) -> set[str]:
    """sys-audit's own flags, its nine categories, and its `remote` sub-subcommand.

    Categories are positional and repeatable, so already-typed ones are dropped — the
    one place in fettle where that matters rather than merely tidying.
    """
    from .secure import audit

    if "remote" in before:
        # `fettle sys-audit remote <host> <categories...>` — a different parser, and
        # the host is deliberately not completed (out of scope, and guessing at ssh
        # aliases from a config we may not be allowed to read is worse than silence).
        return (options(audit.remote_parser())
                | (set(audit.CATEGORIES) - set(before)))
    return (options(audit.parser()) | {"remote"}
            | (set(audit.CATEGORIES) - set(before)))


def _remote_candidates(before: list[str]) -> set[str]:
    """`fettle remote` — ssh options before HOST, forwarded actions after it.

    HOST itself is not completed. Once past it, the candidates are the ordinary action
    words plus `upgrade-check`, because that is literally what gets forwarded to the
    remote fettle.
    """
    from . import cli

    seen_host = any(not w.startswith("-") and w != "remote"
                    and before[i - 1] != "--ssh-arg"
                    for i, w in enumerate(before) if i > 0)
    if not seen_host:
        return set(cli.REMOTE_FLAGS)
    return _action_words() | {"upgrade-check"}


def _subcommand_candidates(sub: str, before: list[str]) -> set[str]:
    from . import cli

    if sub == "report":
        return options(cli.report_parser())
    if sub == "web":
        return options(cli.web_parser())
    if sub in ("advisory-check", "advisory-update"):
        return options(cli.advisory_parser(sub))
    if sub == "upgrade-check":
        return options(cli.upgrade_check_parser())
    if sub == "sys-audit":
        return _sys_audit_candidates(before)
    if sub == "remote":
        return _remote_candidates(before)
    # aur-precheck takes AUR package names and no flags of its own. Completing package
    # names is deliberately out of scope, and an empty list is the honest answer rather
    # than offering flags it would ignore.
    return set()


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

    sub = context(before)
    cands = (sorted(_subcommand_candidates(sub, before)) if sub is not None
             else _toplevel_candidates())

    # An option already on the line is noise, not a suggestion — unless it is one that
    # may legitimately repeat. Positional words are left alone: several actions can be
    # named in one run, and the one place repetition IS wrong (sys-audit categories)
    # filters itself above.
    given = {w for w in before if w.startswith("-")} - repeatable()
    return [c for c in cands if c not in given]


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
