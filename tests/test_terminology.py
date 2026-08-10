"""The words fettle uses on screen, kept consistent by test rather than by vigilance.

Terminology was the stated top priority of this QA pass, and it is the thing most likely
to drift: nothing breaks when a new summary line invents its own vocabulary, so nothing
catches it.
"""

import ast
import pathlib
import re

import pytest

from fettle.actions import HANDLERS, TITLES
from fettle.cli import FLAG_ACTIONS

SRC = pathlib.Path(__file__).resolve().parent.parent / "fettle"

# The naming rule, written down so it can be applied rather than argued about each time:
#
#   <thing>-audit   judges what you ALREADY HAVE and grades it — a graded inventory
#                   (pkg-audit, aur-audit, sys-audit, hardening-audit)
#   <thing>-check   asks a yes/no question about the system's current state
#                   (rebuild-check, advisory-check, firmware-check, compromise-check)
#   bare noun       names the thing it manages or reports, with no verb
#                   (clean, orphans, update, kernel, config-drift, pkg-integrity)
#
# The rule is descriptive: it was derived from the names that already existed, and it
# fits all of them. It exists so the NEXT action does not have to be guessed at.
#
# `compromise-check` is the first action that arrived and did not fit, which is what
# this guard is for. The -check line used to read "asks whether something is PENDING or
# NEEDED", and nothing about a compromise is pending — it either happened or it did
# not. Renaming it `compromise-audit` was the alternative and is worse: every -audit
# name is `<the thing being graded>-audit`, and a compromise is the *finding*, not the
# subject, so it would be the only one whose subject is not a thing you have. The
# generalisation above ("a yes/no question about current state" vs "a graded
# inventory") was checked against all eleven existing names and fits every one, so the
# rule got wider rather than the name getting worse.
AUDITS = {"pkg_audit", "aur_audit", "sys_audit", "hardening_audit"}
CHECKS = {"rebuild_check", "python_rebuild_check", "advisory_check", "firmware_check",
          "compromise_check"}


def test_every_audit_and_check_follows_the_naming_rule():
    for name in HANDLERS:
        if name.endswith("_audit"):
            assert name in AUDITS, (
                f"{name} ends in -audit but is not listed as one. An audit judges what "
                "you already have; a check asks whether something is pending.")
        if name.endswith("_check"):
            assert name in CHECKS, f"{name} ends in -check but is not listed as one"


def test_no_action_uses_a_third_verb():
    """`scan`, `verify`, `test`, `inspect` are all near-synonyms of the two we have.
    A third vocabulary is how a CLI stops being learnable."""
    stray = [n for n in HANDLERS
             if re.search(r"_(scan|verify|test|inspect|analy[sz]e)$", n)]
    assert not stray, stray


# -- the summary vocabulary ----------------------------------------------------
def _summary_lines():
    """Every literal string handed to a summary_* call."""
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr.startswith("summary_")):
                for arg in node.args:
                    for piece in ast.walk(arg):
                        if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                            yield path.relative_to(SRC.parent), node.lineno, piece.value


def test_summary_lines_do_not_hand_write_an_action_prefix():
    """The pipeline adds the prefix now. A hand-written one either doubles up or, worse,
    disagrees — which is how `advisory-check` came to announce itself as `advisories:`
    and `container-update` as `containers:`."""
    # Both the exact command name AND near-misses of it. "advisories:" is not an action
    # name, so an exact-match guard sailed past it and shipped
    # "advisory-check: advisories: 34 pending" — the doubling it was written to prevent.
    names = {a.replace("_", "-") for a in HANDLERS}
    stems = {n.split("-")[0] for n in names} | names
    offenders = [f"{p}:{ln} — {t!r}" for p, ln, t in _summary_lines()
                 if any(t.startswith(f"{s}:") or t.startswith(f"{s}s:")
                        for s in stems)]
    assert not offenders, offenders


@pytest.mark.parametrize("action,title", sorted(TITLES.items()))
def test_every_title_reads_as_a_heading(action, title):
    """Titles are printed above the run; they should read as prose, not as a flag."""
    assert title and title[0].isupper(), f"{action}: {title!r}"
    assert "_" not in title and not title.startswith("-"), f"{action}: {title!r}"


def test_the_long_flag_spells_the_action_the_same_way():
    """`--hardening-audit` for `hardening_audit`. A flag that spells its action
    differently teaches two names for one thing, and the docs then have to pick one."""
    from fettle.cli import build_parser

    parser = build_parser()
    by_dest = {a.dest: a for a in parser._actions}
    mismatched = []
    for opts, action in FLAG_ACTIONS:
        arg = by_dest.get(f"do_{action}")
        if arg is None:
            continue
        longs = [o.lstrip("-") for o in opts if o.startswith("--")]
        if action.replace("_", "-") not in longs:
            mismatched.append(f"{action} -> {longs}")
    assert not mismatched, mismatched


# -- the help itself -----------------------------------------------------------
#
# `--help` is the only documentation most people will ever read, and it drifts silently:
# nothing breaks when an action is added without an entry, or an option ships with no
# description at all.

def test_every_option_has_help_text():
    """Four shipped with none: -v, -q, --no-color and --config. A user reading --help
    learned nothing about them."""
    from fettle.cli import build_parser

    bare = [", ".join(a.option_strings) for a in build_parser()._actions
            if a.option_strings and not a.help]
    assert not bare, bare


def test_every_action_flag_has_real_help_not_its_own_name():
    """`-D, --advisory-check  advisory_check` is what you get when an action is added to
    the flag table but not to the help table."""
    from fettle.cli import ACTION_HELP, FLAG_ACTIONS

    lazy = [a for _, a in FLAG_ACTIONS
            if ACTION_HELP.get(a, a) in (a, a.replace("_", "-"))]
    assert not lazy, lazy


def test_every_runnable_action_appears_in_help():
    """An action you can run but cannot find is invisible: advisory-check was a real
    pipeline action for eight releases with no flag and no entry in the audit list."""
    from fettle.cli import FLAG_ACTIONS, PIPELINE_ONLY_ACTIONS

    flagged = {a for _, a in FLAG_ACTIONS}
    for name in HANDLERS:
        assert name in flagged or name in PIPELINE_ONLY_ACTIONS, (
            f"{name} can be run but appears in no help section")


def test_help_mentions_everything_and_the_audit_commands():
    from fettle.cli import build_parser

    text = build_parser().format_help()
    for needle in ("--everything", "advisory-check", "advisory-update", "sys-audit",
                   "aur-precheck"):
        assert needle in text, needle


def test_the_longform_block_does_not_claim_they_all_take_options():
    """It said "for the ones that take options" while listing two that take none."""
    from fettle.cli import _LONGFORM_TITLE

    assert "take options" not in _LONGFORM_TITLE


# -- one line per action, so the summary reads as a checklist -------------------
def test_every_action_that_ran_gets_a_summary_line():
    """Six actions ran against a real guest and two appeared in the summary, because an
    action that finds nothing said nothing. A two-line summary gives no way to tell
    "twelve checks were clean" from "twelve never ran"."""
    from unittest.mock import patch

    from fettle import actions as A
    from fettle.backends.base import Context, PackageBackend
    from fettle.config import Config
    from fettle.output import Output

    ran = ["clean", "orphans", "config_drift"]
    out = Output(color=False)
    ctx = Context(output=out, config=Config())

    class Stub(PackageBackend):
        name = "stub"
        supported = set(ran)

    # handlers that do nothing at all — the case that used to vanish
    with patch.dict(A.HANDLERS, {n: (lambda b, c: None) for n in ran}):
        A.run(ran, Stub(), ctx)

    lines = out._summary + out._warnings + [ln for ln, _ in out._failures]
    assert len(lines) == len(ran), lines
    for name in ran:
        assert any(ln.startswith(f"{name.replace('_', '-')}:") for ln in lines), name


def test_an_action_that_could_not_run_says_so_rather_than_vanishing():
    from unittest.mock import patch

    from fettle import actions as A
    from fettle.backends.base import Context, PackageBackend
    from fettle.config import Config
    from fettle.output import Output

    out = Output(color=False)
    ctx = Context(output=out, config=Config())

    def unimplemented(b, c):
        raise NotImplementedError

    class Stub(PackageBackend):
        name = "stub"
        supported = {"clean"}

    with patch.dict(A.HANDLERS, {"clean": unimplemented}):
        A.run(["clean"], Stub(), ctx)
    assert any("did NOT run" in ln for ln in out._warnings), out._warnings


def test_an_action_that_reported_something_is_not_given_a_second_line():
    from unittest.mock import patch

    from fettle import actions as A
    from fettle.backends.base import Context, PackageBackend
    from fettle.config import Config
    from fettle.output import Output

    out = Output(color=False)
    ctx = Context(output=out, config=Config())

    class Stub(PackageBackend):
        name = "stub"
        supported = {"clean"}

    with patch.dict(A.HANDLERS, {"clean": lambda b, c: c.output.summary_add("18 MiB freed")}):
        A.run(["clean"], Stub(), ctx)
    assert out._summary == ["clean: 18 MiB freed"], out._summary
