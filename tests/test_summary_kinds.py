"""Every `✗` line must say WHICH kind of bad news it is.

One channel on screen, three different situations behind it:

    failed   the action could not do its job       -> something is broken, go look
    blind    the check could not look              -> you have a blind spot, and the
                                                      all-clear you just got is not one
    found    the check looked and found something  -> the tool worked; go fix the thing

They call for opposite responses from the reader, and until they were labelled the exit
status could not tell them apart — which is why a fourteen-action sweep had to choose
between being red on every real machine and treating "could not look" as success.
"""

import ast
import pathlib

from fettle.output import BLIND, FAILED, FOUND, Output

SRC = pathlib.Path(__file__).resolve().parent.parent / "fettle"


def _call_sites():
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "summary_fail"):
                yield path.relative_to(SRC.parent), node


def test_every_failure_declares_its_kind():
    """The guard. A new `✗` that does not say which kind it is defaults to `failed`,
    which is the safe direction but makes the exit code wrong for a finding — so it has
    to be a deliberate choice at every call site, not an omission."""
    missing = [f"{p}:{n.lineno}" for p, n in _call_sites()
               if not any(k.arg == "kind" for k in n.keywords)]
    assert not missing, "summary_fail() without kind=: " + ", ".join(missing)


def test_every_kind_used_is_a_real_one():
    named = {k.value.id for _, n in _call_sites() for k in n.keywords
             if k.arg == "kind" and isinstance(k.value, ast.Name)}
    assert named <= {"FAILED", "BLIND", "FOUND"}, named


def test_all_three_kinds_are_actually_in_use():
    """If a kind has no call sites the classification is not describing reality."""
    named = {k.value.id for _, n in _call_sites() for k in n.keywords
             if k.arg == "kind" and isinstance(k.value, ast.Name)}
    assert named == {"FAILED", "BLIND", "FOUND"}, named


# -- the recording itself ------------------------------------------------------
def test_kind_is_recorded_and_queryable():
    out = Output(color=False)
    out.summary_fail("update did not complete", kind=FAILED)
    out.summary_fail("could not reach the advisory feed", kind=BLIND)
    out.summary_fail("3 packages have known CVEs", kind=FOUND)
    assert out.failures_of(FAILED) == ["update did not complete"]
    assert out.failures_of(BLIND) == ["could not reach the advisory feed"]
    assert out.failures_of(FAILED, BLIND) == ["update did not complete",
                                              "could not reach the advisory feed"]


def test_default_kind_is_the_strict_one():
    """An unlabelled failure must fail every rule, not slip through the loosest one."""
    out = Output(color=False)
    out.summary_fail("something")
    assert out.failures_of(FAILED) == ["something"]


def test_classification_changes_nothing_that_prints(capsys):
    """This milestone is deliberately inert: same three lines, same marks, same order."""
    out = Output(color=False)
    out.summary_fail("a", kind=FAILED)
    out.summary_fail("b", kind=BLIND)
    out.summary_fail("c", kind=FOUND)
    out.print_summary()
    printed = [ln.strip() for ln in capsys.readouterr().out.splitlines()
               if ln.strip().startswith("✗")]
    assert printed == ["✗ a", "✗ b", "✗ c"]


def test_exit_status_is_still_blind_to_kind():
    """X1 only labels. Every exit code stays exactly what it was, so the change is
    provably inert; X2 is where the status starts branching on this."""
    for kind in (FAILED, BLIND, FOUND):
        out = Output(color=False)
        out.summary_fail("x", kind=kind)
        assert out.had_failures is True
