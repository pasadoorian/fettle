"""Every subcommand must report what happened and return a status that reflects it.

This is the one structural defect this QA pass found over and over: a subcommand with its
own entry point independently forgets BOTH — no summary, and a hardcoded `return 0`. It
was found in sys-audit, advisory-check, upgrade-check, aur-precheck, the remote zipapp
wrapper, and report. The first five were fixed as they were swept; `report` was the last
one standing.

A guard is worth more here than another fix, because the defect is not a bug in any one
place — it is what happens by default every time someone adds a subcommand.
"""

import ast
import pathlib
from unittest.mock import patch

import pytest

from fettle import cli

SRC = pathlib.Path(cli.__file__).resolve().parent

# Entry points that do work HERE and must therefore print a digest of it.
WORK_RUNNERS = ("_run_report", "_run_advisory", "_run_upgrade_check")

# Orchestrators. They do no work themselves — the digest comes from the fettle running on
# the remote, or from the per-host table the group runner prints — but their status must
# still be derived from what they ran rather than assumed.
ORCHESTRATORS = ("_run_remote_maintenance", "_run_group")

# `_run_web` is in neither: it hands control to a server that runs until interrupted, so
# "what happened" is not a question it can answer at the end.
ENTRY_POINTS = WORK_RUNNERS + ORCHESTRATORS


def _func(name):
    tree = ast.parse((SRC / "cli.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in cli.py")


@pytest.mark.parametrize("name", ENTRY_POINTS)
def test_entry_point_does_not_end_in_a_hardcoded_success(name):
    """`return 0` as the LAST statement means the status is a constant, not an answer.

    An early `return 0` is fine — that is a path that genuinely did nothing. What this
    catches is the function running its work and then reporting success unconditionally.
    """
    node = _func(name)
    last = node.body[-1]
    if isinstance(last, ast.Return):
        assert not (isinstance(last.value, ast.Constant) and last.value.value == 0), (
            f"{name} ends in a hardcoded `return 0` — its status cannot reflect what "
            "happened")


@pytest.mark.parametrize("name", WORK_RUNNERS)
def test_work_runner_prints_a_summary(name):
    """A subcommand that does work and prints no digest leaves the user reading raw tool
    output to find out whether it worked."""
    node = _func(name)
    calls = [n for n in ast.walk(node)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "print_summary"]
    assert calls, f"{name} never calls print_summary()"


@pytest.mark.parametrize("name", ORCHESTRATORS)
def test_orchestrator_returns_something_it_computed(name):
    """They print no digest of their own — the group runner prints a per-host table and
    the remote path forwards the remote's summary — but the status must still come from
    what actually ran."""
    node = _func(name)
    returns = [n for n in ast.walk(node) if isinstance(n, ast.Return) and n.value]
    computed = [r for r in returns
                if not (isinstance(r.value, ast.Constant) and r.value.value in (0, 1, 2))]
    assert computed, f"{name} only ever returns constants"


# -- report, the last one that was still doing it ------------------------------
def test_report_fails_when_it_cannot_be_written(tmp_path, capsys):
    from fettle import htmlreport

    with patch.object(htmlreport, "build", side_effect=OSError("Read-only file system")):
        rc = cli._run_report(["--no-config"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "report was NOT written" in out


def test_report_says_so_when_it_contains_no_hosts(tmp_path, capsys):
    """A dashboard built from nothing is a valid HTML file and a useless answer.
    Reporting only "written to <path>" invites the reader to believe their fleet is in
    it."""
    from fettle import htmlreport

    with patch.object(htmlreport, "build", return_value=tmp_path / "report.html"), \
         patch.object(htmlreport, "collect", return_value={}):
        rc = cli._run_report(["--no-config"])
    out = capsys.readouterr().out
    assert rc == 0                      # nothing failed; there is just nothing there
    assert "contains NO hosts" in out
    assert "Not checked" in out


def test_report_counts_the_hosts_it_covered(tmp_path, capsys):
    from fettle import htmlreport

    with patch.object(htmlreport, "build", return_value=tmp_path / "report.html"), \
         patch.object(htmlreport, "collect", return_value={"a": {}, "b": {}}):
        cli._run_report(["--no-config"])
    assert "report for 2 host(s)" in capsys.readouterr().out
