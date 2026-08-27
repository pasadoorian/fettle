"""Elevation: root when the work needs it, never when it does not.

Two questions that look like one and are not — "does this change the system?" and "does
this need root?" — come apart in both directions, which is why the sets that answer them
are written out rather than derived.
"""

from unittest.mock import patch

from fettle import cli
from fettle.cli import (
    NO_ROOT_ACTIONS,
    READ_ONLY_ACTIONS,
    _forwarded_needs_root,
    _MUTATES_BUT_NO_ROOT,
    _READ_ONLY_BUT_NEEDS_ROOT,
)


# -- classification ------------------------------------------------------------
def test_the_two_sets_differ_only_by_the_declared_exceptions():
    assert READ_ONLY_ACTIONS - NO_ROOT_ACTIONS == _READ_ONLY_BUT_NEEDS_ROOT
    assert NO_ROOT_ACTIONS - READ_ONLY_ACTIONS == _MUTATES_BUT_NO_ROOT


def test_advisory_check_does_not_elevate():
    """It reads the package database and a cache under ~/.cache. Giving it a flag in
    v0.104.0 moved it into the pipeline's elevation path, so `fettle -D` started asking
    for a sudo password to answer a read-only question — the subcommand never had."""
    assert "advisory_check" in READ_ONLY_ACTIONS
    assert "advisory_check" in NO_ROOT_ACTIONS


def test_sys_audit_is_read_only_but_still_elevates():
    """Read-only and needs-root at once: firmware, boot chain and hardware are read
    through root-only interfaces. Unprivileged it runs and checks far less."""
    assert "sys_audit" in READ_ONLY_ACTIONS
    assert "sys_audit" in _READ_ONLY_BUT_NEEDS_ROOT
    assert "sys_audit" not in NO_ROOT_ACTIONS


# -- the remote decision -------------------------------------------------------
def test_remote_does_not_elevate_for_read_only_audits():
    """`fettle remote` elevated for everything except --dry-run, so a read-only audit
    ran as root and asked for a password to do it.

    `-H` was in this list until v1.17.0 and moved to the one below. It did not change
    because a test was inconvenient: the AppArmor axis reads state that is root-only,
    so `-H` now genuinely needs root the way `-V` always has."""
    for toks in (["-P"], ["-D"], ["-P", "-D"]):
        assert _forwarded_needs_root(toks) is False, toks


def test_remote_still_elevates_for_work_that_needs_it():
    for toks in (["-u"], ["-c"], ["-V"], ["-H"], ["-P", "-u"], ["--everything"]):
        assert _forwarded_needs_root(toks) is True, toks


def test_an_unrecognised_token_is_assumed_to_need_root():
    """A run with privilege it did not need works; one lacking privilege it did need
    fails partway with a permissions error. Wrong in the safe direction."""
    assert _forwarded_needs_root(["--some-future-flag", "value"]) is True
    assert _forwarded_needs_root([]) is True          # no action named -> default set


def test_modifiers_alone_do_not_decide_anything():
    """`--yes` and friends say how to run, not what to run."""
    assert _forwarded_needs_root(["-P", "--yes", "-v"]) is False


def test_full_preview_elevates_even_under_dry_run():
    """The documented exception: resolving a full dnf transaction needs root, and there
    is no rootless equivalent."""
    sent = {}
    with patch("fettle.remote.run", side_effect=lambda h, f, **k: sent.update(k) or 0), \
         patch.object(cli, "_fetch_remote_reports"):
        cli._remote_one("h", [], ["-u", "--dry-run", "--full-preview"])
    assert sent["sudo"] is True


def test_a_plain_dry_run_never_elevates():
    sent = {}
    with patch("fettle.remote.run", side_effect=lambda h, f, **k: sent.update(k) or 0), \
         patch.object(cli, "_fetch_remote_reports"):
        cli._remote_one("h", [], ["-u", "--dry-run"])
    assert sent["sudo"] is False
