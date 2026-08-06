"""Snap source provider — publisher verification + confinement."""

from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import (
    OVER_PRIVILEGED,
    STALE_OR_ABANDONED,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
    UNVERIFIED_PUBLISHER,
)
from fettle.supplychain.snap_source import SnapSource


def _ctx():
    return Context(output=Output(color=False), config=Config())


def _run(snap_list):
    def fake_run(cmd, *, as_user=None, capture=False):
        if list(cmd)[:2] == ["snap", "list"]:
            return command.Proc(0, snap_list, "")
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake_run):
        return SnapSource().findings(_ctx())


_HEADER = "Name Version Rev Tracking Publisher Notes\n"


def test_verified_publisher_strict_is_clean():
    findings = _run(_HEADER + "firefox 123 456 latest/stable mozilla✓ -\n")
    assert findings == []


def test_unverified_publisher_flagged():
    findings = _run(_HEADER + "sketchy 1 2 latest/stable randomdev -\n")
    assert any(f.question == UNVERIFIED_PUBLISHER and f.package == "sketchy" for f in findings)


def test_classic_confinement_over_privileged():
    findings = _run(_HEADER + "code 1 2 latest/stable microsoft✓ classic\n")
    assert any(f.question == OVER_PRIVILEGED and "classic" in f.detail for f in findings)


def test_devmode_over_privileged():
    findings = _run(_HEADER + "hacktool 1 2 latest/edge somedev✓ devmode\n")
    assert any(f.question == OVER_PRIVILEGED and "devmode" in f.detail for f in findings)


def test_sideloaded_snap_flagged():
    findings = _run(_HEADER + "mybuild 1 x1 - - -\n")  # sideloaded: no publisher
    assert any(f.question == UNOFFICIAL_SOURCE for f in findings)


def test_starred_publisher_is_verified():
    findings = _run(_HEADER + "partnerapp 1 2 latest/stable partner** -\n")
    assert not any(f.question == UNVERIFIED_PUBLISHER for f in findings)


# -- is it still published? ----------------------------------------------------
#
# Withdrawal is what a store DOES to malware, so a snap that has vanished is worth
# knowing about. The trap is that the question is answered over the network: a Store
# that is merely unreachable would make every installed snap look withdrawn at once.

def _run_store(snap_list, *, info_rc=0, info_err=""):
    calls = []

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        calls.append(c)
        if c[:2] == ["snap", "list"]:
            return command.Proc(0, snap_list, "")
        if c[:2] == ["snap", "info"]:
            return command.Proc(info_rc, "", info_err)
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake_run):
        return SnapSource().findings(_ctx()), calls


def test_withdrawn_snap_is_reported():
    findings, _ = _run_store(_HEADER + "gone 1 2 latest/stable mozilla✓ -\n",
                             info_rc=1, info_err='error: no snap found for "gone"')
    f = next(f for f in findings if f.question == STALE_OR_ABANDONED)
    assert f.package == "gone"
    assert "no longer in the Snap Store" in f.detail


def test_unreachable_store_is_not_a_withdrawal():
    """The one that matters. An unreachable Store must never read as "every snap you
    have was pulled" -- that is "could not look" rendering as "found a problem"."""
    findings, _ = _run_store(_HEADER + "firefox 1 2 latest/stable mozilla✓ -\n",
                             info_rc=1, info_err="error: cannot communicate with server")
    assert not [f for f in findings if f.question == STALE_OR_ABANDONED]
    gap = next(f for f in findings if f.question == UNVERIFIABLE)
    assert "could not reach" in gap.detail
    assert "firefox" in gap.package


def test_unreachable_store_reports_once_not_per_snap():
    findings, _ = _run_store(
        _HEADER + "a 1 2 latest/stable mozilla✓ -\nb 1 2 latest/stable mozilla✓ -\n",
        info_rc=1, info_err="error: cannot communicate with server")
    gaps = [f for f in findings if f.question == UNVERIFIABLE]
    assert len(gaps) == 1 and "2 snap(s)" in gaps[0].detail


def test_sideloaded_snap_is_never_asked_about():
    """It was never in the Store, so asking would flag it on every run forever."""
    _, calls = _run_store(_HEADER + "local 1 x2 - - -\n")
    assert not [c for c in calls if c[:2] == ["snap", "info"]]
