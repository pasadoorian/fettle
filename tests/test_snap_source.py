"""Snap source provider — publisher verification + confinement."""

from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import OVER_PRIVILEGED, UNOFFICIAL_SOURCE, UNVERIFIED_PUBLISHER
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
