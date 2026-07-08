"""Secure Boot check — state + the 2026 Microsoft cert-expiry matrix."""

from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.output import Output
from fettle.secure import secureboot
from fettle.secure.base import Scan

# A fixed "now" so the hardcoded cert dates give deterministic day counts:
# 2026-06-27 (KEK) is 11 days past; 2026-10-01 (PCA) is 85 days out.
_NOW = datetime(2026, 7, 8)


def _run(*, tools, cmd_out, capsys, verbose=False):
    out = Output(color=False, verbose=verbose)

    def fake_run(cmd, *, as_user=None, capture=False):
        return command.Proc(0, cmd_out.get(tuple(cmd), ""), "")

    scan = Scan(output=out, root=Path("/"), verbose=verbose)
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n in tools):
        secureboot.check(scan, now=_NOW)
    cap = capsys.readouterr()
    return cap.out + cap.err


def test_days_until_truncates_toward_zero():
    assert secureboot._days_until("2026-10-01", _NOW) == 85
    assert secureboot._days_until("2026-06-27", _NOW) == -11
    assert secureboot._days_until("not-a-date", _NOW) is None


def test_fully_migrated_reports_ok(capsys):
    out = _run(
        tools={"mokutil"},
        cmd_out={
            ("mokutil", "--sb-state"): "SecureBoot enabled",
            ("mokutil", "--kek"): "Microsoft Corporation KEK CA 2023\n",
            ("mokutil", "--db"): ("Microsoft UEFI CA 2023\n"
                                  "Microsoft Option ROM UEFI CA 2023\n"
                                  "Windows UEFI CA 2023\n"),
        },
        capsys=capsys,
    )
    assert "Secure Boot: Enabled" in out
    assert "Migration Status: Migrated to 2023 certificates" in out
    assert "KEK CA 2023 (KEK): Present" in out
    assert "KEK CA 2011 (KEK): Not present" in out   # absence of a 2011 cert is OK


def test_not_migrated_flags_expired_2011_certs(capsys):
    out = _run(
        tools={"mokutil"},
        cmd_out={
            ("mokutil", "--sb-state"): "SecureBoot enabled",
            ("mokutil", "--kek"): "Microsoft Corporation KEK CA 2011\n",
            ("mokutil", "--db"): ("Microsoft Corporation UEFI CA 2011\n"
                                  "Microsoft Windows Production PCA 2011\n"),
        },
        capsys=capsys,
    )
    assert "Migration Status: NOT MIGRATED (still on 2011 certificates)" in out
    # KEK 2011 expiry date is 11 days past -> EXPIRED; PCA 2011 is 85 days out.
    assert "KEK CA 2011 (KEK): Present (EXPIRED 11 days ago)" in out
    assert "Windows PCA 2011 (db): Present (expires in 85 days)" in out
    assert "eclypsium.com" in out  # the reference link is shown


def test_partial_migration_warns(capsys):
    out = _run(
        tools={"mokutil"},
        cmd_out={
            ("mokutil", "--sb-state"): "enabled",
            ("mokutil", "--kek"): "Microsoft Corporation KEK CA 2023\n",  # KEK migrated
            ("mokutil", "--db"): "Microsoft Corporation UEFI CA 2011\n",  # db not
        },
        capsys=capsys,
    )
    assert "Migration Status: Partial migration" in out


def test_no_tool_skips_cert_expiry(capsys):
    out = _run(tools=set(), cmd_out={}, capsys=capsys)
    assert "mokutil: Not installed" in out
    assert "Install 'efitools'" in out  # cert-expiry skipped with guidance


def test_efi_readvar_preferred_over_mokutil(capsys):
    calls = []

    def fake_run(cmd, *, as_user=None, capture=False):
        calls.append(tuple(cmd))
        return command.Proc(0, "Microsoft Corporation KEK CA 2023\n", "")

    scan = Scan(output=Output(color=False), root=Path("/"))
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n in {"efi-readvar", "mokutil"}):
        secureboot.check(scan, now=_NOW)
    assert any(c[:2] == ("efi-readvar", "-v") for c in calls)
    assert not any(c[0] == "mokutil" and c[1] in ("--kek", "--db") for c in calls)
