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


def _run(*, tools, cmd_out, capsys, verbose=False, as_root=False):
    """`as_root` is pinned rather than inherited from whoever runs the suite.

    Two tests below assert on a message that branches on `scan.is_root()`, so they
    passed for the developer (non-root) and failed under `sudo pytest` or in any
    container, which runs as root by default. A test's verdict must not depend on the
    uid of the person running it.
    """
    out = Output(color=False, verbose=verbose)

    def fake_run(cmd, *, as_user=None, capture=False, timeout=None):
        # A response may be "text" (exit 0) or ("text", rc) to drive failures.
        val = cmd_out.get(tuple(cmd), "")
        text, rc = val if isinstance(val, tuple) else (val, 0)
        return command.Proc(rc, text, "")

    scan = Scan(output=out, root=Path("/"), verbose=verbose)
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n in tools), \
         patch.object(Scan, "is_root", lambda self: as_root):
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

    def fake_run(cmd, *, as_user=None, capture=False, timeout=None):
        calls.append(tuple(cmd))
        return command.Proc(0, "Microsoft Corporation KEK CA 2023\n", "")

    scan = Scan(output=Output(color=False), root=Path("/"))
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n in {"efi-readvar", "mokutil"}):
        secureboot.check(scan, now=_NOW)
    assert any(c[:2] == ("efi-readvar", "-v") for c in calls)
    assert not any(c[0] == "mokutil" and c[1] in ("--kek", "--db") for c in calls)


# -- failed UEFI variable reads must not read as a healthy posture -----------
# Regression guard: stderr is merged into the command output, so a failed
# efi-readvar returns its own error message -- a non-empty string containing no
# certificate names. That sailed past the emptiness guard and rendered every row
# "Not present", which for the 2011 certs is printed green/ok. A failed read was
# displayed as a fully-migrated, healthy Secure Boot state.
def test_failed_cert_read_skips_instead_of_greening_every_row(capsys):
    out = _run(
        tools={"efi-readvar", "mokutil"},
        cmd_out={
            ("mokutil", "--sb-state"): "SecureBoot enabled",
            ("efi-readvar", "-v", "KEK"): ("Failed to read KEK: permission denied", 1),
            ("efi-readvar", "-v", "db"): ("Failed to read db: permission denied", 1),
        },
        capsys=capsys,
    )
    assert "could not read the UEFI variables" in out
    assert "Not present" not in out          # nothing may be asserted absent
    assert "Migration Status" not in out     # and no verdict derived from nothing


def test_partial_cert_read_skips_rather_than_half_reporting(capsys):
    """One store readable, the other not — the failed store's certs would all
    report "Not present", so the honest answer is to skip."""
    out = _run(
        tools={"efi-readvar", "mokutil"},
        cmd_out={
            ("mokutil", "--sb-state"): "SecureBoot enabled",
            ("efi-readvar", "-v", "KEK"): "Microsoft Corporation KEK CA 2011\n",
            ("efi-readvar", "-v", "db"): ("Failed to read db: permission denied", 1),
        },
        capsys=capsys,
    )
    assert "could not read the UEFI variables" in out
    assert "UEFI CA 2011 (db)" not in out


def test_successful_read_still_reports_normally(capsys):
    """The guard must not fire on a healthy read (regression on the fix itself)."""
    out = _run(
        tools={"efi-readvar", "mokutil"},
        cmd_out={
            ("mokutil", "--sb-state"): "SecureBoot enabled",
            ("efi-readvar", "-v", "KEK"): "Microsoft Corporation KEK CA 2023\n",
            ("efi-readvar", "-v", "db"): ("Microsoft UEFI CA 2023\n"
                                          "Windows UEFI CA 2023\n"),
        },
        capsys=capsys,
    )
    assert "could not read the UEFI variables" not in out
    assert "Migration Status" in out


def test_mokutil_sb_state_failure_is_loud(capsys):
    out = _run(
        tools={"mokutil"},
        cmd_out={("mokutil", "--sb-state"): ("mokutil: EFI variables are not supported", 1),
                 ("mokutil", "--kek"): "Microsoft Corporation KEK CA 2023\n",
                 ("mokutil", "--db"): "Microsoft UEFI CA 2023\n"},
        capsys=capsys,
    )
    assert "UNKNOWN — mokutil failed (exit 1)" in out


def test_firmware_without_secure_boot_is_an_answer_not_a_failure(capsys):
    """`mokutil --sb-state` exits 255 saying "This system doesn't support Secure
    Boot" — a definite negative, reported as "UNKNOWN — mokutil failed". Measured on
    the lab guests, which boot EDK II without SB support. Distinct from "EFI
    variables are not supported", which genuinely cannot answer (see above)."""
    out = _run(
        tools={"mokutil"},
        cmd_out={("mokutil", "--sb-state"): ("This system doesn't support Secure Boot", 255),
                 ("mokutil", "--kek"): "Microsoft Corporation KEK CA 2023\n",
                 ("mokutil", "--db"): "Microsoft UEFI CA 2023\n"},
        capsys=capsys,
    )
    assert "not supported by this firmware" in out
    assert "UNKNOWN" not in out
