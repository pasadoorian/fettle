"""RHEL backend — sys-audit package integrity via `rpm -Va`.

Fixtures are real `rpm -Va` output captured from AlmaLinux 10, including rows for a
deliberately tampered binary and config file.
"""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.rhel import RhelBackend
from fettle.output import Output
from fettle.secure.base import Scan

# Real output. Note the shapes: `missing` instead of an attribute mask, a `g` ghost
# row, a `c` config row, and a bare packaged file (the tampered binary).
_VA = """\
missing     /boot
.....UG..  g /proc
.....UG..  g /sys
missing     /usr/share/i18n/charmaps
.M.......  c /etc/machine-id
S.5....T.  c /etc/dnf/dnf.conf
S.5....T.    /usr/bin/gzip
"""


def _scan(**kw):
    return Scan(output=Output(color=False), root=Path("/"), **kw)


def _run(*, va=_VA, va_rc=1, probe="rpm-4.19.1-1.el10.x86_64\n", probe_rc=0,
         has_rpm=True, **scan_kw):
    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:3] == ["rpm", "-q", "rpm"]:
            return command.Proc(probe_rc, probe, "")
        if c[:2] == ["rpm", "-Va"]:
            return command.Proc(va_rc, va, "")
        return command.Proc(0, "", "")

    scan = _scan(**scan_kw)
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: has_rpm and n == "rpm"):
        RhelBackend().verify_integrity(scan)
    return scan


# -- the signal vs the noise -------------------------------------------------
def test_only_unmarked_rows_count_as_altered(capsys):
    """Config/ghost/doc rows legitimately differ — on a stock system they are most of
    the output. Only a row with no file-type marker is a packaged binary/library."""
    _run()
    cap = capsys.readouterr()
    out = cap.out + cap.err
    # 3 unmarked rows: /boot and /usr/share/i18n/charmaps are MISSING packaged
    # paths (container image-stripping here, but a real finding on a real host),
    # plus the tampered /usr/bin/gzip. The other 4 carry c/g markers.
    assert "3 packaged file(s) differ" in out
    assert "/usr/bin/gzip" in out
    assert "4 config/ghost/doc file(s) differ" in out


def test_config_only_drift_reports_no_altered_packages(capsys):
    va = "S.5....T.  c /etc/dnf/dnf.conf\n.....UG..  g /proc\n"
    _run(va=va)
    out = capsys.readouterr().out
    assert "No packaged files altered" in out
    assert "2 config/ghost/doc file(s) differ" in out


def test_clean_system_reports_verified(capsys):
    _run(va="", va_rc=0)
    assert "No packaged files altered" in capsys.readouterr().out


# -- exit codes: rpm -Va exits 1 merely for FINDING things -------------------
def test_exit_one_is_findings_not_failure(capsys):
    """rpm -Va returns 1 whenever it finds any discrepancy. Treating non-zero as
    failure would mark every real system unverifiable."""
    _run(va_rc=1)
    out = capsys.readouterr()
    assert "UNKNOWN" not in (out.out + out.err)


def test_exit_above_one_is_reported_as_unknown(capsys):
    _run(va_rc=2)
    err = capsys.readouterr().err
    assert "UNKNOWN" in err and "NOT verified" in err


# -- the failure mode rpm's exit code cannot express -------------------------
def test_unreadable_database_is_not_reported_as_clean(capsys):
    """Measured: `rpm -Va` against an unusable database exits 0 with NO output —
    byte-identical to a clean system. The db probe is the only thing standing between
    "could not look" and "all verified"."""
    scan = _run(va="", va_rc=0, probe="", probe_rc=1)
    err = capsys.readouterr().err
    assert "UNKNOWN" in err and "rpm database could not be queried" in err
    assert not any(r.get("value", "").startswith("No packaged files")
                   for r in scan.records)


def test_missing_rpm_is_reported(capsys):
    _run(has_rpm=False)
    assert "rpm: Not installed" in capsys.readouterr().err


# -- parsing -----------------------------------------------------------------
def test_missing_rows_are_treated_as_altered_when_unmarked():
    """`missing /boot` has no marker, so it is a packaged file that vanished."""
    from fettle.backends.rhel import _VA_RE
    m = _VA_RE.match("missing     /boot")
    assert m and m.group(1) == "missing" and m.group(2) is None and m.group(3) == "/boot"


def test_marker_and_path_are_parsed_unambiguously():
    from fettle.backends.rhel import _VA_RE
    m = _VA_RE.match("S.5....T.  c /etc/dnf/dnf.conf")
    assert m.group(2) == "c" and m.group(3) == "/etc/dnf/dnf.conf"
    m = _VA_RE.match("S.5....T.    /usr/bin/gzip")
    assert m.group(2) is None and m.group(3) == "/usr/bin/gzip"


def test_path_containing_spaces_survives():
    """Splitting on whitespace would truncate these; the regex anchors on the `/`."""
    from fettle.backends.rhel import _VA_RE
    m = _VA_RE.match("S.5....T.  c /etc/some dir/my file.conf")
    assert m.group(3) == "/etc/some dir/my file.conf"
