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
    assert "3 packaged file(s) have CHANGED CONTENT" in out
    assert "/usr/bin/gzip" in out
    assert "4 config/ghost/doc, machine-regenerated or timestamp-only" in out


def test_config_only_drift_reports_no_altered_packages(capsys):
    va = "S.5....T.  c /etc/dnf/dnf.conf\n.....UG..  g /proc\n"
    _run(va=va)
    out = capsys.readouterr().out
    assert "No packaged file's contents have changed" in out
    assert "2 config/ghost/doc, machine-regenerated or timestamp-only" in out


def test_clean_system_reports_verified(capsys):
    _run(va="", va_rc=0)
    assert "No packaged file's contents have changed" in capsys.readouterr().out


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


# -- what differs matters more than how many files differ ----------------------
#
# Measured 2026-08-05 on three freshly built EL9/Fedora cloud images: all three
# reported a red integrity error, and across all 13 findings there was not one content
# change -- only mtimes and directory modes. A tripwire that is red on an untouched
# machine trains you to ignore it. These are the real rows from those guests.

_VA_ROCKY = """\
.M.......    /
.M.......    /boot
.......T.    /boot/efi/EFI/BOOT/BOOTX64.EFI
.......T.    /boot/efi/EFI/rocky/shim.efi
.......T.    /boot/grub2/fonts/unicode.pf2
"""


def test_timestamp_only_rows_are_not_an_integrity_finding(capsys):
    """mtime alone means nothing: cp, rsync and image builders all rewrite it."""
    _run(va=".......T.    /boot/grub2/fonts/unicode.pf2\n")
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "No packaged file's contents have changed" in out
    assert "CHANGED CONTENT" not in out.split("Expected")[0].replace(
        "No packaged file's contents have changed", "")
    assert "1 config/ghost/doc, machine-regenerated or timestamp-only" in out


def test_permission_drift_warns_but_is_not_a_content_finding(capsys):
    """True and worth seeing -- a world-writable binary matters -- but it is not the
    same event as bytes changing, and conflating them is what made a pristine image
    look compromised."""
    _run(va=_VA_ROCKY)
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "No packaged file's contents have changed" in out
    assert "2 packaged file(s) differ in mode, ownership or capabilities" in out
    assert "3 config/ghost/doc, machine-regenerated or timestamp-only" in out


def test_a_real_content_change_still_alarms(capsys):
    """The guard that proves the fix did not simply mute the check.

    A digest mismatch on an unmarked packaged file is the event this audit exists for,
    and it must survive every quieting change made above.
    """
    _run(va="..5......    /usr/bin/sshd\n" + _VA_ROCKY)
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "1 packaged file(s) have CHANGED CONTENT" in out
    assert "/usr/bin/sshd" in out


def test_missing_packaged_file_is_a_content_finding(capsys):
    """Something that was installed is gone -- that is not metadata drift."""
    _run(va="missing     /usr/bin/sudo\n")
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "1 packaged file(s) have CHANGED CONTENT" in out


def test_run_tmpfs_is_expected_not_drift(capsys):
    """/run is rebuilt every boot, so nothing there survives from a package install."""
    _run(va=".M.......    /run/cloud-init\n")
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "No packaged file's contents have changed" in out
    assert "mode, ownership or capabilities" not in out


def test_va_class_covers_every_attribute_column():
    """Each of rpm's nine columns lands in exactly one bucket -- no silent default."""
    from fettle.backends.rhel import _VA_CONTENT, _VA_PERMISSION, _va_class
    assert _VA_CONTENT | _VA_PERMISSION | {"T"} == set("SM5DLUGTP")
    assert not (_VA_CONTENT & _VA_PERMISSION)
    assert _va_class("S.5....T.") == "content"      # content wins over mtime
    assert _va_class(".M.....T.") == "permission"   # permission wins over mtime
    assert _va_class(".......T.") == "timestamp"
    assert _va_class("?????????") == "timestamp"    # nothing testable != a finding
