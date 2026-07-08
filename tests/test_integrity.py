"""sys-audit `packages` integrity — backend.verify_integrity on Arch + Debian."""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.arch import ArchBackend
from fettle.backends.debian import DebianBackend
from fettle.output import Output
from fettle.secure import audit
from fettle.secure.base import Scan


def _scan(tools, responses):
    out = Output(color=False)
    scan = Scan(output=out, root=Path("/"))

    def fake_run(cmd, *, as_user=None, capture=False):
        return command.Proc(0, responses.get(tuple(cmd), ""), "")
    return scan, patch("fettle.command.run", side_effect=fake_run), \
        patch("fettle.command.which", side_effect=lambda n: n in tools)


def _emit(backend, tools, responses, capsys):
    scan, p_run, p_which = _scan(tools, responses)
    with p_run, p_which:
        backend.verify_integrity(scan)
    cap = capsys.readouterr()
    return cap.out + cap.err


# -- Arch --------------------------------------------------------------------
def test_arch_paccheck_clean(capsys):
    out = _emit(ArchBackend(), {"paccheck", "pacman"},
                {("paccheck", "--sha256sum", "--quiet"): ""}, capsys)
    assert "Package Integrity: All packages verified" in out


def test_arch_paccheck_finds_issues(capsys):
    resp = {("paccheck", "--sha256sum", "--quiet"): "foo: /usr/bin/foo sha256 mismatch\n"}
    out = _emit(ArchBackend(), {"paccheck", "pacman"}, resp, capsys)
    assert "Package Integrity: Issues found" in out
    assert "sha256 mismatch" in out


def test_arch_falls_back_to_pacman_qkk(capsys):
    resp = {("pacman", "-Qkk"): ("bash: 1234 total files, 0 altered files\n"
                                 "warning: coreutils: /usr/bin/ls (Modification time mismatch)\n")}
    out = _emit(ArchBackend(), {"pacman"}, resp, capsys)  # no paccheck
    assert "Package Files: Modified files found" in out
    assert "Modification time mismatch" in out
    assert "0 altered files" not in out  # clean summary lines filtered out


# -- Debian ------------------------------------------------------------------
def test_debian_debsums_clean(capsys):
    resp = {("debsums",): "/usr/bin/x OK\n/usr/bin/y OK\n"}
    out = _emit(DebianBackend(), {"debsums"}, resp, capsys)
    assert "Package Integrity: All packages verified" in out


def test_debian_debsums_finds_issues(capsys):
    resp = {("debsums",): "/usr/bin/x OK\n/usr/bin/tampered FAILED\n"}
    out = _emit(DebianBackend(), {"debsums"}, resp, capsys)
    assert "Package Integrity: Issues found" in out
    assert "FAILED" in out and "OK" not in out.split("Issues found")[1]


def test_debian_falls_back_to_dpkg_verify(capsys):
    resp = {("dpkg", "--verify"): "??5?????? c /etc/hosts\n"}
    out = _emit(DebianBackend(), set(), resp, capsys)  # no debsums
    assert "debsums: Not installed" in out
    assert "/etc/hosts" in out


# -- category dispatch -------------------------------------------------------
def test_packages_category_delegates_to_backend(capsys):
    class FakeBackend:
        name = "arch"
        def verify_integrity(self, scan):
            scan.status("Package Integrity", "delegated!", "ok")

    scan = Scan(output=Output(color=False), root=Path("/"))
    with patch("fettle.distro.detect", return_value=FakeBackend()):
        audit._packages_check(scan)
    out = capsys.readouterr().out
    assert "Detected Distribution: arch" in out and "delegated!" in out


def test_packages_category_in_registry_and_list():
    assert "packages" in audit.CATEGORIES
    assert audit._registry()["packages"] is audit._packages_check
