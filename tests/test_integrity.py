"""`fettle pkg-integrity` (-V) — backend.verify_integrity on Arch + Debian.

Split out of sys-audit's `packages` category in v0.72.0.
"""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.arch import ArchBackend
from fettle.backends.debian import DebianBackend
from fettle.config import Config
from fettle import config
from fettle.output import Output
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
    assert "Package Integrity: no unexplained differences" in out


def test_arch_paccheck_finds_issues(capsys):
    resp = {("paccheck", "--sha256sum", "--quiet"): "foo: /usr/bin/foo sha256 mismatch\n"}
    out = _emit(ArchBackend(), {"paccheck", "pacman"}, resp, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "sha256 mismatch" in out


def test_arch_falls_back_to_pacman_qkk(capsys):
    resp = {("pacman", "-Qkk"): ("bash: 1234 total files, 0 altered files\n"
                                 "warning: coreutils: /usr/bin/ls (Modification time mismatch)\n")}
    out = _emit(ArchBackend(), {"pacman"}, resp, capsys)  # no paccheck
    assert "Package Files: 1 package(s) with modified files" in out
    assert "Modification time mismatch" in out
    assert "0 altered files" not in out  # clean summary lines filtered out


# -- Debian ------------------------------------------------------------------
def test_debian_debsums_clean(capsys):
    resp = {("debsums",): "/usr/bin/x OK\n/usr/bin/y OK\n"}
    out = _emit(DebianBackend(), {"debsums"}, resp, capsys)
    assert "Package Integrity: no unexplained differences" in out


def test_debian_debsums_finds_issues(capsys):
    resp = {("debsums",): "/usr/bin/x OK\n/usr/bin/tampered FAILED\n"}
    out = _emit(DebianBackend(), {"debsums"}, resp, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "FAILED" in out and "OK" not in out.split("differ from")[1]


def test_debian_falls_back_to_dpkg_verify(capsys):
    resp = {("dpkg", "--verify"): "??5?????? c /etc/hosts\n"}
    out = _emit(DebianBackend(), set(), resp, capsys)  # no debsums
    assert "debsums: Not installed" in out
    assert "/etc/hosts" in out


# -- category dispatch -------------------------------------------------------
# -- "could not read" is not "found a problem" -------------------------------
def test_arch_unreadable_files_are_not_counted_as_integrity_issues(capsys):
    """Unprivileged, paccheck emits a `read error` line per file it cannot open —
    ~30 on a stock desktop. They were reported as integrity issues."""
    resp = {("paccheck", "--sha256sum", "--quiet"):
            "foo: '/usr/bin/foo' sha256sum mismatch\n"
            "warning: cups: '/usr/bin/cupsd' read error (Permission denied)\n"
            "warning: dbus: '/usr/lib/helper' read error (Permission denied)\n"}
    out = _emit(ArchBackend(), {"paccheck", "pacman"}, resp, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "Not verified: 2 file(s) could not be read" in out


def test_debian_packages_without_checksums_are_a_gap_not_a_finding(capsys):
    """debsums logs `no md5sums for <pkg>` to stderr, which run_text merges in, so
    a package that simply ships no checksums counted as an integrity issue."""
    resp = {("debsums",): "/usr/bin/x OK\n/usr/bin/tampered FAILED\n"
                          "debsums: no md5sums for somepkg\n"}
    out = _emit(DebianBackend(), {"debsums"}, resp, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "Not verified: 1 package(s) ship no checksums" in out


# -- the standalone action (v0.72.0: moved out of sys-audit) -----------------
def test_pkg_integrity_is_its_own_action_not_a_sys_audit_category():
    from fettle import actions, cli
    from fettle.secure import audit
    assert "packages" not in audit.CATEGORIES        # a package question, not firmware
    assert "pkg_integrity" in actions.HANDLERS
    assert (("-V", "--pkg-integrity"), "pkg_integrity") in cli.AUDIT_ACTIONS
    assert "pkg_integrity" not in config.DEFAULT_ACTIONS   # 35s+; opt-in


def test_regenerated_files_are_not_findings():
    """depmod rewrites the whole modules.* index after any kernel package lands, so
    these differ on every machine — 14 of 17 "differences" on the QA workstation."""
    from fettle.backends.base import is_regenerated
    assert is_regenerated("/usr/lib/modules/6.12.96-1-MANJARO/modules.dep")
    assert is_regenerated("/usr/lib/vlc/plugins/plugins.dat")
    assert is_regenerated("/var/lib/pacman-mirrors/mirrors.json")
    assert not is_regenerated("/usr/bin/sshd")
    assert not is_regenerated("/opt/vscodium-bin/resources/app/product.json")


def test_arch_splits_regenerated_from_unexplained(capsys):
    resp = {("paccheck", "--sha256sum", "--quiet"):
            "linux612: '/usr/lib/modules/6.12.96-1/modules.dep' sha256sum mismatch\n"
            "openssh: '/usr/bin/sshd' sha256sum mismatch\n"}
    out = _emit(ArchBackend(), {"paccheck", "pacman"}, resp, capsys)
    assert "Package Integrity: 1 file(s) differ" in out   # sshd only
    assert "Expected differences: 1 file(s) regenerated" in out


def test_clean_integrity_reports_a_verdict(capsys):
    """The action owns its summary — it is no longer folded into sys-audit's."""
    from fettle import integrity
    from fettle.backends.base import Context
    from fettle.output import Output

    class _B:
        name = "arch"

        def verify_integrity(self, scan):
            scan.status("Package Integrity", "no unexplained differences", "ok")

    ctx = Context(output=Output(color=False), config=Config())
    integrity.run(_B(), ctx)
    ctx.output.print_summary()
    assert "installed files match their packages" in capsys.readouterr().out
