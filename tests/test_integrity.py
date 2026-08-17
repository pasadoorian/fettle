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
        val = responses.get(tuple(cmd), "")
        text, rc = val if isinstance(val, tuple) else (val, 0)
        return command.Proc(rc, text, "")
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
    resp = {("paccheck", "--sha256sum", "--quiet"):
            ("foo: '/usr/bin/foo' sha256sum mismatch\n", 1)}   # measured: rc 1 = found
    out = _emit(ArchBackend(), {"paccheck", "pacman"}, resp, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "sha256sum mismatch" in out


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


_DPKG_PKGS = ("dpkg-query", "-W", "-f", "${Package}\\n")


def test_debian_falls_back_to_dpkg_verify(capsys):
    resp = {_DPKG_PKGS: "base-files\nnetbase\n",
            ("dpkg", "--verify"): "??5?????? c /etc/hosts\n"}
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


# -- a verifier that FAILED is not a verifier that found nothing -------------
# Exit codes measured in containers, because none of them mean what you would guess:
#
#     command             clean   found a discrepancy   could not run
#     paccheck            0       1                     1  (`error:`, no quoted path)
#     pacman -Qkk         0       1                     1  (`error:` lines)
#     debsums             0       2                     255
#     dpkg --verify       0       0                     0, with no output at all
#
# So `paccheck` and `-Qkk` are classified by output shape, `debsums` by status, and
# `dpkg --verify` cannot be classified at all — its silence has to be earned by first
# proving the dpkg database lists packages.
_PACCHECK = ("paccheck", "--sha256sum", "--quiet")


def test_arch_a_paccheck_that_failed_silently_is_not_a_clean_result(capsys):
    """The plain false-clean: `run_text` discarded the status, so a verifier that ran
    and died reported exactly what a verifier that checked everything reports."""
    out = _emit(ArchBackend(), {"paccheck", "pacman"}, {_PACCHECK: ("", 1)}, capsys)
    assert "no unexplained differences" not in out
    assert "packages were NOT verified" in out


def test_arch_a_paccheck_error_is_not_filed_as_an_altered_file(capsys):
    """The inverse, and the reason shape beats status here: stderr is merged into the
    output, so `error: failed to initialize alpm.` (measured) was counted as a file
    that differs from its package — a failure rendered as a finding."""
    out = _emit(ArchBackend(), {"paccheck", "pacman"},
                {_PACCHECK: ("error: failed to initialize alpm.\n", 1)}, capsys)
    assert "file(s) differ from their package" not in out
    assert "paccheck failed (exit 1)" in out


def test_arch_paccheck_exit_1_with_findings_is_still_findings(capsys):
    """paccheck exits 1 for a mismatch as well as for failure (measured), so the status
    alone must not be allowed to turn real findings into blindness."""
    out = _emit(ArchBackend(), {"paccheck", "pacman"},
                {_PACCHECK: ("openssh: '/usr/bin/sshd' sha256sum mismatch\n", 1)}, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "NOT verified" not in out


def test_arch_qkk_exit_1_from_findings_and_from_failure_are_told_apart(capsys):
    # A stock container exits 1 legitimately, because the image build strips files.
    found = _emit(ArchBackend(), {"pacman"},
                  {("pacman", "-Qkk"):
                   ("warning: coreutils: /usr/bin/ls (Size mismatch)\n", 1)}, capsys)
    assert "Package Files: 1 package(s) with modified files" in found
    assert "NOT verified" not in found

    failed = _emit(ArchBackend(), {"pacman"},
                   {("pacman", "-Qkk"):
                    ("error: 'failed to resolve path '/nonexistent''\n", 1)}, capsys)
    assert "files were NOT verified" in failed
    assert "package(s) with modified files" not in failed


def test_arch_a_missing_pacman_is_blindness_not_a_finding(capsys):
    scan, p_run, p_which = _scan(set(), {})
    with p_run, p_which:
        ArchBackend().verify_integrity(scan)
    assert [r for r in scan.records if r["blind"]], "recorded as a finding, not blindness"


def test_debian_a_debsums_that_failed_is_not_a_clean_result(capsys):
    # Measured: 0 = clean, 2 = discrepancies, 255 = debsums itself failed.
    out = _emit(DebianBackend(), {"debsums"},
                {("debsums",): ("Unknown option: not-a-flag\n", 255)}, capsys)
    assert "no unexplained differences" not in out
    assert "debsums failed (exit 255)" in out


def test_debian_debsums_exit_2_is_findings_not_failure(capsys):
    out = _emit(DebianBackend(), {"debsums"},
                {("debsums",): ("/usr/bin/x OK\n/usr/bin/tampered FAILED\n", 2)}, capsys)
    assert "Package Integrity: 1 file(s) differ" in out
    assert "NOT verified" not in out


def test_debian_dpkg_verify_silence_is_not_believed_without_a_package_list(capsys):
    """`dpkg --verify` exits 0 with no output against a database it cannot read —
    byte-identical to a clean system (measured). So an empty result only means "clean"
    once the database is known to hold packages."""
    out = _emit(DebianBackend(), set(), {("dpkg", "--verify"): ""}, capsys)
    assert "No issues detected" not in out
    assert "files were NOT verified" in out


def test_debian_dpkg_verify_conffile_rows_are_still_counted(capsys):
    """The file-type marker is optional and `c` is the commonest row on a real machine
    (measured: `??5?????? c /etc/default/useradd`). A pattern that missed it would turn
    every edited conffile into unparseable noise."""
    resp = {_DPKG_PKGS: "base-files\n",
            ("dpkg", "--verify"): ("??5??????   /usr/bin/hostid\n"
                                   "missing     /usr/bin/nproc\n"
                                   "??5?????? c /etc/default/useradd\n")}
    out = _emit(DebianBackend(), set(), resp, capsys)
    assert "Package Files: 3 discrepancy line(s)" in out
    assert "coverage is unproven" not in out


def test_debian_a_dpkg_diagnostic_is_not_counted_as_a_discrepancy(capsys):
    resp = {_DPKG_PKGS: "base-files\n",
            ("dpkg", "--verify"): "dpkg: error: cannot access /var/lib/dpkg/status\n"}
    out = _emit(DebianBackend(), set(), resp, capsys)
    assert "discrepancy line(s)" not in out
    assert "coverage is unproven" in out


# -- Bug B: an all-blind run must not also claim the files matched -----------
def test_an_all_blind_run_does_not_also_say_the_files_match(capsys):
    """The clean gate omitted `unreadable`, so a run that verified NOTHING printed
    "did NOT verify: ..." and "installed files match their packages" in the same
    summary — the second sentence contradicting the first."""
    from fettle import integrity
    from fettle.backends.base import Context

    class _Blind:
        name = "test"

        def verify_integrity(self, scan):
            scan.status("Package Integrity", "UNKNOWN — the database could not be "
                        "queried; packages were NOT verified", "error", blind=True)

    out_obj = Output(color=False)
    ctx = Context(output=out_obj, config=Config(), dry_run=True)
    integrity.run(_Blind(), ctx)
    out_obj.print_summary()          # summary lines are queued, not printed inline
    out = capsys.readouterr().out
    assert "did NOT verify" in out
    assert "installed files match their packages" not in out
