"""Distro-neutral sys-audit checks — driven via root injection + command mocks."""

import json
from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.output import Output
from fettle.secure import checks
from fettle.secure.base import Scan


def _scan(root, *, tools=(), responses=None, verbose=False, config=None):
    return _Harness(root, set(tools), responses or {}, verbose, config)


class _Harness:
    def __init__(self, root, tools, responses, verbose, config=None):
        self.scan = Scan(output=Output(color=False, verbose=verbose), root=root,
                         verbose=verbose, config=config)
        self.tools, self.responses = tools, responses

    def __enter__(self):
        def fake_run(cmd, *, as_user=None, capture=False):
            # A response may be "text" (exit 0) or ("text", rc) to drive failures.
            val = self.responses.get(tuple(cmd), "")
            text, rc = val if isinstance(val, tuple) else (val, 0)
            return command.Proc(rc, text, "")
        self._p1 = patch("fettle.command.run", side_effect=fake_run)
        self._p2 = patch("fettle.command.which", side_effect=lambda n: n in self.tools)
        self._p1.start()
        self._p2.start()
        return self.scan

    def __exit__(self, *a):
        self._p1.stop()
        self._p2.stop()


# -- microcode (pure file reads) ---------------------------------------------
def test_microcode_version_and_vulns(tmp_path, capsys):
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/cpuinfo").write_text(
        "processor\t: 0\nvendor_id\t: AuthenticAMD\nmicrocode\t: 0x830107c\n")
    vdir = tmp_path / "sys/devices/system/cpu/vulnerabilities"
    vdir.mkdir(parents=True)
    (vdir / "meltdown").write_text("Not affected\n")
    (vdir / "spectre_v2").write_text("Mitigation: Retpolines\n")
    (vdir / "l1tf").write_text("Vulnerable\n")
    with _scan(tmp_path) as scan:
        checks.microcode(scan)
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "Microcode Version: 0x830107c" in out
    assert "meltdown: Not affected" in out       # ok (stdout)
    assert "spectre_v2: Mitigation: Retpolines" in out  # ok
    assert "l1tf: Vulnerable" in cap.err          # warn -> stderr


# -- tpm ----------------------------------------------------------------------
def test_tpm_present_with_version(tmp_path, capsys):
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev/tpm0").write_text("")
    (tmp_path / "sys/class/tpm/tpm0").mkdir(parents=True)
    (tmp_path / "sys/class/tpm/tpm0/tpm_version_major").write_text("2\n")
    with _scan(tmp_path) as scan:
        checks.tpm(scan)
    out = capsys.readouterr().out
    assert "TPM Device: Present (/dev/tpm0)" in out
    assert "TPM Version: 2.x" in out


def test_tpm_absent(tmp_path, capsys):
    (tmp_path / "dev").mkdir()
    with _scan(tmp_path) as scan:
        checks.tpm(scan)
    assert "TPM Device: Not found" in capsys.readouterr().err  # warn -> stderr


# -- storage (device enumeration + partition filtering) ----------------------
def test_storage_lists_devices_skipping_partitions(tmp_path, capsys):
    dev = tmp_path / "dev"
    dev.mkdir()
    for n in ("sda", "sda1", "nvme0n1", "nvme0n1p1"):
        (dev / n).write_text("")
    smart = "Device Model:     Samsung SSD 990\nFirmware Version: 4B2QJXD7\nSerial Number: S6\n"
    responses = {("smartctl", "-i", str(dev / "sda")): smart,
                 ("smartctl", "-i", str(dev / "nvme0n1")): smart}
    with _scan(tmp_path, tools={"smartctl"}, responses=responses) as scan:
        checks.storage(scan)
    out = capsys.readouterr().out
    assert str(dev / "sda") in out and str(dev / "nvme0n1") in out
    assert str(dev / "sda1") not in out          # partition skipped
    assert str(dev / "nvme0n1p1") not in out     # nvme partition skipped
    assert "Model: Samsung SSD 990" in out and "Firmware: 4B2QJXD7" in out


def test_storage_without_smartctl(tmp_path, capsys):
    with _scan(tmp_path) as scan:
        checks.storage(scan)
    assert "smartctl: not installed" in capsys.readouterr().err


# -- bios / fwupd absent-tool paths ------------------------------------------
def test_bios_without_tools(tmp_path, capsys):
    with _scan(tmp_path) as scan:
        checks.bios(scan)
    cap = capsys.readouterr()
    assert "dmidecode: not installed" in cap.err   # warn -> stderr
    assert "inxi: Not installed" in cap.err


def test_fwupd_up_to_date(tmp_path, capsys):
    responses = {("fwupdmgr", "get-updates", "--no-unreported-check"): "No updates available",
                 ("fwupdmgr", "get-devices", "--no-unreported-check"): "",
                 ("fwupdmgr", "security", "--force"): ""}
    with _scan(tmp_path, tools={"fwupdmgr"}, responses=responses) as scan:
        checks.fwupd(scan)
    assert "Firmware Updates: System is up to date" in capsys.readouterr().out


def test_fwupd_absent(tmp_path, capsys):
    with _scan(tmp_path) as scan:
        checks.fwupd(scan)
    assert "fwupd: not installed" in capsys.readouterr().err


# -- a security check that could not run must say so ------------------------
# Regression guard: these verdicts are substring matches on the tool's output.
# When chipsec failed, the output matched neither "passed" nor "failed", so the
# check printed NOTHING AT ALL -- and a missing line reads to a human as "no
# problem here". An un-run check is now a finding.
def _chipsec(tmp_path, capsys, *, summary=None, stdout="", rc=0, root=True,
             configured=True, write_json=True):
    """Drive the firmware check with a stubbed chipsec.

    chipsec writes its results to the file named by `-j`; the stub does the same, so
    the test exercises the real parse path rather than a mocked return value.
    """
    from fettle.config import Config
    cfg = Config()
    if configured:
        cfg.secure = {"chipsec_cmd": ["/usr/bin/chipsec_main"]}

    def fake_run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        if write_json and "-j" in cmd:
            Path(cmd[cmd.index("-j") + 1]).write_text(json.dumps(summary or {}))
        return command.Proc(rc, stdout, "")

    scan = Scan(output=Output(color=False), root=tmp_path, config=cfg)
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", return_value=False), \
         patch("os.geteuid", return_value=0 if root else 1000):
        checks.firmware(scan)
    cap = capsys.readouterr()
    return cap.out + cap.err


_REAL_SUMMARY = {                      # measured: sudo chipsec_main on an AMD Ryzen box
    "total": 33,
    "failed to run": ["chipsec.modules.common.cpu.cpu_info"],
    "passed": ["chipsec.modules.common.bios_kbrd_buffer",
               "chipsec.modules.common.uefi.access_uefispec"],
    "information": ["chipsec.modules.common.firmware_info"],
    "failed": ["chipsec.modules.common.rom_armor"],
    "warnings": ["chipsec.modules.common.secureboot.variables"],
    "not applicable": [f"chipsec.modules.m{i}" for i in range(26)],
    "archived": ["chipsec.modules.common.uefi.s3bootscript"],
}
_UNKNOWN = ("ERROR: Unknown Platform: VID = 0x1022, DID = 0x1480\n"
            "[!] Results from this system may be incorrect.\n")


def test_chipsec_reports_every_bucket_it_found(tmp_path, capsys):
    """fettle ran exactly two modules -- me_mfg_mode and bios_wp -- chosen when the
    only target was Intel. Measured on an AMD workstation BOTH are NOT APPLICABLE, so
    the check produced nothing, while the default set found an unprotected flash and
    Secure Boot disabled."""
    out = _chipsec(tmp_path, capsys, summary=_REAL_SUMMARY)
    assert "common.rom_armor: FAILED" in out
    assert "common.secureboot.variables: warning" in out
    assert "common.cpu.cpu_info: could not run" in out
    assert "33 run — 2 passed" in out


def test_not_applicable_is_a_counted_coverage_gap(tmp_path, capsys):
    """26 of 33 were NOT APPLICABLE for want of register definitions. That is not 26
    things being fine."""
    out = _chipsec(tmp_path, capsys, summary=_REAL_SUMMARY)
    assert "26 not applicable" in out
    assert "no checks for this platform" in out


def test_an_unrecognised_platform_leads_the_report(tmp_path, capsys):
    """chipsec says so three times over, and it matters more than any single verdict:
    presenting the seven that ran without the caveat is a blind scan reported as a
    scan."""
    out = _chipsec(tmp_path, capsys, summary=_REAL_SUMMARY, stdout=_UNKNOWN)
    assert "does NOT recognise this platform" in out
    assert "provisional" in out


def test_a_recognised_platform_gets_no_caveat(tmp_path, capsys):
    out = _chipsec(tmp_path, capsys, summary=_REAL_SUMMARY,
                   stdout="[CHIPSEC] Platform: Coffeelake\n")
    assert "does NOT recognise" not in out


def test_no_readable_results_is_not_a_clean_scan(tmp_path, capsys):
    """The file chipsec was told to write is missing or unparseable -- so nothing was
    audited, and that must not render like nothing was wrong."""
    out = _chipsec(tmp_path, capsys, write_json=False, rc=1)
    assert "produced no readable results" in out and "NOT audited" in out


def test_unconfigured_chipsec_says_what_to_write(tmp_path, capsys):
    out = _chipsec(tmp_path, capsys, configured=False)
    assert "not configured — firmware was NOT audited" in out
    assert "[secure]" in out and "chipsec_cmd" in out


def test_unprivileged_says_it_did_not_audit(tmp_path, capsys):
    out = _chipsec(tmp_path, capsys, summary=_REAL_SUMMARY, root=False)
    assert "needs root — firmware was NOT audited" in out


def test_a_string_chipsec_cmd_is_accepted(tmp_path, capsys):
    """`chipsec_cmd = "/usr/bin/chipsec_main"` is the natural thing to write for a
    single-word command; accepting only a list would fail with no explanation."""
    from fettle.config import Config
    from fettle.secure.checks import _chipsec_cmd
    cfg = Config()
    cfg.secure = {"chipsec_cmd": "/usr/bin/chipsec_main"}
    assert _chipsec_cmd(Scan(output=Output(color=False), config=cfg)) == \
        ["/usr/bin/chipsec_main"]


def test_fwupd_no_updates_stays_ok_despite_nonzero_exit(tmp_path, capsys):
    """fwupdmgr exits non-zero when there is nothing to do, so an up-to-date
    system must not be reported as a failure."""
    responses = {("fwupdmgr", "get-updates", "--no-unreported-check"):
                 ("No updates available", 2),
                 ("fwupdmgr", "get-devices", "--no-unreported-check"): "",
                 ("fwupdmgr", "security", "--force"): ""}
    with _scan(tmp_path, tools={"fwupdmgr"}, responses=responses) as scan:
        checks.fwupd(scan)
    assert "Firmware Updates: System is up to date" in capsys.readouterr().out


def test_fwupd_real_failure_is_not_reported_as_updates_available(tmp_path, capsys):
    responses = {("fwupdmgr", "get-updates", "--no-unreported-check"):
                 ("failed to connect to daemon", 1),
                 ("fwupdmgr", "get-devices", "--no-unreported-check"): "",
                 ("fwupdmgr", "security", "--force"): ""}
    with _scan(tmp_path, tools={"fwupdmgr"}, responses=responses) as scan:
        checks.fwupd(scan)
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "UNKNOWN — fwupdmgr exited 1" in out
    assert "Updates available" not in out


def test_fwupd_exit_2_is_up_to_date_not_an_error(tmp_path, capsys):
    """fwupd documents 2 as "no actions but successfully executed", and prints
    "Devices with no available firmware updates:" — which the old English-string
    guard ("no updates") did not match, so a fully patched machine was an ERROR."""
    responses = {("fwupdmgr", "get-updates", "--no-unreported-check"):
                 ("Devices with no available firmware updates:\n • SSD 850 EVO", 2),
                 ("fwupdmgr", "get-devices", "--no-unreported-check"): "",
                 ("fwupdmgr", "security", "--force"): ""}
    with _scan(tmp_path, tools={"fwupdmgr"}, responses=responses) as scan:
        checks.fwupd(scan)
    cap = capsys.readouterr()
    assert "System is up to date" in cap.out + cap.err
    assert "UNKNOWN" not in cap.out + cap.err


# -- the scan must end in a verdict ------------------------------------------
def _summary_of(records):
    from fettle.output import Output
    from fettle.secure import audit
    from fettle.secure.base import Scan
    scan = Scan(output=Output(color=False), records=list(records))
    audit._summarize(scan)
    scan.output.print_summary()
    return scan.output


def test_findings_reach_the_summary(capsys):
    """Ten categories reported through status() and nothing reached the summary, so
    a workstation with Secure Boot off and failing integrity ended with
    "nothing to report"."""
    out = _summary_of([
        {"category": "c", "sub": "", "label": "Secure Boot", "value": "Disabled",
         "level": "warn"},
        {"category": "c", "sub": "", "label": "Package Integrity",
         "value": "3 file(s) differ", "level": "error"},
    ])
    text = capsys.readouterr().out
    assert "nothing to report" not in text
    assert "Secure Boot" in text and "Package Integrity" in text
    assert out.had_failures          # error sets the exit status


def test_warnings_alone_do_not_fail_the_run(capsys):
    """A missing TPM is a fact about the machine the operator may have chosen; it
    must not make every scan exit non-zero."""
    out = _summary_of([{"category": "c", "sub": "", "label": "TPM Device",
                        "value": "Not found", "level": "warn"}])
    assert "!" in capsys.readouterr().out
    assert not out.had_failures


def test_clean_scan_says_so(capsys):
    _summary_of([{"category": "c", "sub": "", "label": "Secure Boot",
                  "value": "Enabled", "level": "ok"}])
    assert "nothing flagged" in capsys.readouterr().out


def test_chipsec_command_is_configured_not_guessed(tmp_path, capsys):
    """Measured on the QA host: chipsec 2.0.7 installed as a distro package at
    /usr/bin/chipsec_main, and fettle reported "Not found" because it only looked for
    a git checkout at /opt/chipsec/chipsec_main.py. Searching harder would have traded
    one wrong guess for another -- the three layouts need three different invocations,
    so a path alone is not enough."""
    out = _chipsec(tmp_path, capsys, summary={"total": 1, "passed": ["m"]})
    assert "Chipsec: /usr/bin/chipsec_main" in out
    assert "1 run — 1 passed" in out

