"""Distro-neutral sys-audit checks — driven via root injection + command mocks."""

from unittest.mock import patch

from fettle import command
from fettle.output import Output
from fettle.secure import checks
from fettle.secure.base import Scan


def _scan(root, *, tools=(), responses=None, verbose=False):
    return _Harness(root, set(tools), responses or {}, verbose)


class _Harness:
    def __init__(self, root, tools, responses, verbose):
        self.scan = Scan(output=Output(color=False, verbose=verbose), root=root, verbose=verbose)
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
    assert "smartctl: Not installed" in capsys.readouterr().err


# -- bios / fwupd absent-tool paths ------------------------------------------
def test_bios_without_tools(tmp_path, capsys):
    with _scan(tmp_path) as scan:
        checks.bios(scan)
    cap = capsys.readouterr()
    assert "dmidecode: Not installed" in cap.err   # error -> stderr
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
    assert "fwupd: Not installed" in capsys.readouterr().err


# -- a security check that could not run must say so ------------------------
# Regression guard: these verdicts are substring matches on the tool's output.
# When chipsec failed, the output matched neither "passed" nor "failed", so the
# check printed NOTHING AT ALL -- and a missing line reads to a human as "no
# problem here". An un-run check is now a finding.
def _chipsec_scan(tmp_path, responses):
    (tmp_path / "opt/chipsec").mkdir(parents=True)
    (tmp_path / "opt/chipsec/chipsec_main.py").write_text("")
    return _scan(tmp_path, tools=(), responses=responses)


def _chipsec_cmd(tmp_path, module):
    return ("python3", str(tmp_path / "opt/chipsec/chipsec_main.py"), "-m", module)


def test_chipsec_failure_reports_unknown_not_silence(tmp_path, capsys):
    responses = {_chipsec_cmd(tmp_path, "common.me_mfg_mode"):
                 ("ERROR: could not load driver", 1),
                 _chipsec_cmd(tmp_path, "common.bios_wp"):
                 ("ERROR: could not load driver", 1)}
    with patch("os.geteuid", return_value=0), \
            _chipsec_scan(tmp_path, responses) as scan:
        checks.firmware(scan)
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "ME Manufacturing Mode: UNKNOWN — chipsec failed (exit 1)" in out
    assert "BIOS Write Protection: UNKNOWN — chipsec failed (exit 1)" in out


def test_chipsec_ran_but_gave_no_verdict_is_neutral(tmp_path, capsys):
    """Ran cleanly, matched neither verdict (e.g. module N/A on this hardware) —
    that is Unknown, not an error; unsupported hardware must not go red."""
    responses = {_chipsec_cmd(tmp_path, "common.me_mfg_mode"): "Module not applicable",
                 _chipsec_cmd(tmp_path, "common.bios_wp"): "Module not applicable"}
    with patch("os.geteuid", return_value=0), \
            _chipsec_scan(tmp_path, responses) as scan:
        checks.firmware(scan)
    out = capsys.readouterr().out
    assert "ME Manufacturing Mode: Unknown (no verdict reported)" in out
    assert "chipsec failed" not in out


def test_chipsec_normal_verdicts_unchanged(tmp_path, capsys):
    """Guard on the fix itself: healthy runs must report exactly as before."""
    responses = {_chipsec_cmd(tmp_path, "common.me_mfg_mode"): "[+] PASSED: ME not in mfg mode",
                 _chipsec_cmd(tmp_path, "common.bios_wp"): "[-] FAILED: BIOS is not write protected"}
    with patch("os.geteuid", return_value=0), \
            _chipsec_scan(tmp_path, responses) as scan:
        checks.firmware(scan)
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert "ME Manufacturing Mode: Disabled (PASSED)" in out
    assert "BIOS Write Protection: Disabled (FAILED)" in out


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
    assert "UNKNOWN — fwupdmgr failed (exit 1)" in out
    assert "Updates available" not in out
