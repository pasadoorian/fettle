"""Remote sys-audit — command construction, arg forwarding, and a real zipapp."""

import subprocess
import sys
from unittest.mock import patch

from fettle.secure import audit, remote


class _Rec:
    """Records subprocess-style calls and returns a fixed rc per command head."""
    def __init__(self, rcs=None):
        self.calls = []
        self.rcs = rcs or {}

    def __call__(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        rc = self.rcs.get(cmd[0], 0)
        return subprocess.CompletedProcess(cmd, rc)


def test_remote_scp_then_ssh_with_forwarded_args(capsys):
    rec = _Rec()
    rc = remote.run("server1", ["--all"], sudo=False, runner=rec)
    assert rc == 0
    scp = next(c for c in rec.calls if c[0] == "scp")
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert scp[-1].startswith("server1:/tmp/fettle-scan.") and scp[-1].endswith(".pyz")
    assert ssh[1] == "-t" and ssh[2] == "server1"
    assert "python3 /tmp/fettle-scan." in ssh[3]
    assert "sys-audit --all" in ssh[3]
    assert "rm -f /tmp/fettle-scan." in ssh[3]  # cleanup preserved
    assert "sudo " not in ssh[3]


def test_remote_sudo_prefixes_command():
    rec = _Rec()
    remote.run("admin@host2", ["secureboot"], sudo=True, runner=rec)
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert ssh[3].startswith("sudo python3 /tmp/fettle-scan.")
    assert "sys-audit secureboot" in ssh[3]


def test_remote_scp_failure_aborts_before_ssh(capsys):
    rec = _Rec(rcs={"scp": 1})
    rc = remote.run("badhost", ["--all"], runner=rec)
    assert rc == 1
    assert not any(c[0] == "ssh" for c in rec.calls)  # never reaches ssh
    assert "scp to badhost failed" in capsys.readouterr().err


def test_remote_propagates_remote_exit_code():
    rec = _Rec(rcs={"ssh": 3})
    assert remote.run("h", ["--all"], runner=rec) == 3


# -- CLI parsing -------------------------------------------------------------
def test_cli_remote_all_with_sudo():
    with patch("fettle.secure.remote.run", return_value=0) as run:
        audit.main(["remote", "--sudo", "myhost", "--all"])
    run.assert_called_once()
    (host, forwarded), kw = run.call_args
    assert host == "myhost" and forwarded == ["--all"] and kw["sudo"] is True


def test_cli_remote_forwards_verbose_and_categories():
    with patch("fettle.secure.remote.run", return_value=0) as run:
        audit.main(["remote", "-v", "host", "secureboot", "tpm"])
    (host, forwarded), kw = run.call_args
    assert forwarded == ["-v", "secureboot", "tpm"] and kw["sudo"] is False


def test_cli_remote_requires_categories(capsys):
    rc = audit.main(["remote", "host"])
    assert rc == 1 and "requires check categories" in capsys.readouterr().err


def test_cli_remote_rejects_unknown_category(capsys):
    rc = audit.main(["remote", "host", "bogus"])
    assert rc == 1 and "unknown check" in capsys.readouterr().err


# -- the zipapp artifact is real and runnable --------------------------------
def test_zipapp_builds_and_runs(tmp_path):
    pyz = tmp_path / "fettle.pyz"
    remote._build_zipapp(pyz)
    assert pyz.is_file()
    # The built artifact must run standalone with a plain interpreter.
    out = subprocess.run([sys.executable, str(pyz), "--version"],
                         capture_output=True, text=True)
    assert out.returncode == 0 and "fettle" in out.stdout
    listing = subprocess.run([sys.executable, str(pyz), "sys-audit", "--list"],
                             capture_output=True, text=True)
    assert "secureboot" in listing.stdout and "packages" in listing.stdout
