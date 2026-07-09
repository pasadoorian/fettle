"""Remote execution — the shared runner (fettle/remote.py) + sys-audit &
maintenance CLI wiring."""

import subprocess
import sys
from unittest.mock import patch

from fettle import remote
from fettle.cli import main as cli_main
from fettle.secure import audit


class _Rec:
    """Records subprocess-style calls; returns a fixed rc per command head."""
    def __init__(self, rcs=None):
        self.calls = []
        self.rcs = rcs or {}

    def __call__(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.rcs.get(cmd[0], 0))


# -- the shared runner -------------------------------------------------------
def test_run_scp_then_ssh_with_args():
    rec = _Rec()
    rc = remote.run("server1", ["clean", "update"], sudo=False, runner=rec)
    assert rc == 0
    scp = next(c for c in rec.calls if c[0] == "scp")
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert scp[-1].startswith("server1:/tmp/fettle-remote.") and scp[-1].endswith(".pyz")
    assert ssh[1] == "-t" and ssh[-2] == "server1"
    assert "python3 /tmp/fettle-remote." in ssh[-1]
    assert "clean update" in ssh[-1]
    assert "rm -f /tmp/fettle-remote." in ssh[-1]   # cleanup preserved
    assert "sudo " not in ssh[-1]


def test_run_sudo_prefix():
    rec = _Rec()
    remote.run("h", ["sys-audit", "--all"], sudo=True, runner=rec)
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert ssh[-1].startswith("sudo python3 /tmp/fettle-remote.")
    assert "sys-audit --all" in ssh[-1]


def test_run_ssh_args_passthrough():
    rec = _Rec()
    remote.run("h", ["clean"], ssh_args=["-oConnectTimeout=5"], runner=rec)
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert "-oConnectTimeout=5" in ssh
    assert ssh.index("-oConnectTimeout=5") < ssh.index("h")  # ssh args precede host


def test_run_scp_failure_aborts(capsys):
    rec = _Rec(rcs={"scp": 1})
    rc = remote.run("badhost", ["clean"], runner=rec)
    assert rc == 1 and not any(c[0] == "ssh" for c in rec.calls)
    assert "scp to badhost failed" in capsys.readouterr().err


def test_run_propagates_remote_rc():
    rec = _Rec(rcs={"ssh": 3})
    assert remote.run("h", ["clean"], runner=rec) == 3


def test_run_no_tty_omits_dash_t():
    rec = _Rec()
    remote.run("h", ["update"], tty=False, runner=rec)
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert "-t" not in ssh  # unattended: no PTY


def test_zipapp_builds_and_runs(tmp_path):
    pyz = tmp_path / "fettle.pyz"
    remote.build_zipapp(pyz)
    assert pyz.is_file()
    out = subprocess.run([sys.executable, str(pyz), "--version"], capture_output=True, text=True)
    assert out.returncode == 0 and "fettle" in out.stdout
    listing = subprocess.run([sys.executable, str(pyz), "sys-audit", "--list"],
                             capture_output=True, text=True)
    assert "secureboot" in listing.stdout


# -- sys-audit remote CLI (forwards ["sys-audit", ...]) ----------------------
def test_sysaudit_remote_all_with_sudo():
    with patch("fettle.remote.run", return_value=0) as run:
        audit.main(["remote", "--sudo", "myhost", "--all"])
    (host, fettle_args), kw = run.call_args
    assert host == "myhost" and fettle_args == ["sys-audit", "--all"] and kw["sudo"] is True


def test_sysaudit_remote_forwards_verbose_and_categories():
    with patch("fettle.remote.run", return_value=0) as run:
        audit.main(["remote", "-v", "host", "secureboot", "tpm"])
    (_, fettle_args), kw = run.call_args
    assert fettle_args == ["sys-audit", "-v", "secureboot", "tpm"] and kw["sudo"] is False


def test_sysaudit_remote_requires_categories(capsys):
    assert audit.main(["remote", "host"]) == 1
    assert "requires check categories" in capsys.readouterr().err


# -- maintenance remote CLI (`fettle remote <host> <actions>`) ---------------
def test_remote_maintenance_default_safe_set():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "server1"])
    (host, fettle_args), kw = run.call_args
    assert host == "server1"
    assert fettle_args == ["clean", "update", "firmware-check"]  # safe default, no orphans/kernels
    assert kw["sudo"] is True                              # maintenance runs under sudo
    assert kw["tty"] is True                               # interactive by default


def test_remote_maintenance_all_flag_is_the_safe_set():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "server1", "-a"])
    (_, fettle_args), _ = run.call_args
    assert fettle_args == ["clean", "update", "firmware-check"]


def test_remote_maintenance_explicit_actions_and_yes():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "host", "update", "orphans", "--yes"])
    (_, fettle_args), kw = run.call_args
    assert fettle_args == ["update", "orphans", "--yes"]  # destructive action named explicitly
    assert kw["sudo"] is True
    assert kw["tty"] is False  # --yes is fully unattended: no PTY


def test_remote_maintenance_dry_run_skips_sudo():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "host", "-a", "--dry-run"])
    (_, fettle_args), kw = run.call_args
    assert "--dry-run" in fettle_args and kw["sudo"] is False


def test_remote_maintenance_unknown_action(capsys):
    rc = cli_main(["remote", "host", "bogus"])
    assert rc == 2 and "unknown action 'bogus'" in capsys.readouterr().err


def test_remote_maintenance_ssh_arg_passthrough():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "--ssh-arg=-oConnectTimeout=5", "host", "-a"])
    _, kw = run.call_args
    assert kw["ssh_args"] == ["-oConnectTimeout=5"]
