"""Remote execution — the shared runner (fettle/remote.py) + sys-audit &
maintenance CLI wiring."""

import subprocess
import sys
from unittest.mock import patch

from fettle import remote
from fettle.cli import main as cli_main
from fettle.secure import audit


class _Rec:
    """Records subprocess-style calls; returns a fixed rc (+ optional stdout) per
    command head."""
    def __init__(self, rcs=None, stdouts=None):
        self.calls = []
        self.rcs = rcs or {}
        self.stdouts = stdouts or {}

    def __call__(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, self.rcs.get(cmd[0], 0),
                                           stdout=self.stdouts.get(cmd[0]))


# -- the shared runner -------------------------------------------------------
def test_run_scp_then_ssh_with_args():
    rec = _Rec()
    rc = remote.run("server1", ["clean", "update"], sudo=False, runner=rec)
    assert rc == 0
    scp = next(c for c in rec.calls if c[0] == "scp")
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    # Random name in the remote $HOME (not a predictable /tmp path).
    assert scp[-1].startswith("server1:.fettle-remote.") and scp[-1].endswith(".pyz")
    assert "/tmp/" not in scp[-1]
    assert ssh[1] == "-t" and ssh[-2] == "server1"
    assert 'python3 "$HOME/.fettle-remote.' in ssh[-1]
    assert "clean update" in ssh[-1]
    assert 'rm -f "$HOME/.fettle-remote.' in ssh[-1]   # cleanup preserved
    assert "sudo " not in ssh[-1]


def test_run_uses_unpredictable_name_each_call():
    a, b = _Rec(), _Rec()
    remote.run("h", ["clean"], runner=a)
    remote.run("h", ["clean"], runner=b)
    scp_a = next(c for c in a.calls if c[0] == "scp")[-1]
    scp_b = next(c for c in b.calls if c[0] == "scp")[-1]
    assert scp_a != scp_b   # random token, not a shared/predictable path


def test_run_sudo_prefix():
    rec = _Rec()
    remote.run("h", ["sys-audit", "--all"], sudo=True, runner=rec)
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert 'sudo python3 "$HOME/.fettle-remote.' in ssh[-1]
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


def test_collect_returns_captured_stdout():
    rec = _Rec(stdouts={"ssh": '{"distro": "Arch"}'})
    out = remote.collect("h", ["upgrade-check", "--collect"], runner=rec)
    assert out == '{"distro": "Arch"}'
    scp = next(c for c in rec.calls if c[0] == "scp")
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert scp[-1].startswith("h:.fettle-remote.")   # uploaded (shared helper)
    assert "-t" not in ssh                            # no PTY for a captured run
    assert "upgrade-check --collect" in ssh[-1]
    assert "sudo " not in ssh[-1]                     # collect never elevates


def test_collect_scp_failure_returns_none():
    rec = _Rec(rcs={"scp": 1})
    assert remote.collect("h", ["upgrade-check", "--collect"], runner=rec) is None
    assert not any(c[0] == "ssh" for c in rec.calls)  # never runs ssh


def test_collect_nonzero_remote_returns_none(capsys):
    rec = _Rec(rcs={"ssh": 2}, stdouts={"ssh": ""})
    assert remote.collect("h", ["upgrade-check", "--collect"], runner=rec) is None
    assert "remote collect on h failed" in capsys.readouterr().err


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


def test_remote_all_flag_forwarded_verbatim():
    # -a is now forwarded (remote runs its own full default set), not remapped.
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "server1", "-a"])
    (_, fettle_args), _ = run.call_args
    assert fettle_args == ["-a"]


def test_remote_bare_yes_still_runs_the_safe_set():
    # Safety net: --yes with no action named must NOT run the full destructive set.
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "host", "--yes"])
    (_, fettle_args), kw = run.call_args
    assert fettle_args == ["clean", "update", "firmware-check", "--yes"]
    assert kw["tty"] is False  # unattended


def test_remote_maintenance_explicit_actions_and_yes():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "host", "update", "orphans", "--yes"])
    (_, fettle_args), kw = run.call_args
    assert fettle_args == ["update", "orphans", "--yes"]  # forwarded verbatim
    assert kw["sudo"] is True
    assert kw["tty"] is False  # --yes is fully unattended: no PTY


def test_remote_forwards_arbitrary_flags_and_dry_run_skips_sudo():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "host", "-c", "--dry-run"])
    (_, fettle_args), kw = run.call_args
    assert fettle_args == ["-c", "--dry-run"] and kw["sudo"] is False


def test_remote_forwards_dispatch_shortcut():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "host", "-S"])
    (_, fettle_args), _ = run.call_args
    assert fettle_args == ["-S"]  # sys-audit runs on the remote


def test_remote_upgrade_check_collects_remote_analyses_local(capsys, monkeypatch, tmp_path):
    # `fettle remote HOST upgrade-check` collects a snapshot on the remote (never
    # remote.run) and analyses it LOCALLY with the local key.
    from fettle.ai.snapshot import Snapshot
    from fettle.ai.upgrade_check import Result
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    snap = Snapshot("Ubuntu", "6.8", "sys", [("bash", "5.1", "5.2")])
    result = Result(safety_verdict="safe", failure_likelihood="low", summary="fine",
                    recommendation="proceed", usage={"input_tokens": 1, "output_tokens": 1})
    with patch("fettle.remote.collect", return_value=snap.to_json()) as coll, \
         patch("fettle.remote.run") as run_fwd, \
         patch("fettle.ai.upgrade_check.analyze", return_value=result) as analyze:
        rc = cli_main(["remote", "ec3", "upgrade-check", "--no-config"])
    out = capsys.readouterr().out
    assert rc == 0
    run_fwd.assert_not_called()                          # NOT the forward path
    coll.assert_called_once()
    assert coll.call_args[0][1] == ["upgrade-check", "--collect"]  # collect on remote
    analyze.assert_called_once()                         # analysed locally
    assert "remote: ec3" in out and "Verdict for ec3" in out
    assert (tmp_path / "upgrade-check-ec3.txt").is_file()  # per-host report


def test_remote_upgrade_check_no_local_key_lists_packages(capsys, monkeypatch):
    from fettle.ai.snapshot import Snapshot
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    snap = Snapshot("Ubuntu", "6.8", "", [("bash", "5.1", "5.2")])
    with patch("fettle.remote.collect", return_value=snap.to_json()):
        rc = cli_main(["remote", "ec3", "-U", "--no-config"])
    cap = capsys.readouterr()
    assert rc == 0 and "no local API key" in cap.err
    assert "bash  5.1 -> 5.2" in cap.out


def test_remote_upgrade_check_collect_failure(capsys):
    with patch("fettle.remote.collect", return_value=None):
        rc = cli_main(["remote", "ec3", "upgrade-check", "--no-config"])
    assert rc == 1 and "could not collect a snapshot from ec3" in capsys.readouterr().err


def test_remote_upgrade_check_up_to_date(capsys, monkeypatch):
    from fettle.ai.snapshot import Snapshot
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    snap = Snapshot("Ubuntu", "6.8", "sys", [])  # nothing pending
    with patch("fettle.remote.collect", return_value=snap.to_json()), \
         patch("fettle.ai.upgrade_check.analyze") as analyze:
        rc = cli_main(["remote", "ec3", "upgrade-check", "--no-config"])
    assert rc == 0 and "ec3 is up to date" in capsys.readouterr().out
    analyze.assert_not_called()                  # no API call when nothing to do


def test_remote_upgrade_check_unreadable_snapshot(capsys):
    with patch("fettle.remote.collect", return_value="not json at all"):
        rc = cli_main(["remote", "ec3", "upgrade-check", "--no-config"])
    assert rc == 1 and "unreadable snapshot" in capsys.readouterr().err


def test_remote_upgrade_check_analysis_unavailable_lists_packages(capsys, monkeypatch):
    from fettle.ai.snapshot import Snapshot
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    snap = Snapshot("Ubuntu", "6.8", "sys", [("bash", "5.1", "5.2")])
    with patch("fettle.remote.collect", return_value=snap.to_json()), \
         patch("fettle.ai.upgrade_check.analyze", return_value=None):
        rc = cli_main(["remote", "ec3", "upgrade-check", "--no-config"])
    cap = capsys.readouterr()
    assert rc == 0 and "AI analysis unavailable" in cap.err
    assert "bash  5.1 -> 5.2" in cap.out


def test_remote_upgrade_check_notes_missing_inxi(capsys, monkeypatch, tmp_path):
    from fettle.ai.snapshot import Snapshot
    from fettle.ai.upgrade_check import Result
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    snap = Snapshot("Ubuntu", "6.8", "", [("bash", "5.1", "5.2")])  # inxi empty
    result = Result(safety_verdict="safe", failure_likelihood="low", summary="ok",
                    recommendation="proceed")
    with patch("fettle.remote.collect", return_value=snap.to_json()), \
         patch("fettle.ai.upgrade_check.analyze", return_value=result):
        rc = cli_main(["remote", "ec3", "upgrade-check", "--no-config"])
    assert rc == 0 and "inxi wasn't available on ec3" in capsys.readouterr().out


def test_remote_option_before_host_errors(capsys):
    rc = cli_main(["remote", "-c", "host"])
    assert rc == 2 and "before HOST" in capsys.readouterr().err


def test_remote_maintenance_ssh_arg_passthrough():
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "--ssh-arg=-oConnectTimeout=5", "host", "-a"])
    (_, fettle_args), kw = run.call_args
    assert kw["ssh_args"] == ["-oConnectTimeout=5"]
    assert fettle_args == ["-a"]
