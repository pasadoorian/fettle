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


def test_remote_forwards_aur_gate_flags():
    # The pre-check gate runs on the remote (same code); its overrides must forward.
    with patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "ec3", "-a", "--force-aur", "--no-aur-precheck"])
    (_, fettle_args), _ = run.call_args
    assert fettle_args == ["-a", "--force-aur", "--no-aur-precheck"]


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
    assert list((tmp_path / ".fettle/reports/ec3").glob("upgrade-check-*.txt"))  # per-host subdir


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


# -- RP-remote: fetch reports back to the controller -------------------------
def _tar_of(files: dict) -> bytes:
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, body in files.items():
            data = body.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_fetch_reports_extracts_and_sets_perms(tmp_path):
    import os
    tar = _tar_of({"hardening-audit-20260721-010101.txt": "h",
                   "pkg-audit-20260721-010101.txt": "p"})
    rec = _Rec(stdouts={"ssh": tar})
    names = remote.fetch_reports("foo", tmp_path, runner=rec)
    assert set(names) == {"hardening-audit-20260721-010101.txt",
                          "pkg-audit-20260721-010101.txt"}
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert "tar cf -" in ssh[-1] and "~/.fettle/reports/local" in ssh[-1]
    got = tmp_path / "hardening-audit-20260721-010101.txt"
    assert got.read_text() == "h"
    assert oct(os.stat(got).st_mode & 0o777) == "0o600"


def test_fetch_reports_empty_tar_returns_nothing(tmp_path):
    rec = _Rec(stdouts={"ssh": b""})     # no reports on the remote
    assert remote.fetch_reports("foo", tmp_path, runner=rec) == []


def test_fetch_reports_rejects_path_traversal(tmp_path):
    # a hostile tar member with a path must not escape dest_dir
    tar = _tar_of({"../evil.txt": "x", "sub/nested.txt": "y",
                   "ok-20260721-010101.txt": "z"})
    names = remote.fetch_reports("foo", tmp_path, runner=_Rec(stdouts={"ssh": tar}))
    assert names == ["ok-20260721-010101.txt"]           # only the safe basename
    assert not (tmp_path.parent / "evil.txt").exists()
    assert not (tmp_path / "sub").exists()


def test_fetch_reports_ssh_failure_is_graceful(tmp_path):
    def boom(cmd, *a, **k):
        raise OSError("ssh missing")
    assert remote.fetch_reports("foo", tmp_path, runner=boom) == []


def test_fetch_logs_pulls_from_remote_log_dir(tmp_path):
    # each host's own run-logs come back so a group `-a` shows under that host
    tar = _tar_of({"run-20260722-020202.txt": "session",
                   "run-20260722-020202.json": "{}"})
    rec = _Rec(stdouts={"ssh": tar})
    names = remote.fetch_logs("ec1", tmp_path, runner=rec)
    assert set(names) == {"run-20260722-020202.txt", "run-20260722-020202.json"}
    ssh = next(c for c in rec.calls if c[0] == "ssh")
    assert "~/.fettle/logs/local" in ssh[-1]              # the remote LOG dir
    assert (tmp_path / "run-20260722-020202.txt").read_text() == "session"


def test_remote_maintenance_fetches_after_run_not_on_dry_run():
    # non-dry-run -> fetch-back invoked with the host + ssh args
    with patch("fettle.remote.run", return_value=0), \
         patch("fettle.cli._fetch_remote_reports") as fetch:
        cli_main(["remote", "--ssh-arg", "-p2222", "web", "-c"])
    fetch.assert_called_once()
    assert fetch.call_args[0][0] == "web" and fetch.call_args[0][1] == ["-p2222"]

    with patch("fettle.remote.run", return_value=0), \
         patch("fettle.cli._fetch_remote_reports") as fetch:
        cli_main(["remote", "host", "-c", "--dry-run"])
    fetch.assert_not_called()                            # dry-run writes nothing remote


def test_fetch_remote_reports_is_a_noop_under_pytest(tmp_path, monkeypatch):
    # regression: a pre-guard version created ~/.fettle/reports/<host> in the REAL
    # home and did a real ssh during the remote CLI tests. The FETTLE_TEST guard
    # must make _fetch_remote_reports do nothing at all.
    from fettle import cli
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))
    called = []
    monkeypatch.setattr("fettle.remote.fetch_reports",
                        lambda *a, **k: called.append(a) or [])
    cli._fetch_remote_reports("server1", [])
    assert called == []                                   # no ssh attempted
    assert not (tmp_path / ".fettle").exists()            # no dir created


# -- RG1: remote host groups (config) ----------------------------------------
def _cfg_with_remote(remote):
    from fettle.config import Config
    c = Config()
    c.remote = remote
    return c


def test_remote_groups_rich_table():
    from fettle.config import Config
    from fettle.remote import remote_groups
    cfg = _cfg_with_remote({"groups": {"ubuntu-lab": {
        "hosts": ["ubu1", "ubu2", "10.0.0.5"],
        "ssh_args": ["-o", "ConnectTimeout=5"],
        "actions": ["-a"], "yes": True}}})
    g = remote_groups(cfg)["ubuntu-lab"]
    assert g.hosts == ["ubu1", "ubu2", "10.0.0.5"]
    assert g.ssh_args == ["-o", "ConnectTimeout=5"]
    assert g.actions == ["-a"] and g.yes is True
    assert remote_groups(Config()) == {}                # no [remote] -> empty


def test_remote_groups_bare_list_shorthand():
    from fettle.remote import remote_groups
    cfg = _cfg_with_remote({"groups": {"arch-lab": ["mjolnir", "wopr"]}})
    g = remote_groups(cfg)["arch-lab"]
    assert g.hosts == ["mjolnir", "wopr"]
    assert g.ssh_args == [] and g.actions == [] and g.yes is False


def test_remote_groups_preserves_host_order():
    from fettle.remote import remote_groups
    cfg = _cfg_with_remote({"groups": {"g": ["a", "b", "c", "d"]}})
    assert remote_groups(cfg)["g"].hosts == ["a", "b", "c", "d"]


def test_remote_groups_tolerates_malformed():
    from fettle.remote import remote_groups
    # not-a-dict remote, empty hosts, wrong types -> skipped, never raises
    assert remote_groups(_cfg_with_remote("garbage")) == {}
    cfg = _cfg_with_remote({"groups": {
        "empty": {"hosts": []},                # dropped (no hosts)
        "bad": 42,                             # skipped (not list/dict)
        "ok": ["h1"],
        "typed": {"hosts": ["h2"], "ssh_args": "notalist", "yes": "x"}}})
    g = remote_groups(cfg)
    assert set(g) == {"ok", "typed"}
    assert g["typed"].hosts == ["h2"] and g["typed"].ssh_args == []
    assert g["typed"].yes is True              # bool("x") -> True (truthy string)


# -- RG2: group execution ----------------------------------------------------
def _grp(name, hosts, **kw):
    return {name: remote.RemoteGroup(name=name, hosts=hosts, **kw)}


def test_group_runs_each_host_in_order():
    calls = []
    with patch("fettle.remote.remote_groups",
               return_value=_grp("bifrost-lab", ["bifrost", "ec1", "ec2", "ec3"])), \
         patch("fettle.remote.run",
               side_effect=lambda h, f, **k: calls.append((h, list(f))) or 0):
        rc = cli_main(["remote", "bifrost-lab", "-a"])
    assert rc == 0
    assert [h for h, _ in calls] == ["bifrost", "ec1", "ec2", "ec3"]   # order kept
    assert all(f == ["-a"] for _, f in calls)                          # -a to each


def test_group_continues_past_failure_and_summarizes(capsys):
    rcs = {"a": 0, "b": 2, "c": 0}
    with patch("fettle.remote.remote_groups", return_value=_grp("g", ["a", "b", "c"])), \
         patch("fettle.remote.run", side_effect=lambda h, f, **k: rcs[h]):
        rc = cli_main(["remote", "g", "-a"])
    out = capsys.readouterr().out
    assert rc == 1                                        # a host failed
    assert "[OK  ] a" in out and "[FAIL] b" in out and "[OK  ] c" in out
    assert "2 ok, 1 failed" in out


def test_group_default_actions_yes_and_ssh_merge():
    seen = {}

    def fake(h, f, **k):
        seen.update(host=h, fwd=list(f), ssh=list(k["ssh_args"]), tty=k["tty"])
        return 0
    grp = _grp("g", ["h1"], ssh_args=["-o", "X=1"], actions=["-a"], yes=True)
    with patch("fettle.remote.remote_groups", return_value=grp), \
         patch("fettle.remote.run", side_effect=fake):
        cli_main(["remote", "--ssh-arg", "-p2222", "g"])
    assert seen["fwd"] == ["-a", "--yes"]                 # group actions + group.yes
    assert seen["ssh"] == ["-p2222", "-o", "X=1"]         # CLI + group ssh_args
    assert seen["tty"] is False                           # --yes -> unattended


def test_unknown_name_is_a_single_host():
    with patch("fettle.remote.remote_groups", return_value={}), \
         patch("fettle.remote.run", return_value=0) as run:
        cli_main(["remote", "justahost", "-a"])
    (host, fwd), _ = run.call_args
    assert host == "justahost" and fwd == ["-a"]          # single-host path


def test_group_confirm_decline_aborts(monkeypatch, capsys):
    from fettle import cli
    monkeypatch.setattr(cli, "_in_test", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    with patch("fettle.remote.run") as run:
        rc = cli._run_group(remote.RemoteGroup(name="g", hosts=["a", "b"]), [], ["-a"])
    assert rc == 1 and not run.called                     # declined -> nothing ran
    assert "Aborted" in capsys.readouterr().out


def test_group_confirm_accept_runs(monkeypatch):
    from fettle import cli
    monkeypatch.setattr(cli, "_in_test", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    with patch("fettle.remote.run", return_value=0) as run, \
         patch("fettle.cli._fetch_remote_reports"):
        rc = cli._run_group(remote.RemoteGroup(name="g", hosts=["a"]), [], ["-a"])
    assert rc == 0 and run.called                         # accepted -> ran
