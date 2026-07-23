"""Web UI (`fettle web`) — Phase 0 skeleton: CLI wiring, core purity, read model.

These run with OR without the `web` extra installed: nothing here imports nicegui
(the app module does, but we patch the loader), so the suite stays green in the
pure-stdlib dev venv too.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fettle import cli
from fettle.web import data

_REPO = Path(__file__).resolve().parent.parent


# -- core stays pure-stdlib: importing the CLI must NOT pull nicegui -----------
def test_core_cli_imports_without_nicegui():
    # hermetic subprocess: even where nicegui IS installed, the core must not
    # import it (the web UI is lazy-loaded only by `fettle web`).
    code = ("import fettle.cli, fettle.htmlreport, fettle.reports, fettle.actions;"
            "import sys; assert 'nicegui' not in sys.modules, 'core imported nicegui'")
    r = subprocess.run([sys.executable, "-c", code], cwd=_REPO,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


# -- `fettle web` without the extra is a friendly message, not a traceback ----
def test_web_missing_extra_is_friendly(monkeypatch, capsys):
    def boom():
        raise ImportError("No module named 'nicegui'", name="nicegui")
    monkeypatch.setattr(cli, "_web_runner", boom)
    assert cli._run_web([]) == 1
    assert "pip install" in capsys.readouterr().err


def test_web_missing_extra_reraises_unrelated_importerror(monkeypatch):
    def boom():
        raise ImportError("No module named 'somethingelse'", name="somethingelse")
    monkeypatch.setattr(cli, "_web_runner", boom)
    try:
        cli._run_web([])
    except ImportError as exc:
        assert exc.name == "somethingelse"     # not swallowed as a missing-extra
    else:
        raise AssertionError("unrelated ImportError should propagate")


# -- the command parses flags and hands them to the runner --------------------
def test_web_command_invokes_runner_with_args(monkeypatch):
    calls = {}
    monkeypatch.setattr(cli, "_web_runner", lambda: (lambda **kw: calls.update(kw)))
    assert cli._run_web(["--host", "0.0.0.0", "--port", "9001", "--reload"]) == 0
    assert calls == {"host": "0.0.0.0", "port": 9001, "reload": True, "show": False}


def test_web_command_defaults_to_localhost(monkeypatch):
    calls = {}
    monkeypatch.setattr(cli, "_web_runner", lambda: (lambda **kw: calls.update(kw)))
    cli._run_web([])
    assert calls["host"] == "127.0.0.1" and calls["port"] == 8080


# -- read model: the same JSON envelopes the HTML dashboard uses --------------
def _write(base: Path, host: str, tool: str, ts: str, dat: dict):
    d = base / "reports" / host
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{tool}-{ts}.json").write_text(json.dumps(
        {"schema": "fettle.report/1", "tool": tool, "host": host,
         "timestamp": ts, "data": dat}))


def test_data_collect_reads_scratch_tree(tmp_path):
    _write(tmp_path, "wopr", "aur-audit", "20260723-010101",
           {"packages": [{"name": "yay"}]})
    _write(tmp_path, "ec1", "pkg-audit", "20260723-010101", {"findings": []})
    tree = data.collect(base=tmp_path)
    assert set(data.hosts(base=tmp_path)) == {"wopr", "ec1"}
    assert tree["wopr"]["reports"][0]["tool"] == "aur-audit"


def test_data_base_dir_defaults_under_home(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))
    assert data.base_dir() == tmp_path / ".fettle"


def test_data_remote_groups_lists_configured_groups():
    from fettle.config import Config
    cfg = Config()
    cfg.remote = {"groups": {"lab": ["h1", "h2"], "arch": {"hosts": ["wopr"]}}}
    assert data.remote_groups(config=cfg) == {"lab": ["h1", "h2"], "arch": ["wopr"]}


def test_data_remote_groups_empty_without_config():
    from fettle.config import Config
    assert data.remote_groups(config=Config()) == {}


def _write_log(base: Path, host: str, ts: str, argv, code, transcript):
    d = base / "logs" / host
    d.mkdir(parents=True, exist_ok=True)
    (d / f"run-{ts}.json").write_text(json.dumps(
        {"schema": "fettle.log/1", "tool": "run", "host": host, "timestamp": ts,
         "argv": argv, "exit_code": code, "transcript": transcript}))


def test_run_history_flattens_and_sorts_newest_first(tmp_path):
    _write_log(tmp_path, "local", "20260723-010101", ["-A"], 0, "aur audit done")
    _write_log(tmp_path, "ec1", "20260723-020202", ["remote", "ec1", "-d"], 1, "drift")
    hist = data.run_history(base=tmp_path)
    assert [r["timestamp"] for r in hist] == ["20260723-020202", "20260723-010101"]
    assert hist[0]["host"] == "ec1" and hist[0]["exit_code"] == 1
    assert hist[1]["transcript"] == "aur audit done"


def test_hist_label_formats_a_run():
    webapp, _ = _client()
    label = webapp._hist_label({"timestamp": "20260723-101958", "host": "wopr",
                                "argv": ["-A"], "exit_code": 0})
    assert "2026-07-23 10:19:58" in label and "wopr" in label
    assert "fettle -A" in label and "ok" in label


def test_report_html_mirrors_the_dashboard(tmp_path):
    # the web UI serves the SAME live HTML as `fettle report`, via the real renderers
    _write(tmp_path, "wopr", "aur-audit", "20260723-010101",
           {"packages": [{"name": "yay", "maintainer": "j", "age_days": 1, "votes": 9,
                          "flags": "", "description": "AUR helper", "homepage": "https://x"}]})
    html = data.report_html(base=tmp_path)
    assert "<!doctype html>" in html.lower()          # a full self-contained page
    assert "wopr" in html                              # the host section is present
    assert "aur.archlinux.org/packages/yay" in html   # real renderer reuse (AUR link)


# -- the app route serves that HTML with a refresh control (needs the web extra) --
def _client():
    pytest.importorskip("nicegui")               # skip in the pure-stdlib dev venv
    from fastapi.testclient import TestClient

    from fettle.web import app as webapp
    # localhost Host so the anti-rebinding middleware admits the request
    return webapp, TestClient(webapp.app, base_url="http://127.0.0.1")


def test_dashboard_route_serves_report_with_refresh(monkeypatch):
    webapp, client = _client()
    monkeypatch.setattr(webapp.data, "report_html",
                        lambda: "<html><body>DASHBOARD</body></html>")
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "DASHBOARD" in r.text                        # the live report body
    assert "location.reload()" in r.text                # injected manual-refresh button
    assert client.get("/report.html").text == r.text    # both paths serve it


def test_dashboard_route_shows_error_instead_of_500(monkeypatch):
    webapp, client = _client()
    def boom():
        raise RuntimeError("kaboom")
    monkeypatch.setattr(webapp.data, "report_html", boom)
    r = client.get("/")
    assert r.status_code == 200 and "report unavailable" in r.text and "kaboom" in r.text


def test_nonlocal_host_is_forbidden(monkeypatch):
    webapp, _ = _client()
    from fastapi.testclient import TestClient
    monkeypatch.setattr(webapp.data, "report_html", lambda: "<html><body>X</body></html>")
    evil = TestClient(webapp.app, base_url="http://evil.example.com")
    r = evil.get("/")
    assert r.status_code == 403 and "localhost-only" in r.text   # anti DNS-rebinding


def test_localhost_variants_are_allowed(monkeypatch):
    webapp, _ = _client()
    from fastapi.testclient import TestClient
    monkeypatch.setattr(webapp.data, "report_html", lambda: "<html><body>OK</body></html>")
    for base in ("http://localhost", "http://127.0.0.1:8080"):
        assert TestClient(webapp.app, base_url=base).get("/").status_code == 200


def test_audit_writes_a_line(tmp_path, monkeypatch):
    webapp, _ = _client()
    monkeypatch.setattr(webapp.data, "base_dir", lambda: tmp_path)
    webapp._audit("sudo fettle -c --yes", 0)
    logged = (tmp_path / "web-actions.log").read_text()
    assert "sudo fettle -c --yes" in logged and "exit 0" in logged


# -- the action runner streams a subprocess's output + exit code (no nicegui) --
def test_run_action_streams_lines_and_exit_code():
    import asyncio

    from fettle.web import runner
    stub = [sys.executable, "-c",
            "print('scanning'); print('done'); import sys; sys.exit(3)"]
    lines: list[str] = []
    code = asyncio.run(runner.run_action([], lines.append, cmd=stub))
    assert lines == ["scanning", "done"] and code == 3


def test_run_action_default_cmd_targets_fettle():
    from fettle.web import runner
    assert runner._cmd(["-A"])[1:] == ["-m", "fettle", "-A"]   # `python -m fettle -A`


def test_cmd_sudo_wraps_with_sudo_S_and_pins_config():
    from fettle.web import runner
    cmd = runner._cmd(["-u", "--yes"], sudo=True)
    assert cmd[0] == "sudo" and "-S" in cmd[:4]     # read password from stdin
    assert "fettle" in cmd and "-u" in cmd and "--yes" in cmd
    assert "--config" in cmd                        # pinned (HOME=/root under sudo)
    plain = runner._cmd(["-A"])                      # non-sudo: no sudo, no --config
    assert plain[0] != "sudo" and "--config" not in plain


def test_run_action_feeds_password_to_stdin():
    import asyncio

    from fettle.web import runner
    stub = [sys.executable, "-c",
            "import sys; pw=sys.stdin.readline().strip(); print('pw='+pw)"]
    lines: list[str] = []
    code = asyncio.run(runner.run_action([], lines.append, cmd=stub, password="s3cret"))
    assert code == 0 and "pw=s3cret" in lines       # password reached the subprocess stdin
