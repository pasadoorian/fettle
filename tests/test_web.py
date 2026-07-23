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
    return webapp, TestClient(webapp.app)


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
