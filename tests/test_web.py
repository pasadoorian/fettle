"""Web UI (`fettle web`) — Phase 0 skeleton: CLI wiring, core purity, read model.

These run with OR without the `web` extra installed: nothing here imports nicegui
(the app module does, but we patch the loader), so the suite stays green in the
pure-stdlib dev venv too.
"""

import json
import subprocess
import sys
from pathlib import Path

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


def test_report_html_mirrors_the_dashboard(tmp_path):
    # the web UI serves the SAME live HTML as `fettle report`, via the real renderers
    _write(tmp_path, "wopr", "aur-audit", "20260723-010101",
           {"packages": [{"name": "yay", "maintainer": "j", "age_days": 1, "votes": 9,
                          "flags": "", "description": "AUR helper", "homepage": "https://x"}]})
    html = data.report_html(base=tmp_path)
    assert "<!doctype html>" in html.lower()          # a full self-contained page
    assert "wopr" in html                              # the host section is present
    assert "aur.archlinux.org/packages/yay" in html   # real renderer reuse (AUR link)
