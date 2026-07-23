"""The web application for ``fettle web``.

Two surfaces:
- **Dashboard** (`/`, `/report.html`): serves the *same* live-generated HTML as
  ``fettle report`` (``data.report_html``) directly, with a small injected toolbar
  (run + refresh). Served as a plain page so the report's own terminal CSS/JS —
  filter, collapse — work untouched (NiceGUI's ``ui.html`` would strip a frame).
- **Run** (`/run`, Phase 2): a NiceGUI page to trigger read-only audits and watch
  their output stream live, then reload the dashboard to see the new report.

The web server stays unprivileged; actions run as `python -m fettle <action>`
subprocesses. This is the only module importing nicegui.
"""

from __future__ import annotations

import html as _html
from functools import partial

from fastapi.responses import HTMLResponse
from nicegui import app, ui

from . import data, runner

# Read-only audits (no sudo). Flag, then a friendly label with the action name.
_READONLY_ACTIONS = [
    ("-P", "Supply-chain audit (pkg-audit)"),
    ("-A", "AUR health (aur-audit)"),
    ("-I", "AUR IoC scan (aur-ioc-scan)"),
    ("-H", "Binary hardening (hardening-audit)"),
    ("-d", "Config drift (config-drift)"),
    ("-x", "Auto-updates posture (auto-updates)"),
    ("-O", "Check upgrades (only-update)"),
]

_BTN = ("font-family:ui-monospace,monospace;font-size:.8rem;background:#0d141e;"
        "color:#4dd0e1;border:1px solid #4dd0e1;border-radius:4px;padding:4px 12px;"
        "cursor:pointer;text-decoration:none")

# Injected into the served report: run + refresh, fixed top-right.
_TOOLBAR = (
    '<div style="position:fixed;top:9px;right:14px;z-index:9999;display:flex;gap:8px">'
    f'<a href="/run" style="{_BTN}">&#x25B6; run</a>'
    f'<button onclick="location.reload()" style="{_BTN}">&#x27F3; refresh</button></div>')

_ERROR_PAGE = ("<!doctype html><meta charset=utf-8>"
               "<body style='background:#0a0f14;color:#ff6b6b;font-family:monospace;"
               "padding:1rem'><h3>report unavailable</h3><pre>{}</pre></body>")


def _dashboard_html() -> str:
    page = data.report_html()
    if "</body>" in page:
        return page.replace("</body>", _TOOLBAR + "</body>", 1)
    return page + _TOOLBAR


@app.get("/", response_class=HTMLResponse)
@app.get("/report.html", response_class=HTMLResponse)
def _dashboard() -> HTMLResponse:
    """The live dashboard — same HTML as ``fettle report``, regenerated per load."""
    try:
        return HTMLResponse(_dashboard_html())
    except Exception as exc:  # never 500 — show the reason
        return HTMLResponse(_ERROR_PAGE.format(_html.escape(repr(exc))), status_code=200)


_PAGE_CSS = (
    "<style>body{margin:0;background:#0a0f14;color:#c6d3e2;"
    "font-family:ui-monospace,Menlo,Consolas,monospace}"
    ".fbar{display:flex;gap:1rem;align-items:center;padding:.6rem .9rem;"
    "border-bottom:1px solid #14212e}"
    "a.flink{color:#4dd0e1;text-decoration:none}a.flink:hover{text-decoration:underline}"
    "</style>")


@ui.page("/run")
def _run_page() -> None:
    ui.add_head_html(_PAGE_CSS)
    with ui.row().classes("fbar items-center"):
        ui.html('<a class="flink" href="/">&#x2190; dashboard</a>')
        ui.label("fettle · run read-only audits (no sudo)").classes("text-sm")

    log = ui.log(max_lines=2000).classes("w-full").style(
        "height:62vh;background:#0d141e;border:1px solid #14212e;border-radius:6px;"
        "padding:.5rem;font-size:.8rem;white-space:pre-wrap")
    log.push("# pick an audit to run — output streams here; then reload the dashboard.")

    state = {"busy": False}

    async def _go(flag: str, label: str) -> None:
        if state["busy"]:
            return
        state["busy"] = True
        log.push(f"\n$ fettle {flag}   # {label}")
        try:
            code = await runner.run_action([flag], log.push)
            log.push(f"[exit {code}] — done. Reload the dashboard to see the report.")
        except Exception as exc:  # never let a failed run wedge the page
            log.push(f"[error] {exc!r}")
        finally:
            state["busy"] = False

    with ui.row().classes("q-pa-sm").style("flex-wrap:wrap;gap:8px;padding:.6rem .9rem"):
        for flag, label in _READONLY_ACTIONS:
            ui.button(label, on_click=partial(_go, flag, label)) \
                .props("flat dense no-caps color=cyan")


def run(*, host: str = "127.0.0.1", port: int = 8080,
        reload: bool = False, show: bool = False) -> None:
    """Start the NiceGUI/uvicorn server (blocks). Bound to localhost by default."""
    ui.run(host=host, port=port, reload=reload, show=show, title="fettle")
