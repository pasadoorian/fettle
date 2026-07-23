"""The web application for ``fettle web``.

Phase 1: an all-hosts dashboard that mirrors ``fettle report`` exactly by serving
the *same* live-generated HTML (``data.report_html``) directly, with a small
injected refresh button. Serving the report as a plain page (rather than embedding
it in a NiceGUI element) keeps the report's terminal CSS/JS — filter, collapse —
working untouched; NiceGUI's ``ui.html`` sanitizer would strip an embedded frame.

NiceGUI still runs the server (``run``), so later phases add interactive
action-runner pages as real NiceGUI routes. This is the only module importing nicegui.
"""

from __future__ import annotations

import html as _html

from fastapi.responses import HTMLResponse
from nicegui import app, ui

from . import data

# A small fixed refresh control injected into the served report (manual refresh =
# a plain reload, which re-runs the live generator). Styled to match the terminal.
_REFRESH = (
    '<div style="position:fixed;top:9px;right:14px;z-index:9999">'
    '<button onclick="location.reload()" style="font-family:ui-monospace,monospace;'
    'font-size:.8rem;background:#0d141e;color:#4dd0e1;border:1px solid #4dd0e1;'
    'border-radius:4px;padding:4px 12px;cursor:pointer">&#x27F3; refresh</button></div>')

_ERROR_PAGE = ("<!doctype html><meta charset=utf-8>"
               "<body style='background:#0a0f14;color:#ff6b6b;font-family:monospace;"
               "padding:1rem'><h3>report unavailable</h3><pre>{}</pre></body>")


def _dashboard_html() -> str:
    page = data.report_html()
    # inject the refresh button just before </body> (fall back to append)
    if "</body>" in page:
        return page.replace("</body>", _REFRESH + "</body>", 1)
    return page + _REFRESH


@app.get("/", response_class=HTMLResponse)
@app.get("/report.html", response_class=HTMLResponse)
def _dashboard() -> HTMLResponse:
    """The live dashboard — same HTML as ``fettle report``, regenerated per load."""
    try:
        return HTMLResponse(_dashboard_html())
    except Exception as exc:  # never 500 — show the reason
        return HTMLResponse(_ERROR_PAGE.format(_html.escape(repr(exc))), status_code=200)


def run(*, host: str = "127.0.0.1", port: int = 8080,
        reload: bool = False, show: bool = False) -> None:
    """Start the NiceGUI/uvicorn server (blocks). Bound to localhost by default."""
    ui.run(host=host, port=port, reload=reload, show=show, title="fettle")
