"""The NiceGUI application for ``fettle web``.

Phase 1: an all-hosts dashboard that mirrors ``fettle report`` exactly by serving
the *same* live-generated HTML (``data.report_html``) inside an iframe, wrapped in a
thin NiceGUI shell with a manual refresh. The iframe isolates the report's terminal
CSS/JS (filter, collapse) from NiceGUI's own styles, so it looks identical to
report.html. Action-runners land in later phases; this is the only module that
imports nicegui.
"""

from __future__ import annotations

from fastapi.responses import HTMLResponse
from nicegui import app, ui

from .. import __version__
from . import data

_ERROR_PAGE = ("<!doctype html><meta charset=utf-8>"
               "<body style='background:#0a0f14;color:#ff6b6b;"
               "font-family:monospace;padding:1rem'>"
               "<h3>report unavailable</h3><pre>{}</pre></body>")


@app.get("/report.html")
def _report_html() -> HTMLResponse:
    """Serve the dashboard, regenerated live from current ~/.fettle on each load."""
    try:
        return HTMLResponse(data.report_html())
    except Exception as exc:  # never 500 the iframe; show the reason instead
        import html as _html
        return HTMLResponse(_ERROR_PAGE.format(_html.escape(repr(exc))), status_code=200)


async def _refresh() -> None:
    # cache-bust so the route regenerates from the newest reports
    await ui.run_javascript("document.getElementById('rep').src='/report.html?t='+Date.now()")


@ui.page("/")
def _index() -> None:
    ui.add_head_html(
        "<style>"
        "body{margin:0;background:#0a0f14;color:#c6d3e2;"
        "font-family:ui-monospace,Menlo,Consolas,monospace}"
        ".fbar{display:flex;gap:.8rem;align-items:center;height:46px;padding:0 .9rem;"
        "border-bottom:1px solid #14212e}"
        "#rep{width:100%;height:calc(100vh - 47px);border:0;display:block}"
        "</style>")
    with ui.row().classes("fbar"):
        ui.label(f"fettle web · v{__version__}").classes("text-sm")
        ui.space()
        ui.button("⟳ refresh", on_click=_refresh).props("flat dense no-caps color=cyan")
    ui.html('<iframe id="rep" src="/report.html"></iframe>')


def run(*, host: str = "127.0.0.1", port: int = 8080,
        reload: bool = False, show: bool = False) -> None:
    """Start the NiceGUI/uvicorn server (blocks). Bound to localhost by default."""
    ui.run(host=host, port=port, reload=reload, show=show, title="fettle")
