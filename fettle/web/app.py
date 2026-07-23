"""The NiceGUI application for ``fettle web`` (Phase 0 skeleton).

This is the only module that imports nicegui. It builds the app, registers pages,
and exposes :func:`run` for the ``fettle web`` CLI command. Real dashboards and
action-runners land in later phases; for now it serves a themed health page that
reads the host list from the stored reports.
"""

from __future__ import annotations

from nicegui import ui

from .. import __version__
from . import data, theme


def _shell(subtitle: str) -> None:
    """Common page chrome: inject the terminal theme + a prompt-style header."""
    ui.add_head_html(theme.head_html())
    with ui.row().classes("items-baseline"):
        ui.label("paul@fettle:~/.fettle$").classes("text-sm opacity-70")
        ui.label(f"fettle {subtitle}").classes("text-lg")


@ui.page("/")
def _index() -> None:
    _shell("web")
    hosts = data.hosts()
    with ui.column():
        ui.label(f"fettle v{__version__} — web UI").classes("text-base")
        ui.label(f"reports base: {data.base_dir()}").classes("text-sm opacity-70")
        if hosts:
            ui.label(f"{len(hosts)} host(s): {', '.join(hosts)}")
        else:
            ui.label("no reports yet — run an audit (e.g. `fettle -A`) to populate")


def run(*, host: str = "127.0.0.1", port: int = 8080,
        reload: bool = False, show: bool = False) -> None:
    """Start the NiceGUI/uvicorn server (blocks). Bound to localhost by default."""
    ui.run(host=host, port=port, reload=reload, show=show, title="fettle")
