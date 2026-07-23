"""The web application for ``fettle web``.

Two surfaces:
- **Dashboard** (`/`, `/report.html`): serves the *same* live-generated HTML as
  ``fettle report`` (``data.report_html``) directly, with a small injected toolbar
  (run + refresh). Served as a plain page so the report's own terminal CSS/JS —
  filter, collapse — work untouched (NiceGUI's ``ui.html`` would strip a frame).
- **Run** (`/run`): a NiceGUI page to run fettle actions and watch them stream.
  Read-only audits run unprivileged; system-modifying actions run under ``sudo -S``
  with a password you type here (per-session, in memory), each behind a dry-run
  Preview and a confirmation.

This is the only module importing nicegui.
"""

from __future__ import annotations

import datetime as _dt
import html as _html
from functools import partial

from fastapi.responses import HTMLResponse, PlainTextResponse
from nicegui import app, ui

from . import data, runner

# fettle web is a PRIVILEGED local tool — keep it strictly localhost. This blocks
# a malicious page / DNS-rebinding from driving the server via a spoofed Host
# header (the requests still hit 127.0.0.1, but the browser sends the attacker's
# host). Non-browser clients (curl/tests) that send a localhost Host pass through.
_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@app.middleware("http")
async def _localhost_only(request, call_next):
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]").lower()
    if host and host not in _LOCAL_HOSTS:
        return PlainTextResponse("fettle web is localhost-only", status_code=403)
    return await call_next(request)


def _audit(header: str, code) -> None:
    """Append a one-line record of a web-triggered action (no secrets — the header
    is the command line, never the password). Best-effort; never blocks a run."""
    try:
        base = data.base_dir()
        base.mkdir(parents=True, exist_ok=True)
        path = base / "web-actions.log"
        ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a") as fh:
            fh.write(f"{ts}  {header}  -> exit {code}\n")
        path.chmod(0o600)
    except Exception:
        pass

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

# System-modifying actions (need root). Each gets a dry-run Preview + a Run (sudo).
_SUDO_ACTIONS = [
    ("-u", "Update packages (update)"),
    ("-c", "Clean caches (clean)"),
    ("-o", "Remove orphans (orphans)"),
    ("-k", "Manage kernels (kernel)"),
    ("-r", "Rebuild check (rebuild-check)"),
    ("-y", "Python rebuild (python-rebuild-check)"),
    ("-f", "Firmware check (firmware)"),
    ("-a", "Full default set (fettle -a)"),
]

_BTN = ("font-family:ui-monospace,monospace;font-size:.8rem;background:#0d141e;"
        "color:#4dd0e1;border:1px solid #4dd0e1;border-radius:4px;padding:4px 12px;"
        "cursor:pointer;text-decoration:none")

# Injected into the served report: run + remote + refresh, fixed top-right.
_TOOLBAR = (
    '<div style="position:fixed;top:9px;right:14px;z-index:9999;display:flex;gap:8px">'
    f'<a href="/run" style="{_BTN}">&#x25B6; run</a>'
    f'<a href="/remote" style="{_BTN}">&#x21C4; remote</a>'
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
    ".fsec{padding:.4rem .9rem;color:#5a6b7d;font-size:.75rem;text-transform:uppercase;"
    "letter-spacing:.05em}"
    "a.flink{color:#4dd0e1;text-decoration:none}a.flink:hover{text-decoration:underline}"
    "</style>")


async def _confirm(message: str) -> bool:
    """A modal yes/no; returns True only on an explicit Run."""
    with ui.dialog() as dialog, ui.card().style("background:#0d141e"):
        ui.label(message).classes("text-sm")
        with ui.row():
            ui.button("Cancel", on_click=lambda: dialog.submit(False)).props("flat")
            ui.button("Run", on_click=lambda: dialog.submit(True)).props("color=red")
    return bool(await dialog)


@ui.page("/run")
def _run_page() -> None:
    ui.add_head_html(_PAGE_CSS)
    with ui.row().classes("fbar items-center"):
        ui.html('<a class="flink" href="/">&#x2190; dashboard</a>')
        ui.label("fettle · run actions").classes("text-sm")

    log = ui.log(max_lines=4000).classes("w-full").style(
        "height:48vh;background:#0d141e;border:1px solid #14212e;border-radius:6px;"
        "padding:.5rem;font-size:.8rem;white-space:pre-wrap")
    log.push("# read-only audits need no sudo; system actions run `sudo fettle …`.")

    state = {"busy": False}

    async def _stream(fargs: list[str], header: str, *, sudo: bool = False,
                      password: str | None = None, footer: str = "done.") -> None:
        if state["busy"]:
            ui.notify("a run is already in progress")
            return
        state["busy"] = True
        log.push(f"\n$ {header}")
        try:
            code = await runner.run_action(fargs, log.push, sudo=sudo, password=password)
            log.push(f"[exit {code}] — {footer}")
            _audit(header, code)
        except Exception as exc:  # never let a failed run wedge the page
            log.push(f"[error] {exc!r}")
        finally:
            state["busy"] = False

    # -- read-only audits (no sudo) ------------------------------------------
    ui.html('<div class="fsec">read-only audits — no sudo</div>')
    with ui.row().style("flex-wrap:wrap;gap:8px;padding:0 .9rem"):
        for flag, label in _READONLY_ACTIONS:
            ui.button(label, on_click=partial(
                _stream, [flag], f"fettle {flag}   # {label}",
                footer="done. Reload the dashboard to see the report.")) \
                .props("flat dense no-caps color=cyan")

    # -- system maintenance (sudo) -------------------------------------------
    ui.html('<div class="fsec">system maintenance — needs your sudo password</div>')
    pw = ui.input("sudo password", password=True, password_toggle_button=True) \
        .props("dense outlined").classes("q-mx-md").style("max-width:280px")
    ui.html('<div style="padding:0 .9rem;color:#5a6b7d;font-size:.72rem">'
            'kept in memory for this page only, never stored or logged. Some flows '
            '(AUR helpers / pamac) may still prompt separately.</div>')

    async def _preview(flag: str, label: str) -> None:
        await _stream([flag, "--dry-run"], f"fettle {flag} --dry-run   # preview: {label}",
                      footer="preview only — nothing changed.")

    async def _run_sudo(flag: str, label: str) -> None:
        if not pw.value:
            log.push("[!] enter your sudo password above first.")
            return
        if not await _confirm(f"Run  sudo fettle {flag} --yes  ({label})? "
                              "This will modify the system."):
            return
        await _stream([flag, "--yes"], f"sudo fettle {flag} --yes   # {label}",
                      sudo=True, password=pw.value,
                      footer="done. Reload the dashboard to see the changes.")

    with ui.column().classes("w-full").style("gap:4px;padding:.3rem .9rem"):
        for flag, label in _SUDO_ACTIONS:
            with ui.row().classes("items-center").style("gap:8px"):
                ui.label(label).style("min-width:260px;font-size:.82rem")
                ui.button("preview", on_click=partial(_preview, flag, label)) \
                    .props("flat dense no-caps color=grey")
                ui.button("run (sudo)", on_click=partial(_run_sudo, flag, label)) \
                    .props("flat dense no-caps color=red")


@ui.page("/remote")
def _remote_page() -> None:
    ui.add_head_html(_PAGE_CSS)
    with ui.row().classes("fbar items-center"):
        ui.html('<a class="flink" href="/">&#x2190; dashboard</a>')
        ui.html('<a class="flink" href="/run">run &#x2192;</a>')
        ui.label("fettle · remote hosts & groups").classes("text-sm")

    log = ui.log(max_lines=4000).classes("w-full").style(
        "height:46vh;background:#0d141e;border:1px solid #14212e;border-radius:6px;"
        "padding:.5rem;font-size:.8rem;white-space:pre-wrap")
    log.push("# runs over SSH; the remote host elevates itself. `run` uses --yes "
             "(needs passwordless sudo on the target); `preview` is a safe --dry-run.")

    state = {"busy": False}

    async def _remote(target: str, tokens: list[str], header: str, footer: str) -> None:
        if state["busy"]:
            ui.notify("a run is already in progress")
            return
        state["busy"] = True
        log.push(f"\n$ {header}")
        try:
            code = await runner.run_action(["remote", target, *tokens], log.push)
            log.push(f"[exit {code}] — {footer}")
            _audit(header, code)
        except Exception as exc:
            log.push(f"[error] {exc!r}")
        finally:
            state["busy"] = False

    actions = ui.input("actions", value="-a").props("dense outlined") \
        .classes("q-mx-md").style("max-width:220px")
    ui.html('<div style="padding:0 .9rem;color:#5a6b7d;font-size:.72rem">'
            'forwarded to fettle on each host (e.g. <code>-a</code>, <code>-c -u</code>, '
            '<code>-P</code>).</div>')

    def _tokens() -> list[str]:
        return (actions.value or "-a").split()

    async def _preview(target: str, hosts_note: str) -> None:
        await _remote(target, [*_tokens(), "--dry-run"],
                      f"fettle remote {target} {actions.value} --dry-run   # {hosts_note}",
                      "preview only — nothing changed.")

    async def _go(target: str, hosts_note: str) -> None:
        if not await _confirm(f"Run  fettle remote {target} {actions.value} --yes  "
                              f"on {hosts_note}? This modifies those systems."):
            return
        await _remote(target, [*_tokens(), "--yes"],
                      f"fettle remote {target} {actions.value} --yes   # {hosts_note}",
                      "done. Reload the dashboard to see each host's results.")

    def _row(target: str, hosts_note: str) -> None:
        with ui.row().classes("items-center").style("gap:8px"):
            ui.label(target).style("min-width:150px;font-size:.85rem;color:#4dd0e1")
            ui.label(hosts_note).style("min-width:280px;font-size:.75rem;color:#5a6b7d")
            ui.button("preview", on_click=partial(_preview, target, hosts_note)) \
                .props("flat dense no-caps color=grey")
            ui.button("run", on_click=partial(_go, target, hosts_note)) \
                .props("flat dense no-caps color=red")

    groups = data.remote_groups()
    ui.html('<div class="fsec">configured groups</div>')
    with ui.column().classes("w-full").style("gap:4px;padding:.2rem .9rem"):
        if groups:
            for name, hosts in groups.items():
                _row(name, ", ".join(hosts))
        else:
            ui.label("no [remote.groups.<name>] in your config").style(
                "color:#5a6b7d;font-size:.8rem")

    ui.html('<div class="fsec">ad-hoc host</div>')
    with ui.row().classes("items-center").style("gap:8px;padding:.2rem .9rem"):
        host_in = ui.input("host or user@host").props("dense outlined") \
            .style("max-width:220px")

        async def _adhoc(run: bool) -> None:
            target = (host_in.value or "").strip()
            if not target:
                log.push("[!] enter a host first.")
                return
            await (_go(target, target) if run else _preview(target, target))

        ui.button("preview", on_click=lambda: _adhoc(False)) \
            .props("flat dense no-caps color=grey")
        ui.button("run", on_click=lambda: _adhoc(True)) \
            .props("flat dense no-caps color=red")


def run(*, host: str = "127.0.0.1", port: int = 8080,
        reload: bool = False, show: bool = False) -> None:
    """Start the NiceGUI/uvicorn server (blocks). Bound to localhost by default."""
    ui.run(host=host, port=port, reload=reload, show=show, title="fettle")
