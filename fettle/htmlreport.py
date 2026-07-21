"""Build a single self-contained HTML dashboard from all stored JSON.

`fettle report` regenerates `~/.fettle/report.html` from every
`reports/<host>/*.json` and `logs/<host>/*.json`, organised by host. Pure stdlib
(`html.escape`, `json`, f-strings) — no templating engine, no external assets.

RH1 is the skeleton (load → by-host structure → escaped output → 0600). RH2 adds
the dashboard cards, collapsible sections, per-type renderers, and filter/search.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from . import reports as _reports
from .util import chown_to_user

_NAME_RE = re.compile(r"^(?P<tool>.+)-(?P<ts>\d{8}-\d{6})(?:-\d+)?$")


def _parse_name(stem: str) -> tuple[str, str]:
    """`hardening-audit-20260721-152641` -> ('hardening-audit', '20260721-152641')."""
    m = _NAME_RE.match(stem)
    return (m.group("tool"), m.group("ts")) if m else (stem, "")


def _load_entry(path: Path) -> dict | None:
    """One report/log as an envelope dict. JSON is authoritative; a `.txt` with no
    `.json` sibling (pre-0.12) falls back to a text wrapper so nothing is lost."""
    tool, ts = _parse_name(path.stem)
    if path.suffix == ".json":
        try:
            env = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        env.setdefault("tool", tool)
        env.setdefault("timestamp", ts)
        return env
    # .txt fallback (only used when no .json sibling exists)
    try:
        body = path.read_text(errors="replace")
    except OSError:
        return None
    return {"tool": tool, "timestamp": ts, "data": {"text": body}, "fallback": True}


def _host_entries(directory: Path) -> list[dict]:
    """All entries in a host's reports/ or logs/ dir; JSON preferred, txt-only
    files included via fallback. Newest first."""
    if not directory.is_dir():
        return []
    entries: list[dict] = []
    seen_stems: set[str] = set()
    for p in sorted(directory.glob("*.json")):
        e = _load_entry(p)
        if e:
            entries.append(e)
            seen_stems.add(p.stem)
    for p in sorted(directory.glob("*.txt")):
        if p.stem in seen_stems:
            continue                      # already have its JSON
        e = _load_entry(p)
        if e:
            entries.append(e)
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return entries


def collect(base: Path) -> dict[str, dict]:
    """{host: {"reports": [entry...], "logs": [entry...]}} across every host."""
    data: dict[str, dict] = {}
    for kind in ("reports", "logs"):
        root = base / kind
        if not root.is_dir():
            continue
        for host_dir in sorted(root.iterdir()):
            if host_dir.is_dir():
                data.setdefault(host_dir.name, {"reports": [], "logs": []})
                data[host_dir.name][kind] = _host_entries(host_dir)
    return data


# -- rendering (RH1: plain but valid; RH2 makes it a dashboard) ---------------
_STYLE = """
body{font-family:system-ui,sans-serif;margin:2rem;line-height:1.4;color:#111}
h1{margin:0 0 .25rem} .meta{color:#666;font-size:.85rem}
section.host{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
h2{margin:.2rem 0} h3{margin:.8rem 0 .3rem;font-size:1rem}
details{margin:.2rem 0} summary{cursor:pointer}
pre{background:#f6f6f6;padding:.6rem;border-radius:6px;overflow-x:auto;font-size:.8rem}
"""


def _fmt_ts(ts: str) -> str:
    if len(ts) == 15 and ts[8] == "-":
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}"
    return ts


def _entry_body(entry: dict) -> str:
    data = entry.get("data") or {}
    if isinstance(data, dict) and set(data) == {"text"}:
        return f"<pre>{html.escape(data['text'])}</pre>"
    return f"<pre>{html.escape(json.dumps(data, indent=2))}</pre>"


def render(hostmap: dict, *, generated_at: str, version: str) -> str:
    parts = ["<h1>fettle report</h1>",
             f'<p class="meta">generated {html.escape(generated_at)} · '
             f'fettle {html.escape(version)} · {len(hostmap)} host(s)</p>']
    for host in sorted(hostmap):
        parts.append('<section class="host">')
        parts.append(f"<h2>{html.escape(host)}</h2>")
        by_tool: dict[str, list[dict]] = {}
        for e in hostmap[host]["reports"]:
            by_tool.setdefault(e.get("tool", "?"), []).append(e)
        for tool in sorted(by_tool):
            parts.append(f"<h3>{html.escape(tool)} ({len(by_tool[tool])})</h3>")
            for e in by_tool[tool]:
                parts.append(
                    f"<details><summary>{html.escape(_fmt_ts(e.get('timestamp','')))}"
                    f"</summary>{_entry_body(e)}</details>")
        logs = hostmap[host]["logs"]
        if logs:
            parts.append(f"<h3>run logs ({len(logs)})</h3>")
            for e in logs:
                parts.append(
                    f"<details><summary>{html.escape(_fmt_ts(e.get('timestamp','')))}"
                    f"</summary>{_entry_body(e)}</details>")
        parts.append("</section>")
    body = "\n".join(parts)
    return (f"<!doctype html>\n<html lang=en>\n<head>\n<meta charset=utf-8>\n"
            f"<meta name=viewport content=\"width=device-width, initial-scale=1\">\n"
            f"<title>fettle report</title>\n<style>{_STYLE}</style>\n</head>\n"
            f"<body>\n{body}\n</body>\n</html>\n")


# -- public API --------------------------------------------------------------
def build(ctx, *, open_browser: bool = False, now=None) -> Path:
    """Regenerate `<base>/report.html` from all stored JSON. Returns its path."""
    import datetime as _dt

    from . import __version__
    base, _ = _reports._settings(ctx)
    hostmap = collect(base)
    generated = (now or _dt.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    out_path = base / "report.html"
    base.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(hostmap, generated_at=generated, version=__version__))
    try:
        out_path.chmod(0o600)
    except OSError:
        pass
    chown_to_user(out_path, getattr(ctx, "sudo_user", None))
    if open_browser:
        try:
            import webbrowser
            webbrowser.open(out_path.as_uri())
        except Exception:  # pragma: no cover - best effort
            pass
    return out_path


def backfill(ctx) -> int:
    """One-off: write a wrapper `.json` for every `.txt` report/log lacking one
    (pre-0.12 files). Idempotent, non-destructive. Returns the count converted."""
    base, _ = _reports._settings(ctx)
    n = 0
    for kind, schema in (("reports", "fettle.report/1"), ("logs", "fettle.log/1")):
        root = base / kind
        if not root.is_dir():
            continue
        for host_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            for txt in sorted(host_dir.glob("*.txt")):
                js = txt.with_suffix(".json")
                if js.exists():
                    continue
                tool, ts = _parse_name(txt.stem)
                try:
                    body = txt.read_text(errors="replace")
                except OSError:
                    continue
                env = {"schema": schema, "tool": tool, "host": host_dir.name,
                       "timestamp": ts, "backfilled": True}
                if kind == "logs":
                    env.update(argv=None, exit_code=None, transcript=body)
                else:
                    env["data"] = {"text": body}
                try:
                    js.write_text(json.dumps(env, indent=2) + "\n")
                    js.chmod(0o600)
                except OSError:
                    continue
                chown_to_user(js, getattr(ctx, "sudo_user", None))
                n += 1
    return n
