"""Build a single self-contained HTML dashboard from all stored JSON.

`fettle report` regenerates `~/.fettle/report.html` from every
`reports/<host>/*.json` and `logs/<host>/*.json`, organised by host: a per-host
summary dashboard, collapsible sections grouped by report type with native
per-type rendering (scored hardening tables, severity-coloured findings, upgrade
verdicts, package lists, log transcripts), and a filter/search box. Pure stdlib
(`html.escape`, `json`, f-strings) — no templating engine, no external assets.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from . import reports as _reports
from .util import chown_to_user

_NAME_RE = re.compile(r"^(?P<tool>.+)-(?P<ts>\d{8}-\d{6})(?:-\d+)?$")
_esc = html.escape


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
    try:
        body = path.read_text(errors="replace")
    except OSError:
        return None
    return {"tool": tool, "timestamp": ts, "data": {"text": body}, "fallback": True}


def _host_entries(directory: Path) -> list[dict]:
    """All entries in a host's reports/ or logs/ dir (JSON preferred), newest first."""
    if not directory.is_dir():
        return []
    entries: list[dict] = []
    seen: set[str] = set()
    for p in sorted(directory.glob("*.json")):
        e = _load_entry(p)
        if e:
            entries.append(e)
            seen.add(p.stem)
    for p in sorted(directory.glob("*.txt")):
        if p.stem in seen:
            continue
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


# -- presentation ------------------------------------------------------------
_BANDS = ("Critical", "High", "Medium", "Low")

_STYLE = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;
  background:#f4f5f7;color:#1a1a1a;line-height:1.45}
header{background:#1f2933;color:#fff;padding:1.1rem 1.5rem}
header h1{margin:0;font-size:1.4rem}
.meta{color:#c3ccd6;font-size:.82rem;margin-top:.2rem}
.controls{margin-top:.7rem;display:flex;gap:.5rem;flex-wrap:wrap}
.controls input,.controls select{padding:.35rem .5rem;border-radius:6px;border:1px solid #3a4653;
  background:#2b3742;color:#fff;font-size:.85rem}
main{padding:1.2rem 1.5rem;max-width:1100px;margin:0 auto}
.dashboard{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:.8rem;margin-bottom:1.4rem}
.card{background:#fff;border:1px solid #dde1e6;border-radius:10px;padding:.8rem .9rem}
.card h3{margin:0 0 .4rem;font-size:1rem}
.chips{display:flex;gap:.3rem;flex-wrap:wrap;margin:.3rem 0}
.chip{font-size:.72rem;padding:.1rem .45rem;border-radius:999px;color:#fff;font-weight:600}
.count{font-size:.78rem;color:#556}
.b-Critical{background:#b00020}.b-High{background:#e65100}.b-Medium{background:#c79100}.b-Low{background:#2e7d32}
section.host{background:#fff;border:1px solid #dde1e6;border-radius:10px;margin:1rem 0;overflow:hidden}
section.host>h2{margin:0;padding:.7rem 1rem;background:#eef1f4;font-size:1.1rem}
.group{padding:.3rem 1rem 1rem}
.group h3{margin:.9rem 0 .4rem;font-size:.95rem;color:#334}
details{border:1px solid #e6e9ed;border-radius:8px;margin:.35rem 0;background:#fbfbfc}
summary{cursor:pointer;padding:.45rem .7rem;font-size:.86rem;display:flex;gap:.6rem;align-items:center}
summary::-webkit-details-marker{display:none}
.when{color:#667;font-variant-numeric:tabular-nums}
.badge{font-size:.72rem;padding:.06rem .4rem;border-radius:5px;color:#fff;font-weight:600}
.body{padding:.2rem .7rem .7rem}
table{border-collapse:collapse;width:100%;font-size:.8rem}
th,td{text-align:left;padding:.25rem .5rem;border-bottom:1px solid #eee}
th{color:#556;font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;min-width:4.5rem;text-align:center;border-radius:5px;color:#fff;font-size:.72rem;padding:.05rem .3rem}
.sev-CRIT{background:#b00020}.sev-WARN{background:#c79100}.sev-LOW{background:#2f6fb0}.sev-INFO{background:#77808a}
.v-safe{background:#2e7d32}.v-caution{background:#c79100}.v-risky{background:#b00020}
ul.k{margin:.3rem 0;padding-left:1.1rem}
pre{background:#f6f7f9;padding:.6rem;border-radius:6px;overflow-x:auto;font-size:.78rem;max-height:26rem}
.muted{color:#778}
.hidden{display:none}
"""

_SCRIPT = """
const q=document.getElementById('q'),hf=document.getElementById('hostf'),
      tf=document.getElementById('typef');
function apply(){
  const s=(q.value||'').toLowerCase(),h=hf.value,t=tf.value;
  document.querySelectorAll('section.host').forEach(sec=>{
    const host=sec.dataset.host; let anyH=false;
    sec.querySelectorAll('.group').forEach(g=>{
      const type=g.dataset.type; let anyG=false;
      g.querySelectorAll('details').forEach(d=>{
        const hit=(!s||d.textContent.toLowerCase().includes(s))&&
                  (!h||host===h)&&(!t||type===t);
        d.classList.toggle('hidden',!hit); if(hit)anyG=true;
      });
      g.classList.toggle('hidden',!anyG); if(anyG)anyH=true;
    });
    sec.classList.toggle('hidden',!anyH);
  });
}
[q,hf,tf].forEach(el=>el.addEventListener('input',apply));
"""


def _fmt_ts(ts: str) -> str:
    if len(ts) == 15 and ts[8] == "-":
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}:{ts[13:15]}"
    return ts


# -- per-type renderers (each returns escaped HTML; never trusts input) ------
def _render_hardening(data: dict) -> str:
    tally = data.get("band_tally") or {}
    chips = "".join(f'<span class="chip b-{b}">{tally.get(b,0)} {b}</span>'
                    for b in _BANDS if tally.get(b))
    scan = data.get("scan") or {}
    meta = (f'<div class="muted">scanned {scan.get("analyzed",0)} binaries · '
            f'{scan.get("static",0)} static skipped</div>')
    rows = ""
    shown = 0
    for p in data.get("packages", []):
        if p.get("band") not in ("Critical", "High"):
            continue
        shown += 1
        miss = ", ".join(f"{k}={v}" for k, v in (p.get("checks") or {}).items())
        rows += (f'<tr><td><span class="pill b-{_esc(str(p.get("band")))}">'
                 f'{_esc(str(p.get("band")))}</span></td>'
                 f'<td class=num>{_esc(str(p.get("score")))}</td>'
                 f'<td>{"!" if p.get("has_privileged") else ""}</td>'
                 f'<td>{_esc(str(p.get("package")))}</td>'
                 f'<td class=num>{_esc(str(p.get("binaries")))}</td>'
                 f'<td>{_esc(miss)}</td></tr>')
    table = ""
    if rows:
        table = ('<table><tr><th>band</th><th>score</th><th>!</th><th>package</th>'
                 f'<th>bins</th><th>missing</th></tr>{rows}</table>')
    rest = sum(tally.get(b, 0) for b in ("Medium", "Low"))
    tail = f'<div class="muted">+ {rest} Medium/Low package(s)</div>' if rest else ""
    return f'{chips}{meta}{table or "<div class=muted>no Critical/High packages</div>"}{tail}'


def _render_findings(data: dict) -> str:
    findings = data.get("findings") or []
    if not findings:
        return '<div class="muted">no findings</div>'
    order = {"CRIT": 0, "WARN": 1, "LOW": 2, "INFO": 3}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity"), 9))
    rows = "".join(
        f'<tr><td><span class="pill sev-{_esc(str(f.get("severity","INFO")))}">'
        f'{_esc(str(f.get("severity","")))}</span></td>'
        f'<td>{_esc(str(f.get("source","")))}</td>'
        f'<td>{_esc(str(f.get("package","")))}</td>'
        f'<td>{_esc(str(f.get("detail","")))}</td></tr>' for f in findings)
    return (f'<table><tr><th>sev</th><th>source</th><th>package</th><th>detail</th></tr>'
            f'{rows}</table>')


def _render_upgrade(data: dict) -> str:
    v = str(data.get("safety_verdict", "?"))
    head = (f'<span class="pill v-{_esc(v)}">{_esc(v.upper())}</span> '
            f'<span class="muted">failure likelihood: '
            f'{_esc(str(data.get("failure_likelihood","?")))}</span>')
    out = [head, f'<p>{_esc(str(data.get("summary","")))}</p>']

    def _lst(title, items):
        items = items or []
        if not items:
            return ""
        li = "".join(f"<li>{_esc(str(x))}</li>" for x in items)
        return f'<div><strong>{title}</strong><ul class=k>{li}</ul></div>'
    out.append(_lst("Before upgrading", data.get("must_do_before")))
    out.append(_lst("After upgrading", data.get("should_do_after")))
    rec = data.get("recommendation")
    if rec:
        out.append(f'<p class="muted">Recommendation: {_esc(str(rec))}</p>')
    return "".join(out)


def _render_pkglist(data: dict) -> str:
    pkgs = data.get("packages") or []
    if not pkgs:
        return '<div class="muted">none</div>'
    if isinstance(pkgs[0], dict):
        li = "".join(f'<li>{_esc(str(p.get("name","")))} '
                     f'<span class=muted>{_esc(str(p.get("version","")))}</span></li>'
                     for p in pkgs)
    else:
        li = "".join(f"<li>{_esc(str(p))}</li>" for p in pkgs)
    return f'<div class=muted>{len(pkgs)} package(s)</div><ul class=k>{li}</ul>'


def _render_aur_audit(data: dict) -> str:
    pkgs = data.get("packages") or []
    rows = "".join(
        f'<tr><td>{_esc(str(p.get("name","")))}</td>'
        f'<td>{_esc(str(p.get("maintainer","")))}</td>'
        f'<td class=num>{_esc(str(p.get("age_days","")))}</td>'
        f'<td class=num>{_esc(str(p.get("votes","")))}</td>'
        f'<td>{_esc(str(p.get("flags","")))}</td></tr>' for p in pkgs[:60])
    table = (f'<table><tr><th>package</th><th>maintainer</th><th>age(d)</th>'
             f'<th>votes</th><th>flags</th></tr>{rows}</table>') if rows else ""
    missing = data.get("not_found_in_aur") or []
    changes = data.get("maintainer_changes") or []
    extra = ""
    if missing:
        extra += f'<p><strong>Not in AUR:</strong> {_esc(", ".join(map(str,missing)))}</p>'
    if changes:
        extra += ('<p><strong>Maintainer changes:</strong></p><ul class=k>'
                  + "".join(f"<li>{_esc(str(c))}</li>" for c in changes) + "</ul>")
    return f'{table}{extra}' or '<div class=muted>no packages</div>'


def _render_log(entry: dict) -> str:
    ec = entry.get("exit_code")
    meta = (f'<div class=muted>argv: {_esc(str(entry.get("argv")))} · '
            f'exit: {_esc(str(ec))}</div>')
    return f'{meta}<pre>{_esc(str(entry.get("transcript","")))}</pre>'


_RENDERERS = {
    "hardening-audit": _render_hardening,
    "pkg-audit": _render_findings, "aur-ioc-scan": _render_findings,
    "upgrade-check": _render_upgrade, "aur-audit": _render_aur_audit,
    "alien-pkgs": _render_pkglist, "obsolete-pkgs": _render_pkglist,
}


def _render_entry_body(entry: dict) -> str:
    if entry.get("schema") == "fettle.log/1" or "transcript" in entry:
        return _render_log(entry)
    data = entry.get("data")
    if not isinstance(data, dict):
        return '<div class="muted">(no data)</div>'
    if set(data) == {"text"}:                       # wrapper / backfilled / fallback
        return f'<pre>{_esc(data["text"])}</pre>'
    fn = _RENDERERS.get(entry.get("tool", ""))
    try:
        return fn(data) if fn else f'<pre>{_esc(json.dumps(data, indent=2))}</pre>'
    except Exception:                               # a bad payload must never break the page
        return f'<pre>{_esc(json.dumps(data, indent=2))}</pre>'


def _entry_badge(entry: dict) -> str:
    """A small severity/verdict badge on the entry's summary line, when relevant."""
    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    tally = data.get("band_tally") or {}
    for b in _BANDS:
        if tally.get(b):
            return f'<span class="badge b-{b}">{tally[b]} {b}</span>'
    v = data.get("safety_verdict")
    if v:
        return f'<span class="badge v-{_esc(str(v))}">{_esc(str(v).upper())}</span>'
    return ""


def _host_summary(host: dict) -> str:
    """The dashboard card body: latest hardening bands, per-type counts, latest run."""
    chips = ""
    for e in host["reports"]:
        if e.get("tool") == "hardening-audit":
            tally = (e.get("data") or {}).get("band_tally") or {}
            chips = "".join(f'<span class="chip b-{b}">{tally.get(b,0)} {b}</span>'
                            for b in _BANDS if tally.get(b))
            break
    types: dict[str, int] = {}
    for e in host["reports"]:
        types[e.get("tool", "?")] = types.get(e.get("tool", "?"), 0) + 1
    counts = " · ".join(f"{_esc(t)}:{n}" for t, n in sorted(types.items()))
    latest = max((e.get("timestamp", "") for e in host["reports"] + host["logs"]),
                 default="")
    return (f'<div class="chips">{chips or "<span class=muted>no hardening scan</span>"}</div>'
            f'<div class="count">{counts or "no reports"}</div>'
            f'<div class="count muted">latest: {_esc(_fmt_ts(latest)) or "—"}</div>')


def render(hostmap: dict, *, generated_at: str, version: str) -> str:
    hosts = sorted(hostmap)
    all_types = sorted({e.get("tool", "?")
                        for h in hostmap.values() for e in h["reports"]})
    host_opts = "".join(f'<option value="{_esc(h)}">{_esc(h)}</option>' for h in hosts)
    type_opts = "".join(f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in all_types)

    cards = "".join(f'<div class="card"><h3>{_esc(h)}</h3>{_host_summary(hostmap[h])}</div>'
                    for h in hosts)

    sections = []
    for h in hosts:
        groups = []
        by_tool: dict[str, list[dict]] = {}
        for e in hostmap[h]["reports"]:
            by_tool.setdefault(e.get("tool", "?"), []).append(e)
        for tool in sorted(by_tool):
            items = "".join(
                f'<details data-host="{_esc(h)}" data-type="{_esc(tool)}">'
                f'<summary><span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'{_entry_badge(e)}</summary>'
                f'<div class="body">{_render_entry_body(e)}</div></details>'
                for e in by_tool[tool])
            groups.append(f'<div class="group" data-host="{_esc(h)}" data-type="{_esc(tool)}">'
                          f'<h3>{_esc(tool)} ({len(by_tool[tool])})</h3>{items}</div>')
        logs = hostmap[h]["logs"]
        if logs:
            items = "".join(
                f'<details data-host="{_esc(h)}" data-type="run-log">'
                f'<summary><span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'</summary><div class="body">{_render_entry_body(e)}</div></details>'
                for e in logs)
            groups.append(f'<div class="group" data-host="{_esc(h)}" data-type="run-log">'
                          f'<h3>run logs ({len(logs)})</h3>{items}</div>')
        sections.append(f'<section class="host" data-host="{_esc(h)}">'
                        f'<h2>{_esc(h)}</h2>{"".join(groups)}</section>')

    return f"""<!doctype html>
<html lang=en>
<head>
<meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>fettle report</title>
<style>{_STYLE}</style>
</head>
<body>
<header>
<h1>fettle report</h1>
<div class="meta">generated {_esc(generated_at)} · fettle {_esc(version)} · {len(hosts)} host(s)</div>
<div class="controls">
<input id="q" type="search" placeholder="search…">
<select id="hostf"><option value="">all hosts</option>{host_opts}</select>
<select id="typef"><option value="">all types</option>{type_opts}</select>
</div>
</header>
<main>
<div class="dashboard">{cards}</div>
{"".join(sections)}
</main>
<script>{_SCRIPT}</script>
</body>
</html>
"""


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
