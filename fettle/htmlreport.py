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
:root{
  --bg:#080b10;--panel:#0c121b;--panel2:#0f1722;--border:#1b2a3a;
  --fg:#c6d3e2;--dim:#5a6b7d;--green:#4ade80;--amber:#e3b341;
  --red:#ff6b6b;--cyan:#4dd0e1;--yellow:#f2cc60;
  --mono:ui-monospace,"JetBrains Mono","Cascadia Code","Fira Code","DejaVu Sans Mono",Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html{color-scheme:dark}
body{font-family:var(--mono);margin:0;background:var(--bg);color:var(--fg);
  font-size:14px;line-height:1.5;letter-spacing:.2px}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:9;
  background:repeating-linear-gradient(0deg,transparent 0 2px,rgba(0,0,0,.16) 2px 3px);
  mix-blend-mode:multiply;opacity:.5}
header{background:linear-gradient(180deg,#0c131d,#0a0f16);border-bottom:1px solid var(--border);padding:0 0 .9rem}
.titlebar{display:flex;align-items:center;gap:.45rem;padding:.5rem .9rem;
  border-bottom:1px solid var(--border);background:#0a0f16}
.dot{width:11px;height:11px;border-radius:50%;display:inline-block}
.d-r{background:#ff5f56}.d-y{background:#ffbd2e}.d-g{background:#27c93f}
.tb-title{margin-left:.6rem;color:var(--dim);font-size:.8rem}
.prompt-line{font-size:1.05rem;white-space:nowrap;overflow-x:auto;padding:.9rem 1.1rem 0}
.user,.host{color:var(--green)}.cwd{color:var(--cyan)}.sep,.dollar{color:var(--dim)}
.cmd{color:var(--fg);text-shadow:0 0 8px rgba(74,222,128,.25)}
.cursor{display:inline-block;width:.6em;height:1.05em;background:var(--green);
  margin-left:.15em;vertical-align:-.15em;animation:blink 1.1s steps(1) infinite;
  box-shadow:0 0 8px rgba(74,222,128,.6)}
@keyframes blink{50%{opacity:0}}
.meta{color:var(--dim);font-size:.82rem;margin:.5rem 0 0;padding:0 1.1rem}
.controls{margin:.7rem 0 0;padding:0 1.1rem;display:flex;gap:.5rem;flex-wrap:wrap}
.controls input,.controls select{font-family:var(--mono);padding:.35rem .55rem;border-radius:4px;
  border:1px solid var(--border);background:#0a0f16;color:var(--fg);font-size:.82rem}
.controls input:focus,.controls select:focus{outline:none;border-color:var(--green);
  box-shadow:0 0 0 1px rgba(74,222,128,.3)}
main{padding:1.3rem 1.1rem;max-width:1180px;margin:0 auto}
.dashboard{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:.8rem;margin-bottom:1.6rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:.7rem .85rem}
.card::before{content:"● ";color:var(--green)}
.card h3{display:inline;margin:0;font-size:.98rem;color:var(--fg)}
.chips{display:flex;gap:.35rem;flex-wrap:wrap;margin:.5rem 0 .35rem}
.chip{font-size:.72rem;padding:.06rem .4rem;border-radius:3px;border:1px solid;font-weight:600}
.chip::before{content:"["}.chip::after{content:"]"}
.count{font-size:.76rem;color:var(--dim)}
.b-Critical{color:var(--red);border-color:var(--red)}
.b-High{color:var(--amber);border-color:var(--amber)}
.b-Medium{color:var(--yellow);border-color:var(--yellow)}
.b-Low{color:var(--green);border-color:var(--green)}
section.host{background:var(--panel);border:1px solid var(--border);border-radius:6px;margin:1rem 0;overflow:hidden}
section.host>h2{margin:0;padding:.6rem .9rem;background:var(--panel2);font-size:1.02rem;
  border-bottom:1px solid var(--border);color:var(--green)}
section.host>h2::before{content:"# ";color:var(--dim)}
.group{padding:.2rem .9rem .9rem}
.group h3{margin:.9rem 0 .35rem;font-size:.9rem;color:var(--cyan)}
.group h3::before{content:"## ";color:var(--dim)}
details{border:1px solid var(--border);border-radius:4px;margin:.35rem 0;background:#0a0f16}
details[open]{border-color:#26384b}
summary{cursor:pointer;padding:.4rem .65rem;font-size:.84rem;display:flex;gap:.55rem;align-items:center;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"[+]";color:var(--green);font-weight:700;flex:none}
details[open]>summary::before{content:"[-]";color:var(--amber)}
summary:hover{background:#0d141e}
summary:hover::before{text-shadow:0 0 8px currentColor}
.when{color:var(--dim);font-variant-numeric:tabular-nums}
.badge,.pill{font-family:var(--mono);font-size:.72rem;font-weight:600;padding:.05rem .35rem;border-radius:3px;border:1px solid}
.badge::before,.pill::before{content:"["}.badge::after,.pill::after{content:"]"}
.badge{color:var(--fg)}
.badge.b-ok{color:var(--green);border-color:var(--green)}
.badge.b-bad{color:var(--red);border-color:var(--red)}
.grow{display:flex;gap:.6rem;align-items:baseline;padding:.15rem .2rem;font-size:.82rem}
.cmdtag{font-family:var(--mono);font-size:.72rem;color:var(--cyan)}
.cmdtag::before{content:"$ ";color:var(--dim)}
.body{padding:.3rem .7rem .75rem}
table{border-collapse:collapse;width:100%;font-size:.8rem}
th,td{text-align:left;padding:.28rem .55rem;border-bottom:1px solid #14212e}
th{color:var(--dim);font-weight:600;text-transform:lowercase}
tr:hover td{background:#0d141e}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;text-align:center;background:transparent}
.sev-CRIT{color:var(--red);border-color:var(--red)}
.sev-WARN{color:var(--amber);border-color:var(--amber)}
.sev-LOW{color:var(--cyan);border-color:var(--cyan)}
.sev-INFO{color:var(--dim);border-color:var(--dim)}
.v-safe{color:var(--green);border-color:var(--green)}
.v-caution{color:var(--amber);border-color:var(--amber)}
.v-risky{color:var(--red);border-color:var(--red)}
ul.k{margin:.35rem 0;padding-left:1.2rem}
ul.k li::marker{content:"\\203a  ";color:var(--green)}
strong{color:var(--fg)}
pre{background:#070a0e;border:1px solid var(--border);padding:.6rem;border-radius:4px;
  overflow-x:auto;font-size:.78rem;max-height:26rem;color:#a9bccf}
.muted{color:var(--dim)}
h4.cat{margin:.6rem 0 .2rem;color:var(--cyan);font-size:.85rem;font-weight:600}
h4.cat::before{content:"» ";color:var(--dim)}
.hidden{display:none}
::selection{background:rgba(74,222,128,.25)}
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


def _current_user() -> str:
    try:
        import getpass
        return getpass.getuser()
    except Exception:  # pragma: no cover - getpass can fail without a passwd entry
        return "you"


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


_LEVEL_PILL = {"error": "sev-CRIT", "warn": "sev-WARN", "ok": "v-safe",
               "info": "sev-INFO"}


def _render_sysaudit(data: dict) -> str:
    cats = data.get("categories") or []
    out = []
    for c in cats:
        out.append(f'<h4 class="cat">{_esc(str(c.get("name", "")))}</h4>')
        items = c.get("items", [])
        if items:
            rows = "".join(
                f'<tr><td><span class="pill {_LEVEL_PILL.get(it.get("level"), "sev-INFO")}">'
                f'{_esc(str(it.get("level", "")))}</span></td>'
                f'<td>{_esc(str(it.get("label", "")))}</td>'
                f'<td>{_esc(str(it.get("value", "")))}</td></tr>'
                for it in items)
            out.append(f"<table>{rows}</table>")
        else:
            out.append('<div class="muted">summary in raw output below</div>')
    text = data.get("text")
    if text:                                        # full transcript (all check detail)
        out.append('<details class="raw"><summary>raw output</summary>'
                   f'<pre>{_esc(str(text))}</pre></details>')
    return "".join(out) or '<div class="muted">no results</div>'


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
    "sys-audit": _render_sysaudit,
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


def _is_empty(entry: dict) -> bool:
    """True when a report/log carries no meaningful content (nothing to show).

    A clean `obsolete-pkgs` with no packages, an `aur-ioc-scan` with no
    indicators, a blank backfilled text report, etc. — hidden from the dashboard.
    """
    if entry.get("schema") == "fettle.log/1" or "transcript" in entry:
        return not str(entry.get("transcript") or "").strip()
    data = entry.get("data")
    if not isinstance(data, dict):
        return True
    if set(data) == {"text"}:                       # wrapper / backfilled / fallback
        return not data["text"].strip()
    tool = entry.get("tool")
    if tool in ("pkg-audit", "aur-ioc-scan"):
        return not data.get("findings")
    if tool in ("obsolete-pkgs", "alien-pkgs", "hardening-audit"):
        return not data.get("packages")
    if tool == "aur-audit":
        return not (data.get("packages") or data.get("not_found_in_aur")
                    or data.get("maintainer_changes"))
    if tool == "sys-audit":
        return not (data.get("categories") or data.get("text"))
    return False                                    # upgrade-check / unknown: keep


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


# friendly descriptions shown before the technical section name, e.g.
# "Package Supply-Chain Audit (pkg-audit)".
_SECTION_LABELS = {
    "hardening-audit": "Binary Hardening Audit",
    "pkg-audit": "Package Supply-Chain Audit",
    "aur-audit": "AUR Package Health",
    "aur-ioc-scan": "AUR Threat Scan",
    "alien-pkgs": "Foreign / AUR Packages",
    "obsolete-pkgs": "Obsolete Packages",
    "upgrade-check": "AI Upgrade Check",
    "sys-audit": "System Security Scan",
    "run-log": "Session Transcripts",
    "group-run": "Group Orchestration",
}


def _section_title(key: str, count: int) -> str:
    desc = _SECTION_LABELS.get(key, key.replace("-", " ").title())
    shown = "run logs" if key == "run-log" else "group" if key == "group-run" else key
    return f'{_esc(desc)} <span class="muted">({_esc(shown)}) · {count}</span>'


def _run_label(entry: dict) -> str:
    """A short 'what did this run do' hint for a run-log summary, from its argv."""
    argv = entry.get("argv")
    return ("fettle " + " ".join(str(a) for a in argv)) if isinstance(argv, list) and argv else ""


def _cmd_tag(entry: dict) -> str:
    """The exact command line that produced a report, shown as a `$ fettle …` chip
    in the entry's summary. Absent on pre-0.13.1 reports (no `command` recorded)."""
    cmd = entry.get("command")
    if not isinstance(cmd, str) or not cmd:
        return ""
    return f'<span class="cmdtag" title="command that produced this report">{_esc(cmd)}</span>'


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
        if _is_empty(e):
            continue
        types[e.get("tool", "?")] = types.get(e.get("tool", "?"), 0) + 1
    counts = " · ".join(f"{_esc(t)}:{n}" for t, n in sorted(types.items()))
    latest = max((e.get("timestamp", "") for e in host["reports"] + host["logs"]),
                 default="")
    return (f'<div class="chips">{chips or "<span class=muted>no hardening scan</span>"}</div>'
            f'<div class="count">{counts or "no reports"}</div>'
            f'<div class="count muted">latest: {_esc(_fmt_ts(latest)) or "—"}</div>')


def render(hostmap: dict, *, generated_at: str, version: str, user: str = "you",
           groups=frozenset()) -> str:
    # A configured group name (e.g. `fettle remote bifrost-lab`) is NOT a host — its
    # only artifact here is the controller's orchestration run-log. Keep it out of
    # the host dashboard and show it in a separate "group runs" area; the real
    # per-host results already live under each host's own directory.
    all_names = sorted(hostmap)
    hosts = [h for h in all_names if h not in groups]
    group_names = [h for h in all_names if h in groups]
    all_types = sorted({e.get("tool", "?") for h in hosts
                        for e in hostmap[h]["reports"] if not _is_empty(e)})
    host_opts = "".join(f'<option value="{_esc(h)}">{_esc(h)}</option>' for h in hosts)
    type_opts = "".join(f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in all_types)

    cards = "".join(f'<div class="card"><h3>{_esc(h)}</h3>{_host_summary(hostmap[h])}</div>'
                    for h in hosts)

    sections = []
    for h in hosts:
        groups = []
        hidden = 0
        by_tool: dict[str, list[dict]] = {}
        for e in hostmap[h]["reports"]:
            by_tool.setdefault(e.get("tool", "?"), []).append(e)
        for tool in sorted(by_tool):
            entries = [e for e in by_tool[tool] if not _is_empty(e)]
            hidden += len(by_tool[tool]) - len(entries)
            if not entries:                         # whole group is empty — skip it
                continue
            items = "".join(
                f'<details data-host="{_esc(h)}" data-type="{_esc(tool)}">'
                f'<summary><span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'{_entry_badge(e)}{_cmd_tag(e)}</summary>'
                f'<div class="body">{_render_entry_body(e)}</div></details>'
                for e in entries)
            groups.append(f'<div class="group" data-host="{_esc(h)}" data-type="{_esc(tool)}">'
                          f'<h3>{_section_title(tool, len(entries))}</h3>{items}</div>')
        logs = [e for e in hostmap[h]["logs"] if not _is_empty(e)]
        if logs:
            items = "".join(
                f'<details data-host="{_esc(h)}" data-type="run-log">'
                f'<summary><span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'<span class="muted">{_esc(_run_label(e))}</span>'
                f'</summary><div class="body">{_render_entry_body(e)}</div></details>'
                for e in logs)
            groups.append(f'<div class="group" data-host="{_esc(h)}" data-type="run-log">'
                          f'<h3>{_section_title("run-log", len(logs))}</h3>{items}</div>')
        if not groups:                              # nothing to show for this host
            continue
        note = (f'<div class="group muted" style="font-size:.75rem">'
                f'({hidden} empty report(s) hidden)</div>') if hidden else ""
        sections.append(f'<section class="host" data-host="{_esc(h)}">'
                        f'<h2>{_esc(h)}</h2>{"".join(groups)}{note}</section>')

    # "Group runs" — a tiny pass/fail summary of each `fettle remote <group>`
    # session. The real per-host results (incl. the update output) live under each
    # target host above, fetched from that host's own run-log; here we only note
    # that the orchestration ran, so this stays a one-liner per run.
    group_blocks = []
    for g in group_names:
        logs = [e for e in hostmap[g]["logs"] if not _is_empty(e)]
        if not logs:
            continue
        rows = []
        for e in sorted(logs, key=lambda e: e.get("timestamp", ""), reverse=True):
            code = e.get("exit_code")
            ok = code in (0, None)
            label = _esc(_run_label(e)) or "fettle remote"
            badge = ("<span class=\"badge b-ok\">ok</span>" if ok
                     else f'<span class="badge b-bad">exit {_esc(str(code))}</span>')
            rows.append(
                f'<div class="grow" data-host="{_esc(g)}" data-type="group-run">'
                f'<span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'<span class="muted">{label}</span>{badge}</div>')
        group_blocks.append(
            f'<div class="group" data-host="{_esc(g)}" data-type="group-run">'
            f'<h3>{_esc(g)} <span class="muted">(group) · {len(logs)}</span></h3>'
            f'{"".join(rows)}</div>')
    group_section = ""
    if group_blocks:
        group_section = (
            '<section class="host" data-host="(group runs)"><h2>group runs</h2>'
            '<div class="muted" style="padding:.2rem .9rem .4rem;font-size:.78rem">'
            'pass/fail summary of each `fettle remote &lt;group&gt;` — each host’s '
            'own results are under that host above</div>'
            f'{"".join(group_blocks)}</section>')

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
<div class="titlebar"><span class="dot d-r"></span><span class="dot d-y"></span><span class="dot d-g"></span><span class="tb-title">— ~/.fettle/report.html —</span></div>
<div class="prompt-line"><span class="user">{_esc(user)}</span><span class="sep">@</span><span class="host">fettle</span><span class="sep">:</span><span class="cwd">~/.fettle</span><span class="dollar">$</span> <span class="cmd">fettle report</span><span class="cursor"></span></div>
<div class="meta"># generated {_esc(generated_at)} · fettle v{_esc(version)} · {len(hosts)} host(s)</div>
<div class="controls">
<input id="q" type="search" placeholder="grep…">
<select id="hostf"><option value="">all hosts</option>{host_opts}</select>
<select id="typef"><option value="">all types</option>{type_opts}</select>
</div>
</header>
<main>
<div class="dashboard">{cards}</div>
{"".join(sections)}
{group_section}
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
    user = getattr(ctx, "sudo_user", None) or _current_user()
    try:
        from . import remote
        groups = frozenset(remote.remote_groups(getattr(ctx, "config", None)))
    except Exception:
        groups = frozenset()
    out_path = base / "report.html"
    base.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(hostmap, generated_at=generated,
                               version=__version__, user=user, groups=groups))
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
