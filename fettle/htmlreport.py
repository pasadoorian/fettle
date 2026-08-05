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
import urllib.parse
from pathlib import Path

from . import reports as _reports
from .util import chown_to_user

_NAME_RE = re.compile(r"^(?P<tool>.+)-(?P<ts>\d{8}-\d{6})(?:-\d+)?$")
_esc = html.escape

_AUR_PKG_BASE = "https://aur.archlinux.org/packages/"


# Where a package name can be looked up, per source. `arch` is the OFFICIAL repo:
# advisory-check's arch rows come from security.archlinux.org, which tracks core/extra
# — the AUR packages are the ones in its "not covered" list, which link to the AUR.
_PKG_BASE = {
    "arch": "https://archlinux.org/packages/?name={}",
    "aur": "https://aur.archlinux.org/packages/{}",
    "apt": "https://packages.debian.org/{}",
    "debian": "https://packages.debian.org/{}",
    "ubuntu": "https://packages.ubuntu.com/{}",
    "dnf": "https://packages.fedoraproject.org/pkgs/{}/",
    "rhel": "https://packages.fedoraproject.org/pkgs/{}/",
    "flatpak": "https://flathub.org/apps/{}",
    "snap": "https://snapcraft.io/{}",
}
# Language registries, for OSV findings that record their ecosystem.
_ECO_BASE = {
    "PyPI": "https://pypi.org/project/{}/",
    "npm": "https://www.npmjs.com/package/{}",
    "crates.io": "https://crates.io/crates/{}",
    "Packagist": "https://packagist.org/packages/{}",
    "RubyGems": "https://rubygems.org/gems/{}",
    "Go": "https://pkg.go.dev/{}",
}
# Each advisory identifier to the authority that actually holds it. GHSA advisories
# frequently have no NVD entry at all, so sending them to NVD would dead-end.
_ADVISORY_BASE = (
    ("CVE-", "https://nvd.nist.gov/vuln/detail/{}"),
    ("GHSA-", "https://github.com/advisories/{}"),
    ("PYSEC-", "https://osv.dev/vulnerability/{}"),
    ("RUSTSEC-", "https://rustsec.org/advisories/{}.html"),
    ("AVG-", "https://security.archlinux.org/{}"),
    ("ASA-", "https://security.archlinux.org/{}"),
    ("DSA-", "https://security-tracker.debian.org/tracker/{}"),
    ("DLA-", "https://security-tracker.debian.org/tracker/{}"),
    ("USN-", "https://ubuntu.com/security/notices/{}"),
)


def _pkg_link(name: str, *, source: str = "", ecosystem: str = "") -> str:
    """A package name as a link to wherever that package actually lives, or plain
    text when nothing sensible can be derived. Deterministic from the name."""
    base = _ECO_BASE.get(ecosystem) or _PKG_BASE.get(str(source).lower())
    if not base or not name:
        return _esc(name)
    href = base.format(urllib.parse.quote(str(name), safe=""))
    return (f'<a href="{_esc(href)}" target="_blank" rel="noopener">'
            f'{_esc(name)}</a>')


def _advisory_link(ident: str) -> str:
    """One advisory/CVE identifier as a link to its own authority."""
    ident = str(ident or "")
    # Ubuntu mirrors CVEs under its own prefix. Its own page carries the per-release
    # fix status, which is the useful part for an Ubuntu finding -- NVD would give the
    # CVE without saying whether Ubuntu has shipped anything.
    if ident.startswith("UBUNTU-CVE-"):
        cve = urllib.parse.quote(ident[len("UBUNTU-"):], safe="")
        href = f"https://ubuntu.com/security/{cve}"
        return (f'<a href="{_esc(href)}" target="_blank" rel="noopener">'
                f'{_esc(ident)}</a>')
    lookup = ident
    for prefix, base in _ADVISORY_BASE:
        if lookup.startswith(prefix):
            href = base.format(urllib.parse.quote(lookup, safe=""))
            return (f'<a href="{_esc(href)}" target="_blank" rel="noopener">'
                    f'{_esc(ident)}</a>')
    return _esc(ident)


def _aur_pkg_link(name: str) -> str:
    """A package name as a link to its AUR page (deterministic from the name)."""
    href = _AUR_PKG_BASE + urllib.parse.quote(name, safe="")
    return (f'<a href="{_esc(href)}" target="_blank" rel="noopener">'
            f'{_esc(name)}</a>')


def _safe_url(url: str) -> str:
    """Return ``url`` only if it is an http(s) URL — the gate for AUR-supplied
    upstream URLs, which are attacker-influenceable (block ``javascript:`` etc.)."""
    if not isinstance(url, str):
        return ""
    return url if url.lower().startswith(("http://", "https://")) else ""


def _ext_link(url: str, text: str) -> str:
    """An external link, or ``""`` when the url is absent/unsafe."""
    safe = _safe_url(url)
    return (f'<a href="{_esc(safe)}" target="_blank" rel="noopener">{_esc(text)}</a>'
            if safe else "")


def _homepage_link(pkg: dict) -> str:
    """A small ` ↗ homepage` link for a package's (safe) upstream URL, else ``""``."""
    link = _ext_link(str(pkg.get("homepage", "")), "↗ homepage")
    return f' <span class="homepage">{link}</span>' if link else ""


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
.b-Info{color:var(--dim);border-color:var(--dim)}
.b-ok{color:var(--green);border-color:var(--green)}
.d-new{color:var(--amber)}.d-gone{color:var(--green)}
.delta{font-size:.72rem;margin-left:.4rem;cursor:help}
section.host{background:var(--panel);border:1px solid var(--border);border-radius:6px;margin:1rem 0;overflow:hidden}
section.host>h2{margin:0;padding:.6rem .9rem;background:var(--panel2);font-size:1.02rem;
  border-bottom:1px solid var(--border);color:var(--green)}
section.host>h2::before{content:"# ";color:var(--dim)}
.group{padding:.2rem .9rem .9rem}
.group h3{margin:.9rem 0 .35rem;font-size:.9rem;color:var(--cyan)}
.group h3::before{content:"## ";color:var(--dim)}
details.envs{border:0;background:none;margin:0}
details.envs>summary{padding:0;font-size:inherit;gap:.35rem}
details.envs>pre{margin:.3rem 0 .1rem;padding:.35rem .5rem;background:#080d14;
  border:1px solid var(--border);border-radius:3px;font-size:.74rem;overflow-x:auto}
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
.d-new{color:var(--amber)}.d-gone{color:var(--green)}
.delta{font-size:.72rem;margin-left:.4rem;cursor:help}
.badge.b-bad{color:var(--red);border-color:var(--red)}
.grow{display:flex;gap:.6rem;align-items:baseline;padding:.15rem .2rem;font-size:.82rem}
.cmdtag{font-family:var(--mono);font-size:.72rem;color:var(--cyan)}
.cmdtag::before{content:"$ ";color:var(--dim)}
.body{padding:.3rem .7rem .75rem;overflow-x:auto}
table{min-width:max-content}
table{border-collapse:collapse;width:100%;font-size:.8rem}
th,td{text-align:left;padding:.28rem .55rem;border-bottom:1px solid #14212e}
th{color:var(--dim);font-weight:600;text-transform:lowercase}
tr:hover td{background:#0d141e}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.desc{max-width:44ch}
.desc-text{display:inline-block;max-width:30ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}
td a{color:var(--cyan);text-decoration:none}
td a:hover{text-decoration:underline}
.homepage{margin-left:.4rem;font-size:.72rem}
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
      tf=document.getElementById('typef'),sf=document.getElementById('sevf');
function apply(){
  const s=(q.value||'').toLowerCase(),h=hf.value,t=tf.value,
        sev=sf.value?parseInt(sf.value,10):null;
  document.querySelectorAll('section.host').forEach(sec=>{
    const host=sec.dataset.host; let anyH=false;
    sec.querySelectorAll('.group').forEach(g=>{
      const type=g.dataset.type; let anyG=false;
      g.querySelectorAll('details[data-host]').forEach(d=>{
        // data-sev is -1 for entries that carry no findings at all (run-logs,
        // package lists). Those are hidden by a severity filter rather than shown
        // regardless: asking for "High and above" and getting a run-log back is not
        // an answer to the question.
        const r=parseInt(d.dataset.sev||'-1',10);
        const hit=(!s||d.textContent.toLowerCase().includes(s))&&
                  (!h||host===h)&&(!t||type===t)&&(sev===null||r>=sev);
        d.classList.toggle('hidden',!hit); if(hit)anyG=true;
      });
      g.classList.toggle('hidden',!anyG); if(anyG)anyH=true;
    });
    sec.classList.toggle('hidden',!anyH);
  });
  document.querySelectorAll('.card').forEach(c=>{
    const r=parseInt(c.dataset.sev||'0',10);
    c.classList.toggle('hidden',(h&&c.dataset.host!==h)||(sev!==null&&r<sev));
  });
}
[q,hf,tf,sf].forEach(el=>el.addEventListener('input',apply));
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
def _hardening_distro(data: dict) -> str:
    """Which distro's package pages to link to.

    The hardening report records no distro field, but its baseline names the toolchain
    it was derived from -- "debian (dpkg-buildflags)", "arch (makepkg.conf + gcc -v)".
    Read from there rather than adding a field that every existing report lacks.
    """
    name = str(((data.get("baseline") or {}).get("name") or "")).split()[:1]
    return name[0] if name else ""


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
                 f'<td>{_pkg_link(str(p.get("package")), source=_hardening_distro(data))}</td>'
                 f'<td class=num>{_esc(str(p.get("binaries")))}</td>'
                 f'<td>{_esc(miss)}</td></tr>')
    table = ""
    if rows:
        table = ('<table><tr><th>band</th><th>score</th><th>!</th><th>package</th>'
                 f'<th>bins</th><th>missing</th></tr>{rows}</table>')
    rest = sum(tally.get(b, 0) for b in ("Medium", "Low"))
    tail = f'<div class="muted">+ {rest} Medium/Low package(s)</div>' if rest else ""
    return f'{chips}{meta}{table or "<div class=muted>no Critical/High packages</div>"}{tail}'


def _pkg_cell(f: dict) -> str:
    """A finding's package name, linked to wherever that package lives.

    It used to link only AUR names, on the grounds that "apt/flatpak/snap have no AUR
    entry" — true, and they have their own pages, which is the thing you actually want
    when a finding names something you do not recognise.
    """
    return _pkg_link(str(f.get("package", "")), source=str(f.get("source", "")))


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
        f'<td>{_pkg_cell(f)}</td>'
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
    # `alien-pkgs` is "installed from no known repo" and `obsolete-pkgs` is "no longer
    # in any repo" -- on Arch both mean the AUR or a manual build, which is precisely
    # the case where you want to look the name up.
    src = data.get("source") or "aur"
    if isinstance(pkgs[0], dict):
        li = "".join(f'<li>{_pkg_link(str(p.get("name", "")), source=src)} '
                     f'<span class=muted>{_esc(str(p.get("version","")))}</span></li>'
                     for p in pkgs)
    else:
        li = "".join(f"<li>{_pkg_link(str(p), source=src)}</li>" for p in pkgs)
    return f'<div class=muted>{len(pkgs)} package(s)</div><ul class=k>{li}</ul>'


def _render_aur_audit(data: dict) -> str:
    pkgs = data.get("packages") or []
    rows = "".join(
        f'<tr><td>{_aur_pkg_link(str(p.get("name","")))}</td>'
        f'<td class=desc title="{_esc(str(p.get("description","")))}">'
        f'<span class="desc-text">{_esc(str(p.get("description","")))}</span>'
        f'{_homepage_link(p)}</td>'
        f'<td>{_esc(str(p.get("maintainer","")))}</td>'
        f'<td class=num>{_esc(str(p.get("age_days","")))}</td>'
        f'<td class=num>{_esc(str(p.get("votes","")))}</td>'
        f'<td>{_esc(str(p.get("flags","")))}</td></tr>' for p in pkgs[:60])
    table = (f'<table><tr><th>package</th><th>software</th><th>maintainer</th>'
             f'<th>age(d)</th><th>votes</th><th>flags</th></tr>{rows}</table>') if rows else ""
    missing = data.get("not_found_in_aur") or []
    removal = data.get("removal_candidates") or []
    changes = data.get("maintainer_changes") or []
    extra = ""
    if missing:
        extra += f'<p><strong>Not in AUR:</strong> {_esc(", ".join(map(str,missing)))}</p>'
    if removal:
        items = "".join(
            f'<li>{_aur_pkg_link(str(c.get("name","")))}'
            f'{" <span class=badge>LIB</span>" if c.get("is_library") else ""} '
            f'<code>sudo pacman -Rns {_esc(str(c.get("name","")))}</code></li>'
            for c in removal)
        extra += ('<p><strong>Candidates for removal</strong> '
                  '<span class=muted>(nothing packaged requires them)</span></p>'
                  f'<ul class=k>{items}</ul>'
                  '<p class=muted>pacman only tracks packaged dependents — unpackaged '
                  'software (AppImage, /opt, manually built, dlopen) could still use '
                  'these. Verify before removing.</p>')
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


_ADV_SEV = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def _vkey(version: str) -> tuple:
    """Numeric sort key for a version string.

    String order is wrong the moment a component reaches double digits -- it ranks
    `6.8.0-99` above `6.8.0-124`, the exact trap the kernel code documents. Oldest
    first is the point here, so it has to be right.
    """
    return tuple(int(n) for n in re.findall(r"\d+", str(version))) or (0,)


def _render_advisories(data: dict) -> str:
    findings = data.get("findings") or []

    def _group(items: list) -> list:
        """Collapse rows differing only by environment — matches the text report
        (one package in 28 virtualenvs is one problem with 28 places to fix)."""
        groups: dict[tuple, list] = {}
        for f in items:
            # keyed on the remediation, not the installed version — matches check._group
            key = (f.get("source"), f.get("package"), f.get("fixed_version"),
                   f.get("severity"), tuple(map(str, f.get("cves") or [])))
            groups.setdefault(key, []).append(f)
        # Pairs, not just names: within one finding the installed version varies a
        # lot -- `pip` sat at 11 distinct versions across its 44 venvs -- and which
        # ones are furthest behind is the thing that turns a count into a work queue.
        out = []
        for fs in groups.values():
            pairs = sorted({(str(f.get("environment") or ""),
                             str(f.get("installed_version") or "")) for f in fs}
                           - {("", "")}, key=lambda ev: (_vkey(ev[1]), ev[0]))
            out.append((fs[0], pairs))
        return out

    def _row(f: dict, envs: list) -> str:
        # The CVSS vector is reference detail, not something read at a glance -- and
        # at 44 monospace characters it forced this column wide enough to push
        # package, version, CVEs and the link out of a container that could not
        # scroll. Into the badge's tooltip.
        sev = _sev(f.get("severity"))
        cvss = f.get("cvss")
        tip = f' title="CVSS {_esc(str(cvss))}"' if cvss else ""
        badge = f'<span class="badge b-{_esc(sev)}"{tip}>{_esc(sev)}</span>'
        ver = _esc(str(f.get("installed_version", "")))
        fx = f.get("fixed_version")
        ver += f" &rarr; {_esc(str(fx))}" if fx else ""
        cves = ", ".join(_advisory_link(c) for c in (f.get("cves") or []))
        link = _ext_link(str(f.get("url", "")), str(f.get("group_id") or "details"))
        pkg = (f'<span class=muted>{_esc(str(f.get("source", "")))}/</span>'
               + _pkg_link(str(f.get("package", "")), source=str(f.get("source", "")),
                           ecosystem=str(f.get("ecosystem", ""))))
        if not envs:
            where = '<span class=muted>&mdash;</span>'
        elif len(envs) == 1:
            where = _esc(envs[0][0])
        else:
            # A tooltip could not be read, copied, or reached on a touch device, and
            # 44 paths do not fit in one anyway. Same [+]/[-] idiom as the entries,
            # plain lines so a drag-select copies clean paths.
            body = "\n".join(f"{v:<12} {e}" for e, v in envs)
            where = (f'<details class="envs"><summary>{len(envs)} environments'
                     f'</summary><pre>{_esc(body)}</pre></details>')
        return (f'<tr><td>{badge}</td><td>{pkg}</td><td>{where}</td><td>{ver}</td>'
                f'<td>{cves}</td><td>{link}</td></tr>')

    def _table(items: list) -> str:
        rows = sorted(_group(items), key=lambda ge: -_ADV_SEV.get(ge[0].get("severity"), 0))
        if not rows:
            return '<div class="muted">none</div>'
        return ('<table><tr><th>sev</th><th>package</th><th>where</th>'
                '<th>installed</th><th>CVEs</th><th></th></tr>'
                f'{"".join(_row(f, envs) for f, envs in rows)}</table>')

    pending = [f for f in findings if f.get("status") == "pending_fix"]
    fixable = [f for f in findings if f.get("status") != "pending_fix"]
    out = ['<p><strong>Pending fixes</strong> '
           '<span class=muted>(vulnerable, no fix released yet)</span></p>', _table(pending),
           '<p><strong>Fix available</strong> '
           '<span class=muted>(installed trails a security fix)</span></p>', _table(fixable)]
    for src, unc in (data.get("uncovered") or {}).items():
        if unc:
            # These are the AUR/foreign ones, by definition -- the tracker covers the
            # official repos, so anything it cannot see came from somewhere else.
            names = " ".join(_pkg_link(str(n), source="aur")
                             for n in sorted(map(str, unc))[:200])
            out.append(f'<p class=muted>Not covered by the {_esc(str(src))} tracker '
                       f'(AUR/manual/foreign): {len(unc)} package(s) — vet via '
                       f'<code>fettle -P</code> / <code>-A</code>.<br>'
                       f'<span style="font-size:.72rem">{names}</span></p>')
    if data.get("manjaro"):
        out.append('<p class=muted>On Manjaro, "fix available" can reflect normal 1&ndash;2 '
                   'week sync lag behind Arch, not special exposure.</p>')
    return "".join(out)


_RENDERERS = {
    "hardening-audit": _render_hardening,
    # Reports written before v0.73.0 are on disk forever and must still render.
    "pkg-audit": _render_findings, "aur-ioc-scan": _render_findings,  # stale-flag-ok
    "upgrade-check": _render_upgrade, "aur-audit": _render_aur_audit,
    "alien-pkgs": _render_pkglist, "obsolete-pkgs": _render_pkglist,
    "sys-audit": _render_sysaudit, "advisory-check": _render_advisories,
    # pkg-integrity was split out of sys-audit in v0.72.0 and is built from the same
    # `Scan`, so its payload has the identical shape — but it was never registered
    # here, and five reports rendered as a raw JSON dump on the dashboard.
    "pkg-integrity": _render_sysaudit,
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

    A clean `obsolete-pkgs` with no packages, a stored `aur-ioc-scan` with no   # stale-flag-ok
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
    if tool in ("pkg-audit", "aur-ioc-scan"):        # stale-flag-ok: stored reports
        return not data.get("findings")
    if tool in ("obsolete-pkgs", "alien-pkgs", "hardening-audit"):
        return not data.get("packages")
    if tool == "aur-audit":
        return not (data.get("packages") or data.get("not_found_in_aur")
                    or data.get("maintainer_changes"))
    if tool in ("sys-audit", "pkg-integrity"):
        return not (data.get("categories") or data.get("text"))
    if tool == "advisory-check":
        # The uncovered list is not decoration: it is the tracker saying which
        # packages it cannot see at all. A host with no tracked CVEs and 77 untracked
        # packages was rendering as nothing to report.
        return not (data.get("findings") or any((data.get("uncovered") or {}).values()))
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
    "aur-ioc-scan": "AUR Threat Scan",           # stale-flag-ok: stored reports
    "alien-pkgs": "Foreign / AUR Packages",
    "obsolete-pkgs": "Obsolete Packages",
    "upgrade-check": "AI Upgrade Check",
    "sys-audit": "System Security Scan",
    "advisory-check": "Security Advisories",
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


_SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0, "Unknown": 1}
# Reports written before v0.80.0 carry the old supply-chain vocabulary. They are on
# disk forever, so the dashboard normalises on read rather than pretending otherwise.
_SEV_LEGACY = {"Crit": "Critical", "Warn": "Medium", "Info": "Info", "Low": "Low"}


def _sev(raw) -> str:
    name = str(raw or "Unknown").title()
    return _SEV_LEGACY.get(name, name)


def _worst(entries) -> tuple[int, str]:
    return max(entries, default=(0, ""))


def _entry_rank(entry: dict) -> int:
    """Worst severity in one report, for the severity filter. -1 = not a finding
    report (run-logs, package lists), which the filter treats as "always show"."""
    data = entry.get("data") or {}
    ranks = [_SEV_RANK.get(_sev(f.get("severity")), 1)
             for f in (data.get("findings") or [])]
    ranks += [_SEV_RANK.get(_sev(b), 1) for b, n in (data.get("band_tally") or {}).items()
              if n]
    counts = data.get("level_counts") or {}
    if counts.get("error"):
        ranks.append(3)
    elif counts.get("warn"):
        ranks.append(2)
    return max(ranks, default=-1)


def _item_keys(entry: dict) -> tuple[str, set]:
    """``(what the items are, identity set)`` for diffing two snapshots.

    Three shapes exist and they are not interchangeable. Findings and packages carry
    an identity that survives between runs; `sys-audit` and `pkg-integrity` record
    only counts and a transcript, so those can honestly report "3 -> 1" and nothing
    finer. Saying which is which beats inventing an identity that would silently
    mismatch every run.
    """
    data = entry.get("data") or {}
    if isinstance(data.get("findings"), list):
        return "finding", {
            (str(f.get("source", "")), str(f.get("package", "")),
             str(f.get("question") or ",".join(map(str, f.get("cves") or []))))
            for f in data["findings"]}
    if isinstance(data.get("packages"), list):
        out = set()
        for pkg in data["packages"]:
            out.add(pkg if isinstance(pkg, str)
                    else str(pkg.get("package") or pkg.get("name") or pkg))
        return "package", out
    counts = data.get("level_counts") or {}
    n = sum(v for k, v in counts.items() if k in ("error", "warn"))
    return "count", {f"__count__{n}"} if n else set()


def _delta(entries: list) -> dict | None:
    """Newest snapshot vs the newest one from an EARLIER DAY, or None.

    Day-based on purpose: three runs in an hour would otherwise reset the baseline and
    show an empty delta right after you fixed something. "What changed since I last
    looked" is the question; "since I last pressed enter" is not.
    """
    dated = sorted((e for e in entries if e.get("timestamp")),
                   key=lambda e: e["timestamp"])
    if len(dated) < 2:
        return None
    newest = dated[-1]
    day = newest["timestamp"][:8]
    prior = [e for e in dated[:-1] if e["timestamp"][:8] < day]
    if not prior:
        return None
    before = prior[-1]
    kind, now_keys = _item_keys(newest)
    _kind2, old_keys = _item_keys(before)
    if kind == "count":
        n_now = len(now_keys) and int(next(iter(now_keys)).removeprefix("__count__"))
        n_old = len(old_keys) and int(next(iter(old_keys)).removeprefix("__count__"))
        if n_now == n_old:
            return None
        return {"kind": kind, "since": before["timestamp"], "added": [], "gone": [],
                "n_added": max(0, n_now - n_old), "n_gone": max(0, n_old - n_now)}
    added = sorted(now_keys - old_keys)
    gone = sorted(old_keys - now_keys)
    if not added and not gone:
        return None
    return {"kind": kind, "since": before["timestamp"],
            "added": [k[1] if isinstance(k, tuple) else k for k in added],
            "gone": [k[1] if isinstance(k, tuple) else k for k in gone],
            "n_added": len(added), "n_gone": len(gone)}


def _host_deltas(host: dict) -> dict:
    """``{tool: delta}`` for every type with a comparable earlier day."""
    by_tool: dict[str, list] = {}
    for e in host["reports"]:
        by_tool.setdefault(e.get("tool", ""), []).append(e)
    out = {}
    for tool, entries in by_tool.items():
        d = _delta(entries)
        if d:
            out[tool] = d
    return out


def _host_problems(host: dict, *, stale_days: int, now=None) -> list[tuple[int, str]]:
    """``(rank, one-line problem)`` for a host, worst first.

    The card used to show **hardening bands only** — an opt-in audit where every real
    desktop has bands — so a host with files failing integrity, unpatched Criticals or
    Secure Boot off displayed no chip at all, while one with a routine hardening tally
    looked alarming. This asks every report what it found.

    Hardening is deliberately capped at Medium here for the same reason the CLI does
    not fail on it: its "Critical" is the worst band of a scoring scheme, not a
    compromised machine, and letting it dominate the fleet view would train you to
    ignore the colour.
    """
    import datetime as _dt

    out: list[tuple[int, str]] = []
    # Newest report per type only. Five retained advisory-check reports otherwise put
    # the same 770 CVEs on the card five times, which is noise pretending to be scale.
    newest: dict[str, dict] = {}
    for e in host["reports"]:
        if _is_empty(e):
            continue
        t = e.get("tool", "")
        if e.get("timestamp", "") >= newest.get(t, {}).get("timestamp", ""):
            newest[t] = e
    for e in newest.values():
        tool = e.get("tool", "")
        data = e.get("data") or {}
        if tool in ("pkg-audit", "advisory-check"):
            tally: dict[str, int] = {}
            for f in data.get("findings") or []:
                sev = _sev(f.get("severity"))
                tally[sev] = tally.get(sev, 0) + 1
            if tally:
                worst = max(tally, key=lambda k: _SEV_RANK.get(k, 1))
                n = sum(tally.values())
                what = (f"supply-chain finding{'s' if n != 1 else ''}"
                        if tool == "pkg-audit"
                        else f"package{'s' if n != 1 else ''} with a known CVE")
                out.append((_SEV_RANK.get(worst, 1),
                            f"{n} {what} ({tally[worst]} {worst})"))
        elif tool == "hardening-audit":
            tally = data.get("band_tally") or {}
            n = sum(tally.values())
            if n:
                worst = max(tally, key=lambda k: _SEV_RANK.get(_sev(k), 1))
                out.append((min(2, _SEV_RANK.get(_sev(worst), 1)),
                            f"{n} package{'s' if n != 1 else ''} missing build "
                            "hardening"))
        elif tool in ("sys-audit", "pkg-integrity"):
            counts = data.get("level_counts") or {}
            label = "firmware/boot" if tool == "sys-audit" else "package file integrity"
            if counts.get("error"):
                out.append((3, f"{counts['error']} {label} finding(s) needing attention"))
            elif counts.get("warn"):
                out.append((2, f"{counts['warn']} {label} warning(s)"))
        elif tool == "upgrade-check":
            v = str(data.get("safety_verdict", ""))
            if v in ("risky", "caution"):
                out.append((3 if v == "risky" else 2, f"upgrade check: {v.upper()}")) 
        elif tool == "aur-audit":
            gone = data.get("not_found_in_aur") or []
            if gone:
                out.append((2, f"{len(gone)} AUR package(s) no longer in the AUR"))
        elif tool in ("alien-pkgs", "obsolete-pkgs"):
            pkgs = data.get("packages") or []
            if pkgs:
                out.append((1, f"{len(pkgs)} {tool.replace('-', ' ')}"))

    latest = max((e.get("timestamp", "") for e in host["reports"] + host["logs"]),
                 default="")
    if latest:
        try:
            age = ((now or _dt.datetime.now())
                   - _dt.datetime.strptime(latest[:8], "%Y%m%d")).days
        except ValueError:
            age = 0
        if age >= stale_days:
            # No data is not good news — the fleet-level form of the invariant this
            # whole QA pass is about. A host that stopped reporting looked exactly
            # like one that reported clean this morning.
            out.append((2, f"has not reported in {age} days"))
    return sorted(out, reverse=True)


def _delta_line(deltas: dict) -> str:
    """`+2 new, -7 resolved since 2026-08-01` — the direction of travel, which is the
    most useful single fact about a host you have seen before."""
    if not deltas:
        return ""
    added = sum(d["n_added"] for d in deltas.values())
    gone = sum(d["n_gone"] for d in deltas.values())
    since = _fmt_ts(min(d["since"] for d in deltas.values())).split()[0]
    bits = []
    if added:
        bits.append(f'<span class="d-new">+{added} new</span>')
    if gone:
        # Showing what went away matters as much as what arrived: "you fixed it" must
        # not render the same as "it was never there".
        bits.append(f'<span class="d-gone">-{gone} resolved</span>')
    return f'<div class="count">{", ".join(bits)} since {_esc(since)}</div>'


def _delta_badge(delta: dict | None) -> str:
    """`+2 / -7` on the newest entry of a type, with the changed names in the tooltip
    — the delta next to the evidence it came from."""
    if not delta:
        return ""
    tip = "; ".join(filter(None, [
        ("new: " + ", ".join(delta["added"][:12])) if delta["added"] else "",
        ("gone: " + ", ".join(delta["gone"][:12])) if delta["gone"] else ""]))
    if not tip:
        # A count-only type (sys-audit, pkg-integrity) records no identities, so the
        # honest tooltip is the count change rather than an empty string.
        n = delta["n_added"] or delta["n_gone"]
        tip = f"{n} {'more' if delta['n_added'] else 'fewer'} finding(s) than"
    bits = []
    if delta["n_added"]:
        bits.append(f'<span class="d-new">+{delta["n_added"]}</span>')
    if delta["n_gone"]:
        bits.append(f'<span class="d-gone">-{delta["n_gone"]}</span>')
    since = _fmt_ts(delta["since"]).split()[0]
    return (f'<span class="delta" title="{_esc(tip)} (since {_esc(since)})">'
            f'{" ".join(bits)}</span>')


def _host_summary(host: dict, *, stale_days: int = 7, now=None) -> str:
    """The dashboard card body: a verdict across ALL audits, then what drove it."""
    problems = _host_problems(host, stale_days=stale_days, now=now)
    rank = _worst(problems)[0]
    verdict = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(rank, "OK")
    badge = (f'<span class="chip b-{verdict}">{verdict}</span>' if problems
             else '<span class="chip b-ok">OK</span>')
    lines = "".join(f'<div class="count">· {_esc(t)}</div>' for _r, t in problems[:3])
    more = (f'<div class="count muted">+{len(problems) - 3} more</div>'
            if len(problems) > 3 else "")
    types: dict[str, int] = {}
    for e in host["reports"]:
        if not _is_empty(e):
            types[e.get("tool", "?")] = types.get(e.get("tool", "?"), 0) + 1
    counts = " · ".join(f"{_esc(t)}:{n}" for t, n in sorted(types.items()))
    latest = max((e.get("timestamp", "") for e in host["reports"] + host["logs"]),
                 default="")
    return (f'<div class="chips">{badge}</div>{lines}{more}'
            f'{_delta_line(_host_deltas(host))}'
            f'<div class="count muted" style="margin-top:.3rem">{counts or "no reports"}</div>'
            f'<div class="count muted">latest: {_esc(_fmt_ts(latest)) or "—"}</div>')


def _has_content(entry_map: dict) -> bool:
    """Whether this host has anything at all worth a card."""
    return any(not _is_empty(e)
               for kind in ("reports", "logs") for e in entry_map.get(kind, []))


def render(hostmap: dict, *, generated_at: str, version: str, user: str = "you",
           groups=frozenset(), stale_days: int = 7, now=None) -> str:
    # A configured group name (e.g. `fettle remote bifrost-lab`) is NOT a host — its
    # only artifact here is the controller's orchestration run-log. Keep it out of
    # the host dashboard and show it in a separate "group runs" area; the real
    # per-host results already live under each host's own directory.
    all_names = sorted(hostmap)
    hosts = [h for h in all_names if h not in groups]
    group_names = [h for h in all_names if h in groups]
    # A host directory with nothing in it still rendered a card reading "no reports /
    # latest: -". Eight of them on the QA machine, left by fetch-backs that found
    # nothing and by lab guests whose DHCP address moved. Counted, so they are hidden
    # rather than disappeared.
    empty_hosts = [h for h in hosts if not _has_content(hostmap[h])]
    hosts = [h for h in hosts if h not in empty_hosts]
    all_types = sorted({e.get("tool", "?") for h in hosts
                        for e in hostmap[h]["reports"] if not _is_empty(e)})
    host_opts = "".join(f'<option value="{_esc(h)}">{_esc(h)}</option>' for h in hosts)
    type_opts = "".join(f'<option value="{_esc(t)}">{_esc(t)}</option>' for t in all_types)

    cards = "".join(
        f'<div class="card" data-host="{_esc(h)}" '
        f'data-sev="{_worst(_host_problems(hostmap[h], stale_days=stale_days, now=now))[0]}">'
        f'<h3>{_esc(h)}</h3>'
        f'{_host_summary(hostmap[h], stale_days=stale_days, now=now)}</div>'
        for h in hosts)

    sections = []
    for h in hosts:
        blocks = []          # NOT `groups` -- that is the parameter, shadowed here
        hidden = 0
        by_tool: dict[str, list[dict]] = {}
        for e in hostmap[h]["reports"]:
            by_tool.setdefault(e.get("tool", "?"), []).append(e)
        deltas = _host_deltas(hostmap[h])
        for tool in sorted(by_tool):
            entries = [e for e in by_tool[tool] if not _is_empty(e)]
            hidden += len(by_tool[tool]) - len(entries)
            if not entries:                         # whole group is empty — skip it
                continue
            newest_ts = max(e.get("timestamp", "") for e in entries)
            items = "".join(
                f'<details data-host="{_esc(h)}" data-type="{_esc(tool)}" '
                f'data-sev="{_entry_rank(e)}">'
                f'<summary><span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'{_entry_badge(e)}'
                f'{_delta_badge(deltas.get(tool)) if e.get("timestamp") == newest_ts else ""}'
                f'{_cmd_tag(e)}</summary>'
                f'<div class="body">{_render_entry_body(e)}</div></details>'
                for e in entries)
            blocks.append(f'<div class="group" data-host="{_esc(h)}" data-type="{_esc(tool)}">'
                          f'<h3>{_section_title(tool, len(entries))}</h3>{items}</div>')
        logs = [e for e in hostmap[h]["logs"] if not _is_empty(e)]
        if logs:
            items = "".join(
                f'<details data-host="{_esc(h)}" data-type="run-log">'
                f'<summary><span class="when">{_esc(_fmt_ts(e.get("timestamp","")))}</span>'
                f'<span class="muted">{_esc(_run_label(e))}</span>'
                f'</summary><div class="body">{_render_entry_body(e)}</div></details>'
                for e in logs)
            blocks.append(f'<div class="group" data-host="{_esc(h)}" data-type="run-log">'
                          f'<h3>{_section_title("run-log", len(logs))}</h3>{items}</div>')
        if not blocks:                              # nothing to show for this host
            continue
        note = (f'<div class="group muted" style="font-size:.75rem">'
                f'({hidden} empty report(s) hidden)</div>') if hidden else ""
        sections.append(f'<section class="host" data-host="{_esc(h)}">'
                        f'<h2>{_esc(h)}</h2>{"".join(blocks)}{note}</section>')

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
<div class="meta"># generated {_esc(generated_at)} · fettle v{_esc(version)} · {len(hosts)} host(s){_esc(f" · {len(empty_hosts)} empty hidden") if empty_hosts else ""}</div>
<div class="controls">
<input id="q" type="search" placeholder="grep…">
<select id="hostf"><option value="">all hosts</option>{host_opts}</select>
<select id="typef"><option value="">all types</option>{type_opts}</select>
<select id="sevf"><option value="">any severity</option><option value="4">Critical</option><option value="3">High and above</option><option value="2">Medium and above</option><option value="1">Low and above</option></select>
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
def render_page(ctx, *, base=None, now=None) -> str:
    """Build the full dashboard HTML from stored JSON and return it as a string
    (no disk write). Shared by `build` (writes report.html) and the web UI (serves
    it live). Pass `base` to read a specific tree, else it's resolved from `ctx`."""
    import datetime as _dt

    from . import __version__
    b = Path(base) if base is not None else _reports._settings(ctx)[0]
    hostmap = collect(b)
    generated = (now or _dt.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    user = getattr(ctx, "sudo_user", None) or _current_user()
    try:
        from . import remote
        groups = frozenset(remote.remote_groups(getattr(ctx, "config", None)))
    except Exception:
        groups = frozenset()
    rep = getattr(getattr(ctx, "config", None), "reports", None) or {}
    try:
        stale_days = int(rep.get("stale_days", 7))
    except (TypeError, ValueError):
        stale_days = 7
    return render(hostmap, generated_at=generated, version=__version__,
                  user=user, groups=groups, stale_days=stale_days,
                  now=(now or _dt.datetime.now()))


def build(ctx, *, open_browser: bool = False, now=None) -> Path:
    """Regenerate `<base>/report.html` from all stored JSON. Returns its path."""
    base, _ = _reports._settings(ctx)
    out_path = base / "report.html"
    base.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_page(ctx, base=base, now=now))
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
