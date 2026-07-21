"""Attribute deviations to packages, apply the user's exclude lists, render.

The reporting policy is *long list by default*: nothing is pre-trimmed to
"interesting" findings. The only trimming is the user's own exclude lists from
``[hardening]`` in the config — which ship EMPTY, so the first run shows
everything and the user narrows to taste. (The always-on accuracy corrections in
engine.py are separate: they fix wrong data, not preference.)
"""

from __future__ import annotations

import collections
import fnmatch
from dataclasses import dataclass, field

# short column headers for the per-criterion matrix (fortify_source is wide)
_ABBR = {"relro": "relro", "pie": "pie", "canary": "canary",
         "fortify_source": "fortify", "cfi": "cfi", "nx": "nx",
         "rpath": "rpath", "runpath": "runpath"}

# what the user may exclude, and a stable order for the per-check summary
_CRITERION_ORDER = ["relro", "pie", "canary", "fortify_source", "cfi", "nx",
                    "rpath", "runpath"]

# one-line human gloss per criterion (report header legend)
_CRITERION_HELP = {
    "relro": "GOT (partial/no RELRO) — GOT overwrite hardening incomplete",
    "pie": "no PIE — image not position-independent (weakens ASLR)",
    "canary": "no stack canary — stack-smash detection absent",
    "fortify_source": "no _FORTIFY_SOURCE — bounds-checked libc wrappers absent",
    "cfi": "no CET (SHSTK/IBT) — control-flow integrity absent",
    "nx": "no NX — writable stack/heap is executable",
    "rpath": "RPATH set — insecure library search path (non-overridable)",
    "runpath": "RUNPATH set — non-standard library search path",
}


@dataclass
class Exclusions:
    checks: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.checks or self.packages or self.paths)


def exclusions(cfg) -> Exclusions:
    """Read ``[hardening]`` exclude lists off the config (all optional)."""
    h = getattr(cfg, "hardening", None) or {}
    if not isinstance(h, dict):
        return Exclusions()

    def _list(key):
        v = h.get(key) or []
        return [str(x) for x in v] if isinstance(v, (list, tuple)) else []

    return Exclusions(checks=_list("exclude_checks"),
                      packages=_list("exclude_packages"),
                      paths=_list("exclude_paths"))


def _match_any(value: str, globs) -> bool:
    return any(fnmatch.fnmatch(value, g) for g in globs)


@dataclass
class PackageReport:
    package: str
    checks: dict[str, int] = field(default_factory=dict)   # criterion -> count
    binaries: int = 0
    score: float = 0.0            # the package's WORST binary's score (its rank)
    total_score: float = 0.0      # sum across binaries (tiebreak)
    band: str = "Low"
    worst_binary: str = ""        # path of the highest-scoring binary
    has_privileged: bool = False  # any setuid/setgid or sensitive-pkg binary

    @property
    def total(self) -> int:
        return sum(self.checks.values())


def apply(deviations, pkgmap, excl: Exclusions, scorer=None):
    """Attribute, filter, score, and roll up. Returns ``(package_reports, stats)``.

    Each *binary's* score is the weighted sum of the protections it's missing
    (see :mod:`.score`); a package's rank is its **worst** binary's score, so the
    single most-vulnerable binary floats its package to the top even though rows
    are per-package. ``stats`` records how many deviations each exclude rule
    dropped, so the run can tell the user what its own config hid.
    """
    from .score import Scorer, band
    scorer = scorer or Scorer()

    stats = {"input": 0, "excluded_check": 0, "excluded_package": 0,
             "excluded_path": 0, "kept": 0}
    per_pkg: dict[str, PackageReport] = {}
    per_pkg_bins: dict[str, set] = {}
    bin_checks: dict[str, set] = {}   # path -> missing checks (kept only)
    bin_pkg: dict[str, str] = {}

    for dev in deviations:
        stats["input"] += 1
        if dev.check in excl.checks:
            stats["excluded_check"] += 1
            continue
        if _match_any(dev.path, excl.paths):
            stats["excluded_path"] += 1
            continue
        pkg = pkgmap.get(dev.path, "(unowned)")
        if _match_any(pkg, excl.packages):
            stats["excluded_package"] += 1
            continue
        stats["kept"] += 1
        rep = per_pkg.setdefault(pkg, PackageReport(package=pkg))
        rep.checks[dev.check] = rep.checks.get(dev.check, 0) + 1
        per_pkg_bins.setdefault(pkg, set()).add(dev.path)
        bin_checks.setdefault(dev.path, set()).add(dev.check)
        bin_pkg[dev.path] = pkg

    # score every affected binary, roll the worst/sum up to its package
    for path, checks in bin_checks.items():
        pkg = bin_pkg[path]
        rep = per_pkg[pkg]
        privileged = scorer.is_privileged(path, pkg)
        s = scorer.binary_score(checks, privileged=privileged)
        rep.total_score = round(rep.total_score + s, 2)
        if s > rep.score:
            rep.score, rep.worst_binary = s, path
        if privileged:
            rep.has_privileged = True

    for pkg, rep in per_pkg.items():
        rep.binaries = len(per_pkg_bins[pkg])
        rep.band = band(rep.score)
    reports = sorted(per_pkg.values(),
                     key=lambda r: (-r.score, -r.total_score, r.package))
    return reports, stats


def _tabulate(headers, rows, aligns=None) -> list[str]:
    """Pad ``rows`` into aligned columns. ``aligns`` is per-column 'l'/'r'."""
    cols = len(headers)
    aligns = aligns or ["l"] * cols
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt(cells):
        out = []
        for i, cell in enumerate(cells):
            text = str(cell)
            out.append(text.rjust(widths[i]) if aligns[i] == "r"
                       else text.ljust(widths[i]))
        return "  ".join(out).rstrip()

    return [fmt(headers), fmt(["-" * w for w in widths]), *[fmt(r) for r in rows]]


def band_tally(reports) -> "collections.Counter":
    return collections.Counter(r.band for r in reports)


def band_summary(reports) -> str:
    """Lead with the band counts — what a reader wants first."""
    from .score import BAND_ORDER
    if not reports:
        return "no hardening deviations from the distro baseline."
    tally = band_tally(reports)
    parts = [f"{tally[b]} {b}" for b in BAND_ORDER if tally.get(b)]
    devs = sum(r.total for r in reports)
    return (f"{', '.join(parts)}  ({devs} deviations across "
            f"{len(reports)} packages, worst first)")


def summary_line(reports, stats) -> str:
    return band_summary(reports)


def _missing_by_weight(rep) -> str:
    """The package's missing criteria, heaviest-weighted first, with counts."""
    from .score import DEFAULT_WEIGHTS
    keys = sorted(rep.checks, key=lambda k: (-DEFAULT_WEIGHTS.get(k, 1.0), k))
    return ", ".join(f"{k}={rep.checks[k]}" if rep.checks[k] > 1 else k
                     for k in keys)


# On screen we show only the bands worth acting on; Medium/Low go to the file.
SCREEN_BANDS = ("Critical", "High")


def render_screen(reports, show_bands=SCREEN_BANDS) -> list[str]:
    """Compact, scored, on-screen table (worst first) — only the severe bands.

    Medium/Low packages are summarized in a trailing line and left to the full
    saved matrix, so the terminal shows only what's worth acting on.
    """
    from .score import BAND_ORDER
    if not reports:
        return ["no hardening deviations from the distro baseline."]
    shown = [r for r in reports if r.band in show_bands]
    hidden = [r for r in reports if r.band not in show_bands]

    def _hidden_tail() -> str:
        tally = collections.Counter(r.band for r in hidden)
        parts = [f"{tally[b]} {b}" for b in BAND_ORDER if tally.get(b)]
        return f"… plus {', '.join(parts)} package(s) — full list in the saved matrix"

    if not shown:
        return [f"no Critical or High packages ({_hidden_tail()[6:]})" if hidden
                else "no Critical or High packages."]
    headers = ["BAND", "SCORE", "P", "PACKAGE", "BINS",
               "MISSING (worst-weighted first)"]
    rows = [[r.band, f"{r.score:g}", "!" if r.has_privileged else "",
             r.package, r.binaries, _missing_by_weight(r)] for r in shown]
    lines = _tabulate(headers, rows, aligns=["l", "r", "l", "l", "r", "l"])
    if hidden:
        lines.append(_hidden_tail())
    return lines


def render(reports, stats, baseline, scan_stats) -> list[str]:
    """Full plain-text report body (also the on-screen detail)."""
    lines = ["hardening-audit report", ""]
    lines.append(f"baseline: {baseline.name}")
    for note in baseline.notes:
        lines.append(f"  note: {note}")
    lines.append("criteria (what the distro says it builds with):")
    for key in _CRITERION_ORDER:
        if key in baseline.criteria:
            lines.append(f"  {key:14s} -> {' or '.join(baseline.criteria[key])}")
    lines.append("")
    lines.append(f"scanned {scan_stats.get('analyzed', 0)} ELF binaries "
                 f"({scan_stats.get('static', 0)} static skipped, "
                 f"{scan_stats.get('unreadable', 0)} unreadable)")
    dropped = (stats["excluded_check"] + stats["excluded_package"]
               + stats["excluded_path"])
    if dropped:
        lines.append(f"excluded by your [hardening] config: {dropped} "
                     f"(check={stats['excluded_check']}, "
                     f"package={stats['excluded_package']}, "
                     f"path={stats['excluded_path']})")
    lines.append("")

    if not reports:
        lines.append("No deviations. Every scanned binary matches the baseline.")
        return lines

    lines.append(band_summary(reports))
    lines.append("")
    lines.append("score = Σ weight(missing protection) × 3 if setuid/setgid or "
                 "sensitive; bands: Critical≥14, High≥8, Medium≥3, Low<3")
    lines.append("P = ! marks a setuid/setgid or sensitive-package binary; "
                 "a matrix cell is the count of binaries missing that protection")
    lines.append("")
    lines.append("legend:")
    seen = {k for r in reports for k in r.checks}
    for key in _CRITERION_ORDER:
        if key in seen:
            lines.append(f"  {key:14s} {_CRITERION_HELP.get(key, '')}")
    lines.append("")
    # full per-criterion matrix — every column, one row per package (worst first)
    headers = ["PACKAGE", "SCORE", "BAND", "P", "BINS"] + \
        [_ABBR[k] for k in _CRITERION_ORDER]
    rows = []
    for r in reports:
        cells = [r.package, f"{r.score:g}", r.band,
                 "!" if r.has_privileged else "", r.binaries]
        cells += [str(r.checks[k]) if r.checks.get(k) else "." for k in _CRITERION_ORDER]
        rows.append(cells)
    aligns = ["l", "r", "l", "l", "r"] + ["r"] * len(_CRITERION_ORDER)
    lines += _tabulate(headers, rows, aligns)
    return lines
