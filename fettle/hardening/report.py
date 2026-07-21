"""Attribute deviations to packages, apply the user's exclude lists, render.

The reporting policy is *long list by default*: nothing is pre-trimmed to
"interesting" findings. The only trimming is the user's own exclude lists from
``[hardening]`` in the config — which ship EMPTY, so the first run shows
everything and the user narrows to taste. (The always-on accuracy corrections in
engine.py are separate: they fix wrong data, not preference.)
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

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

    @property
    def total(self) -> int:
        return sum(self.checks.values())


def apply(deviations, pkgmap, excl: Exclusions):
    """Attribute, filter, and roll up. Returns ``(package_reports, stats)``.

    ``package_reports`` is a list of :class:`PackageReport` sorted by deviation
    count (desc), then name. ``stats`` records how many deviations each exclude
    rule dropped, so the run can tell the user what its own config hid.
    """
    stats = {"input": 0, "excluded_check": 0, "excluded_package": 0,
             "excluded_path": 0, "kept": 0}
    per_pkg: dict[str, PackageReport] = {}
    per_pkg_bins: dict[str, set] = {}

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

    for pkg, rep in per_pkg.items():
        rep.binaries = len(per_pkg_bins[pkg])
    reports = sorted(per_pkg.values(), key=lambda r: (-r.total, r.package))
    return reports, stats


def summary_line(reports, stats) -> str:
    if not reports:
        return "no hardening deviations from the distro baseline."
    devs = sum(r.total for r in reports)
    return (f"{devs} hardening deviation(s) across {len(reports)} package(s) "
            f"(vs the distro's declared build baseline)")


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

    lines.append(summary_line(reports, stats))
    lines.append("")
    lines.append("legend:")
    seen = {k for r in reports for k in r.checks}
    for key in _CRITERION_ORDER:
        if key in seen:
            lines.append(f"  {key:14s} {_CRITERION_HELP.get(key, '')}")
    lines.append("")
    for r in reports:
        kinds = ", ".join(f"{k}={r.checks[k]}" for k in _CRITERION_ORDER
                          if k in r.checks)
        lines.append(f"{r.package}  ({r.binaries} binary/-ies)  {kinds}")
    return lines
