"""Run checksec over a scope and evaluate it against the distro baseline.

Four corrections are applied unconditionally — they are *accuracy*, not user
preference, and each was measured on a real system (see PLAN.md Phase 14):

1. **ELF-only.** checksec reports ``"Error checking <X>"`` with ``status: red``
   for non-ELF input, so Perl/shell scripts otherwise "fail" every criterion.
   1639 of 6058 candidate paths on a live box were not ELF.
2. **Static Go/Rust are skipped.** ``fortify_source == "N/A"`` marks them;
   symbol-based canary/fortify checks cannot say anything about such binaries.
3. **FORTIFY is gated on ``fortifyable > 0``.** ``fortify_source: "No"`` with
   nothing fortifyable says nothing about build flags — 47% of "No" verdicts.
4. **``stack_clash`` is never pass/fail.** It is a probe-detection heuristic:
   ``/usr/bin/passwd`` is built *with* ``-fstack-clash-protection`` yet reports
   "No Probes" simply because it needs none. ~83% false-positive rate.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .. import command
from .baseline import Baseline

ELF_MAGIC = b"\x7fELF"

# Keys that must never become pass/fail criteria, with why (shown in docs/tests).
NEVER_CRITERIA = {
    "safestack": "Clang-only; red even on a correctly built GCC binary",
    "selfrando": "not used by any mainstream distro",
    "sanitizers": "a debug feature, not a hardening baseline",
    "glibcxx_assert": "reports Unknown — not verifiable from the binary",
    "fortify_level": "reports Unknown — level 2 vs 3 is not detectable",
    "stack_clash": "probe heuristic; 'No Probes' means small frames, not missing flag",
    "symbols": "stripping is not a hardening property",
    "separate_code": "linker default, not a distro build-flag promise",
    "fortified": "a count, not a verdict",
    "fortifyable": "a count, not a verdict",
}


@dataclass
class Deviation:
    """One binary failing one criterion the distro said it builds with."""

    path: str
    check: str
    got: str
    want: tuple[str, ...]

    @property
    def want_str(self) -> str:
        return " or ".join(self.want)


def is_elf(path: str) -> bool:
    """Cheap 4-byte magic test — the mandatory gate before checksec sees a path."""
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return False
        with open(path, "rb") as fh:
            return fh.read(4) == ELF_MAGIC
    except OSError:
        return False


def default_targets(root: Path = Path("/")) -> list[str]:
    """Scope: every executable in the standard bin dirs, plus every setuid/setgid
    file (privilege boundaries) under the standard lib/sbin dirs."""
    targets: set[str] = set()
    for d in ("usr/bin", "usr/sbin"):
        base = root / d
        if base.is_dir():
            try:
                targets.update(str(p) for p in base.iterdir())
            except OSError:
                pass
    for d in ("usr/lib", "usr/libexec"):
        base = root / d
        if not base.is_dir():
            continue
        for dirpath, _dirnames, filenames in os.walk(base, followlinks=False):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    if os.stat(p).st_mode & 0o6000:
                        targets.add(p)
                except OSError:
                    continue
    return sorted(t for t in targets if is_elf(t))


def run_checksec(paths, *, runner=None) -> list[dict]:
    """One `checksec listfile <file> -o json` pass. Returns [] if checksec is
    missing or emits unparseable output (never raises)."""
    run = runner or command.run
    paths = list(paths)
    if not paths:
        return []
    tmp = tempfile.NamedTemporaryFile("w", suffix=".lst", delete=False)
    try:
        tmp.write("\n".join(paths) + "\n")
        tmp.close()
        proc = run(["checksec", "listfile", tmp.name, "-o", "json", "--no-banner"],
                   capture=True)
        try:
            data = json.loads(proc.stdout or "[]")
        except (json.JSONDecodeError, TypeError):
            return []
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return data if isinstance(data, list) else []


def _val(checks: dict, key: str) -> str:
    entry = checks.get(key)
    return str(entry.get("value", "")) if isinstance(entry, dict) else ""


def _int(checks: dict, key: str) -> int:
    try:
        return int(_val(checks, key))
    except ValueError:
        return 0


def is_unreadable(checks: dict) -> bool:
    """checksec could not parse the file (correction 1)."""
    return any("Error checking" in _val(checks, k) for k in checks)


def is_static(checks: dict) -> bool:
    """Static Go/Rust — symbol-based checks are meaningless (correction 2)."""
    return _val(checks, "fortify_source") == "N/A"


def evaluate(results, baseline: Baseline) -> tuple[list[Deviation], dict]:
    """Compare checksec results to the baseline. Returns (deviations, stats)."""
    devs: list[Deviation] = []
    stats = {"total": 0, "analyzed": 0, "unreadable": 0, "static": 0}
    for entry in results or []:
        if not isinstance(entry, dict):
            continue
        checks = entry.get("checks")
        if not isinstance(checks, dict):
            continue
        stats["total"] += 1
        if is_unreadable(checks):
            stats["unreadable"] += 1
            continue
        if is_static(checks):
            stats["static"] += 1
            continue
        stats["analyzed"] += 1
        path = str(entry.get("name", "?"))
        for key, want in baseline.criteria.items():
            if key in NEVER_CRITERIA:
                continue
            got = _val(checks, key)
            if not got or got in want:
                continue
            # correction 3: "No" with nothing fortifyable is not a finding
            if key == "fortify_source" and _int(checks, "fortifyable") == 0:
                continue
            devs.append(Deviation(path=path, check=key, got=got, want=want))
    return devs, stats


def scan(paths=None, *, baseline: Baseline, root: Path = Path("/"),
         runner=None) -> tuple[list[Deviation], dict]:
    """Full pass: resolve targets, run checksec, evaluate. Never raises."""
    targets = list(paths) if paths is not None else default_targets(root)
    return evaluate(run_checksec(targets, runner=runner), baseline)
