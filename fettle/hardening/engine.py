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

from .. import command, util
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
    file (privilege boundaries) under the standard lib dirs.

    Paths are canonicalized with ``realpath`` and de-duplicated, so a merged-usr
    layout (``/usr/sbin -> bin``, ``/bin -> usr/bin``) doesn't scan every binary
    twice — and the canonical spelling is the one the package DB records
    (``pacman -Qo /usr/sbin/x`` fails; ``/usr/bin/x`` succeeds)."""
    candidates: set[str] = set()
    for d in ("usr/bin", "usr/sbin", "bin", "sbin"):
        base = root / d
        if base.is_dir():
            try:
                candidates.update(str(p) for p in base.iterdir())
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
                        candidates.add(p)
                except OSError:
                    continue
    targets = {os.path.realpath(t) for t in candidates if is_elf(t)}
    return sorted(targets)


# checksec 2.x reports each property as a bare string; 3.x wraps it in
# `{"value": ...}`. These map 2.x's vocabulary onto the 3.x wording the baselines are
# written in, so exactly one comparison vocabulary exists downstream.
_V2_VALUES = {
    "relro": {"full": "Full RELRO", "partial": "Partial RELRO", "no": "No RELRO"},
    "canary": {"yes": "Canary Found", "no": "No Canary Found"},
    "nx": {"yes": "NX enabled", "no": "NX disabled"},
    "pie": {"yes": "PIE Enabled", "no": "No PIE", "dso": "DSO"},
    "rpath": {"no": "No RPATH", "yes": "RPATH"},
    "runpath": {"no": "No RUNPATH", "yes": "RUNPATH"},
    "fortify_source": {"yes": "Yes", "no": "No", "partial": "Yes"},
}


def _from_v2(payload: dict) -> list[dict]:
    """Reshape checksec 2.x output into the 3.x structure the evaluator expects.

    2.x emits ``{"/path": {"relro":"full","canary":"yes",...}}`` — a mapping keyed by
    path, with bare string values. 3.x emits a list of ``{"name":..., "checks":
    {"relro": {"value": "Full RELRO"}, ...}}``. Normalising here keeps every downstream
    comparison in one vocabulary instead of teaching the baselines two.
    """
    out = []
    for path, props in payload.items():
        if not isinstance(props, dict):
            continue
        checks = {}
        for key, table in _V2_VALUES.items():
            raw = str(props.get(key, "")).strip().lower()
            if raw:
                checks[key] = {"value": table.get(raw, raw)}
        # 2.x spells these with a hyphen and keeps them outside the property set.
        for src, dst in (("fortify-able", "fortifyable"), ("fortified", "fortified")):
            if src in props:
                checks[dst] = {"value": str(props[src])}
        if checks:
            out.append({"name": path, "checks": checks})
    return out


def run_checksec(paths, *, runner=None) -> list[dict]:
    """Run checksec over `paths`, returning entries in the 3.x shape.

    **Two interfaces, because two checksec generations are in the wild and they share
    no command line.** 3.x takes `listfile <file> -o json`; 2.x (which Fedora still
    ships — 2.7.1, dated 2015) takes `--format=json --file=<path>`, one file at a time,
    and emits a different JSON schema entirely.

    Getting this wrong is not a loud failure: the 3.x invocation on a 2.x binary yields
    nothing parseable, every binary drops out, and the audit reports a clean baseline
    having examined none of them. Callers must treat "analysed 0" as "did not run" —
    see `hardening/audit.py`.

    Returns [] if checksec is missing or unusable (never raises).
    """
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
            data = []
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    if isinstance(data, list) and data:
        return data
    # 3.x form produced nothing — fall back to the 2.x interface, one file per call.
    return _run_checksec_v2(paths, run)


def _run_checksec_v2(paths, run) -> list[dict]:
    """checksec 2.x: `--format=json --file=<path>`, one invocation per binary.

    **Runs unprivileged when we are root, because checksec 2.x sleeps 2 seconds per
    invocation as root.** Measured on Rocky 9 (checksec 2.5.0): 61 ms as a user,
    2063 ms as root. `fettle remote` elevates, so an EL9 host with ~900 binaries spent
    over half an hour asleep and was killed by the harness timeout before it could
    report anything. The cause is in checksec itself, at its line 6::

        [ "$(env | sed -r -e '/^(PWD|SHLVL|_)=/d')" ] && exec -c "$0" "$@"

    It sanitizes its environment by re-execing with an empty one, which wipes PATH —
    and then restores `/sbin`:`/usr/sbin` **only when not root**. So as root it cannot
    find `sysctl`, prints "Not all necessary commands found", and sleeps. Dropping
    privileges puts us on the branch that repairs PATH. Nothing else works: the
    environment we would fix is discarded by that re-exec, and `--listfile` does not
    help because checksec implements it by invoking itself once per file anyway.

    Output is unaffected — byte-identical as user and as root for the same binary.
    What *is* affected is which files can be opened, so whatever the unprivileged pass
    could not read is retried as root. Those are few (12 of 2318 bin-dir entries on
    Rocky 9), so the sleep is affordable for them. Silently scanning fewer binaries
    would be the exact failure this audit exists to prevent: a smaller answer that
    looks like a cleaner one.

    A file it cannot read is detected by its **absence**, not by an error entry:
    measured, 2.x prints ``Error: No read permissions for '<f>' (run as root).`` as
    coloured text on *stdout* and still exits 0, so the JSON parse simply fails and
    that path yields nothing at all.
    """
    user = util.invoking_user() if os.geteuid() == 0 else None
    out = _v2_pass(paths, run, user)
    if not user:
        return out
    missing = [p for p in paths if p not in {e["name"] for e in out}]
    return out + (_v2_pass(missing, run, None) if missing else [])


def _v2_pass(paths, run, as_user: str | None) -> list[dict]:
    """One checksec 2.x sweep over `paths`, optionally with privileges dropped."""
    out: list[dict] = []
    for path in paths:
        proc = run(["checksec", "--format=json", f"--file={path}"],
                   capture=True, **({"as_user": as_user} if as_user else {}))
        try:
            payload = json.loads(proc.stdout or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(payload, dict):
            out.extend(_from_v2(payload))
    return out


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
