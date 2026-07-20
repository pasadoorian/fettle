"""Resolve what the distro *says* it builds with, as checksec criteria.

The subtle part: the effective baseline is the distro's build flags **plus the
compiler's compiled-in defaults**. Arch's GCC is ``--enable-default-pie
--enable-default-ssp`` and ``makepkg.conf`` carries no ``-fstack-protector*`` at
all — so reading ``makepkg.conf`` alone yields a *wrong* baseline that never
expects PIE or a stack canary.

Criteria map a checksec key to the values that satisfy the baseline. Keys the
distro never promises are deliberately absent (see NEVER_CRITERIA in engine.py):
``safestack`` is red even on a perfectly-built binary, and ``stack_clash`` is a
heuristic that reports "No Probes" for any binary too small to need one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .. import command

# Values that satisfy each criterion (checksec 3.2.0 wording).
GOOD_RELRO_FULL = ("Full RELRO",)
GOOD_RELRO_ANY = ("Full RELRO", "Partial RELRO")
GOOD_PIE = ("PIE Enabled",)
GOOD_CANARY = ("Canary Found",)
GOOD_FORTIFY = ("Yes",)
GOOD_CFI = ("SHSTK & IBT",)
GOOD_NX = ("NX enabled",)
GOOD_NO_RPATH = ("No RPATH",)
GOOD_NO_RUNPATH = ("No RUNPATH",)


@dataclass
class Baseline:
    """The distro's declared build policy, expressed as checksec criteria."""

    name: str
    criteria: dict[str, tuple[str, ...]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def wants(self, key: str) -> tuple[str, ...] | None:
        return self.criteria.get(key)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _shell_var(text: str, name: str) -> str:
    """Extract NAME="..." from a shell-ish config, following backslash line
    continuations (makepkg.conf splits CFLAGS across four lines)."""
    m = re.search(rf'^\s*{re.escape(name)}=(["\']?)(.*?)\1\s*$', text,
                  re.MULTILINE | re.DOTALL)
    if not m:
        # continuation form: grab until the first line not ending in a backslash
        m2 = re.search(rf'^\s*{re.escape(name)}="(.*?)"', text, re.MULTILINE | re.DOTALL)
        return " ".join(m2.group(1).split()) if m2 else ""
    return " ".join(m.group(2).split())


def _gcc_defaults(runner=None) -> tuple[bool, bool]:
    """(default_pie, default_ssp) from `gcc -v`. Arch/Debian both build GCC with
    these on, which is where PIE and the stack canary actually come from."""
    run = runner or command.run
    if not command.which("gcc"):
        return (False, False)
    proc = run(["gcc", "-v"], capture=True)
    text = (proc.stdout or "") + (proc.stderr or "")  # gcc -v writes to stderr
    return ("--enable-default-pie" in text, "--enable-default-ssp" in text)


def _criteria_from_flags(cflags: str, ldflags: str, *,
                         default_pie: bool, default_ssp: bool) -> dict:
    """Common flag->criteria derivation (identical logic on Arch and Debian)."""
    crit: dict[str, tuple[str, ...]] = {
        "nx": GOOD_NX,
        "rpath": GOOD_NO_RPATH,
        "runpath": GOOD_NO_RUNPATH,
    }
    has_relro = "-z,relro" in ldflags or "-z relro" in ldflags
    has_now = "-z,now" in ldflags or "-z now" in ldflags
    if has_relro:
        crit["relro"] = GOOD_RELRO_FULL if has_now else GOOD_RELRO_ANY
    if default_pie or "-fPIE" in cflags or "-pie" in ldflags:
        crit["pie"] = GOOD_PIE
    if default_ssp or "-fstack-protector" in cflags:
        crit["canary"] = GOOD_CANARY
    if "_FORTIFY_SOURCE" in cflags:
        crit["fortify_source"] = GOOD_FORTIFY
    if "-fcf-protection" in cflags:
        crit["cfi"] = GOOD_CFI
    return crit


def _arch(root: Path, runner=None) -> Baseline:
    text = _read_text(root / "etc" / "makepkg.conf")
    cflags = _shell_var(text, "CFLAGS")
    ldflags = _shell_var(text, "LDFLAGS")
    pie, ssp = _gcc_defaults(runner)
    notes = []
    if not text:
        notes.append("/etc/makepkg.conf unreadable — falling back to generic defaults")
        cflags, ldflags = "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro -Wl,-z,now"
    if pie or ssp:
        got = " and ".join(n for n, on in (("PIE", pie), ("stack canary", ssp)) if on)
        notes.append(f"GCC supplies {got} by default (not from makepkg.conf CFLAGS)")
    crit = _criteria_from_flags(cflags, ldflags, default_pie=pie, default_ssp=ssp)
    return Baseline(name="arch (makepkg.conf + gcc defaults)", criteria=crit, notes=notes)


def _debian(root: Path, runner=None) -> Baseline:
    run = runner or command.run
    cflags = ldflags = ""
    notes = []
    if command.which("dpkg-buildflags"):
        cflags = (run(["dpkg-buildflags", "--get", "CFLAGS"], capture=True).stdout or "").strip()
        ldflags = (run(["dpkg-buildflags", "--get", "LDFLAGS"], capture=True).stdout or "").strip()
    if not cflags and not ldflags:
        # dpkg-dev absent: Debian's documented hardening defaults since wheezy.
        cflags = "-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE"
        ldflags = "-Wl,-z,relro -Wl,-z,now -pie"
        notes.append("dpkg-buildflags not available — using Debian's documented defaults")
    pie, ssp = _gcc_defaults(runner)
    crit = _criteria_from_flags(cflags, ldflags, default_pie=pie, default_ssp=ssp)
    return Baseline(name="debian (dpkg-buildflags)", criteria=crit, notes=notes)


def resolve(distro: str, *, root: Path = Path("/"), runner=None) -> Baseline:
    """Build the criteria set for ``distro`` (``arch`` | ``debian``)."""
    if distro == "arch":
        return _arch(root, runner)
    if distro == "debian":
        return _debian(root, runner)
    return Baseline(
        name="generic",
        criteria={"nx": GOOD_NX, "relro": GOOD_RELRO_FULL, "pie": GOOD_PIE,
                  "canary": GOOD_CANARY, "rpath": GOOD_NO_RPATH,
                  "runpath": GOOD_NO_RUNPATH},
        notes=[f"no build-flag source for '{distro}' — using a generic baseline"],
    )
