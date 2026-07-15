"""Per-package AUR install-time pre-flight — the ``aur-precheck.sh`` replacement.

Advisory supply-chain check for AUR packages that are about to be installed (the
gap the yay ``AURPreInstall`` event can't fill from its own data: orphan /
out-of-date / stale / compromised-name / malicious-maintainer). Queries the AUR
RPC + the TTL-cached IOC lists and prints one finding per line, each tagged with a
severity:

    CRIT <msg>   compromised package name or malicious maintainer (warn LOUDLY)
    WARN <msg>   orphaned / out-of-date / stale / not-found / offline

The ``CRIT ``/``WARN `` line contract is byte-for-byte the bash original's, so
``yay-init.lua`` only needs its helper path repointed at ``fettle aur-precheck``.
Always exits 0 (advisory; never blocks an install).

Unlike ``pkg-audit`` (which audits the *installed* foreign set), this operates on
package names handed in as arguments and runs unprivileged as the user — so it is
deliberately self-contained (env-driven, no Context/TOML load) to stay fast when
the hook fires once per package in a bulk upgrade. It shares the IOC disk cache
with ``pkg-audit`` (``~/.cache/fettle/ioc``).
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from ..util import matches_any
from . import ioc as aur_ioc
from . import meta as aur_meta


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() not in ("false", "0", "no", "off")


def _load_allowlist(path: Path) -> list[str]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def _campaigns() -> list[str]:
    raw = os.environ.get("AUR_IOC_CAMPAIGNS")
    if not raw:
        return list(aur_ioc.DEFAULT_CAMPAIGNS)
    return [c for c in raw.replace(",", " ").split() if c]


def check(pkgs, *, home: Path | None = None, emit=print,
          owner: str | None = None) -> None:
    """Emit CRIT/WARN advisory lines for each package name in ``pkgs``.

    ``owner`` chowns the IoC cache back to that user — pass ``ctx.sudo_user`` when
    calling this from an elevated run so it doesn't leave a root-owned cache.
    """
    home = home or Path(os.environ.get("HOME") or Path.home())

    # Master toggle (default on). Off => skip the network-backed checks entirely;
    # the yay hook's local PKGBUILD build-logic scan still runs on its own.
    if not _env_bool("AUR_PRECHECK", True):
        return

    allow_file = Path(os.environ.get("YAY_ALLOWLIST_FILE")
                      or home / ".config/yay/allowlist.txt")
    allow = _load_allowlist(allow_file)
    targets = [p for p in pkgs if p and not matches_any(p, allow)]
    if not targets:
        return

    max_age = int(os.environ.get("AUR_PRECHECK_MAX_AGE_DAYS") or 365)
    ttl = int(os.environ.get("AUR_IOC_CACHE_TTL") or aur_ioc.DEFAULT_TTL)
    cache_dir = Path(os.environ.get("AUR_PRECHECK_CACHE_DIR")
                     or home / ".cache/fettle/ioc")
    ioc = aur_ioc.IOC(cache_dir=cache_dir, campaigns=_campaigns(), ttl=ttl,
                      owner=owner)

    # Fetch the IOC lists (served from cache offline) and RPC metadata once for the
    # whole batch, so a bulk upgrade doesn't refetch per package.
    bad_pkgs = ioc.bad_packages()
    bad_accounts = ioc.bad_accounts()
    results = aur_meta.fetch_info(targets)  # None => RPC unreachable (offline)
    by_name = ({r.get("Name"): r for r in results if r.get("Name")}
               if results is not None else {})
    now = time.time()

    for pkg in targets:
        # 1) Compromised package name (LOUD) — works offline from the IOC cache.
        if pkg in bad_pkgs:
            emit(f"CRIT {pkg} is on the KNOWN-COMPROMISED package list "
                 "-- do NOT install without verifying")

        # 2) RPC metadata: distinguish offline from a genuine not-found.
        if results is None:
            emit(f"WARN {pkg}: could not reach the AUR RPC (offline?) "
                 "-- metadata checks skipped")
            continue
        rec = by_name.get(pkg)
        if rec is None:
            emit(f"WARN {pkg} was NOT found in the AUR (deleted / renamed / typo?) "
                 "-- verify the source")
            continue

        maint = rec.get("Maintainer")
        if not maint:
            emit(f"WARN {pkg} is ORPHANED in the AUR (no maintainer)")
        if rec.get("OutOfDate"):
            emit(f"WARN {pkg} is flagged OUT-OF-DATE in the AUR")
        last = rec.get("LastModified")
        if isinstance(last, (int, float)):
            age = int((now - last) // 86400)
            if age > max_age:
                emit(f"WARN {pkg} PKGBUILD last updated {age} days ago "
                     f"(> {max_age}d; stale)")

        # 3) Malicious maintainer account (LOUD).
        if maint and maint in bad_accounts:
            emit(f"CRIT {pkg} is maintained by KNOWN-MALICIOUS account "
                 f"'{maint}' -- do NOT install")


def scan(pkgs, *, home: Path | None = None,
         owner: str | None = None) -> tuple[list[str], list[str]]:
    """Run the precheck over ``pkgs`` and return ``(crit_msgs, warn_msgs)`` — the
    findings split by severity, with the ``CRIT ``/``WARN `` prefix stripped. The
    pre-upgrade gate uses this to decide whether to pause before ``yay -Sua``."""
    lines: list[str] = []
    check(pkgs, home=home, owner=owner, emit=lines.append)
    crit = [ln[5:] for ln in lines if ln.startswith("CRIT ")]
    warn = [ln[5:] for ln in lines if ln.startswith("WARN ")]
    return crit, warn


def _installed_foreign() -> list[str]:
    """Installed foreign (AUR / manually-built) package names via `pacman -Qmq`."""
    from .. import command

    if not command.which("pacman"):
        return []
    out = command.run(["pacman", "-Qmq"], capture=True).stdout
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def main(argv) -> int:
    """``fettle aur-precheck [<pkg> ...]`` — always returns 0 (advisory).

    With package names (the yay hook path) it checks exactly those and stays
    silent when clean, byte-for-byte as before. With NO arguments it scans every
    installed AUR/foreign package and prints a friendly summary.
    """
    # Split package names from any stray forwarded flags. Everything after a
    # literal `--` is taken as a package name verbatim (standard convention),
    # so a name is never silently dropped for looking like a flag.
    argv = list(argv)
    if "--" in argv:
        sep = argv.index("--")
        pkgs = [a for a in argv[:sep] if not a.startswith("-")] + argv[sep + 1:]
    else:
        pkgs = [a for a in argv if not a.startswith("-")]
    if pkgs:
        check(pkgs)
        return 0

    installed = _installed_foreign()
    if not installed:
        print("no foreign/AUR packages installed to check.")
        return 0
    print(f"scanning {len(installed)} installed AUR/foreign package(s) "
          "for supply-chain issues...")
    findings: list[str] = []

    def _emit(line: str) -> None:
        findings.append(line)
        print(line)

    check(installed, emit=_emit)
    if not findings:
        print("no issues found.")
    return 0
