"""sys-audit orchestration + CLI — the System Supply Chain scanner front end.

``fettle sys-audit [CATEGORIES...] [--all] [--list]`` mirrors the bash scanner's
UX. Distro-neutral checks live here (M9); ``packages`` (integrity via the backend)
lands in M10 and ``remote`` execution in M11.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from ..output import Output
from .base import Scan

# Ordered category -> description (mirrors the bash CHECK_CATEGORIES). `packages`
# is added in M10 (needs the backend's verify_integrity).
CATEGORIES: dict[str, str] = {
    "secureboot": "Secure Boot status and configuration",
    "bios": "BIOS/UEFI version and information",
    "firmware": "Firmware security checks (requires chipsec)",
    "fwupd": "Firmware update status via fwupd",
    "intel-me": "Intel Management Engine status",
    "microcode": "CPU microcode version and vulnerabilities",
    "tpm": "TPM device validation",
    "packages": "Package integrity verification",
    "hardware": "Hardware inventory and details",
    "storage": "Storage device firmware",
}


def _packages_check(scan) -> None:
    """The one distro-specific check: delegate to the backend's verify_integrity."""
    from ..distro import UnknownDistro, detect
    try:
        backend = detect()
    except UnknownDistro as exc:
        scan.status("Package Verification", str(exc), "warn")
        return
    scan.status("Detected Distribution", backend.name, "info")
    try:
        backend.verify_integrity(scan)
    except NotImplementedError:
        scan.status("Package Verification",
                    f"not implemented for the {backend.name} backend", "warn")


def _registry() -> dict:
    """category -> check callable(scan). Imported lazily to keep import cost low."""
    from . import checks, secureboot
    return {
        "secureboot": secureboot.check,
        "bios": checks.bios,
        "firmware": checks.firmware,
        "fwupd": checks.fwupd,
        "intel-me": checks.intel_me,
        "microcode": checks.microcode,
        "tpm": checks.tpm,
        "packages": _packages_check,
        "hardware": checks.hardware,
        "storage": checks.storage,
    }


def list_checks(out: Output) -> None:
    print("Available check categories:\n")
    for cat, desc in CATEGORIES.items():
        print(f"  {out.CYN}{cat:<12}{out.NC} {desc}")
    print()


def run(categories: list[str], scan: Scan) -> None:
    reg = _registry()
    scan.output.step_total = len(categories)
    if not scan.is_root():
        scan.output.note("running unprivileged — some checks need root for full results "
                         "(re-run with sudo).")
    for cat in categories:
        scan.section(CATEGORIES.get(cat, cat))
        reg[cat](scan)
    scan.output.print_summary()


def _parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fettle sys-audit",
        description="System Supply Chain scanner: firmware, boot chain, hardware.",
    )
    p.add_argument("categories", nargs="*", help="check categories to run (see --list)")
    p.add_argument("-a", "--all", action="store_true", help="run every check")
    p.add_argument("-l", "--list", action="store_true", help="list check categories and exit")
    p.add_argument("-v", "--verbose", action="store_true", help="show raw command output")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    if argv and argv[0] == "remote":
        print("sys-audit remote execution arrives in M11.")
        return 0

    args = _parse(argv)
    out = Output(color=(False if args.no_color else None),
                 quiet=args.quiet, verbose=args.verbose)

    if args.list:
        list_checks(out)
        return 0

    chosen = list(CATEGORIES) if args.all else [c.replace("_", "-") for c in args.categories]
    unknown = [c for c in chosen if c not in CATEGORIES]
    if unknown:
        out.err(f"unknown check(s): {', '.join(unknown)}. Try: fettle sys-audit --list")
        return 1
    if not chosen:
        out.warn("nothing to check. Pick categories, use --all, or --list.")
        return 0

    run(chosen, Scan(output=out, root=Path("/"), verbose=args.verbose))
    return 0
