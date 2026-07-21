"""sys-audit orchestration + CLI — the System Supply Chain scanner front end.

``fettle sys-audit [CATEGORIES...] [--all] [--list]`` mirrors the bash scanner's
UX. Distro-neutral checks live here (M9); ``packages`` (integrity via the backend)
lands in M10 and ``remote`` execution in M11.
"""

from __future__ import annotations

import argparse
import sys
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


_SYS_AUDIT_EPILOG = """\
sys-audit elevates itself (prompts for sudo); pass --user to stay unprivileged.
--list and remote never elevate.

remote — run the scan on another host over SSH:
  fettle sys-audit remote [--sudo] [-v] <host> <categories | --all>
  <host> is any ~/.ssh/config alias or user@host. fettle packages itself as a
  zipapp, scp's it to the host, runs it over `ssh -t`, and removes it. --sudo
  runs the remote scan as root; -v is forwarded.

examples:
  fettle sys-audit --all
  fettle sys-audit secureboot tpm
  fettle sys-audit --user hardware
  fettle sys-audit remote server1 --all
  fettle sys-audit remote --sudo admin@host2 secureboot tpm
"""


def _parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="fettle sys-audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="System Supply Chain scanner: firmware, boot chain, hardware.",
        epilog=_SYS_AUDIT_EPILOG,
    )
    p.add_argument("categories", nargs="*",
                   help="check categories to run (default: all; see --list)")
    p.add_argument("-a", "--all", action="store_true",
                   help="run every check (the default when no categories are given)")
    p.add_argument("-l", "--list", action="store_true", help="list check categories and exit")
    p.add_argument("-v", "--verbose", action="store_true", help="show raw command output")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--user", action="store_true",
                   help="run unprivileged (skip auto-sudo; partial results)")
    return p.parse_args(argv)


def _remote(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        prog="fettle sys-audit remote",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run a sys-audit scan on a remote host over SSH.\n"
                    "fettle is packaged as a zipapp, scp'd to the host, run over "
                    "`ssh -t`, and removed (remote exit code preserved).",
        epilog="examples:\n"
               "  fettle sys-audit remote server1 --all\n"
               "  fettle sys-audit remote --sudo admin@host2 secureboot tpm\n"
               "  fettle sys-audit remote -v gateway microcode")
    p.add_argument("--sudo", action="store_true", help="run the remote scan as root (sudo)")
    p.add_argument("-v", "--verbose", action="store_true", help="forward -v to the remote scan")
    p.add_argument("-q", "--quiet", action="store_true", help="forward -q to the remote scan")
    p.add_argument("-a", "--all", action="store_true", help="run every check on the host")
    p.add_argument("host", help="ssh host or ~/.ssh/config alias (e.g. server1, user@host)")
    p.add_argument("categories", nargs="*", help="check categories to run (or --all)")
    args = p.parse_args(argv)

    chosen = list(CATEGORIES) if args.all else [c.replace("_", "-") for c in args.categories]
    if not chosen:
        print("Error: remote requires check categories or --all", file=sys.stderr)
        return 1
    unknown = [c for c in chosen if c not in CATEGORIES]
    if unknown:
        print(f"Error: unknown check(s): {', '.join(unknown)}", file=sys.stderr)
        return 1

    forwarded: list[str] = []
    if args.verbose:
        forwarded.append("-v")
    if args.quiet:
        forwarded.append("-q")
    forwarded += ["--all"] if args.all else chosen

    from .. import remote
    return remote.run(args.host, ["sys-audit", *forwarded], sudo=args.sudo)


def main(argv: list[str]) -> int:
    if argv and argv[0] == "remote":
        return _remote(argv[1:])

    args = _parse(argv)
    out = Output(color=(False if args.no_color else None),
                 quiet=args.quiet, verbose=args.verbose)

    if args.list:
        list_checks(out)
        return 0

    # Bare `fettle sys-audit` (no categories, no --all) runs every check.
    if args.all or not args.categories:
        chosen = list(CATEGORIES)
    else:
        chosen = [c.replace("_", "-") for c in args.categories]
        unknown = [c for c in chosen if c not in CATEGORIES]
        if unknown:
            out.err(f"unknown check(s): {', '.join(unknown)}. Try: fettle sys-audit --list")
            return 1

    # Most checks need root. Self-elevate (like the maintenance actions) so
    # `fettle sys-audit` Just Works without the user typing `sudo fettle` — which
    # fails when the launcher lives in ~/.local/bin (not on root's PATH). The
    # re-exec uses the full `python3 -m fettle` path, so it's PATH-independent.
    from .. import cli
    if not args.user and not cli._is_root() and not cli._in_test():
        cli._reexec_with_sudo()  # replaces the process (carries PYTHONPATH via env)

    scan = Scan(output=out, root=Path("/"), verbose=args.verbose)
    run(chosen, scan)
    _write_report(scan, out)
    return 0


def _write_report(scan: Scan, out: Output) -> None:
    """Persist the sys-audit result under ~/.fettle/reports/<host>/ so it shows in
    `fettle report`. Best-effort; owned by the invoking user even under sudo."""
    import os
    import pwd
    from types import SimpleNamespace

    from .. import reports
    from ..cli import DEFAULT_CONFIG
    from ..config import load
    if not scan.records:
        return
    try:
        cfg, _ = load(DEFAULT_CONFIG)
    except Exception:
        cfg = None
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    home = Path.home()
    if sudo_user:
        try:
            home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    ctx = SimpleNamespace(config=cfg, user_home=home, sudo_user=sudo_user, output=out)
    try:
        path = reports.write_report("sys-audit", scan.report_text(), ctx,
                                    data=scan.report_data())
        out.note(f"report saved to {path}")
    except OSError as exc:
        out.warn(f"could not write sys-audit report: {exc}")
