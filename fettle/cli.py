"""Command-line interface: hybrid short/long flags + bare action words.

``fettle -c -u`` and ``fettle clean update`` are equivalent. With no action given,
the configured ``default_actions`` run. Root elevation happens lazily — only when
fettle is about to change the system — so ``--help`` / ``--print-config`` work
unprivileged.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .backends.base import Context
from .config import Config
from .config import load as load_config
from .distro import UnknownDistro, detect
from .output import Output

DEFAULT_CONFIG = Path.home() / ".config/fettle/config.toml"

# (short, long, action-name). Mirrors update.sh letters where the concept carries over.
FLAG_ACTIONS = [
    ("-c", "--clean", "clean"),
    ("-o", "--orphans", "orphans"),
    ("-u", "--update", "update"),
    ("-r", "--rebuilds", "rebuilds"),
    ("-y", "--python-rebuild", "python_rebuild"),
    ("-p", "--pacnew", "config_drift"),
    ("-f", "--firmware", "firmware"),
    ("-k", "--kernel", "kernels"),
    ("-A", "--aur-audit", "aur_audit"),
    ("-S", "--aur-scan", "aur_scan"),
]
ACTION_NAMES = {action for *_, action in FLAG_ACTIONS} | {"integrity", "source_audit"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fettle", description="Cross-distribution Linux system maintenance."
    )
    for short, long, action in FLAG_ACTIONS:
        p.add_argument(short, long, dest=f"do_{action}", action="store_true",
                       help=f"run the '{action}' action")
    p.add_argument("-a", "--all", action="store_true", help="run the default action set")
    p.add_argument("actions", nargs="*", help="action names (same as the flags above)")
    p.add_argument("--distro", metavar="NAME", help="override distro detection")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="show what would run; change nothing")
    p.add_argument("--only", metavar="ACTION", action="append", default=[],
                   help="restrict to these actions (repeatable)")
    p.add_argument("--skip", metavar="ACTION", action="append", default=[],
                   help="skip these actions (repeatable)")
    p.add_argument("--config", metavar="PATH", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--no-config", action="store_true", help="ignore the config file")
    p.add_argument("--print-config", action="store_true", help="print effective config and exit")
    p.add_argument("--version", action="version", version=f"fettle {__version__}")
    return p


def _requested_actions(args: argparse.Namespace, cfg: Config) -> list[str]:
    chosen: list[str] = []
    for *_, action in FLAG_ACTIONS:
        if getattr(args, f"do_{action}"):
            chosen.append(action)
    for word in args.actions:
        name = word.replace("-", "_")
        if name not in ACTION_NAMES:
            raise SystemExit(f"fettle: unknown action '{word}'")
        chosen.append(name)

    if args.all or not chosen:
        chosen = list(cfg.default_actions)

    # De-dupe (preserve order), then apply --only / --skip.
    seen: set[str] = set()
    ordered = [a for a in chosen if not (a in seen or seen.add(a))]
    if args.only:
        only = {o.replace("-", "_") for o in args.only}
        ordered = [a for a in ordered if a in only]
    if args.skip:
        skip = {s.replace("-", "_") for s in args.skip}
        ordered = [a for a in ordered if a not in skip]
    return ordered


def _print_config(cfg: Config, args: argparse.Namespace) -> None:
    src = "(skipped: --no-config)" if args.no_config else str(args.config)
    print("Effective configuration")
    print("-" * 46)
    print(f"  {'config file':18} {src}")
    print(f"  {'default_actions':18} {' '.join(cfg.default_actions)}")
    print(f"  {'auto_rebuild':18} {cfg.auto_rebuild}")
    print(f"  {'exclude_foreign':18} {' '.join(cfg.exclude_foreign) or '(none)'}")
    print(f"  {'keep_orphans':18} {' '.join(cfg.keep_orphans) or '(none)'}")


def _is_root() -> bool:
    return os.geteuid() == 0


def _in_test() -> bool:
    return os.environ.get("FETTLE_TEST") == "1"


def _reexec_with_sudo() -> None:  # pragma: no cover - exec replaces the process
    os.execvp("sudo", ["sudo", sys.executable, "-m", "fettle", *sys.argv[1:]])


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = Output(color=(False if args.no_color else None),
                 quiet=args.quiet, verbose=args.verbose)

    if args.no_config:
        cfg, warnings = Config(), []
    else:
        cfg, warnings = load_config(args.config)
    for w in warnings:
        out.warn(w)

    if args.print_config:
        _print_config(cfg, args)
        return 0

    try:
        backend = detect(override=args.distro)
    except UnknownDistro as exc:
        out.err(str(exc))
        return 1

    actions = _requested_actions(args, cfg)
    runnable = [a for a in actions if backend.supports(a)]
    for a in actions:
        if not backend.supports(a):
            out.note(f"skipping '{a}' — not supported by the {backend.name} backend")

    if not runnable:
        out.warn("nothing to do (no supported actions selected).")
        return 0

    # Elevate only when we will actually change the system.
    if not args.dry_run and not _is_root() and not _in_test():
        _reexec_with_sudo()

    out.step_total = len(runnable)
    _ctx = Context(output=out, config=cfg, dry_run=args.dry_run)
    for a in runnable:
        out.section(a)
        out.note(f"[M1 skeleton] '{a}' via the {backend.name} backend "
                 f"— implementation lands in a later milestone")
    out.print_summary()
    return 0
