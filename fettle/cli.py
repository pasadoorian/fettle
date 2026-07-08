"""Command-line interface: hybrid short/long flags + bare action words.

``fettle -c -u`` and ``fettle clean update`` are equivalent. With no action given,
the configured ``default_actions`` run. Root elevation happens lazily — only when
fettle is about to change the system — so ``--help`` / ``--print-config`` work
unprivileged.
"""

from __future__ import annotations

import argparse
import os
import pwd
import sys
from pathlib import Path

from . import __version__, actions
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
    ("-S", "--aur-ioc-scan", "aur_ioc_scan"),
]
ACTION_NAMES = {action for *_, action in FLAG_ACTIONS} | {"pkg_audit", "integrity", "source_audit"}

# Read-only actions never mutate the system, so they don't need root elevation.
READ_ONLY_ACTIONS = {"pkg_audit", "aur_audit", "aur_ioc_scan", "config_drift"}

# The safe set `fettle remote <host>` / `-a` runs. Destructive/interactive actions
# (orphan removal, kernel management) are NOT here — they must be named explicitly.
REMOTE_DEFAULT_ACTIONS = ("clean", "update", "firmware")

# Human-facing one-liners for each maintenance action (shown in --help).
ACTION_HELP = {
    "clean": "clean package-manager caches",
    "orphans": "list foreign packages; remove true orphans",
    "update": "update everything (repos, then AUR / flatpak / snap)",
    "rebuilds": "find packages/services needing a rebuild or restart",
    "python_rebuild": "rebuild packages stranded on an old Python",
    "config_drift": "list pending config-file merges (.pacnew / .dpkg-dist)",
    "firmware": "check for firmware updates (fwupd)",
    "kernels": "manage installed kernels (running one protected)",
    "aur_audit": "AUR health table -> ~/aur-audit.txt",
    "aur_ioc_scan": "scan installed AUR pkgs for IoCs -> ~/aur-ioc-scan.txt",
}

_EPILOG = """\
subcommands (run in place of the action flags above):
  fettle pkg-audit           package supply-chain audit — where installed
                             software came from and whether it's tampered
                             (AUR / APT / Flatpak / Snap) -> ~/pkg-audit.txt
  fettle sys-audit [CATS]    firmware / boot / hardware security scan
                             (Secure Boot, TPM, microcode, ...); try --list,
                             --all, or 'remote <host>'. Elevates itself; no sudo.
  fettle aur-precheck PKG    install-time AUR pre-flight (used by the yay hook)
  fettle remote HOST [acts]  run maintenance on a remote host over ssh (safe set
                             by default; --yes for unattended). try 'remote -h'

Actions/commands tagged [arch]/[debian] are specific to that distro; untagged
ones work everywhere. fettle runs only what your distro's backend supports and
skips the rest with a note.

examples:
  fettle                             run the default maintenance set
  fettle -c -u                       clean + update
  fettle --all --dry-run             show everything that would run; change nothing
  fettle -A                          AUR health audit
  fettle sys-audit --all             full security scan (elevates itself)
  fettle sys-audit remote HOST --all scan a remote host over ssh
"""


def _distro_tags() -> dict[str, str]:
    """Map each action to a ``' [arch]'``-style tag naming the distro families that
    support it — empty when every backend does. Derived from the backends' own
    ``supported`` sets, so it stays correct as backends gain capabilities.
    """
    from .distro import _REGISTRY

    backends = {cls.name: cls.supported for cls in set(_REGISTRY.values())}
    all_names = set(backends)
    tags: dict[str, str] = {}
    for action in ACTION_NAMES:
        supporting = {name for name, sup in backends.items() if action in sup}
        tags[action] = (f" [{'/'.join(sorted(supporting))}]"
                        if supporting and supporting != all_names else "")
    return tags


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fettle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Cross-distribution Linux system maintenance and supply-chain tool.\n"
                    "Run with no action to execute the default maintenance set.",
        epilog=_EPILOG,
    )
    tags = _distro_tags()
    maint = p.add_argument_group(
        "maintenance actions",
        "combine freely, as flags or bare words (fettle -c -u == fettle clean update)")
    for short, long, action in FLAG_ACTIONS:
        maint.add_argument(short, long, dest=f"do_{action}", action="store_true",
                           help=f"{ACTION_HELP.get(action, action)}{tags[action]}")
    p.add_argument("-a", "--all", action="store_true", help="run the default action set")
    p.add_argument("-R", "--auto-rebuild", action="store_true",
                   help="offer to rebuild (with -r / -y) instead of only listing")
    p.add_argument("--yes", action="store_true", help="assume yes to prompts (non-interactive)")
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
    # sudo's env_reset drops PYTHONPATH, so root's `python -m fettle` would fail to
    # find the package when fettle runs from a checkout (via bin/fettle) rather than
    # an installed location. Carry the package's parent dir across with `env` so the
    # real package resolves — a regular package wins over any namespace-dir shadow.
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    existing = os.environ.get("PYTHONPATH")
    pythonpath = pkg_parent + (os.pathsep + existing if existing else "")
    os.execvp("sudo", ["sudo", "env", f"PYTHONPATH={pythonpath}",
                       sys.executable, "-m", "fettle", *sys.argv[1:]])


_REMOTE_EPILOG = """\
Runs fettle maintenance on a remote host over SSH: fettle is packaged as a zipapp,
scp'd to the host, run there under sudo over `ssh -t`, and removed. The host needs
a python3 interpreter — nothing is installed.

With no actions (or -a) the SAFE default set runs: clean, update, firmware.
Destructive/interactive actions run only when named explicitly, e.g.
  fettle remote HOST orphans kernels     (removes packages — asks per item)

Prompts (sudo password, AUR review, removals) are interactive over the TTY by
default; --yes makes the run fully unattended (auto-confirm + non-interactive
package managers). NOTE: --yes also SKIPS AUR PKGBUILD review.

examples:
  fettle remote server1 -a                 clean + update + firmware
  fettle remote server1 -a --dry-run       preview; change nothing
  fettle remote server1 update --yes       unattended update only
  fettle remote --ssh-arg=-oConnectTimeout=5 server1 -a
"""


def _run_remote_maintenance(argv: list[str]) -> int:
    from . import remote

    p = argparse.ArgumentParser(
        prog="fettle remote",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Run fettle maintenance on a remote host over SSH.",
        epilog=_REMOTE_EPILOG,
    )
    p.add_argument("-a", "--all", action="store_true",
                   help="run the safe remote default set (clean update firmware)")
    p.add_argument("--yes", action="store_true",
                   help="unattended: auto-confirm prompts + non-interactive package managers")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would run on the host; change nothing (no sudo)")
    p.add_argument("--ssh-arg", action="append", default=[], metavar="ARG",
                   help="extra ssh argument, repeatable (e.g. --ssh-arg=-oConnectTimeout=5)")
    p.add_argument("host", help="ssh host or ~/.ssh/config alias")
    p.add_argument("actions", nargs="*", help="maintenance actions (default: the safe set)")
    args = p.parse_args(argv)

    chosen: list[str] = []
    for word in args.actions:
        name = word.replace("-", "_")
        if name not in ACTION_NAMES:
            print(f"fettle remote: unknown action '{word}'", file=sys.stderr)
            return 2
        chosen.append(name)
    if args.all or not chosen:
        chosen = list(REMOTE_DEFAULT_ACTIONS)

    remote_args = [a.replace("_", "-") for a in chosen]
    if args.yes:
        remote_args.append("--yes")
    if args.dry_run:
        remote_args.append("--dry-run")
    # Maintenance needs root, so run the remote fettle under sudo — which also means
    # it runs as root and won't try to self-elevate inside the zipapp. A dry-run
    # changes nothing, so it needs neither sudo nor elevation.
    return remote.run(args.host, remote_args, sudo=not args.dry_run, ssh_args=args.ssh_arg)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # ``aur-precheck`` is a standalone, unprivileged helper (called per-package by
    # the yay install hook), not one of the maintenance actions — route it before
    # the flag parser so it bypasses config load, root elevation, and section UI.
    if argv and argv[0] == "aur-precheck":
        from .aur import precheck
        return precheck.main(argv[1:])

    # sys-audit is the System Supply Chain scanner — its own subcommand with a
    # separate category/--all/--list surface, routed before the maintenance parser.
    if argv and argv[0] == "sys-audit":
        from .secure import audit
        return audit.main(argv[1:])

    # `fettle remote <host> <actions>` runs maintenance on a remote host over SSH.
    if argv and argv[0] == "remote":
        return _run_remote_maintenance(argv[1:])

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

    requested = _requested_actions(args, cfg)
    runnable = [a for a in requested if backend.supports(a)]
    for a in requested:
        if not backend.supports(a):
            out.note(f"skipping '{a}' — not supported by the {backend.name} backend")

    if not runnable:
        out.warn("nothing to do (no supported actions selected).")
        return 0

    # Elevate only when a selected action will actually change the system.
    needs_root = any(a not in READ_ONLY_ACTIONS for a in runnable)
    if needs_root and not args.dry_run and not _is_root() and not _in_test():
        _reexec_with_sudo()

    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    user_home = Path.home()
    if sudo_user:
        try:
            user_home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass

    ctx = Context(output=out, config=cfg, dry_run=args.dry_run,
                  assume_yes=args.yes, auto_rebuild=args.auto_rebuild or cfg.auto_rebuild,
                  sudo_user=sudo_user, user_home=user_home)
    actions.run(runnable, backend, ctx)
    return 0
