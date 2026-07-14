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

# (option-strings, action-name). Pipeline actions selectable as flags or bare words.
# Dispatch-only shortcuts (-S sys-audit, -U upgrade-check, -p aur-precheck) are NOT
# here — they route to their own runners (see main()).
FLAG_ACTIONS = [
    (("-c", "--clean"), "clean"),
    (("-o", "--orphans"), "orphans"),
    (("-u", "--update", "--upgrade"), "update"),
    (("-O", "--only-update"), "only_update"),
    (("-r", "--rebuild-check"), "rebuild_check"),
    (("-y", "--python-rebuild-check"), "python_rebuild_check"),
    (("-d", "--config-drift"), "config_drift"),
    (("-f", "--firmware"), "firmware_check"),
    (("-k", "--kernel"), "kernel"),
    (("-A", "--aur-audit"), "aur_audit"),
    (("-I", "--aur-ioc-scan"), "aur_ioc_scan"),
    (("-P", "--pkg-audit"), "pkg_audit"),
]
ACTION_NAMES = {action for *_, action in FLAG_ACTIONS}

# Bare-word synonyms -> canonical action. `upgrade` mirrors the --upgrade flag
# (both alias -u/update): `fettle upgrade` == `fettle update` (install upgrades).
WORD_ALIASES = {"upgrade": "update"}

# Read-only actions never mutate the system, so they don't need root elevation.
READ_ONLY_ACTIONS = {"pkg_audit", "aur_audit", "aur_ioc_scan", "config_drift"}

# The safe set `fettle remote <host>` / `-a` runs. Destructive/interactive actions
# (orphan removal, kernel management) are NOT here — they must be named explicitly.
REMOTE_DEFAULT_ACTIONS = ("clean", "update", "firmware_check")

# Human-facing one-liners for each maintenance action (shown in --help).
ACTION_HELP = {
    "clean": "clean package-manager caches (asks first; --yes to skip the prompt)",
    "orphans": "list foreign packages; remove true orphans",
    "update": "update everything (asks before upgrading; --yes to skip)",
    "only_update": "refresh repo metadata + report upgradable (no upgrade; safe)",
    "rebuild_check": "find packages/services needing a rebuild or restart",
    "python_rebuild_check": "rebuild packages stranded on an old Python",
    "config_drift": "list pending config-file merges (.pacnew / .dpkg-dist)",
    "firmware_check": "check for firmware updates (fwupd)",
    "kernel": "manage installed kernels (running one protected)",
    "aur_audit": "AUR health census: age/votes/out-of-date/orphan -> ~/aur-audit.txt",
    "aur_ioc_scan": "scan installed AUR pkgs vs known-compromise feeds -> ~/aur-ioc-scan.txt",
    "pkg_audit": "cross-ecosystem supply-chain audit (AUR/APT/Flatpak/Snap) -> ~/pkg-audit.txt",
}

_EPILOG = """\
shortcut flags & their fuller subcommand forms (use the subcommand for options):
  -S  ==  fettle sys-audit [CATS] [--all|--list]   firmware/boot/hardware security
                                                   scan (-S runs --all; self-elevates)
  -U  ==  fettle upgrade-check [--effort ...]      [experimental] AI pre-upgrade
                                                   safety check; needs ANTHROPIC_API_KEY
  -p  ==  fettle aur-precheck [PKG ...]            AUR pre-flight; bare = scan every
                                                   installed AUR pkg (also the yay hook) [arch]
  fettle remote HOST [actions]                     run maintenance on a remote host
                                                   over ssh (safe set by default; 'remote -h')

which package audit? (all read-only; the three -A/-I/-p are AUR-only [arch])
  -P  pkg-audit     ALL ecosystems (AUR/APT/Flatpak/Snap): provenance + tampering
  -A  aur-audit     AUR health census: age, votes, out-of-date, orphan
  -I  aur-ioc-scan  match installed AUR pkgs to known-compromise (IoC) feeds
  -p  aur-precheck  per-package pre-install check (RPC + IoC); bare = all installed

Actions/commands tagged [arch]/[debian] are specific to that distro; untagged
ones work everywhere. fettle runs only what your distro's backend supports and
skips the rest with a note.

examples:
  fettle                       run the default maintenance set
  fettle clean update          actions as words (== `fettle -c -u`)
  fettle upgrade               upgrade packages (synonym of `update` / -u)
  fettle -a --dry-run          preview the whole default set; change nothing
  fettle -O                    refresh metadata + show what's upgradable (no upgrade)
  fettle -S                    full security scan (sys-audit --all; self-elevates)
  fettle -U                    AI pre-upgrade safety check
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
        "each runs as a flag OR a bare word, and they combine: `fettle -c -u` == "
        "`fettle clean update`. (`upgrade` is a synonym for `update`.)")
    for opts, action in FLAG_ACTIONS:
        maint.add_argument(*opts, dest=f"do_{action}", action="store_true",
                           help=f"{ACTION_HELP.get(action, action)}{tags[action]}")
    p.add_argument("-a", "--all", action="store_true", help="run the default action set")
    p.add_argument("-R", "--auto-rebuild", action="store_true",
                   help="offer to rebuild (with -r / -y) instead of only listing")
    p.add_argument("--yes", action="store_true",
                   help="assume yes to all prompts incl. the upgrade confirmation (non-interactive)")
    p.add_argument("actions", nargs="*", help="action names (same as the flags above)")
    p.add_argument("--distro", metavar="NAME", help="override distro detection")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="show what would run; change nothing")
    p.add_argument("--no-sync", action="store_true",
                   help="dry-run preview: use cached repo data instead of a fresh sync")
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
        name = WORD_ALIASES.get(name, name)
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
    print(f"  {'ai_model':18} {cfg.ai_model}")
    # The API key is never printed in full — only its source and a last-4 hint.
    from .ai.client import redact_key
    env_key = os.environ.get("ANTHROPIC_API_KEY")
    if env_key:
        print(f"  {'ai_api_key':18} {redact_key(env_key)} (from $ANTHROPIC_API_KEY)")
    elif cfg.ai_api_key:
        print(f"  {'ai_api_key':18} {redact_key(cfg.ai_api_key)} (from config)")
    else:
        print(f"  {'ai_api_key':18} (unset — set $ANTHROPIC_API_KEY or config ai_api_key)")


def _is_root() -> bool:
    return os.geteuid() == 0


def _in_test() -> bool:
    return os.environ.get("FETTLE_TEST") == "1"


def _reexec_argv(args: argparse.Namespace | None, pythonpath: str) -> list[str]:
    """The `sudo env … -m fettle …` argv to re-exec, carrying config + PYTHONPATH.

    ``args`` is the maintenance namespace (None for sys-audit, which reads no TOML
    config). sudo's env_reset also sets HOME=/root, so without pinning, the
    elevated process would re-resolve DEFAULT_CONFIG to /root's config (usually
    absent) and silently fall back to built-in defaults — dropping the user's
    keep_orphans / exclude_foreign / [updaters]. So pin the resolved path.
    (--no-config is honoured: it's already in sys.argv and we add nothing.)
    """
    extra = [] if (args is None or args.no_config) else ["--config", str(args.config)]
    return ["sudo", "env", f"PYTHONPATH={pythonpath}",
            sys.executable, "-m", "fettle", *sys.argv[1:], *extra]


def _reexec_with_sudo(args: argparse.Namespace | None = None) -> None:  # pragma: no cover - exec replaces the process
    # sudo's env_reset drops PYTHONPATH, so root's `python -m fettle` would fail to
    # find the package when fettle runs from a checkout (via bin/fettle) rather than
    # an installed location. Carry the package's parent dir across with `env` so the
    # real package resolves — a regular package wins over any namespace-dir shadow.
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    existing = os.environ.get("PYTHONPATH")
    pythonpath = pkg_parent + (os.pathsep + existing if existing else "")
    os.execvp("sudo", _reexec_argv(args, pythonpath))


_REMOTE_EPILOG = """\
fettle remote [--ssh-arg ARG]... HOST [any fettle action/flags...]

Runs fettle on a remote host over SSH: fettle is packaged as a zipapp, scp'd to
the host, run there (under sudo for changes) over `ssh -t`, and removed. The host
needs a python3 interpreter — nothing is installed, and the host must run the same
fettle version to understand the forwarded flags.

Everything after HOST is forwarded verbatim to fettle on the remote, so ANY action
works remotely. With NO action named, the SAFE set runs: clean, update,
firmware-check (never orphan/kernel removal unless you name it).

--dry-run (change nothing; no sudo) and --yes (unattended: auto-confirm +
non-interactive) are forwarded and interpreted on the remote. NOTE: --yes also
SKIPS AUR PKGBUILD review. `-U`/upgrade-check needs ANTHROPIC_API_KEY on the host.

examples:
  fettle remote server1                     safe set (clean + update + firmware)
  fettle remote server1 -c -u               clean, then upgrade packages
  fettle remote server1 update --dry-run    preview an update; change nothing
  fettle remote server1 -a --yes            the full default set, unattended
  fettle remote server1 -S                  security scan on the host
  fettle remote --ssh-arg=-oConnectTimeout=5 server1 -u
"""

# Tokens that count as "an action was named" (so we DON'T inject the safe set):
# any action flag, any dispatch shortcut, or -a/--all. Bare words also count.
def _remote_has_action(forwarded: list[str]) -> bool:
    intent = ({opt for opts, _ in FLAG_ACTIONS for opt in opts}
              | set(DISPATCH_SHORTCUTS) | {"-a", "--all"})
    return any(tok in intent or not tok.startswith("-") for tok in forwarded)


def _run_remote_maintenance(argv: list[str]) -> int:
    from . import remote

    # Grammar: [--ssh-arg X]... HOST <rest forwarded>. ssh options precede HOST;
    # the first bare token is HOST; everything after it forwards verbatim.
    ssh_args: list[str] = []
    host: str | None = None
    forwarded: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if host is None:
            if tok in ("-h", "--help"):
                print(_REMOTE_EPILOG)
                return 0
            if tok == "--ssh-arg":
                if i + 1 >= len(argv):
                    print("fettle remote: --ssh-arg needs a value", file=sys.stderr)
                    return 2
                ssh_args.append(argv[i + 1])
                i += 2
                continue
            if tok.startswith("--ssh-arg="):
                ssh_args.append(tok.split("=", 1)[1])
            elif tok.startswith("-"):
                print(f"fettle remote: ssh options go before HOST and actions after "
                      f"it; got '{tok}' before HOST", file=sys.stderr)
                return 2
            else:
                host = tok
            i += 1
            continue
        forwarded.append(tok)
        i += 1

    if host is None:
        print("fettle remote: missing HOST. Try 'fettle remote -h'.", file=sys.stderr)
        return 2

    # upgrade-check is special: collect a snapshot on the remote, analyse it here
    # with the local key (the key never leaves this machine). Route it out of the
    # generic forward-and-run path.
    uc_tokens = {"-U", "--upgrade-check", "upgrade-check"}
    if any(t in uc_tokens for t in forwarded):
        return _remote_upgrade_check(host, ssh_args, [t for t in forwarded
                                                      if t not in uc_tokens])

    # No action named -> run the SAFE set (never destructive unless asked for).
    if not _remote_has_action(forwarded):
        forwarded = [a.replace("_", "-") for a in REMOTE_DEFAULT_ACTIONS] + forwarded

    # dry-run needs neither sudo nor a PTY; --yes is fully unattended (no PTY).
    dry_run = "--dry-run" in forwarded
    unattended = "--yes" in forwarded
    return remote.run(host, forwarded, sudo=not dry_run,
                      ssh_args=ssh_args, tty=not unattended)


def _run_upgrade_check(argv: list[str]) -> int:
    from .ai import snapshot as ai_snapshot
    from .ai import upgrade_check as uc
    from .ai.client import resolve_auth
    from .backends.base import Context

    p = argparse.ArgumentParser(
        prog="fettle upgrade-check",
        description="[EXPERIMENTAL] AI-assisted pre-upgrade safety check (Claude). "
                    "Read-only. Under active testing — treat its advice as a second "
                    "opinion, not gospel.",
        epilog="Uses ANTHROPIC_API_KEY (or config ai_api_key). Hardware serials are "
               "redacted before sending. Report only — you run `fettle -u` yourself.")
    p.add_argument("--no-web", action="store_true", help="disable distro-forum web search")
    p.add_argument("--model", metavar="ID", help="override the model (default claude-sonnet-5)")
    p.add_argument("--effort", choices=["low", "medium", "high"], help="thinking depth vs cost")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="explain why the AI step failed (HTTP status, errors)")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--config", metavar="PATH", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--no-config", action="store_true", help="ignore the config file")
    # Internal transport flag: emit the (redacted) snapshot as JSON and exit — no
    # API call, no UI. `fettle remote HOST upgrade-check` runs this on the remote,
    # then analyses locally with the local key.
    p.add_argument("--collect", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args(argv)

    out = Output(color=(False if args.no_color else None), quiet=args.quiet)
    cfg, warnings = (Config(), []) if args.no_config else load_config(args.config)
    for w in warnings:
        out.warn(w)
    if args.model:
        cfg.ai_model = args.model
    if args.effort:
        cfg.ai_effort = args.effort
    if args.verbose:
        from .ai.client import set_debug
        set_debug(True)

    try:
        backend = detect()
    except UnknownDistro as exc:
        out.err(str(exc))
        return 1
    ctx = Context(output=out, config=cfg, user_home=Path.home())

    if args.collect:
        # Gather + emit JSON ONLY (stdout stays clean for the caller to parse);
        # rootless, no Anthropic call. Warnings/errors above went to stderr.
        print(ai_snapshot.gather(ctx, backend).to_json())
        return 0

    out.section("Upgrade check")
    out.warn("experimental feature — still under testing; verify its advice before "
             "acting on it.")
    pending = backend.pending_upgrades(ctx)
    if not pending:
        out.ok("system is up to date — nothing to upgrade.")
        return 0

    out.note(f"{len(pending)} package(s) pending; gathering system details (inxi)...")
    snap = ai_snapshot.gather(ctx, backend)

    if resolve_auth(cfg) is None:
        out.warn("no API key set (ANTHROPIC_API_KEY or config ai_api_key) — "
                 "showing the package list only:")
        _print_pending(pending)
        return 0

    out.note(f"asking {cfg.ai_model} (may take a minute; searching distro forums)...")
    result = uc.analyze(snap, config=cfg, allow_web=not args.no_web)
    if result is None:
        out.warn("AI analysis unavailable (offline / declined / error) — package list:")
        if not args.verbose:
            out.note("re-run with --verbose to see why the AI step failed.")
        _print_pending(pending)
        return 0

    _render_upgrade_check(out, result, user_home=ctx.user_home, sudo_user=ctx.sudo_user)
    return 0


def _print_pending(pending) -> None:
    for name, old, new in pending:
        print(f"    {name}  {old} -> {new}")


def _render_upgrade_check(out: Output, result, *, user_home: Path,
                          sudo_user: str | None = None, host: str | None = None) -> None:
    import re

    from .ai.upgrade_check import format_report
    from .util import chown_to_user

    verdict = {"safe": out.ok, "caution": out.warn, "risky": out.alert}.get(
        result.safety_verdict, out.note)
    verdict(f"Verdict{' for ' + host if host else ''}: {result.safety_verdict.upper()}"
            f"  (failure likelihood: {result.failure_likelihood})")
    report = format_report(result)
    for line in report.splitlines()[1:]:  # verdict already printed (coloured)
        print(line)
    u = result.usage or {}
    out.note(f"[usage: {u.get('input_tokens', 0)} in / {u.get('output_tokens', 0)} out "
             f"tokens, {u.get('web_searches', 0)} web search(es)]")

    if host:  # per-host filename so multiple hosts don't clobber each other
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
        path = user_home / f"upgrade-check-{safe}.txt"
        report = f"Upgrade check — remote host: {host}\n\n{report}"
    else:
        path = user_home / "upgrade-check.txt"
    try:
        path.write_text(report + "\n")
        chown_to_user(path, sudo_user)
        out.note(f"saved to {path}")
    except OSError as exc:
        out.warn(f"could not write {path}: {exc}")


def _remote_upgrade_check(host: str, ssh_args: list[str], uc_flags: list[str]) -> int:
    """Collect a snapshot from ``host`` (rootless, no key), then analyse it LOCALLY
    with the local key — so the key never leaves this machine and only this machine
    needs Anthropic access. Analyse-side flags (--effort/--no-web/--model) apply here.
    """
    from . import remote
    from .ai import upgrade_check as uc
    from .ai.client import resolve_auth, set_debug
    from .ai.snapshot import Snapshot

    p = argparse.ArgumentParser(prog=f"fettle remote {host} upgrade-check", add_help=False)
    p.add_argument("--no-web", action="store_true")
    p.add_argument("--model", metavar="ID")
    p.add_argument("--effort", choices=["low", "medium", "high"])
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--config", metavar="PATH", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("--no-config", action="store_true")
    args, _unknown = p.parse_known_args(uc_flags)

    out = Output(color=(False if args.no_color else None), quiet=args.quiet)
    cfg, warnings = (Config(), []) if args.no_config else load_config(args.config)
    for w in warnings:
        out.warn(w)
    if args.model:
        cfg.ai_model = args.model
    if args.effort:
        cfg.ai_effort = args.effort
    if args.verbose:
        set_debug(True)

    out.section(f"Upgrade check (remote: {host})")
    out.warn("experimental feature — verify its advice before acting on it.")
    out.note(f"collecting a system snapshot from {host} (read-only, no sudo)...")
    payload = remote.collect(host, ["upgrade-check", "--collect"], ssh_args=ssh_args)
    if payload is None:
        out.err(f"could not collect a snapshot from {host}.")
        return 1
    try:
        snap = Snapshot.from_json(payload)
    except (ValueError, KeyError, TypeError):
        out.err(f"{host} returned an unreadable snapshot (fettle version mismatch?).")
        return 1

    if not snap.pending:
        out.ok(f"{host} is up to date — nothing to upgrade.")
        return 0
    if resolve_auth(cfg) is None:
        out.warn("no local API key (ANTHROPIC_API_KEY or config ai_api_key) — "
                 f"showing {host}'s pending packages only:")
        _print_pending(snap.pending)
        return 0

    if not snap.inxi:  # inxi absent on the remote — analysis still runs, less context
        out.note(f"(inxi wasn't available on {host}; analysis has less hardware context)")
    out.note(f"{len(snap.pending)} package(s) pending on {host}; asking "
             f"{cfg.ai_model} locally (your key stays here)...")
    result = uc.analyze(snap, config=cfg, allow_web=not args.no_web)
    if result is None:
        out.warn("AI analysis unavailable (offline / declined / error) — package list:")
        if not args.verbose:
            out.note("re-run with -v to see why the AI step failed.")
        _print_pending(snap.pending)
        return 0

    _render_upgrade_check(out, result, user_home=Path.home(), host=host)
    return 0


# Single-flag aliases -> subcommand runner. Handled before the pipeline parser.
DISPATCH_SHORTCUTS = {
    "-S": "sys-audit", "--sys-audit": "sys-audit",
    "-U": "upgrade-check", "--upgrade-check": "upgrade-check",
    "-p": "aur-precheck", "--aur-precheck": "aur-precheck",
}


def _find_dispatch_shortcut(argv: list[str]) -> tuple[str, list[str]] | None:
    """If argv contains a dispatch shortcut, return (target, remaining_args);
    else None. Raises SystemExit on two different shortcuts at once."""
    hits = [i for i, tok in enumerate(argv) if tok in DISPATCH_SHORTCUTS]
    if not hits:
        return None
    targets = {DISPATCH_SHORTCUTS[argv[i]] for i in hits}
    if len(targets) > 1:
        raise SystemExit("fettle: choose only one of -S/-U/-p")
    i = hits[0]
    return DISPATCH_SHORTCUTS[argv[i]], argv[:i] + argv[i + 1:]


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

    # `fettle upgrade-check` — AI-assisted pre-upgrade safety advisor (read-only).
    if argv and argv[0] == "upgrade-check":
        return _run_upgrade_check(argv[1:])

    # Dispatch shortcuts: -S / -U / -p are single-flag aliases for the sys-audit,
    # upgrade-check, and aur-precheck runners (Q4: flag = shortcut, subcommand =
    # full control). Detected anywhere in argv; the remaining args forward to the
    # runner, so `fettle -S --list` and `fettle -U --effort high` still work.
    # Two shortcuts at once is an explicit error.
    shortcut = _find_dispatch_shortcut(argv)
    if shortcut is not None:
        target, rest = shortcut
        # A shortcut is a standalone command — mixing it with a pipeline action
        # flag (e.g. `fettle -A -S`) forwards a fettle flag the sub-runner can't
        # parse. Catch it here with a clear message instead of a cryptic subparser
        # error. (Sub-options like --list / --effort and sys-audit categories are
        # not action flags, so they still pass through.)
        pipeline_flags = {opt for opts, _ in FLAG_ACTIONS for opt in opts}
        clash = [t for t in rest if t in pipeline_flags]
        if clash:
            letter = {"sys-audit": "-S", "upgrade-check": "-U",
                      "aur-precheck": "-p"}[target]
            print(f"fettle: {letter} ({target}) can't be combined with other action "
                  f"flags ({' '.join(clash)}) — run them separately.", file=sys.stderr)
            return 2
        if target == "sys-audit":
            from .secure import audit
            return audit.main(["--all", *rest])  # bare -S == sys-audit --all
        if target == "upgrade-check":
            return _run_upgrade_check(rest)
        from .aur import precheck
        return precheck.main(rest)

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
        _reexec_with_sudo(args)

    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    user_home = Path.home()
    if sudo_user:
        try:
            user_home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass

    ctx = Context(output=out, config=cfg, dry_run=args.dry_run,
                  assume_yes=args.yes, auto_rebuild=args.auto_rebuild or cfg.auto_rebuild,
                  sync=not args.no_sync,
                  sudo_user=sudo_user, user_home=user_home)
    actions.run(runnable, backend, ctx)
    return 0
