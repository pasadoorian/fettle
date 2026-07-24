"""Configuration: built-in defaults < TOML config file < CLI overrides.

The TOML file is read even when fettle runs as root, so we refuse to read one
that is world-writable or owned by someone other than root or the invoking user
(a privilege-escalation guard ported from ``update.sh``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path

# tomllib is stdlib only on Python 3.11+. fettle is otherwise pure-stdlib, so on
# an older interpreter — notably the remote scanner landing on Ubuntu 22.04
# (Python 3.10) — we fall back to the `tomli` backport if present, else run with
# built-in defaults (no config parsing). Everything except the TOML config file
# works regardless.
try:
    import tomllib
except ModuleNotFoundError:  # < 3.11
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

DEFAULT_ACTIONS = ["clean", "orphans", "update", "rebuild_check",
                   "python_rebuild_check", "config_drift", "auto_updates",
                   "firmware_check",
                   "pkg_audit", "aur_ioc_scan"]  # security audits last (read-only)


@dataclass
class Config:
    default_actions: list[str] = field(default_factory=lambda: list(DEFAULT_ACTIONS))
    auto_rebuild: bool = False
    exclude_foreign: list[str] = field(default_factory=list)
    keep_orphans: list[str] = field(default_factory=list)
    # Per-distro tool selection, e.g. {"arch": {"aur_updater": "yay"}}. Kept as a
    # passthrough for now; the exact per-distro schema is finalized with each backend.
    updaters: dict[str, dict] = field(default_factory=dict)
    # AUR supply-chain settings.
    aur_max_age_days: int = 365  # stale threshold (pkg-audit)
    aur_recent_days: int = 21    # RECENTLY-CHANGED threshold in the -A audit table
    aur_ioc_campaigns: list[str] = field(
        default_factory=lambda: ["aur-infected", "chaos-rat", "russian-spam"]
    )
    aur_ioc_cache_ttl: int = 21600
    # Binary hardening audit (fettle hardening-audit). Exclude lists to prune the
    # report — all ship EMPTY, so the first run shows everything and the user
    # narrows to taste. Keys: exclude_checks (criterion names, e.g. "runpath"),
    # exclude_packages (name globs), exclude_paths (path globs). The always-on
    # accuracy corrections are NOT tunable here (they fix wrong data, not taste).
    hardening: dict = field(default_factory=dict)
    # Report/log storage (fettle/reports.py). Keys: keep (how many of each report
    # type per host to retain, default 5), dir (base dir override, default
    # ~/.fettle), log (bool, run-log on/off), json (bool, write a .json sibling for
    # each report/log — default on; the `fettle report` HTML dashboard reads them).
    # Reports live under <dir>/reports/<host>/, run-logs under <dir>/logs/<host>/.
    reports: dict = field(default_factory=dict)
    # Remote host groups (fettle/remote.py). `[remote.groups.<name>]` tables map a
    # group name to hosts (+ optional per-group ssh_args / actions / yes), so
    # `fettle remote <group>` runs on each host in order. A bare list is shorthand
    # for {hosts = [...]}.
    remote: dict = field(default_factory=dict)
    # Security-advisory / CVE tracking (fettle advisory-check). Keys: cache_ttl
    # (seconds before the SQLite cache is refreshed on a run, default 21600),
    # severity_threshold ("" = all, else Critical/High/Medium/Low), exclude_packages
    # (name globs), exclude_classes (distro status/class tags to hide, e.g. Debian
    # "unimportant"/"no-dsa"), warn_gate (bool, default true — extra confirm before
    # `-u`/`-a` when Critical CVEs are unpatched). All ship EMPTY/quiet.
    advisories: dict = field(default_factory=dict)
    # Pre-check AUR packages against the IoC feeds BEFORE `yay -Sua` builds them,
    # and prompt to abort on a finding. On by default; `--no-aur-precheck` skips it.
    aur_precheck_on_update: bool = True
    # Upgrade Checker (fettle upgrade-check). ai_api_key is optional — prefer the
    # ANTHROPIC_API_KEY env var; never printed in full (see --print-config).
    ai_model: str = "claude-sonnet-5"
    ai_effort: str = "medium"
    ai_max_web_searches: int = 5
    ai_api_key: str = ""


def _allowed_uids() -> set[int]:
    uids = {0, os.getuid()}
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        uids.add(int(sudo_uid))
    return uids


# Action names retired in v0.4.0 -> the new name to point users at (config help).
_RETIRED_ACTIONS = {
    "rebuilds": "rebuild-check",
    "python_rebuild": "python-rebuild-check",
    "firmware": "firmware-check",
    "kernels": "kernel",
    "source_audit": "removed (use pkg-audit)",
    "integrity": "removed (now part of sys-audit)",
}


def _normalize_default_actions(actions) -> tuple[list[str], list[str]]:
    """Accept hyphen or underscore action names; drop + explain retired ones."""
    out: list[str] = []
    warnings: list[str] = []
    for a in actions:
        key = str(a).replace("-", "_")
        if key in _RETIRED_ACTIONS:
            warnings.append(f"config default_actions: '{a}' -> "
                            f"{_RETIRED_ACTIONS[key]}; ignoring the old name")
            continue
        out.append(key)
    return out, warnings


def _is_safe(path: Path, allowed: set[int]) -> tuple[bool, str]:
    st = path.stat()
    if st.st_uid not in allowed:
        return False, f"{path} is owned by uid {st.st_uid} (not root or you); refusing to read it."
    if st.st_mode & 0o002:
        return False, f"{path} is world-writable; refusing to read it. Fix: chmod o-w '{path}'"
    return True, ""


def load(path: Path, *, allowed_uids: set[int] | None = None) -> tuple[Config, list[str]]:
    """Return ``(config, warnings)``.

    A missing file yields defaults with no warning; an unsafe or malformed file
    yields defaults plus an explanatory warning (fettle never hard-fails on config).
    """
    warnings: list[str] = []
    cfg = Config()
    if not path.is_file():
        return cfg, warnings

    safe, why = _is_safe(path, allowed_uids or _allowed_uids())
    if not safe:
        warnings.append(why)
        return cfg, warnings

    if tomllib is None:  # Python < 3.11 without the tomli backport
        warnings.append(f"{path}: TOML config needs Python 3.11+ (or the 'tomli' "
                        "package); using built-in defaults.")
        return cfg, warnings

    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        warnings.append(f"{path}: invalid TOML ({exc}); using defaults.")
        return Config(), warnings

    known = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key in known:
            setattr(cfg, key, value)
        else:
            warnings.append(f"config: ignoring unknown key '{key}'")

    # Accept hyphenated action names and steer old ones to their new spelling.
    cfg.default_actions, da_warnings = _normalize_default_actions(cfg.default_actions)
    warnings.extend(da_warnings)
    return cfg, warnings
