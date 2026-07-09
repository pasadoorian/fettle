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
                   "python_rebuild_check", "config_drift", "firmware_check"]


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
    return cfg, warnings
