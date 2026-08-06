"""Small shared helpers (no fettle imports — safe to use anywhere)."""

from __future__ import annotations

import fnmatch
import shutil
from pathlib import Path


def invoking_user_home() -> Path:
    """The home of the user who *invoked* fettle, not of whoever it is running as.

    Under sudo, ``HOME`` is ``/root`` and ``Path.home()`` follows it — so anything
    resolved from it reads a path that does not exist and silently falls back to
    built-in defaults. That was already this project's highest-impact bug once (the
    sudo re-exec had to be taught to carry ``--config``), and it came back the moment
    a *second* elevating entry point learned to read config: ``fettle -S`` elevates
    itself, so it looked for ``/root/.config/fettle/config.toml`` and reported chipsec
    as unconfigured on a machine where it was configured.

    Four places did this lookup by hand. This is the one that gets fixed.
    """
    import os
    import pwd

    name = os.environ.get("SUDO_USER")
    if name:
        try:
            return Path(pwd.getpwnam(name).pw_dir)
        except KeyError:                       # the user went away mid-session
            pass
    return Path.home()


def invoking_user() -> str | None:
    """The name of the user who invoked fettle, or None if not running under sudo.

    The companion to :func:`invoking_user_home`, for the cases that need to hand
    privileges *back* — running a helper tool unprivileged, or chowning a file we
    created as root.
    """
    import os

    return os.environ.get("SUDO_USER") or None


# How to install a package, per package manager. Detected from what is on PATH rather
# than from the backend, so any code path can produce a working instruction without
# having to be handed a distro.
_INSTALLERS = (
    ("pacman", "sudo pacman -S {pkg}"),
    ("apt-get", "sudo apt install {pkg}"),
    ("dnf", "sudo dnf install {pkg}"),
    ("zypper", "sudo zypper install {pkg}"),
    ("apk", "sudo apk add {pkg}"),
)


def install_hint(package: str) -> str:
    """``sudo pacman -S smartmontools`` — the command that would install *package* here.

    Empty when no known package manager is on PATH, because a confidently wrong install
    command is worse than none: it sends someone to a shell prompt to be told the tool
    does not exist, and they conclude fettle is broken rather than that the hint was.
    """
    from . import command

    if not package:
        return ""
    for tool, template in _INSTALLERS:
        if command.which(tool):
            return template.format(pkg=package)
    return ""


def matches_any(name: str, patterns) -> bool:
    """True if ``name`` equals or glob-matches any pattern (case-sensitive)."""
    return any(fnmatch.fnmatchcase(name, p) for p in patterns if p)


def chown_to_user(path: Path, user: str | None) -> None:
    """Best-effort chown a file back to the invoking user; ignore failure."""
    if not user:
        return
    try:
        shutil.chown(path, user=user, group=user)
    except (LookupError, PermissionError, OSError):
        pass
