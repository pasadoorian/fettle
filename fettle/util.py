"""Small shared helpers (no fettle imports — safe to use anywhere)."""

from __future__ import annotations

import fnmatch
import shutil
from pathlib import Path


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
