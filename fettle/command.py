"""The single subprocess entry point — every external command goes through here.

One wrapper means tests mock exactly one function, and the sudo-drop-to-user logic
(AUR builds and pamac's per-user DB must NOT run as root) lives in one place.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class Proc:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def which(name: str) -> bool:
    """True if ``name`` is on PATH."""
    return shutil.which(name) is not None


def run(cmd: Sequence[str], *, as_user: str | None = None, capture: bool = False) -> Proc:
    """Run ``cmd``. With ``as_user`` set, drop privileges via ``sudo -u`` first.

    Never raises — a missing binary returns ``Proc(127)`` (not a traceback), and a
    non-zero exit is returned as-is. Callers decide what a failure means (this is
    an advisory maintenance tool, not a fail-fast pipeline).
    """
    argv = list(cmd)
    # Only drop privileges when we actually hold them: `sudo -u` from a non-root
    # user re-prompts for a password, which would stall an unprivileged/dry-run
    # query (e.g. `yay -Qua`). If euid != 0 we're already unprivileged — run direct.
    if as_user and os.geteuid() == 0:
        argv = ["sudo", "-u", as_user, *argv]
    try:
        completed = subprocess.run(argv, capture_output=capture, text=True)  # noqa: S603
    except FileNotFoundError:
        prog = argv[0] if argv else "(empty command)"
        return Proc(returncode=127, stderr=f"command not found: {prog}")
    except OSError as exc:
        return Proc(returncode=126, stderr=f"could not run {argv[0]}: {exc}")
    return Proc(
        returncode=completed.returncode,
        stdout=(completed.stdout or "") if capture else "",
        stderr=(completed.stderr or "") if capture else "",
    )
