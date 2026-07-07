"""The single subprocess entry point — every external command goes through here.

One wrapper means tests mock exactly one function, and the sudo-drop-to-user logic
(AUR builds and pamac's per-user DB must NOT run as root) lives in one place.
"""

from __future__ import annotations

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

    Never raises on a non-zero exit — callers decide what a failure means (this is
    an advisory maintenance tool, not a fail-fast pipeline).
    """
    argv = list(cmd)
    if as_user:
        argv = ["sudo", "-u", as_user, *argv]
    completed = subprocess.run(argv, capture_output=capture, text=True)  # noqa: S603
    return Proc(
        returncode=completed.returncode,
        stdout=(completed.stdout or "") if capture else "",
        stderr=(completed.stderr or "") if capture else "",
    )
