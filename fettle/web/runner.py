"""Run fettle actions as subprocesses and stream their output (Phase 2–3).

The web server stays UNPRIVILEGED. Read-only audits run as ``python -m fettle
<action>`` with no sudo. System-modifying actions run under ``sudo -S`` with the
user's password fed on stdin (never logged, never on the argv) so fettle starts
already-root and doesn't need its own interactive re-exec. Output (stderr merged
into stdout, in order) streams line-by-line to a callback. Pure stdlib — no nicegui.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Callable


def _cmd(args: list[str], *, sudo: bool = False) -> list[str]:
    """Build the subprocess argv. For sudo runs: pin ``--config`` to the invoking
    user's file (HOME becomes /root under sudo) and forward PYTHONPATH (sudo resets
    the env), mirroring fettle's own ``_reexec_with_sudo``."""
    fargs = list(args)
    if sudo:
        from ..cli import DEFAULT_CONFIG
        fargs += ["--config", str(DEFAULT_CONFIG)]
    base = [sys.executable, "-m", "fettle", *fargs]
    if not sudo:
        return base
    prefix = ["sudo", "-S", "-p", ""]          # -S: read password from stdin
    pythonpath = os.environ.get("PYTHONPATH")
    if pythonpath:
        prefix += ["env", f"PYTHONPATH={pythonpath}"]
    return prefix + base


async def run_action(args: list[str], on_line: Callable[[str], None], *,
                     cmd: list[str] | None = None, sudo: bool = False,
                     password: str | None = None) -> int:
    """Run ``fettle <args>``; call ``on_line(line)`` for each output line; return
    the exit code. ``sudo=True`` wraps in ``sudo -S`` and ``password`` (if given) is
    written to stdin then the pipe is closed. ``cmd`` overrides the argv (tests)."""
    argv = cmd or _cmd(args, sudo=sudo)
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if password is not None else None,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    if password is not None and proc.stdin is not None:
        proc.stdin.write((password + "\n").encode())
        try:
            await proc.stdin.drain()
        finally:
            proc.stdin.close()
    assert proc.stdout is not None
    async for raw in proc.stdout:
        on_line(raw.decode("utf-8", "replace").rstrip("\n"))
    return await proc.wait()
