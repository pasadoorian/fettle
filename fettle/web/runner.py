"""Run fettle actions as subprocesses and stream their output (Phase 2).

The web server stays UNPRIVILEGED: read-only audits run as ``python -m fettle
<action>`` with no sudo. Output (stderr merged into stdout, in order) is streamed
line-by-line to a callback so the UI can show it live. Pure stdlib — no nicegui —
so it's testable on its own.
"""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable


def _cmd(args: list[str]) -> list[str]:
    # the same interpreter/env as the server, so fettle resolves the same way
    return [sys.executable, "-m", "fettle", *args]


async def run_action(args: list[str], on_line: Callable[[str], None], *,
                     cmd: list[str] | None = None) -> int:
    """Run ``fettle <args>``; call ``on_line(line)`` for each output line; return
    the exit code. Pass ``cmd`` to override the full command (used by tests)."""
    argv = cmd or _cmd(args)
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    assert proc.stdout is not None
    async for raw in proc.stdout:
        on_line(raw.decode("utf-8", "replace").rstrip("\n"))
    return await proc.wait()
