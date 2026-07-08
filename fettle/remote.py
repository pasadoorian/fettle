"""Remote execution over SSH — ship fettle as a zipapp, run it on a host, clean up.

Shared by ``sys-audit remote`` (the scanner) and ``fettle remote`` (maintenance).
Builds a single-file zipapp of fettle (pure stdlib → runs under any ``python3``),
scp's it to the host, runs ``[sudo] python3 fettle.pyz <args>`` over ``ssh -t``,
and removes it — preserving the remote exit code. The host may be any
``~/.ssh/config`` alias; extra ssh arguments are passed through.

A standalone binary (no ``python3`` on the host) is a deferred option — see the
Phase-3 plan; the zipapp is the current transport.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path


def build_zipapp(dest: Path) -> None:
    """Package the fettle module into a runnable ``dest`` (.pyz), stdlib-only."""
    import fettle

    pkg = Path(fettle.__file__).resolve().parent
    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / "stage"
        stage.mkdir()
        shutil.copytree(pkg, stage / "fettle",
                        ignore=shutil.ignore_patterns("__pycache__", "*.py[co]"))
        zipapp.create_archive(stage, dest, main="fettle.cli:main")


def run(host: str, fettle_args, *, sudo: bool = False, ssh_args=(),
        runner=subprocess.run) -> int:
    """Run ``fettle <fettle_args>`` on ``host`` via a shipped zipapp.

    ``fettle_args`` is the full argument list to hand the remote fettle, e.g.
    ``["sys-audit", "--all"]`` or ``["clean", "update", "--yes"]``. ``runner`` is
    the subprocess entry point (injected for tests). Returns the remote exit code
    (or 1 if the upload fails).
    """
    remote_path = f"/tmp/fettle-remote.{os.getpid()}.pyz"
    print(f"Remote target: {host}  (sudo={'on' if sudo else 'off'})")
    with tempfile.TemporaryDirectory() as td:
        pyz = Path(td) / "fettle.pyz"
        build_zipapp(pyz)
        print(f"Uploading fettle to {host}:{remote_path} ...")
        scp = runner(["scp", "-q", str(pyz), f"{host}:{remote_path}"])
        if scp.returncode != 0:
            print(f"Error: scp to {host} failed", file=sys.stderr)
            return 1

    argv = " ".join(shlex.quote(a) for a in fettle_args)
    prefix = "sudo " if sudo else ""
    # -t: allocate a TTY (interactive sudo prompt + ANSI). Clean up, keep the rc.
    remote_cmd = (f"{prefix}python3 {remote_path} {argv}; "
                  f"rc=$?; rm -f {remote_path}; exit $rc")
    return runner(["ssh", "-t", *ssh_args, host, remote_cmd]).returncode
