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

import secrets
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


def _upload_zipapp(host: str, runner) -> str | None:
    """Build the fettle zipapp and scp it to the remote user's ``$HOME`` under a
    random, unpredictable name (not world-writable ``/tmp``, so another local user
    can't pre-place or swap the file we then run under sudo). Returns the remote
    filename relative to ``$HOME``, or ``None`` on upload failure."""
    remote_name = f".fettle-remote.{secrets.token_hex(16)}.pyz"
    with tempfile.TemporaryDirectory() as td:
        pyz = Path(td) / "fettle.pyz"
        build_zipapp(pyz)
        print(f"Uploading fettle to {host}:~/{remote_name} ...")
        scp = runner(["scp", "-q", str(pyz), f"{host}:{remote_name}"])
    if scp.returncode != 0:
        print(f"Error: scp to {host} failed", file=sys.stderr)
        return None
    return remote_name


def _remote_cmd(remote_name: str, fettle_args, *, sudo: bool) -> str:
    """One-line remote shell: chmod 600, run fettle, capture rc, clean up. The
    relative upload resolves to ``$HOME``, expanded in the ssh user's shell before
    sudo runs."""
    remote_file = f'"$HOME/{remote_name}"'
    argv = " ".join(shlex.quote(a) for a in fettle_args)
    prefix = "sudo " if sudo else ""
    return (f"chmod 600 {remote_file} 2>/dev/null; "
            f"{prefix}python3 {remote_file} {argv}; "
            f"rc=$?; rm -f {remote_file}; exit $rc")


def run(host: str, fettle_args, *, sudo: bool = False, ssh_args=(),
        tty: bool = True, runner=subprocess.run) -> int:
    """Run ``fettle <fettle_args>`` on ``host`` via a shipped zipapp.

    ``fettle_args`` is the full argument list to hand the remote fettle, e.g.
    ``["sys-audit", "--all"]`` or ``["clean", "update", "--yes"]``. ``tty`` forces
    an ``ssh -t`` PTY (needed for interactive sudo/prompts); drop it for a fully
    unattended run. ``runner`` is the subprocess entry point (injected for tests).
    Returns the remote exit code (or 1 if the upload fails).
    """
    print(f"Remote target: {host}  (sudo={'on' if sudo else 'off'})")
    remote_name = _upload_zipapp(host, runner)
    if remote_name is None:
        return 1
    # -t allocates a PTY for interactive sudo/prompts + ANSI; skip it for
    # unattended runs (a non-TTY stdin would otherwise warn).
    ssh_cmd = ["ssh", *(["-t"] if tty else []), *ssh_args, host,
               _remote_cmd(remote_name, fettle_args, sudo=sudo)]
    return runner(ssh_cmd).returncode


def collect(host: str, fettle_args, *, ssh_args=(), runner=subprocess.run) -> str | None:
    """Run ``fettle_args`` on ``host`` and return its captured stdout, or ``None``
    on failure. Rootless, no PTY — for ``upgrade-check --collect``, where the
    remote prints a snapshot we analyse locally. Remote stderr passes through."""
    print(f"Remote target: {host}  (collect; no sudo)")
    remote_name = _upload_zipapp(host, runner)
    if remote_name is None:
        return None
    ssh_cmd = ["ssh", *ssh_args, host, _remote_cmd(remote_name, fettle_args, sudo=False)]
    proc = runner(ssh_cmd, capture_output=True, text=True)
    if getattr(proc, "stderr", None):
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        print(f"Error: remote collect on {host} failed (exit {proc.returncode})",
              file=sys.stderr)
        return None
    return proc.stdout
