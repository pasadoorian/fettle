"""Remote sys-audit execution (ports supply_chain_check.sh's run_remote).

The bash scanner was one self-contained script, scp'd to the target and run over
``ssh -t``. fettle is a pure-stdlib *package*, so the equivalent single artifact
is a **zipapp**: we build a ``fettle.pyz`` from the installed package, scp it to
the host, run ``python3 fettle.pyz sys-audit <args>`` there (optionally under
sudo), and clean it up — preserving the remote exit code.

Host may be any ``~/.ssh/config`` alias (ssh resolves it); verbosity is forwarded.
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


def _build_zipapp(dest: Path) -> None:
    """Package the fettle module into a runnable ``dest`` (.pyz), stdlib-only."""
    import fettle

    pkg = Path(fettle.__file__).resolve().parent
    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / "stage"
        stage.mkdir()
        shutil.copytree(pkg, stage / "fettle",
                        ignore=shutil.ignore_patterns("__pycache__", "*.py[co]"))
        zipapp.create_archive(stage, dest, main="fettle.cli:main")


def run(host: str, forwarded: list[str], *, sudo: bool = False,
        runner=subprocess.run) -> int:
    """Upload fettle to ``host`` and run ``sys-audit <forwarded>`` there.

    ``runner`` is the subprocess entry point (injected for tests). Returns the
    remote exit code, or 1 if the upload fails.
    """
    remote_path = f"/tmp/fettle-scan.{os.getpid()}.pyz"
    print(f"Remote target: {host}  (sudo={'on' if sudo else 'off'})")
    with tempfile.TemporaryDirectory() as td:
        pyz = Path(td) / "fettle.pyz"
        _build_zipapp(pyz)
        print(f"Uploading fettle to {host}:{remote_path} ...")
        scp = runner(["scp", "-q", str(pyz), f"{host}:{remote_path}"])
        if scp.returncode != 0:
            print(f"Error: scp to {host} failed", file=sys.stderr)
            return 1

    argv = " ".join(shlex.quote(a) for a in ["sys-audit", *forwarded])
    prefix = "sudo " if sudo else ""
    # -t: allocate a TTY (interactive sudo prompt + ANSI). Clean up but keep rc.
    remote_cmd = (f"{prefix}python3 {remote_path} {argv}; "
                  f"rc=$?; rm -f {remote_path}; exit $rc")
    return runner(["ssh", "-t", host, remote_cmd]).returncode
