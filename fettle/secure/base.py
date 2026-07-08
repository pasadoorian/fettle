"""Scan context + presentation helpers for the sys-audit security checks.

Every check is handed a :class:`Scan`, which is the single seam the tests mock:
command execution, tool presence, and file reads all go through it (files via a
``root`` prefix, so a pytest ``tmp_path`` fake ``/sys``/``/proc`` tree exercises
the checks with no root and no real hardware). Presentation routes through
``output.py`` so sys-audit shares fettle's one colour/verbosity language.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .. import command


@dataclass
class Scan:
    output: "object"           # fettle.output.Output
    root: Path = Path("/")     # injected so /sys, /proc, /dev reads are testable
    verbose: bool = False

    # -- capability probes ---------------------------------------------------
    def which(self, name: str) -> bool:
        return command.which(name)

    def is_root(self) -> bool:
        return os.geteuid() == 0

    # -- command execution (the mock point) ----------------------------------
    def run(self, cmd) -> command.Proc:
        """Run a read-only diagnostic command, capturing output (never raises)."""
        if self.verbose:
            self.output.note(f"running: {' '.join(cmd)}")
        return command.run(list(cmd), capture=True)

    def run_text(self, cmd) -> str:
        """stdout+stderr of ``cmd`` as one stripped string (tools log to either)."""
        p = self.run(cmd)
        return (p.stdout + p.stderr).strip()

    # -- filesystem reads (root-injected) ------------------------------------
    def path(self, rel: str) -> Path:
        return self.root / rel.lstrip("/")

    def exists(self, rel: str) -> bool:
        return self.path(rel).exists()

    def glob(self, pattern: str) -> list[Path]:
        """Glob ``pattern`` (an absolute-style path) under the injected root."""
        return sorted(self.root.glob(pattern.lstrip("/")))

    def read(self, rel: str) -> str | None:
        try:
            return self.path(rel).read_text(errors="replace")
        except OSError:
            return None

    # -- presentation (mirrors the bash print_* helpers via output.py) -------
    def section(self, title: str) -> None:
        self.output.section(title)

    def sub(self, title: str) -> None:
        if not self.output.quiet:
            print(f"  {self.output.CYN}── {title} ──{self.output.NC}")

    def status(self, label: str, value: str, level: str = "info") -> None:
        line = f"{label}: {value}"
        {"ok": self.output.ok, "warn": self.output.warn,
         "error": self.output.err}.get(level, self.output.note)(line)

    def result(self, text: str) -> None:
        """Raw command output, indented 4 spaces (bash ``print_result``)."""
        if self.output.quiet:
            return
        if text and text.strip():
            for ln in text.splitlines():
                print(f"    {ln}")
        else:
            print(f"    {self.output.DIM}(no output){self.output.NC}")

    def dim(self, text: str) -> None:
        """An indented dim hint line (bash ``echo -e "    ${DIM}..${NC}"``)."""
        if not self.output.quiet:
            print(f"    {self.output.DIM}{text}{self.output.NC}")
