"""Scan context + presentation helpers for the sys-audit security checks.

Every check is handed a :class:`Scan`, which is the single seam the tests mock:
command execution, tool presence, and file reads all go through it (files via a
``root`` prefix, so a pytest ``tmp_path`` fake ``/sys``/``/proc`` tree exercises
the checks with no root and no real hardware). Presentation routes through
``output.py`` so sys-audit shares fettle's one colour/verbosity language.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .. import command


@dataclass
class Scan:
    output: "object"           # fettle.output.Output
    root: Path = Path("/")     # injected so /sys, /proc, /dev reads are testable
    verbose: bool = False
    # accumulated for the persisted report (in addition to live terminal output)
    records: list = field(default_factory=list)   # [{category, sub, label, value, level}]
    lines: list = field(default_factory=list)      # plain-text report body
    _sections: list = field(default_factory=list)  # every category, in scan order
    _cat: str = ""
    _sub: str = ""

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
        self._cat, self._sub = title, ""
        if title not in self._sections:
            self._sections.append(title)
        self.lines.append(f"\n== {title} ==")
        self.output.section(title)

    def sub(self, title: str) -> None:
        self._sub = title
        self.lines.append(f"-- {title} --")
        if not self.output.quiet:
            print(f"  {self.output.CYN}── {title} ──{self.output.NC}")

    def status(self, label: str, value: str, level: str = "info") -> None:
        self.records.append({"category": self._cat, "sub": self._sub,
                             "label": label, "value": value, "level": level})
        self.lines.append(f"[{level}] {label}: {value}")
        line = f"{label}: {value}"
        {"ok": self.output.ok, "warn": self.output.warn,
         "error": self.output.err}.get(level, self.output.note)(line)

    def result(self, text: str) -> None:
        """Raw command output, indented 4 spaces (bash ``print_result``)."""
        if text and text.strip():
            for ln in text.splitlines():
                self.lines.append(f"    {ln}")
        if self.output.quiet:
            return
        if text and text.strip():
            for ln in text.splitlines():
                print(f"    {ln}")
        else:
            print(f"    {self.output.DIM}(no output){self.output.NC}")

    def dim(self, text: str) -> None:
        """An indented dim hint line (bash ``echo -e "    ${DIM}..${NC}"``)."""
        self.lines.append(f"    {text}")
        if not self.output.quiet:
            print(f"    {self.output.DIM}{text}{self.output.NC}")

    # -- persisted report ----------------------------------------------------
    def report_text(self) -> str:
        return "\n".join(self.lines).strip()

    def report_data(self) -> dict:
        """Structured payload grouped by category (for the JSON + HTML report)."""
        cats: dict[str, list] = {}
        for r in self.records:
            c = r["category"] or "general"
            cats.setdefault(c, []).append(
                {k: r[k] for k in ("sub", "label", "value", "level")})
        # every category that ran, in scan order — even ones whose detail was
        # emitted only via result()/dim() (they point to the raw output).
        order = list(self._sections)
        for c in cats:
            if c not in order:
                order.append(c)
        levels = ("error", "warn", "ok", "info")
        return {
            "categories": [{"name": c, "items": cats.get(c, [])} for c in order],
            "level_counts": {lvl: sum(1 for r in self.records if r["level"] == lvl)
                             for lvl in levels},
            # the full transcript (status + sub-headers + raw command output + hints)
            # — most check detail is emitted via result()/dim(), not status().
            "text": self.report_text(),
        }
