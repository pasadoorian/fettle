"""Terminal output helpers — a Python port of the bash ``lib/output.sh``.

Color turns on only for an interactive TTY when the user has not opted out
(``NO_COLOR`` set, ``TERM=dumb``, or ``color=False``). Diagnostics (warn / err /
alert) always go to stderr. Instantiate one :class:`Output` and pass it around
via the backend ``Context`` — no module-level global state.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field


def _want_color(stream, override: bool | None) -> bool:
    if override is not None:
        return override
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


@dataclass
class Output:
    """Sectioned, optionally-colored output with a step counter and end summary."""

    color: bool | None = None
    quiet: bool = False
    verbose: bool = False
    step_total: int = 0
    _step_cur: int = field(default=0, init=False)
    _summary: list[str] = field(default_factory=list, init=False)
    _next_steps: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        c = _want_color(sys.stdout, self.color)
        self.B = "\033[1m" if c else ""
        self.DIM = "\033[2m" if c else ""
        self.GRN = "\033[32m" if c else ""
        self.YLW = "\033[33m" if c else ""
        self.RED = "\033[31m" if c else ""
        self.CYN = "\033[36m" if c else ""
        self.NC = "\033[0m" if c else ""

    # -- sections & status ---------------------------------------------------
    def section(self, title: str) -> None:
        if self.quiet:
            return
        if self.step_total > 0:
            self._step_cur += 1
            print(f"\n{self.B}{self.CYN}▸ [{self._step_cur}/{self.step_total}] {title}{self.NC}")
        else:
            print(f"\n{self.B}{self.CYN}▸ {title}{self.NC}")

    def ok(self, msg: str) -> None:
        if not self.quiet:
            print(f"  {self.GRN}✓{self.NC} {msg}")

    def note(self, msg: str) -> None:
        if not self.quiet:
            print(f"  {self.DIM}{msg}{self.NC}")

    def warn(self, msg: str) -> None:
        print(f"  {self.YLW}!{self.NC} {msg}", file=sys.stderr)

    def err(self, msg: str) -> None:
        print(f"  {self.RED}✗{self.NC} {msg}", file=sys.stderr)

    def alert(self, msg: str) -> None:
        print(f"{self.B}{self.RED}  !! {msg}{self.NC}", file=sys.stderr)

    # -- run a noisy command, show a one-line status -------------------------
    def run_quiet(self, msg: str, cmd, *, as_user: str | None = None):
        """Run ``cmd`` showing only ``msg`` on success; full output on failure
        (or always, under ``verbose``). Returns the ``command.Proc``."""
        from . import command  # local import keeps output import-free at module load

        proc = command.run(cmd, as_user=as_user, capture=not self.verbose)
        if proc.ok:
            self.ok(msg)
        else:
            self.err(f"{msg} failed (exit {proc.returncode}):")
            text = (proc.stdout + proc.stderr).strip()
            if text:
                print(text, file=sys.stderr)
        return proc

    # -- run an interactive command, framed so its output isn't mistaken for ours --
    @staticmethod
    def _tool_name(argv) -> str:
        """The real tool being run, skipping `env`/`VAR=val` wrappers (so a
        `env DEBIAN_FRONTEND=… apt-get …` reads as `apt-get`, not `env`)."""
        for tok in argv:
            if tok == "env" or "=" in tok:
                continue
            return tok
        return argv[0] if argv else "?"

    def run_streamed(self, cmd, *, as_user: str | None = None):
        """Run ``cmd`` streaming its output live (no capture — interactive prompts
        like PKGBUILD review / sudo still work), bracketed by a labeled banner so
        it's unmistakable that the enclosed output is the tool's, not fettle's."""
        from . import command

        tool = self._tool_name([str(c) for c in cmd])
        rule = "─" * 12
        if not self.quiet:
            print(f"  {self.DIM}{rule} {self.NC}{self.B}{tool}{self.NC}"
                  f"{self.DIM} {rule} output below is {tool}'s, not fettle's {rule}{self.NC}")
            sys.stdout.flush()  # emit the banner BEFORE the tool writes to the fd
        proc = command.run(cmd, as_user=as_user)
        if not self.quiet:
            print(f"  {self.DIM}{rule} end {tool} {rule}{rule}{self.NC}")
        return proc

    # -- end-of-run summary --------------------------------------------------
    def summary_add(self, line: str) -> None:
        self._summary.append(line)

    def next_step(self, line: str) -> None:
        self._next_steps.append(line)

    def print_summary(self) -> None:
        if self.quiet:
            return
        print(f"\n{self.B}{self.CYN}▸ Summary{self.NC}")
        if self._summary:
            for line in self._summary:
                print(f"  {self.GRN}✓{self.NC} {line}")
        else:
            print(f"  {self.DIM}nothing to report{self.NC}")
        if self._next_steps:
            print()
            for line in self._next_steps:
                print(f"  {self.CYN}→{self.NC} {line}")
