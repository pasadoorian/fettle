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


# What a `✗` line actually means. One channel on screen, three different situations
# behind it — and they call for opposite responses from the reader:
#
#   FAILED  the action could not do its job          -> something is broken, go look
#   BLIND   the check could not look                 -> you have a blind spot, and the
#                                                       all-clear you just got is not one
#   FOUND   the check looked and found something     -> the tool worked; go fix the thing
#
# Rendering is identical for all three on purpose; this is about what the exit status is
# allowed to conclude, not about what the user reads.
FAILED, BLIND, FOUND = "failed", "blind", "found"


@dataclass
class Output:
    """Sectioned, optionally-colored output with a step counter and end summary."""

    color: bool | None = None
    quiet: bool = False
    verbose: bool = False
    step_total: int = 0
    # Which machine this output is describing. Set only for a group run, where six
    # hosts' output runs together in one terminal and the per-host banner scrolls off
    # long before the actions do — so by the third host you are reading a summary with
    # no idea whose it is. A single host does not need it: its banner is right there.
    host_label: str = ""
    _step_cur: int = field(default=0, init=False)
    _summary: list[str] = field(default_factory=list, init=False)
    _failures: list[str] = field(default_factory=list, init=False)
    _warnings: list[str] = field(default_factory=list, init=False)
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
        where = f" ({self.host_label})" if self.host_label else ""
        if self.step_total > 0:
            self._step_cur += 1
            print(f"\n{self.B}{self.CYN}▸ [{self._step_cur}/{self.step_total}] "
                  f"{title}{where}{self.NC}")
        else:
            print(f"\n{self.B}{self.CYN}▸ {title}{where}{self.NC}")

    def ok(self, msg: str) -> None:
        if not self.quiet:
            print(f"  {self.GRN}✓{self.NC} {msg}")

    def note(self, msg: str) -> None:
        if not self.quiet:
            print(f"  {self.DIM}{msg}{self.NC}")

    def _to_stderr(self, line: str) -> None:
        """Write a diagnostic, keeping it in step with the surrounding output.

        stderr is unbuffered while stdout is *block*-buffered whenever it is not a
        terminal — so over ssh, in a run-log, or through a pipe, every warning jumped
        ahead of the section it belongs to. QA caught a signature warning printed above
        the `▸ Updating packages` header it was warning about, and a failed-command
        message detached from its step. Flushing stdout first costs nothing and keeps
        the transcript readable.
        """
        sys.stdout.flush()
        print(line, file=sys.stderr)
        sys.stderr.flush()

    def warn(self, msg: str) -> None:
        self._to_stderr(f"  {self.YLW}!{self.NC} {msg}")

    def err(self, msg: str) -> None:
        self._to_stderr(f"  {self.RED}✗{self.NC} {msg}")

    def alert(self, msg: str) -> None:
        self._to_stderr(f"{self.B}{self.RED}  !! {msg}{self.NC}")

    # -- run a noisy command, show a one-line status -------------------------
    def run_quiet(self, msg: str, cmd, *, as_user: str | None = None,
                  ok_codes: tuple[int, ...] = (0,)):
        """Run ``cmd`` showing only ``msg`` on success; full output on failure
        (or always, under ``verbose``). Returns the ``command.Proc``.

        ``ok_codes`` exists because "non-zero" and "failed" are not synonyms: fwupd
        documents ``2`` as *"no actions but successfully executed"* and returns it from
        `refresh` whenever the metadata is already current — so every healthy machine was
        being shown a red ✗ for a routine condition.
        """
        from . import command  # local import keeps output import-free at module load

        proc = command.run(cmd, as_user=as_user, capture=not self.verbose)
        if proc.returncode in ok_codes:
            self.ok(msg)
        else:
            self.err(f"{msg} failed (exit {proc.returncode}):")
            text = (proc.stdout + proc.stderr).strip()
            if text:
                self._to_stderr(text)   # same ordering guarantee as warn/err
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

    def summary_fail(self, line: str, *, kind: str = FAILED) -> None:
        """Record something that did NOT work, for the end-of-run summary.

        Every summary line used to render with a green tick, so an action that failed
        could only report itself as a success or say nothing — QA found a clean blocked
        by a permission error signing off with `✓ caches already clean`. A failure needs
        its own channel, and it sets the process exit status via :attr:`had_failures`.

        ``kind`` says **which** of the three this is (see the module constants). It
        changes nothing about what prints — all three render `✗` — and for now nothing
        about the exit status either. It exists so the status can later answer the right
        question for how fettle was invoked: a single check should fail on any of the
        three, while a fourteen-action sweep that fails on every *finding* is red on
        every real machine and stops being read. What such a sweep must never do is
        treat **could not look** as success, and today it cannot tell the difference.
        """
        self._failures.append((line, kind))

    def summary_warn(self, line: str) -> None:
        """Record something that did not happen, without calling it a failure.

        The middle state, and it is needed more often than it looks: a package manager
        exits non-zero both when you answer "no" at its prompt and when it genuinely
        fails, so an interactive run that ends early is ambiguous. Reporting it as
        success is a lie; reporting it as a failure cries wolf at a user who simply
        declined. This says what is known — it did not complete — and leaves the exit
        status alone.
        """
        self._warnings.append(line)

    @property
    def had_failures(self) -> bool:
        """Whether anything reported a failure — the process exit status.

        Deliberately still blind to ``kind``: this milestone only labels the lines, so
        every exit code stays exactly what it was and the change is provably inert.
        """
        return bool(self._failures)

    def failures_of(self, *kinds: str) -> list[str]:
        """The recorded failure lines of the given kind(s)."""
        return [line for line, kind in self._failures if kind in kinds]

    def next_step(self, line: str) -> None:
        self._next_steps.append(line)

    def print_summary(self) -> None:
        if self.quiet:
            return
        where = f" ({self.host_label})" if self.host_label else ""
        print(f"\n{self.B}{self.CYN}▸ Summary{where}{self.NC}")
        if self._summary or self._failures or self._warnings:
            for line in self._summary:
                print(f"  {self.GRN}✓{self.NC} {line}")
            for line in self._warnings:
                print(f"  {self.YLW}!{self.NC} {line}")
            for line, _kind in self._failures:
                print(f"  {self.RED}✗{self.NC} {line}")
        else:
            print(f"  {self.DIM}nothing to report{self.NC}")
        if self._next_steps:
            print()
            for line in self._next_steps:
                print(f"  {self.CYN}→{self.NC} {line}")
