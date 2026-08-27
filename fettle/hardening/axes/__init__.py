"""System-hardening axes — the questions beyond "was this binary built hardened?".

``hardening-audit`` began as one thing: a checksec sweep of every ELF on the box.
That is *an* axis of hardening, not the whole of it, and treating it as the whole had
a concrete cost — a missing checksec returned ``Result(ok=False)`` and the action was
over, so a host with no checksec available got no hardening answer at all rather than
four of the five it could have had.

Each axis answers one question, independently:

===========  ===============================================================
binary       were these binaries built with the distro's hardening flags?
filesystem   can a local user tamper with shared directories?
services     how much of the system is each running service exposed to?
kernel       are the runtime kernel protections switched on?
ssh          is the *effective* sshd configuration weak anywhere?
firewall     is a host firewall active, and does it actually have rules?
certs        are any TLS certificates expired or about to be?
apparmor     is mandatory access control confining anything, or just on?
selinux      what mode is SELinux in, and does the machine agree with itself?
===========  ===============================================================

The contract every axis keeps, and the reason this module exists at all:

* **Findings and blindness are different channels.** ``findings`` is "I looked and
  found this"; ``blind`` is "I could not look, and here is why". An axis that cannot
  run must never return an empty ``findings`` list and let the reader conclude the
  system is clean — the governing invariant of this project's QA pass.
* **Not applicable is a third thing.** ``na`` says the question does not arise here
  (no sshd installed, no systemd in a container). That is neither a finding nor
  blindness, and rendering it as either is a lie in a different direction.
* **Findings warn, they do not fail.** Same reasoning as the binary axis's scoring
  bands: every real machine has some, so exiting non-zero would make ``-H`` red
  forever and teach people to ignore it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Severity is deliberately a word rather than a 0-100 score. Lynis's hardening index is
# a single number whose weighting nobody can see, which makes it feel precise and be
# unarguable; bands with a stated meaning are less impressive and more useful. The binary
# axis keeps its own *scoring* — it is comparing thousands of binaries against each
# other, which is the case a score is actually for — but it lands in these same bands.
#
# One scale, deliberately: these were lower-case while the binary axis said
# "Critical/High/Medium/Low", so a single screen carried two vocabularies for the same
# idea and neither the combined report nor the dashboard could rank across them.
# `Critical` is defined for that shared ordering; no axis emits it today, and saying so
# is better than pretending the scale is shorter than it is.
CRITICAL, HIGH, MEDIUM, LOW = "Critical", "High", "Medium", "Low"
SEVERITY_ORDER = (CRITICAL, HIGH, MEDIUM, LOW)


@dataclass
class Finding:
    """One thing an axis looked at and judged wrong.

    ``detail`` says what an attacker or accident could do with it, not what the
    setting is called. "world-writable without the sticky bit" is a restatement of
    the mode; "any local user can delete or replace other users' files here" is the
    reason to care, and it is what belongs here.
    """

    check: str        # stable id, e.g. "sticky-bit" — what the user excludes by
    subject: str      # what it is about, e.g. "/tmp" or "tailscaled.service"
    detail: str       # why it matters, in a sentence
    severity: str = MEDIUM
    fix: str = ""     # optional concrete remedy
    # Short form for the on-screen table. Usually derived: see `short()`.
    summary: str = ""

    def short(self) -> str:
        """The table cell — what is wrong, without the explanation of why.

        ``detail`` is written as ``<what is wrong> — <why it matters>``, so the first
        clause is already the label a table wants and setting ``summary`` by hand at
        twenty call sites would mostly restate it. Where a detail does not take that
        shape, ``summary`` is given explicitly.

        `tests/test_hardening_render.py` asserts every finding a real axis produces has
        a short form that actually fits a column, so a detail written in the wrong shape
        fails a test rather than quietly rendering a paragraph into a table cell.
        """
        return self.summary or self.detail.split(" — ")[0]


@dataclass
class AxisResult:
    """What one axis has to say. See the module docstring for the three channels."""

    name: str                                   # "filesystem"
    title: str                                  # "Filesystem hygiene"
    findings: list[Finding] = field(default_factory=list)
    # (what was not checked, why, package-to-install) — fed straight to
    # Output.not_checked, which works out this machine's install command at print time.
    blind: list[tuple[str, str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Review material that belongs in the saved report but not on screen — the same
    # split the binary axis already makes, where the terminal shows the Critical/High
    # packages and the full per-criterion matrix goes to the report. Printing every row
    # is how a check becomes a wall of text nobody reads, which is precisely what makes
    # the tool that prompted this work ignorable.
    detail_rows: list[str] = field(default_factory=list)
    checked: int = 0                            # how many subjects were examined
    na: str = ""                                # non-empty = does not apply, and why

    @property
    def ran(self) -> bool:
        """Did this axis actually examine anything?"""
        return not self.na and self.checked > 0

    def tally(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# Order is the order they print in: cheapest and most concrete first, so the reader
# meets "/tmp is world-writable" before a wall of service-exposure scores.
#
# This tuple holds the axes that EXIST, and grows one entry per milestone. The table
# above describes the design; listing an unbuilt axis here would make `run_all` report
# it as blind on every host, which is a louder lie than not mentioning it.
AXIS_NAMES = ("filesystem", "services", "kernel", "ssh", "firewall", "certs",
              "apparmor", "selinux")

# The binary axis predates this module and still lives in engine/report/score. It is
# named here so `disable_axes = ["binary"]` works and so the help can list one set.
ALL_AXIS_NAMES = ("binary",) + AXIS_NAMES


def disabled(cfg) -> set[str]:
    """Axis names the user switched off via ``[hardening] disable_axes``.

    Every axis is on by default — same policy as the exclude lists, which ship empty
    so the first run shows everything and the user narrows to taste. An unknown name
    here is the user's typo, and silently running everything would hide it; the caller
    warns rather than guessing what was meant.
    """
    h = getattr(cfg, "hardening", None) or {}
    if not isinstance(h, dict):
        return set()
    raw = h.get("disable_axes") or []
    if not isinstance(raw, (list, tuple)):
        return set()
    return {str(x).strip().lower().replace("_", "-") for x in raw if str(x).strip()}


def unknown_disabled(cfg) -> list[str]:
    """Names in ``disable_axes`` that are not axes — a typo silently disables nothing."""
    return sorted(disabled(cfg) - set(ALL_AXIS_NAMES))


def apply_excludes(results: list[AxisResult], checks, paths) -> int:
    """Drop findings the user excluded, in place. Returns how many were dropped.

    Reuses ``[hardening] exclude_checks`` and ``exclude_paths`` rather than inventing
    per-axis lists: an id is an id, and a second exclude mechanism for the same job is
    how two of them drift into disagreeing. The count is returned so the run can tell
    the user what its own config hid — silent filtering is indistinguishable from
    having found nothing.
    """
    import fnmatch

    dropped = 0
    for res in results:
        keep = []
        for f in res.findings:
            if any(fnmatch.fnmatch(f.check, g) for g in checks) or \
               any(fnmatch.fnmatch(f.subject, g) for g in paths):
                dropped += 1
                continue
            keep.append(f)
        res.findings = keep
    return dropped


def _module(name: str):
    from importlib import import_module

    return import_module(f".{name.replace('-', '_')}", __package__)


def run_all(backend, ctx) -> list[AxisResult]:
    """Run every enabled axis, in :data:`AXIS_NAMES` order.

    An axis that raises is reported as *blind*, never as clean: a bug in one axis must
    not be indistinguishable from that axis having nothing to report. It also must not
    take the other five down with it — this action's whole reason for growing axes was
    that one missing tool used to end the run.
    """
    off = disabled(ctx.config)
    results: list[AxisResult] = []
    for name in AXIS_NAMES:
        if name in off:
            continue
        try:
            results.append(_module(name).run(backend, ctx))
        except Exception as exc:                       # noqa: BLE001 — see docstring
            results.append(AxisResult(
                name=name, title=name.capitalize(),
                blind=[(f"the {name} checks did not complete", f"{type(exc).__name__}: {exc}", "")],
            ))
    return results
