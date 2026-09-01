"""auditd: is anything recording the changes the other checks look for?

Every other check in fettle answers *what is on this machine now*. This one answers a
different question, and it is the one that decides whether the first question can ever be
answered after the fact: **if something writes a unit file into `/etc/systemd/system`
tonight, will there be any record that it happened?**

`compromise-check` finds the unit. Only the audit log can say when it arrived and what
put it there.

## Measured on four hosts, 2026-09-01, and the numbers shape every rule below

=====================  ==========  ========  ========  ==================  =============
host                   `auditctl`  enabled   active    `/etc/audit/rules.d`  rules loaded
=====================  ==========  ========  ========  ==================  =============
Manjaro (reference)    present     disabled  inactive  0755, 1 file, 4 watches  n/a, not running
Debian 13              **absent**  not-found inactive  does not exist      n/a
Ubuntu 26.04           **absent**  not-found inactive  does not exist      n/a
AlmaLinux 9            present     enabled   active    0750, `audit.rules` **0**
=====================  ==========  ========  ========  ==================  =============

**auditd is not installed at all on a stock Debian 13 or Ubuntu 26.04.** Reporting "auditd
is not running" there would fire on every Debian-family host in the fleet for a package
the distribution never shipped. Same treatment as the AppArmor axis gives Arch: the
question does not arise, and the axis says so.

**A stock AlmaLinux 9 runs auditd with zero rules loaded.** Its `audit.rules` holds four
non-comment lines and every one of them is a buffer or failure-mode setting rather than a
rule, so `auditctl -l` prints "No rules" and exits 0. "No rules loaded" is therefore the
shipped RHEL default and cannot be a finding on its own without firing on every stock
install.

What survives is narrower and fires on the reference desktop today: **rules are written on
disk and nothing is loading them.** `audit` 4.2.1-1 is installed, `50-persistence.rules`
carries four watches, and `auditd` is both disabled and inactive. Somebody wrote the
policy and no process is applying it, which is the one state where the machine's own
configuration proves the intent.

## Three traps, each of which produces a confident wrong answer

``/etc/audit/rules.d is mode 0750 root:root``
    On AlmaLinux an unprivileged `ls` returns Permission denied. The first pass of this
    measurement counted that as **zero rules files**, which renders as "no auditd rules are
    configured" when the truth is "this run could not look". Unreadable is blindness here,
    never an empty result. Manjaro ships the same directory 0755, so the trap appears on
    some hosts and not others.
``a rules file on disk is not a loaded rule``
    AlmaLinux has `audit.rules` present and the kernel holds nothing. Reading the
    directory and asking the kernel are two different questions and this axis asks both.
``auditd installed is not auditd running``
    The reference desktop has the package, the rules and the directory, and the service is
    off.

Unlike `aa-status`, `auditctl` is honest about privilege: it exits **4** unprivileged
while printing "You must be root to run this program", so the exit code can be trusted.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import LOW, MEDIUM, AxisResult, Finding

_TOOL = "auditctl"

#: Families that ship auditd installed and enabled. Debian, Ubuntu and Arch do not
#: install it at all, so its absence there is a choice the distribution made.
_DEFAULTS_TO_AUDITD = {"rhel"}

#: Package that provides auditctl, per family. Named on the blindness line so the reader
#: is told what to install rather than left to guess.
_PACKAGES = {"rhel": "audit", "debian": "auditd", "arch": "audit"}

#: The startup locations `compromise-check` reports on, and therefore the ones worth
#: recording changes to. Deliberately short: every path added here lengthens the "not
#: watched" list on every host, and these four are where a persistent implant lands.
#: `/run/motd.d` is the Arch spelling of `/etc/update-motd.d`, so either satisfies it.
WATCH_PATHS = (
    ("/etc/systemd/system", ()),
    ("/usr/lib/systemd/system", ()),
    ("/etc/init.d", ()),
    ("/etc/update-motd.d", ("/run/motd.d",)),
)


def rules_files(root: Path) -> tuple[list[str], bool]:
    """``(filenames, readable)`` for ``/etc/audit/rules.d``.

    The second value is the whole point. An unreadable directory and an empty one produce
    the same list, and they mean opposite things.
    """
    try:
        return sorted(p.name for p in (root / "etc/audit/rules.d").iterdir()), True
    except PermissionError:
        return [], False
    except OSError:
        return [], True          # absent, which is a real answer: nothing is configured


def configured_watches(root: Path) -> int:
    """How many watch directives the files on disk hold, or -1 if they cannot be read.

    Counts both spellings: ``-w /path`` and the ``-a always,exit -F dir=/path`` form that
    `auditctl -l` prints back.
    """
    total = 0
    seen = False
    try:
        entries = sorted((root / "etc/audit/rules.d").iterdir())
    except OSError:
        return 0
    for path in entries:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        seen = True
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("-w ") or "-F dir=" in line:
                total += 1
    return total if seen else -1


def watched_paths(raw: str) -> set[str]:
    """Directories the kernel is currently watching, from ``auditctl -l``.

    Both forms appear in the wild and `auditctl` normalises between them depending on
    version, so both are parsed rather than assuming which one this host prints::

        -w /etc/systemd/system -p wa -k systemd_persist
        -a always,exit -F dir=/etc/systemd/system/ -F perm=wa -F key=systemd_persist
    """
    out: set[str] = set()
    for line in raw.splitlines():
        fields = line.split()
        for i, field in enumerate(fields):
            if field == "-w" and i + 1 < len(fields):
                out.add(fields[i + 1].rstrip("/"))
            elif field.startswith("-F") and i + 1 < len(fields) \
                    and fields[i + 1].startswith("dir="):
                out.add(fields[i + 1][4:].rstrip("/"))
            elif field.startswith("dir="):
                out.add(field[4:].rstrip("/"))
    return out


def _unit_state(command, name: str) -> tuple[str, str]:
    """``(is-enabled, is-active)``, each "" when systemctl cannot answer."""
    if not command.which("systemctl"):
        return "", ""
    out = []
    for verb in ("is-enabled", "is-active"):
        proc = command.run(["systemctl", verb, name], capture=True, timeout=10)
        out.append(proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else "")
    return out[0], out[1]


def _missing(watching: set[str]) -> list[str]:
    """Which of :data:`WATCH_PATHS` nothing is recording, ignoring absent directories."""
    missing = []
    for primary, alternatives in WATCH_PATHS:
        if any(p.rstrip("/") in watching for p in (primary, *alternatives)):
            continue
        missing.append(primary)
    return missing


def run(backend, ctx) -> AxisResult:
    from ... import command

    res = AxisResult(name="auditing", title="Audit logging")
    root = Path(getattr(ctx, "root", "/") or "/")
    package = _PACKAGES.get(backend.name, "audit")

    files, readable = rules_files(root)
    configured = configured_watches(root)

    if not command.which(_TOOL):
        # Rules written for a tool that is not installed. Rare, and worth saying plainly
        # because the reader clearly meant to have auditing and does not.
        if files:
            res.checked = 1
            res.findings.append(Finding(
                check="auditd-not-installed", subject="auditd", severity=MEDIUM,
                summary="audit rules are configured and auditd is not installed",
                detail=(f"/etc/audit/rules.d holds {len(files)} rule file(s) and "
                        f"{_TOOL} is not installed, so nothing can load them and nothing "
                        f"is being recorded.")))
            return res
        if backend.name in _DEFAULTS_TO_AUDITD:
            res.checked = 1
            res.findings.append(Finding(
                check="auditd-not-installed", subject="auditd", severity=LOW,
                summary="auditd is absent on a distribution that ships it",
                detail=("auditd is installed and enabled on a default install of this "
                        "distribution and is not here, so changes to the startup "
                        "locations leave no record at all.")))
            return res
        res.na = (f"auditd is not installed, and this distribution does not install it "
                  f"by default (it is in the {package} package)")
        return res

    enabled, active = _unit_state(command, "auditd")
    res.checked = 1

    if not readable:
        res.blind.append((
            "the configured audit rules were NOT read",
            "/etc/audit/rules.d is mode 0750 and this run is not root, so a machine with "
            "no rules at all cannot be told apart from one whose rules could not be "
            "listed", ""))
    else:
        res.notes.append(f"{len(files)} rule file(s) in /etc/audit/rules.d"
                         + (f", holding {configured} watch directive(s)"
                            if configured > 0 else ""))

    # The finding the reference desktop is in today. Somebody wrote the policy, and the
    # service that would apply it is switched off, so the machine's own configuration
    # says what was intended and the intent is not in effect.
    if configured > 0 and active != "active":
        res.findings.append(Finding(
            check="auditd-configured-but-not-running", subject="auditd", severity=MEDIUM,
            summary="audit rules are written and auditd is not running",
            detail=(f"/etc/audit/rules.d holds {configured} watch directive(s) and the "
                    f"auditd service is {active or 'not running'}"
                    + (" and disabled, so it will not start at the next boot either"
                       if enabled == "disabled" else "") +
                    ". The rules describe what should be recorded and nothing is "
                    "recording it."),
            fix="systemctl enable --now auditd && augenrules --load"))
        res.detail_rows.extend(files)
        return res

    if active != "active":
        if backend.name in _DEFAULTS_TO_AUDITD:
            res.findings.append(Finding(
                check="auditd-not-running", subject="auditd", severity=LOW,
                summary="auditd is installed and not running on a distribution that "
                        "enables it",
                detail=("auditd is enabled by default on this distribution and is "
                        f"{active or 'not running'} here, so nothing is recording "
                        "changes to the startup locations."),
                fix="systemctl enable --now auditd"))
        else:
            res.notes.append(
                f"auditd is installed and {active or 'not running'}; this distribution "
                f"does not enable it by default, and no rules are configured")
        return res

    # Running. Ask the kernel what it is actually watching, which is a different question
    # from what is written in the files.
    proc = command.run([_TOOL, "-l"], capture=True, timeout=15)
    if proc.returncode != 0:
        why = ("needs root" if os.geteuid() != 0
               else f"{_TOOL} -l exited {proc.returncode}")
        res.blind.append((
            "the loaded audit rules were NOT read",
            f"{why}; auditd is running, so something is or is not being recorded and "
            f"this run cannot tell which", ""))
        return res

    watching = watched_paths(proc.stdout)
    missing = _missing(watching)
    res.notes.append(f"auditd is running and watching {len(watching)} path(s)")
    res.detail_rows.extend(sorted(watching))

    # Fires on a stock AlmaLinux 9, deliberately and at Low, on the same reasoning the
    # AppArmor axis fires on a stock Debian: the host really is in this state, and there
    # is a specific thing to do about it. The rule lines are printed rather than
    # installed, so the operator applies them.
    if missing:
        # The `-a always,exit -F dir=` form rather than `-w`, because auditctl prints
        # "Old style watch rules are slower" for every `-w` it accepts. Verified on
        # AlmaLinux 9 by loading both and reading the warning back.
        rules = "  ".join(f"-a always,exit -F dir={p}/ -F perm=wa -F key=startup_persist"
                          for p in missing)
        res.findings.append(Finding(
            check="auditd-startup-paths-unwatched", subject="auditd", severity=LOW,
            summary=f"{len(missing)} startup location(s) are not recorded",
            detail=(f"auditd is running and is not watching {', '.join(missing)}. A unit "
                    f"file or init script written there leaves no record of when it "
                    f"arrived or what wrote it, which is the question that cannot be "
                    f"answered afterwards."),
            fix=(f"add to /etc/audit/rules.d/50-persistence.rules, then "
                 f"augenrules --load:  {rules}")))
    return res
