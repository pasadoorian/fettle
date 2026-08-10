"""Scheduled jobs — cron, anacron and `at`.

Cron persistence is still the most common way Linux malware survives a reboot, for the
unglamorous reason that it is simple, it works everywhere, and nobody looks at it. This
module answers the same question the systemd half asks: *what is scheduled to run that
nobody sanctioned?*

**Two sources, two different criteria, and conflating them would make this unusable.**

* **System cron** — `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`,
  `/etc/crontab`, `/etc/anacrontab`. These are package-managed directories, so "no
  package owns this file" is a real signal. On the reference machine it produces exactly
  one hit: `/etc/cron.d/timeshift-hourly`, which timeshift writes at runtime when you
  enable scheduled snapshots rather than shipping in its package.
* **User crontabs and `at` jobs** — `/var/spool/cron/**`, `/var/spool/at*`. These are
  **never** package-owned: `crontab -e` creates them by definition. Applying the
  ownership test here would report every user crontab on every machine as a finding,
  which is the "unnecessary homework" failure in its purest form. So they are reported
  as *review material* — here is what is scheduled, and for whom — and only become a
  finding when the command runs from somewhere a scheduled job's binary does not belong.

The same asymmetry governs user systemd units in :mod:`fettle.compromise.persistence`,
and for the same reason: ownership tells you something about `/etc`, and nothing at all
about a user's own config.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import is_directory, is_regular_file

# `m h dom mon dow` — or one of cron's shorthand tokens, which replace all five.
_SHORTHAND = ("@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily",
              "@midnight", "@hourly")

# `NAME=value` at the top of a crontab sets an environment variable rather than
# scheduling anything. Matched strictly (no space before `=`) so that a command
# containing an `=` is not mistaken for one.
_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")

# Files in the cron drop directories that cron itself ignores. run-parts skips anything
# with a dot in the name, which is how `.pacsave`/`.dpkg-dist` leftovers stop running —
# reporting them as scheduled jobs would be wrong, because they are not scheduled.
_IGNORED_SUFFIXES = (".pacnew", ".pacsave", ".pacorig", ".rpmnew", ".rpmsave",
                     ".rpmorig", ".dpkg-dist", ".dpkg-old", ".dpkg-new", ".swp", "~")

# Package-managed: a file here that no package owns was put here by something else.
SYSTEM_CRON_DIRS = ("etc/cron.d", "etc/cron.hourly", "etc/cron.daily",
                    "etc/cron.weekly", "etc/cron.monthly")
SYSTEM_CRON_FILES = ("etc/crontab", "etc/anacrontab")

# Never package-managed — see the module docstring. Both spool layouts are listed
# because they differ by family: Arch and RHEL use `/var/spool/cron/<user>`, Debian and
# Ubuntu use `/var/spool/cron/crontabs/<user>`.
USER_CRON_DIRS = ("var/spool/cron", "var/spool/cron/crontabs")
AT_DIRS = ("var/spool/atd", "var/spool/atjobs", "var/spool/at", "var/spool/cron/atjobs")


def _readable(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _entries(directory: Path) -> list[Path]:
    try:
        return [p for p in sorted(directory.iterdir())
                if is_regular_file(p)
                and not p.name.startswith(".")
                and not p.name.endswith(_IGNORED_SUFFIXES)]
    except OSError:
        return []


def unreadable(root: Path, dirs) -> list[str]:
    """Directories that exist but this process cannot open.

    Kept apart from :func:`_entries`, which swallows the error, because the two states
    are not the same answer: `/var/spool/cron` **absent** means no user crontabs exist,
    while `/var/spool/cron` **present and mode 0700** means there may be any number and
    we cannot see them. Debian ships that directory `0730 root:crontab`, so an
    unprivileged run there hits the second case every time — and silently reporting zero
    scheduled jobs on a host that has them is the failure this project is named for.
    """
    blocked: list[str] = []
    for rel in dirs:
        directory = root / rel
        # A directory nested inside one already reported adds nothing: on Debian both
        # `/var/spool/cron` and `/var/spool/cron/crontabs` are in the search list, and
        # naming the second when the first is already unreadable says the same thing
        # twice while implying we know the second exists.
        if any(str(directory).startswith(b + "/") for b in blocked):
            continue
        if not is_directory(directory):
            continue
        try:
            next(directory.iterdir(), None)
        except OSError:
            blocked.append(str(directory))
    return blocked


def commands(text: str, *, has_user_field: bool) -> list[str]:
    """The commands a crontab schedules, in order.

    ``has_user_field`` is the difference between a system crontab
    (``m h dom mon dow USER command`` — `/etc/crontab`, `/etc/cron.d/*`) and a user one
    (``m h dom mon dow command`` — `/var/spool/cron/<user>`). Getting it backwards
    silently reports the *user name* as the command on one and swallows the first word
    of the command on the other, and both still look like plausible output.
    """
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or _ENV.match(line):
            continue
        fields = line.split()
        if fields[0] in _SHORTHAND:
            rest = fields[1:]
        elif len(fields) > 5:
            rest = fields[5:]
        else:
            continue                       # not a schedule line we understand
        if has_user_field:
            rest = rest[1:]                # drop the user column
        if rest:
            out.append(" ".join(rest))
    return out


def system_jobs(root: Path) -> list[tuple[Path, list[str]]]:
    """Package-managed cron locations: ``(path, commands)`` for each real file.

    The `cron.{hourly,daily,…}` directories hold *scripts*, not crontabs — the file
    itself is the scheduled thing and it has no schedule line to parse, so its command
    list is empty and the finding rests on the file's own provenance.
    """
    jobs: list[tuple[Path, list[str]]] = []
    for rel in SYSTEM_CRON_DIRS:
        directory = root / rel
        for path in _entries(directory):
            text = _readable(path)
            # cron.d entries are crontabs with a user column; run-parts directories
            # hold plain executables.
            parsed = (commands(text, has_user_field=True)
                      if rel.endswith("cron.d") else [])
            jobs.append((path, parsed))
    for rel in SYSTEM_CRON_FILES:
        path = root / rel
        if is_regular_file(path):
            jobs.append((path, commands(_readable(path), has_user_field=True)))
    return jobs


def user_jobs(root: Path) -> list[tuple[Path, list[str]]]:
    """Per-user crontabs. Never package-owned, so never judged on ownership."""
    jobs: list[tuple[Path, list[str]]] = []
    seen: set[Path] = set()
    for rel in USER_CRON_DIRS:
        for path in _entries(root / rel):
            if path in seen:
                continue                   # crontabs/ nests inside cron/ on Debian
            seen.add(path)
            jobs.append((path, commands(_readable(path), has_user_field=False)))
    return jobs


def at_jobs(root: Path) -> list[Path]:
    """Queued `at` jobs.

    Reported wherever they exist rather than parsed: an at job is a shell script with a
    large generated environment preamble, and a one-shot job queued on a machine that
    does not otherwise use `at` is worth a human look on its own — which is the whole
    finding. They are also rare enough that listing them costs nothing.
    """
    found: list[Path] = []
    for rel in AT_DIRS:
        found.extend(p for p in _entries(root / rel)
                     if p.name not in (".SEQ", ".lockfile"))
    return found


def argv0(command: str) -> str:
    """The absolute path a command starts with, or empty.

    `timeshift --check --scripted` yields nothing, deliberately: resolving a bare name
    against `$PATH` would answer a different question (what *would* run now, under
    fettle's environment) from the one asked (what does this line say), and cron's PATH
    is set inside the crontab anyway.

    Wrappers are stepped over along with their own options, so `nice -n 19 /var/tmp/x`
    resolves to the payload rather than to `19`. The scan then stops at the **first**
    token that is not part of a wrapper, and returns it only if it is absolute — it does
    not keep hunting for something that looks like a path. That direction is chosen
    deliberately: `timeshift --check /tmp/report` would otherwise resolve to `/tmp/report`
    and be reported as a job running out of `/tmp`. Missing a finding is recoverable;
    an alarm over an argument teaches people to stop reading the alarms.
    """
    wrappers = ("sudo", "nice", "ionice", "env", "/usr/bin/env", "/bin/nice",
                "/usr/bin/nice", "/usr/bin/sudo", "/bin/env")
    in_wrapper = False
    for token in command.split():
        if token in wrappers:
            in_wrapper = True
            continue
        if in_wrapper and (token.startswith("-") or token.isdigit() or "=" in token):
            continue                       # the wrapper's own options and assignments
        return token if token.startswith("/") else ""
    return ""
