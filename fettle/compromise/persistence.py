"""Persistence — what starts at boot that no package installed?

The June 2026 AUR wave persisted with a systemd unit: `Restart=always`, dropped in
`/etc/systemd/system/` with root or `~/.config/systemd/user/` without, running a payload
from `/var/lib/`. `pkg-audit` can tell you a package you installed was in that wave.
This tells you whether the unit it dropped is still here.

**Why this is not the `services` axis check.** `hardening-audit`'s services axis already
reports unpackaged units — but only those scoring `EXPOSED` (7.0) or worse on
`systemd-analyze security`, because there it is one input to an *exposure* judgement. A
quiet unit that runs a single binary and opens no sockets scores low, so the exact shape
the AUR wave used is **skipped by that check today**. `tests/test_compromise_persistence.py`
builds that unit and proves it.

The two checks also ask different questions of the same file. Exposure asks *how much
could this reach if it were hostile*; this asks *did anybody sanction it being here*.

## What the false-positive floor actually is, measured

On the reference desktop (Manjaro, 2026-08-10) the three system unit directories hold
**482 real unit files, of which 480 are owned by a package**. The two that are not are
runZero Explorer agents, installed on purpose. So this check reports two things on a
clean machine, and both are explicable in one line — which is the bar.

Getting there meant throwing away two rules that sounded right and were not:

* **`Restart=always` is not a signal.** It is in **27 of the 480** distro units, and in
  both runZero units. It is context worth printing and nothing more; escalating on it
  would have made the reference machine produce two High findings and a preservation
  banner on a healthy box, which is precisely how a real alarm gets ignored.
* **"An unowned binary" is not a signal either.** Every vendor install is unowned by
  definition. `/opt/rumble/bin/…` (runZero) and `/opt/android-sdk/…` are both unowned
  and both fine.

What survived is the *location* of the target. `/opt` and `/usr/local` are where the FHS
puts software the package manager did not install; `/tmp`, `/dev/shm` and the `/var`
state directories are not places a persistent service's binary belongs. That distinction
holds on the reference machine, where it separates the two legitimate agents from
nothing at all — the intended answer.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import HIGH, LOW, MEDIUM, CheckResult, Finding, is_regular_file
from . import cron
from .users import real_users

# Searched in this order. All three are *system* scope; user units are M1.3.
#
# `/usr/lib/systemd/system` is included even though it is the distro's own directory,
# and it is the cheapest high-value entry here: all 480 of its unit files on the
# reference machine are package-owned, so an unowned one is a file sitting in the
# distribution's unit directory that the distribution did not put there. Excluding it
# to save the scan would leave the one place an implant would most want to hide.
#
# `/run/systemd/system` is deliberately absent: it is generator output, regenerated
# every boot and owned by nothing by construction, so every entry would be a finding.
UNIT_DIRS = (
    "etc/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
)

# Directories a long-running service's executable has no business being in. Deliberately
# NOT "anything unowned" and NOT all of /var — see the module docstring. `/var/vanta` on
# the reference machine is a compliance agent's install prefix, and rules that flagged
# either would have been wrong there.
SUSPECT_DIRS = (
    "/tmp/", "/var/tmp/", "/dev/shm/",          # world-writable, wiped on reboot
    "/var/lib/", "/var/cache/", "/var/spool/",  # state, not executables — the AUR wave
    "/run/user/",                               # per-session tmpfs
)

# systemd's ExecStart prefixes: `-` ignore failure, `@` argv[0] override, `+` full
# privilege, `!`/`!!` privilege variants, `:` no variable expansion. Any combination,
# any order.
_PREFIXES = "-@+!:"


def _unit_files(root: Path) -> list[Path]:
    """Real `.service`/`.timer` files in the system unit directories.

    **Symlinks are excluded, and that is the difference between 2 findings and 41.** A
    recursive listing of `/etc/systemd/system` on the reference machine returns 41
    entries; ten are symlinks and the rest live in `.wants/`/`.requires/` subdirectories.
    Both are what `systemctl enable` creates — they carry no content of their own and
    each points at a unit that is examined here anyway, on its own merits.
    """
    found: list[Path] = []
    for rel in UNIT_DIRS:
        directory = root / rel
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for path in entries:
            if path.suffix not in (".service", ".timer"):
                continue
            # is_regular_file() excludes symlinks and never raises — see its
            # docstring for why the second half matters here specifically.
            if not is_regular_file(path):
                continue
            found.append(path)
    return found


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def exec_targets(text: str) -> list[str]:
    """The executables an ExecStart* line would run, in order.

    Only `argv[0]` per line. `ExecStart=/bin/sh -c '<script>'` therefore reports
    `/bin/sh`, which is owned and unremarkable — the script is the interesting part and
    it goes to the saved report as the raw line rather than being parsed here. Guessing
    which token of an arbitrary shell command is "the real binary" is how a check starts
    being wrong in ways nobody can predict.

    Lines whose target still contains an unresolved `%` specifier are dropped: `%i` and
    friends only mean something for an instantiated template, and a path with a literal
    `%i` in it would be reported as a missing file on every host.
    """
    targets: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not re.match(r"^ExecStart(Pre|Post)?\s*=", stripped):
            continue
        value = stripped.split("=", 1)[1].strip().lstrip(_PREFIXES).strip()
        if not value:
            continue                       # `ExecStart=` alone resets the list
        argv0 = value.split()[0]
        if not argv0.startswith("/") or "%" in argv0:
            continue
        targets.append(argv0)
    return targets


def _restarts(text: str) -> bool:
    return bool(re.search(r"^\s*Restart\s*=\s*always\s*$", text, re.MULTILINE))


def _suspect(target: str) -> str:
    """Why this location is wrong for a service binary, or empty if it is not."""
    for prefix in SUSPECT_DIRS:
        if target.startswith(prefix):
            return prefix.rstrip("/")
    return ""


def run(backend, ctx) -> CheckResult:
    """Every source of scheduled or boot-time execution, into one result.

    Ordered by how much a finding means: system scope first, where "no package owns
    this" is a real signal, then user scope, where it is not one at all.
    """
    res = CheckResult(name="persistence", title="Boot persistence")
    _system_units(backend, ctx, res)
    _user_units(ctx, res)
    _system_cron(backend, ctx, res)
    _user_cron(ctx, res)
    _at_jobs(ctx, res)

    if res.findings:
        res.notes.append(
            "Something no package owns is not by itself wrong — it is how every vendor "
            "agent, hand-written service and `crontab -e` entry looks. What each "
            "finding gives you is what it runs and whether anything vouches for that, "
            "so you can confirm you put it there.")
    return res


def _system_units(backend, ctx, res: CheckResult) -> None:
    """Unit files in the package-managed system directories."""
    units = _unit_files(ctx.root)
    res.checked += len(units)
    if not units:
        # Every supported distro uses systemd, so no unit files at all means the
        # directories could not be read rather than that none exist — a container
        # without /usr/lib/systemd, or a --root pointed somewhere wrong.
        res.blind.append(("system unit files",
                          f"no unit files found under {', '.join(UNIT_DIRS)} — "
                          "nothing was examined", ""))
        return

    owners = backend.map_files_to_packages([str(p) for p in units])
    unowned = [p for p in units if str(p) not in owners]

    # Second lookup, only for the units that survived the first. On the reference
    # machine that is two paths rather than four hundred and eighty-two.
    bodies = {p: _read(p) for p in unowned}
    targets: dict[Path, list[str]] = {p: exec_targets(t) for p, t in bodies.items()}
    flat = sorted({t for ts in targets.values() for t in ts})
    target_owners = backend.map_files_to_packages(flat) if flat else {}

    for path in unowned:
        res.findings.append(_finding(path, bodies[path], targets[path], target_owners,
                                     ctx.root))
        raw = [ln.strip() for ln in bodies[path].splitlines()
               if ln.strip().startswith("ExecStart")]
        res.detail_rows.append(f"{path}: {'; '.join(raw) or '(no ExecStart)'}")
def _finding(path: Path, body: str, targets: list[str],
             target_owners: dict[str, str], root: Path) -> Finding:
    """One unowned unit, graded on where its binary lives rather than on who owns it."""
    name = path.name
    suspect = next((s for t in targets if (s := _suspect(t))), "")
    missing = [t for t in targets
               if not (root / t.lstrip("/")).exists()]

    # Ordered by what the unit could actually DO, which is not the same as how odd it
    # looks. The first live run of this check graded a missing executable High and
    # printed the preservation banner over it — on the reference machine, where the
    # cause was a vendor renaming its binary. A unit whose target does not exist cannot
    # execute anything: it is the *least* dangerous state here, not the most.
    if suspect:
        severity, why = HIGH, (
            f"its executable runs from {suspect}, which is not a location a service "
            f"binary belongs in — this is the shape the June 2026 AUR supply-chain "
            f"implant used")
    elif missing:
        severity, why = LOW, (
            f"it is dead — the binary it starts is not there ({', '.join(missing)}), "
            f"so the unit cannot run at all. Usually a leftover from software that was "
            f"removed or renamed itself; worth deleting once you know which")
    else:
        severity, why = MEDIUM, (
            "no package installed it, so no packaging review looked at what it runs")

    if targets:
        vouched = [f"{t} ({target_owners[t]})" for t in targets if t in target_owners]
        orphan = [t for t in targets if t not in target_owners and t not in missing]
        runs = "; ".join(vouched + [f"{t} (no package owns it)" for t in orphan])
    else:
        runs = "no ExecStart — a timer, or a unit that only orders others"

    detail = f"unit file owned by no package — {why}. Runs: {runs}"
    if _restarts(body):
        # Stated, never scored. 27 of the reference machine's 480 distro units set it,
        # and so do both of its legitimate unowned agents.
        detail += ". Restarts forever (Restart=always)"

    return Finding(
        check="unowned-unit", subject=name, severity=severity, detail=detail,
        summary=("runs from " + suspect if suspect else
                 "dead unit — its binary is gone" if missing else
                 "no package owns this unit"),
        fix=(f"confirm you installed it: systemctl cat {name}; "
             f"check the binary's provenance before removing anything"))


def _user_units(ctx, res: CheckResult) -> None:
    """`~/.config/systemd/user/` for every real user — the non-root branch.

    **Ownership is not the test here, and applying it would be a bug.** A user unit is
    the user's own config; no package ever owns one, so "unowned" would flag every user
    unit on every machine. What is judged instead is where the binary lives — the same
    rule the system half uses to separate a vendor agent in `/opt` from a payload in
    `/var/lib`. Units whose target is unremarkable are counted and listed in the saved
    report, so the coverage is auditable without being noise on screen.
    """
    scan = real_users(ctx.root, readable_only=False)
    unreadable = 0
    for user in scan.users:
        directory = user.home / ".config/systemd/user"
        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            unreadable += 1
            continue
        except OSError:
            continue                      # no user units at all — the common case
        for path in entries:
            if path.suffix not in (".service", ".timer"):
                continue
            if not is_regular_file(path):
                continue
            res.checked += 1
            body = _read(path)
            targets = exec_targets(body)
            suspect = next((s for t in targets if (s := _suspect(t))), "")
            res.detail_rows.append(
                f"{user.name}: {path.name} -> {', '.join(targets) or '(no ExecStart)'}")
            if not suspect:
                continue
            res.findings.append(Finding(
                check="user-unit", subject=f"{user.name}: {path.name}", severity=HIGH,
                detail=(f"a user service runs from {suspect}, which is not a location "
                        f"a service binary belongs in — this is the non-root branch of "
                        f"the June 2026 AUR supply-chain implant"),
                summary=f"user service runs from {suspect}",
                fix=(f"read it: cat {path}; check the binary before removing anything")))

    if unreadable:
        res.blind.append((
            f"user services for {unreadable} account(s)",
            "their home directories are not readable — run as root to include them", ""))


def _system_cron(backend, ctx, res: CheckResult) -> None:
    """Package-managed cron locations, judged on ownership like the system units."""
    jobs = cron.system_jobs(ctx.root)
    res.checked += len(jobs)
    if not jobs:
        return

    owners = backend.map_files_to_packages([str(p) for p, _ in jobs])
    for path, commands in jobs:
        if str(path) in owners:
            continue
        targets = [t for c in commands if (t := cron.argv0(c))]
        suspect = next((s for t in targets if (s := _suspect(t))), "")
        runs = "; ".join(commands) or "the file itself is the scheduled script"
        if suspect:
            severity = HIGH
            why = (f"it runs something from {suspect}, which is not a location a "
                   f"scheduled job's binary belongs in")
        else:
            severity = MEDIUM
            why = "no package installed it, so no packaging review looked at what it runs"
        res.findings.append(Finding(
            check="unowned-cron", subject=str(path.relative_to(ctx.root)),
            severity=severity,
            detail=f"scheduled job owned by no package — {why}. Runs: {runs}",
            summary=(f"scheduled job runs from {suspect}" if suspect
                     else "no package owns this scheduled job"),
            fix=f"read it: cat {path}; confirm you or your software put it there"))


def _user_cron(ctx, res: CheckResult) -> None:
    """Per-user crontabs. Reported as review material; a finding only on location.

    See `cron`'s module docstring: these are never package-owned, so judging them on
    ownership would report every user crontab on every machine.
    """
    jobs = cron.user_jobs(ctx.root)
    res.checked += len(jobs)
    for path, commands in jobs:
        res.detail_rows.append(f"crontab {path.name}: {'; '.join(commands) or '(empty)'}")
        for command in commands:
            target = cron.argv0(command)
            suspect = _suspect(target) if target else ""
            if not suspect:
                continue
            res.findings.append(Finding(
                check="user-cron", subject=f"crontab {path.name}", severity=HIGH,
                detail=(f"a scheduled job runs from {suspect}, which is not a location "
                        f"a scheduled binary belongs in. Runs: {command}"),
                summary=f"scheduled job runs from {suspect}",
                fix=f"read it: crontab -l -u {path.name}"))
    if jobs:
        res.notes.append(
            f"{len(jobs)} per-user crontab(s) exist. No package owns any crontab — "
            f"`crontab -e` creates them — so they are listed in the saved report rather "
            f"than judged on provenance.")
    blocked = cron.unreadable(ctx.root, cron.USER_CRON_DIRS)
    if blocked:
        res.blind.append(("per-user crontabs",
                          f"{', '.join(blocked)} exists but could not be read — "
                          "run as root to include it", ""))


def _at_jobs(ctx, res: CheckResult) -> None:
    """Queued `at` jobs — rare enough that their existence is the report."""
    blocked = cron.unreadable(ctx.root, cron.AT_DIRS)
    if blocked:
        res.blind.append(("queued `at` jobs",
                          f"{', '.join(blocked)} exists but could not be read — "
                          "run as root to include it", ""))
    jobs = cron.at_jobs(ctx.root)
    res.checked += len(jobs)
    if not jobs:
        return
    res.notes.append(
        f"{len(jobs)} queued `at` job(s): {', '.join(p.name for p in jobs)}. A one-shot "
        f"job on a machine that does not otherwise use `at` is worth reading — they are "
        f"listed rather than parsed because an at job is a shell script with a large "
        f"generated preamble.")
    res.detail_rows.extend(f"at job: {p}" for p in jobs)
