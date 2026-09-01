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

## Widened 2026-09-01, and the floor was re-measured before it was

`.socket` and `.path` units joined `.service` and `.timer`, and drop-in overrides became
their own check. All three persist in ways the original scan could not see: a `.socket`
starts its service when something connects, a `.path` starts it when a file appears, and
a drop-in changes a unit that a package owns without altering the unit's own file, so
`cat sshd.service` shows nothing at all.

Counted across four hosts (Manjaro, Debian 13, Ubuntu 26.04, AlmaLinux 9):

===================  =====  =======
subject              files  unowned
===================  =====  =======
`.socket` units        195        0
`.path` units           17        0
drop-in `.conf`         35        0
===================  =====  =======

**247 files added to the scan and not one new finding.** The reference desktop went from
482 files checked to 626 and reported the same four things it reported before.

Two results worth keeping, because a naive version of this check would have got both
wrong:

* **The symlink exclusion carries over to the new suffixes.** `pacman` does not own
  `/etc/systemd/system/nix-daemon.socket`, and it is still not a finding, because the Nix
  installer wrote it as a symlink into `/nix/store` and `_unit_files` skips symlinks. The
  rule that took 41 findings down to 2 for `.service` does the same job here.
* **Packages really do ship drop-ins into `/etc/systemd/system`.** All 8 on the reference
  desktop are package-owned, including `httpd.service.d/hardening.conf`, which belongs to
  `apache`. Treating everything under `/etc` as admin-authored would have been wrong.

**One number that is not a floor.** No host measured has ever had `systemctl edit` run on
it, and that command writes drop-ins to exactly this path. A hand-made override is
therefore indistinguishable from a hijacked one here, and the finding says so instead of
implying a confidence the check has not earned.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import HIGH, LOW, MEDIUM, CheckResult, Finding, is_regular_file
from . import baseline, cron
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
# Re-measured 2026-09-01 rather than taken on trust: wopr and AlmaLinux 9 hold 0 entries,
# Debian 13 holds 3, and all three of Debian's are netplan and networkd generator output
# that no package owns. The directory is real persistence surface, so it belongs in the
# inventory, but not under a test whose answer is known in advance.
UNIT_DIRS = (
    "etc/systemd/system",
    "usr/local/lib/systemd/system",
    "usr/lib/systemd/system",
)

# `.service` and `.timer` were the original two. `.socket` and `.path` were added
# 2026-09-01 because they persist with no always-running process to notice: a `.socket`
# starts its service when something connects, a `.path` starts it when a file appears.
# Measured across four hosts, adding them costs 212 more files to check and produces no
# new findings at all, so the ownership test holds up on the wider set.
UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path")

# Drop-in overrides sit in `<unit>.d/*.conf` beside the unit they modify. Scanned apart
# from unit files because the claim is different: a drop-in does not add a service, it
# changes one that is already installed, so an unowned drop-in is an unreviewed edit to
# somebody else's unit. `.wants/` and `.requires/` are excluded here for the same reason
# `_unit_files` excludes them, and only `.d` directories are read.
DROPIN_GLOB = "*.d/*.conf"

# Boot and login execution that is not a systemd unit. Every directory here is
# package-managed on all four hosts measured, which is what makes "no package owns this"
# mean something. Each entry carries what the location *does*, because "an unowned file"
# is not a finding anybody can act on and "runs as root early in every boot" is.
#
# Measured 2026-09-01 across Manjaro, Debian 13, Ubuntu 26.04 and AlmaLinux 9: 178 regular
# files, 2 of them unowned.
SCRIPT_DIRS = (
    ("usr/lib/systemd/system-generators", "a systemd generator, run as root before "
                                          "almost anything else in the boot"),
    ("etc/systemd/system-generators", "a systemd generator, run as root before almost "
                                      "anything else in the boot"),
    ("etc/init.d", "a SysV init script"),
    ("etc/profile.d", "sourced into every login shell"),
    ("etc/update-motd.d", "run on every interactive SSH login"),
    ("etc/xdg/autostart", "started with every desktop session"),
)

# Three locations from the same family that are deliberately NOT in SCRIPT_DIRS, each
# dropped on measurement rather than on taste:
#
# `/etc/rc*.d`
#     Every entry is a symlink into `/etc/init.d` by design. Debian 13 holds 63 of them
#     and Ubuntu 26.04 holds 40, and neither holds a single regular file. The targets are
#     scanned through `/etc/init.d` already, so this would add nothing but a second name
#     for each one. Same reasoning as the `.wants/` exclusion above.
# `/run/motd.d`
#     Runtime state, not configuration. `85-fwupd` is written there by fwupd on both the
#     reference desktop and Debian 13 and is owned by nothing on either, so the test's
#     answer is known before it runs.
# `/etc/profile` and `/etc/bash.bashrc`
#     **`/etc/profile` is owned by no package on Debian 13 and Ubuntu 26.04.** `dpkg-query
#     -S` exits 1 for it and `base-files` does not list it, while Manjaro and AlmaLinux
#     both own theirs. A rule this good-sounding would have fired on half the hosts
#     measured, on a file that exists on every Linux system. Their content is P3's
#     question, not this one's.

# Content that has no business in a file that runs at boot or at login, whatever package
# owns it. Measured 2026-09-01 over **2,104 startup files on six hosts** (Manjaro, Arch,
# Debian 13, Ubuntu 26.04, AlmaLinux 9, Fedora 44). Every rule below scored **0**.
#
# Three candidates were rejected on the same measurement, and they are the reason this
# list is short:
#
#   eval                  12 hits, every one a distro-shipped /etc/profile.d script.
#                         It is how colorls.sh, lang.sh and which2.sh do their work on
#                         the RHEL family. Six of AlmaLinux's, five of Fedora's.
#   curl or wget at all   1 hit, /etc/update-motd.d/50-motd-news on Ubuntu, which
#                         legitimately fetches news over HTTP. Downloading is ordinary;
#                         piping the download into a shell is not, and that is the rule
#                         that survived.
#   chmod +x              1 hit, AlmaLinux's shipped /etc/rc.local. Weak on its own
#                         anyway: every installer does it.
#
# Two more scored 0 and were still dropped, because a floor of zero is not on its own a
# reason to ship a rule. `python -c` and `perl -e` appear in perfectly ordinary
# ExecStartPre lines, and `bash -i` means little without something to connect it to. What
# is left is five signals whose *meaning* is unambiguous, not merely rare.
CONTENT_SIGNALS = (
    ("LD_PRELOAD", re.compile(r"LD_PRELOAD"),
     "a library is injected into everything this starts, which lets it intercept calls "
     "the program makes without changing the program"),
    ("a download piped straight into a shell",
     re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b", re.I),
     "whatever the server returns is executed, so what this runs is decided somewhere "
     "else and can change between one boot and the next"),
    ("a base64 payload piped into a shell",
     re.compile(r"base64\s+(-d|--decode)[^|]*\|\s*(ba)?sh\b", re.I),
     "the command is encoded rather than written out, which has no purpose here except "
     "to keep it from being read"),
    ("a bash network redirection",
     re.compile(r"/dev/(tcp|udp)/", re.I),
     "/dev/tcp is bash opening a socket, and a startup file has no legitimate reason to "
     "do it"),
    ("netcat executing a program on connect",
     re.compile(r"\bn(c|cat)\b[^#\n]*\s-e\s", re.I),
     "netcat's -e hands a program to whoever connects, which is the shape of a reverse "
     "shell"),
)

#: What starts the service, for unit types that carry no ExecStart of their own.
_NO_EXEC = {
    ".timer": "no ExecStart, it starts its service on a schedule",
    ".socket": "no ExecStart, it starts its service when something connects",
    ".path": "no ExecStart, it starts its service when a file appears or changes",
}

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
    """Real unit files, of every type in :data:`UNIT_SUFFIXES`, in the system dirs.

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
            if path.suffix not in UNIT_SUFFIXES:
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
    _dropins(backend, ctx, res)
    _startup_scripts(backend, ctx, res)
    _user_units(ctx, res)
    _system_cron(backend, ctx, res)
    _user_cron(ctx, res)
    _at_jobs(ctx, res)
    _content_signals(backend, ctx, res)
    # Last, and deliberately so: it enriches findings that are already in `res` and adds
    # one of its own. Running it first would invite a design where the baseline decides
    # what the ownership checks report, which is the thing baseline.py exists not to do.
    _inventory(backend, ctx, res)

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
def scan_content(text: str) -> list[tuple[str, str]]:
    """``[(signal name, the line that matched)]`` for one file's contents.

    Comment lines are skipped before matching. A unit or shell script that *documents*
    `curl … | sh` in a comment is not doing it, and a check that cannot tell those apart
    would report the README-ish header at the top of half the scripts on a machine.
    """
    hits: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        for name, pattern, _ in CONTENT_SIGNALS:
            if pattern.search(line):
                hits.append((name, line[:160]))
    return hits


def _content_signals(backend, ctx, res: CheckResult) -> None:
    """Content that does not belong in a startup file, whoever owns the file.

    Deliberately **not** limited to unowned files, unlike the location rule in
    :func:`_finding`. The floor measured 0 across 2,104 files on six hosts including every
    package-owned one, so there is no cost to reading them all, and the case worth
    catching is precisely a unit a package owns with a line added to it. That is the same
    gap :mod:`fettle.compromise.baseline` exists for, approached from the other side: the
    baseline knows the file changed, this knows what the change says.
    """
    seen: set[str] = set()
    for path, _ in _inventory_subjects(ctx.root):
        text = _read(path)
        if not text:
            continue
        for name, line in scan_content(text):
            why = next(w for n, _, w in CONTENT_SIGNALS if n == name)
            key = f"{path}:{name}"
            if key in seen:
                continue           # one finding per file per signal, not per line
            seen.add(key)
            shown = "/" + str(path.relative_to(ctx.root)) \
                if path.is_relative_to(ctx.root) else str(path)
            res.findings.append(Finding(
                check="startup-content-signal", subject=shown, severity=HIGH,
                summary=f"contains {name}",
                detail=(f"{shown} runs at boot or at login and contains {name}, which "
                        f"scored zero across 2,104 startup files on six clean hosts. "
                        f"{why[0].upper() + why[1:]}. The line is: {line}"),
                fix=f"read the whole file before changing anything: cat {shown}"))


def _inventory_subjects(root: Path) -> list[tuple[Path, str]]:
    """Every startup file on the machine, with the class it belongs to.

    Wider than what the ownership checks report on, by one directory.
    ``/run/systemd/system`` is generator output that nothing owns by construction, so it
    is excluded from the ownership test above and included here: it is real persistence
    surface, and "list it and let the reader judge" is exactly the right treatment for
    something whose ownership answer is known in advance.
    """
    subjects = [(p, "unit") for p in _unit_files(root)]
    subjects += [(p, "drop-in") for p in _dropin_files(root)]
    for rel, _ in SCRIPT_DIRS:
        try:
            entries = sorted((root / rel).iterdir())
        except OSError:
            continue
        subjects += [(p, "script") for p in entries if is_regular_file(p)]
    rc = root / "etc/rc.local"
    if is_regular_file(rc):
        subjects.append((rc, "script"))
    try:
        entries = sorted((root / "run/systemd/system").iterdir())
    except OSError:
        entries = []
    subjects += [(p, "generated") for p in entries if is_regular_file(p)]
    return subjects


def _inventory(backend, ctx, res: CheckResult) -> None:
    """The saved inventory and the comparison against the last run.

    The ownership findings are already in ``res`` by the time this runs and none of them
    is touched. What this adds is a sentence on the ones that are new since the baseline,
    plus the one finding no ownership test can produce: a package-owned file whose
    contents were edited in place.
    """
    subjects = _inventory_subjects(ctx.root)
    if not subjects:
        return
    owners = backend.map_files_to_packages([str(p) for p, _ in subjects])
    appeared = baseline.apply(ctx, res, subjects, owners)
    if not appeared:
        return
    for finding in res.findings:
        # Match on the subject the ownership checks actually printed, which is a bare
        # unit name for units and a rooted path for scripts, so both spellings are tried.
        if any(p.endswith(finding.subject) or p == finding.subject for p in appeared):
            # rstrip first: the detail strings do not all end in punctuation, and
            # concatenating produced "…orders others It was not here…" on the first
            # live run.
            finding.detail = (finding.detail.rstrip(". ") +
                              ". It was not here when the startup baseline was taken, "
                              "so it arrived since.")


def _startup_scripts(backend, ctx, res: CheckResult) -> None:
    """Boot and login execution that no systemd unit describes.

    Six directories, one question, and it is the same question the unit scan asks. What
    changes between them is only how the thing gets run: a generator runs as root before
    the boot has properly started, a `profile.d` script is sourced into every login shell,
    an `update-motd.d` script runs on every interactive SSH login.

    Measured 2026-09-01: 178 regular files across four hosts, **2 unowned**. Those two are
    `/etc/profile.d/nix.sh` on the reference desktop, written by the Nix installer, and
    `/etc/update-motd.d/60-unminimize` on Ubuntu 26.04. Both are real, both are explicable
    in one line, and that is the bar this check was calibrated to in the first place.
    """
    root = ctx.root
    subjects: list[tuple[Path, str]] = []
    unreadable: list[str] = []

    for rel, what in SCRIPT_DIRS:
        try:
            entries = sorted((root / rel).iterdir())
        except PermissionError:
            unreadable.append("/" + rel)
            continue
        except OSError:
            continue          # not present on this distribution, which is the norm
        subjects.extend((p, what) for p in entries if is_regular_file(p))

    res.checked += len(subjects)
    if subjects:
        owners = backend.map_files_to_packages([str(p) for p, _ in subjects])
        for path, what in subjects:
            if str(path) in owners:
                continue
            shown = "/" + str(path.relative_to(root)) if path.is_relative_to(root) \
                else str(path)
            res.findings.append(Finding(
                check="unowned-startup-script", subject=shown, severity=MEDIUM,
                detail=(f"{shown} is {what}, and no package owns it. Nothing about the "
                        f"file says who put it there, so the only way to account for it "
                        f"is to recognise it"),
                summary=f"no package owns this, and it is {what}",
                fix=f"read it: cat {shown}"))

    if unreadable:
        res.blind.append((
            f"startup scripts in {', '.join(unreadable)}",
            "the directory could not be read, so anything in it was not examined", ""))

    _rc_local(backend, ctx, res)


def _rc_local(backend, ctx, res: CheckResult) -> None:
    """`/etc/rc.local`, which only runs when it is executable.

    Its presence is not a signal. AlmaLinux 9 ships the file, owned by a package and
    without the execute bit, and the other three hosts do not have it at all. The state
    worth reporting is the one where it would actually run and nothing accounts for it.
    """
    path = ctx.root / "etc/rc.local"
    if not is_regular_file(path):
        return
    res.checked += 1
    if not os.access(path, os.X_OK):
        return                # present but inert, which is AlmaLinux's shipped state
    if str(path) in backend.map_files_to_packages([str(path)]):
        return
    res.findings.append(Finding(
        check="unowned-startup-script", subject="/etc/rc.local", severity=MEDIUM,
        detail=("/etc/rc.local is executable, so its contents run late in every boot as "
                "root, and no package owns it. The file is inert unless the execute bit "
                "is set, and here it is set"),
        summary="executable and owned by no package, so it runs at every boot",
        fix="read it: cat /etc/rc.local"))


def _dropin_files(root: Path) -> list[Path]:
    """Real `<unit>.d/*.conf` drop-ins in the system unit directories."""
    found: list[Path] = []
    for rel in UNIT_DIRS:
        try:
            entries = sorted((root / rel).glob(DROPIN_GLOB))
        except OSError:
            continue
        found.extend(p for p in entries if is_regular_file(p))
    return found


def _dropins(backend, ctx, res: CheckResult) -> None:
    """Overrides that change a unit without touching the unit's own file.

    A drop-in is invisible to anyone reading the unit it modifies, which is what makes it
    worth a separate check: `cat sshd.service` shows none of it, and `systemctl cat
    sshd.service` shows all of it.

    Measured 2026-09-01 across four hosts: 8 drop-ins on wopr, 9 on Debian 13, 11 on
    Ubuntu 26.04, 7 on AlmaLinux 9, and **none unowned on any of them**. The limit of that
    number is worth stating, because none of those hosts has ever had `systemctl edit`
    run on it. That command writes to exactly this path, so a hand-made override is
    indistinguishable from a hijack here and the finding says so rather than implying a
    certainty the check does not have.
    """
    dropins = _dropin_files(ctx.root)
    if not dropins:
        return
    res.checked += len(dropins)

    owners = backend.map_files_to_packages([str(p) for p in dropins])
    unowned = [p for p in dropins if str(p) not in owners]

    bodies = {p: _read(p) for p in unowned}
    targets = {p: exec_targets(t) for p, t in bodies.items()}
    flat = sorted({t for ts in targets.values() for t in ts})
    target_owners = backend.map_files_to_packages(flat) if flat else {}

    for path in unowned:
        res.findings.append(
            _dropin_finding(path, bodies[path], targets[path], target_owners))
    res.detail_rows.extend(f"{p.parent.name}/{p.name}: {_directives(bodies.get(p, ''))}"
                           for p in unowned)


def _directives(body: str) -> str:
    """The settings a drop-in actually applies, without the section headers or comments."""
    lines = [ln.strip() for ln in body.splitlines()]
    return "; ".join(ln for ln in lines
                     if "=" in ln and not ln.startswith(("#", ";", "["))) or "(empty)"


def _dropin_finding(path: Path, body: str, targets: list[str],
                    target_owners: dict[str, str]) -> Finding:
    """One unowned drop-in, graded the same way an unowned unit is."""
    unit = path.parent.name[: -len(".d")]
    suspect = next((s for t in targets if (s := _suspect(t))), "")
    vouched = [f"{t} ({target_owners[t]})" if t in target_owners
               else f"{t} (no package owns it)" for t in targets]

    if suspect:
        severity, why = HIGH, (
            f"it makes {unit} run something from {suspect}, which is not a location a "
            f"service binary belongs in")
    else:
        severity, why = MEDIUM, (
            f"nothing that ships {unit} put this here. `systemctl edit` writes to this "
            f"path too, so an override you made by hand looks the same as one you did "
            f"not, and this check cannot tell them apart")

    detail = (f"drop-in override for {unit} owned by no package. {why}. "
              f"Sets: {_directives(body)}")
    if vouched:
        detail += f". Runs: {'; '.join(vouched)}"

    return Finding(
        check="unowned-dropin", subject=f"{path.parent.name}/{path.name}",
        severity=severity, detail=detail,
        summary=(f"override makes {unit} run from {suspect}" if suspect
                 else f"no package owns this override for {unit}"),
        fix=f"see everything that applies to it: systemctl cat {unit}")


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
        # Each of these persists with no always-running process to notice, which is the
        # reason they are scanned at all. Naming the trigger is the whole value of the
        # line, so it is not collapsed into one sentence about "a unit with no ExecStart".
        runs = _NO_EXEC.get(path.suffix, "no ExecStart, a unit that only orders others")

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
            if path.suffix not in UNIT_SUFFIXES:
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
            "their home directories are not readable — run it without --dry-run and fettle elevates for you", ""))


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
                          "run it without --dry-run and fettle elevates for you", ""))


def _at_jobs(ctx, res: CheckResult) -> None:
    """Queued `at` jobs — rare enough that their existence is the report."""
    blocked = cron.unreadable(ctx.root, cron.AT_DIRS)
    if blocked:
        res.blind.append(("queued `at` jobs",
                          f"{', '.join(blocked)} exists but could not be read — "
                          "run it without --dry-run and fettle elevates for you", ""))
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
