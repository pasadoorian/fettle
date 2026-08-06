"""Service exposure — how much of the system can each running service reach?

``systemd-analyze security`` scores every unit 0–10 on how little the sandbox around
it restricts. The score is genuinely useful review material and a genuinely bad
finding, and keeping those apart is most of what this module does.

**A high score is not a defect.** ``sshd.service`` scores 9.6 UNSAFE on the machine
this was written against, and that is correct: it runs as root and opens a listening
socket because that is its job. So does ``docker.service``, ``libvirtd.service``,
``gdm.service``. A check that reports eighteen "UNSAFE" services on a working desktop
has told the reader nothing they can act on, and has taught them to skip the section.
The tool that prompted this work printed all sixty-seven units, unfiltered, in its
findings stream.

So this axis reports two different things:

* **Findings** — units at high exposure whose unit file is owned by **no package**.
  That is a fact, not a judgement: something outside the package manager installed a
  service, nobody's packaging review looked at it, and it runs with wide access. It
  is also the one thing here that fettle can state without inventing a taxonomy of
  "vendor" versus "distro".
* **Review material** — the worst running-or-enabled units with their owning package,
  written to the saved report rather than the screen.

Filtering to **running or enabled** does the rest of the work: on the reference
machine that is 37 units rather than 67, and 18 UNSAFE rather than 42. A unit that
exists but has never run is not exposure.
"""

from __future__ import annotations

import json

from ... import command
from . import LOW, MEDIUM, AxisResult, Finding

# `systemd-analyze security` predicate thresholds, from systemd's own table. Used to
# decide what counts as "high exposure", never to decide that something is wrong.
UNSAFE = 9.0
EXPOSED = 7.0

# How many rows of review material to write to the saved report.
_DETAIL_ROWS = 15

# How many missing directives to name per finding. The per-unit query is 7ms and
# structured, so this costs nothing — but a finding that lists forty directives is
# back to being a wall of text.
_NAME_DIRECTIVES = 3


def _run(argv: list[str]) -> tuple[int, str]:
    proc = command.run(argv, capture=True)
    return proc.returncode, (proc.stdout or "")


def is_template(unit: str) -> bool:
    """``getty@.service`` — a pattern for making units, not a unit.

    Worth its own function because getting this wrong is expensive in a way that is not
    obvious: ``systemctl show`` **fails the entire batch** on a template name, exits 1
    and prints nothing, so a single one anywhere in the list blanks every unit's owner.
    Every service at high exposure then looks unpackaged, which is a wall of false
    findings from the one axis built to avoid exactly that. And ``list-unit-files
    --state=enabled`` returns ``getty@.service`` on an ordinary desktop.
    """
    name, _, _ = unit.partition(".")
    return name.endswith("@")


def _active_units() -> set[str]:
    """Units that are running, plus units enabled to start at boot.

    Both halves matter and neither implies the other: a socket-activated daemon may be
    enabled and not currently running, and a hand-started one may be running and not
    enabled. Exposure applies to either.

    ``list-unit-files --state=enabled`` costs about **1.4 s** because it stats every
    unit file on disk, and it is kept anyway. ``systemctl show '*.service'`` answers in
    149 ms and was tried — but its glob only matches units systemd has **loaded**, so
    a service that is enabled and has never started is simply absent from it. That is
    the exact category the paragraph above exists to include, and it is not
    hypothetical: on the machine this was written against it dropped one of the two
    unpackaged agent units, which was a real finding. A second of wall clock is not
    worth silently losing a class of result.
    """
    units: set[str] = set()
    for argv in (["systemctl", "list-units", "--type=service", "--state=running",
                  "--no-legend", "--no-pager", "--plain"],
                 ["systemctl", "list-unit-files", "--type=service", "--state=enabled",
                  "--no-legend", "--no-pager", "--plain"]):
        rc, text = _run(argv)
        if rc != 0:
            continue
        for line in text.splitlines():
            parts = line.split()
            if parts and parts[0].endswith(".service") and not is_template(parts[0]):
                units.add(parts[0])
    return units


def _parse_fragments(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    unit = ""
    for line in text.splitlines():
        if line.startswith("Id="):
            unit = line[3:].strip()
        elif line.startswith("FragmentPath=") and unit:
            path = line[len("FragmentPath="):].strip()
            if path:
                out[unit] = path
    return out


def _fragment_paths(units: list[str]) -> dict[str, str]:
    """unit -> the path of its unit file, in one call rather than one call per unit.

    Falls back to asking one at a time when the batch comes back empty. ``systemctl
    show`` aborts the whole batch on a single unresolvable name, and the consequence
    here is not a missing row — it is that *no* unit gets an owner, so every service
    at high exposure is reported as unpackaged. A slow correct answer beats a fast
    wall of false findings, and the fallback only runs when the batch already failed.
    """
    if not units:
        return {}
    _, text = _run(["systemctl", "show", "-p", "Id", "-p", "FragmentPath", *units])
    out = _parse_fragments(text)
    if out or len(units) == 1:
        return out
    for unit in units:
        _, one = _run(["systemctl", "show", "-p", "Id", "-p", "FragmentPath", unit])
        out.update(_parse_fragments(one))
    return out


def missing_directives(unit: str, limit: int = _NAME_DIRECTIVES) -> list[str]:
    """The unset hardening directives that cost this unit the most, worst first.

    Names what to *do* about a finding. "snapd.service scores 9.9" is a number;
    "runs as root, no system-call filter, world-readable UMask" is a review.
    """
    rc, text = _run(["systemd-analyze", "security", "--json=short", unit])
    if rc != 0 or not text.strip():
        return []
    try:
        rows = json.loads(text)
    except (ValueError, TypeError):
        return []
    unset = [r for r in rows if isinstance(r, dict) and r.get("set") is False]
    unset.sort(key=lambda r: -_num(r.get("exposure")))
    seen, names = set(), []
    for r in unset:
        # Many rows share one description (SystemCallFilter has a dozen), and listing
        # "does not filter system calls" three times reads as three problems.
        desc = str(r.get("description") or r.get("name") or "").strip()
        if not desc or desc in seen:
            continue
        seen.add(desc)
        names.append(desc)
        if len(names) >= limit:
            break
    return names


def _num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def run(backend, ctx) -> AxisResult:
    res = AxisResult(name="services", title="Service exposure")

    if not command.which("systemctl"):
        # Not a failure and not blindness: a host without systemd has no unit files to
        # be exposed. Most containers land here.
        res.na = "this host does not use systemd"
        return res
    if not command.which("systemd-analyze"):
        res.blind.append(("service exposure was NOT checked",
                          "systemd-analyze is not available", ""))
        return res

    rc, text = _run(["systemd-analyze", "security", "--json=short"])
    if rc != 0 or not text.strip():
        # systemd is installed but not booted (the usual container case), or the
        # --json interface is absent on a much older systemd. Either way this run did
        # not look, and must not be read as having found nothing.
        res.blind.append(("service exposure was NOT checked",
                          "systemd-analyze security produced no usable output — "
                          "systemd may not be the running init here", ""))
        return res
    try:
        rows = json.loads(text)
    except (ValueError, TypeError) as exc:
        res.blind.append(("service exposure was NOT checked",
                          f"could not parse systemd-analyze output ({exc})", ""))
        return res

    active = _active_units()
    scored = [(str(r.get("unit") or ""), _num(r.get("exposure")),
               str(r.get("predicate") or ""))
              for r in rows if isinstance(r, dict)]
    # A unit systemd scored but that is neither running nor enabled is not exposure.
    # If the active-set queries failed entirely, fall back to scoring everything rather
    # than silently reporting nothing — but say so, because the output is then noisier
    # than it should be for a reason the reader cannot see.
    if active:
        selected = [s for s in scored if s[0] in active]
    else:
        selected = scored
        res.notes.append("could not list running/enabled units, so every unit systemd "
                         "knows about is included — expect units that never run")
    res.checked = len(selected)
    if not selected:
        return res

    paths = _fragment_paths([u for u, _, _ in selected])
    owners = backend.map_files_to_packages(set(paths.values())) if paths else {}

    selected.sort(key=lambda s: (-s[1], s[0]))
    for unit, exposure, predicate in selected:
        path = paths.get(unit, "")
        owner = owners.get(path, "")
        if exposure < EXPOSED or owner:
            continue
        # Unowned unit file at wide exposure. The finding is the provenance, not the
        # score: the score is why it matters, the missing owner is what is wrong.
        why = missing_directives(unit)
        # The unit file's path is deliberately not repeated here: it is long, it is
        # usually just the unit name again under /etc/systemd/system, and `systemctl
        # cat` in the fix line shows it along with the contents worth reading.
        detail = (f"exposure {exposure:.1f} {predicate}, and no package owns its unit "
                  f"file — something outside the package manager installed a service "
                  f"with wide access to this system")
        if why:
            detail += f". Unrestricted: {'; '.join(why)}"
        res.findings.append(Finding(
            check="unpackaged-service", subject=unit,
            severity=MEDIUM if exposure >= UNSAFE else LOW, detail=detail,
            fix=f"confirm you installed this deliberately: systemctl cat {unit}"))

    bands: dict[str, int] = {}
    for _, _, predicate in selected:
        bands[predicate] = bands.get(predicate, 0) + 1
    order = ("UNSAFE", "EXPOSED", "MEDIUM", "OK", "SAFE")
    shown = [f"{bands[b]} {b.lower()}" for b in order if bands.get(b)]
    res.notes.append(
        f"{len(selected)} running or enabled service(s): {', '.join(shown)}. A high "
        f"score is not by itself a defect — sshd and docker score badly because they "
        f"legitimately need root and sockets. The table is in the saved report.")

    res.detail_rows.append(f"{'EXPOSURE':<10}{'UNIT':<44}OWNER")
    for unit, exposure, predicate in selected[:_DETAIL_ROWS]:
        owner = owners.get(paths.get(unit, ""), "") or "(no package owns it)"
        res.detail_rows.append(
            f"{exposure:<4.1f}{predicate:<6}{unit:<44}{owner}")
    if len(selected) > _DETAIL_ROWS:
        res.detail_rows.append(f"… plus {len(selected) - _DETAIL_ROWS} more, "
                               f"lower-exposure")
    return res
