"""Filesystem hygiene — can a local user tamper with shared directories?

Two questions, both answered by stat and ``/proc/mounts``, with no directory walk:

1. **Is a world-writable directory missing its sticky bit?** Without it, any local
   user can delete or rename any other user's files there, regardless of who owns
   them. This is the one check here that finds real bugs on real machines.
2. **Does a separate filesystem lack ``nosuid`` / ``noexec`` / ``nodev``?** Only
   askable when the path is its own mount — you cannot set mount options on a
   directory that lives inside ``/``, so on a single-filesystem host the honest
   answer is "not applicable", not "missing".

Deliberately no walk. Lynis's equivalent (FILE-6311) scans the whole filesystem for
world-writable files and took **19 seconds** on the machine this was written against,
earning its own "long execution" warning in its own findings stream. Every other axis
here is sub-second and this one stays that way. The paths examined are a short list
the user can extend via ``[hardening] filesystem_paths``.
"""

from __future__ import annotations

import os
import stat as statmod
from pathlib import Path

from . import HIGH, LOW, MEDIUM, AxisResult, Finding

# Checked in this order. `/` is here for the world-writable check only — no mount
# options are expected on a root filesystem, since you cannot noexec the thing the
# binaries live on.
DEFAULT_PATHS = ("/", "/tmp", "/var/tmp", "/dev/shm", "/home", "/var", "/boot")

# World-writable *by design* — these are shared scratch space, so the finding is a
# missing sticky bit rather than the write bit itself. Anywhere else, world-writable
# is the finding.
SHARED = frozenset({"/tmp", "/var/tmp", "/dev/shm"})

# Mount options worth having, per path. Conservative on purpose: `/var` gets `nodev`
# only, because `nosuid` there breaks package scriptlets on some distros, and a
# recommendation that breaks the system is worse than no recommendation.
WANT = {
    "/tmp": ("nosuid", "noexec", "nodev"),
    "/var/tmp": ("nosuid", "noexec", "nodev"),
    "/dev/shm": ("nosuid", "noexec", "nodev"),
    "/home": ("nosuid", "nodev"),
    "/boot": ("nosuid", "nodev"),
    "/var": ("nodev",),
}

# What each missing option actually costs, and how much. `nodev` is the mildest by a
# distance — it defends against a device node planted on a filesystem you already
# have to be root to mount — so calling it medium alongside `nosuid` would flatten a
# real difference.
_OPTION_RISK = {
    "nosuid": (MEDIUM, "a setuid binary placed here would keep its privileges"),
    "noexec": (MEDIUM, "a payload written here can be executed directly"),
    "nodev":  (LOW, "a device node placed here would be honoured"),
}


def _unescape(field: str) -> str:
    """Undo the octal escaping the kernel applies to mount fields (``\\040`` = space)."""
    if "\\" not in field:
        return field
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and field[i + 1:i + 4].isdigit() and len(field) >= i + 4:
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def read_mounts(root: Path = Path("/")) -> dict[str, set[str]] | None:
    """Mount point -> its options. ``None`` when the table cannot be read.

    The **last** entry for a mount point wins, because that is the one in effect: a
    later mount over the same directory shadows the earlier one, and reading the first
    would report options that nothing is currently using.
    """
    src = root / "proc/mounts" if root != Path("/") else Path("/proc/mounts")
    try:
        text = src.read_text(errors="replace")
    except OSError:
        return None
    table: dict[str, set[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        table[_unescape(parts[1])] = set(parts[3].split(","))
    return table


def extra_paths(cfg) -> list[str]:
    """Additional paths from ``[hardening] filesystem_paths``.

    Additive rather than a replacement: a user who wants ``/srv`` watched should not
    have to restate the built-in list to get it, and silently losing ``/tmp`` because
    someone added one entry is the kind of surprise that makes a security check
    useless. To drop a built-in path, exclude it with ``exclude_paths``.
    """
    h = getattr(cfg, "hardening", None) or {}
    if not isinstance(h, dict):
        return []
    raw = h.get("filesystem_paths") or []
    if not isinstance(raw, (list, tuple)):
        return []
    return [str(p) for p in raw if str(p).strip()]


def run(backend, ctx) -> AxisResult:
    res = AxisResult(name="filesystem", title="Filesystem hygiene")
    root = ctx.root
    paths: list[str] = list(DEFAULT_PATHS)
    for p in extra_paths(ctx.config):
        if p not in paths:
            paths.append(p)

    mounts = read_mounts(root)
    if mounts is None:
        # The mode checks below still work — only the mount-option half is blind, and
        # saying so precisely beats declaring the whole axis unavailable.
        res.blind.append(("mount options were NOT checked",
                          "could not read /proc/mounts", ""))

    inherited: list[str] = []
    for p in paths:
        target = root / p.lstrip("/") if root != Path("/") else Path(p)
        try:
            st = os.stat(target)
        except OSError:
            continue                     # absent path: the question does not arise
        if not statmod.S_ISDIR(st.st_mode):
            continue
        res.checked += 1
        mode = statmod.S_IMODE(st.st_mode)

        # -- world-writable, with or without the sticky bit --------------------
        if mode & statmod.S_IWOTH:
            if not mode & statmod.S_ISVTX:
                res.findings.append(Finding(
                    check="sticky-bit", subject=p, severity=HIGH,
                    detail=(f"world-writable ({mode:04o}) with no sticky bit — any "
                            f"local user can delete or replace another user's files "
                            f"here, whoever owns them"),
                    fix=f"chmod +t {p}"))
            elif p not in SHARED:
                res.findings.append(Finding(
                    check="world-writable", subject=p, severity=MEDIUM,
                    detail=(f"world-writable ({mode:04o}); the sticky bit limits the "
                            f"damage but any local user can still create files here"),
                    fix=f"chmod o-w {p}"))
        elif p in SHARED:
            pass                          # correct: shared scratch, not world-writable

        # -- mount options, only where they can exist --------------------------
        want = WANT.get(p)
        if not want or mounts is None:
            continue
        if p not in mounts:
            inherited.append(p)           # lives inside another filesystem
            continue
        have = mounts[p]
        for opt in want:
            if opt in have:
                continue
            sev, why = _OPTION_RISK[opt]
            res.findings.append(Finding(
                check=f"mount-{opt}", subject=p, severity=sev,
                detail=f"mounted without {opt} — {why}",
                fix=f"add {opt} to the {p} entry in /etc/fstab"))

    if inherited:
        # One line, not one per path. These are not findings: mount options are a
        # property of a filesystem, and asking for them on a directory that is not one
        # is asking the user to repartition — advice, not a defect.
        res.notes.append(
            f"not separate filesystems, so mount options are inherited from their "
            f"parent and cannot be set independently: {', '.join(inherited)}")
    return res
