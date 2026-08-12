"""Running processes — is anything executing that the package manager never put here?

One question asked five ways. The first is the sharpest and the cheapest.

* **Executed from memory** — a process whose binary was never a file at all.
* **Deleted but running** — a process whose binary is gone from disk.
* **Listening sockets** — a service accepting connections that nothing vouches for.
* **Promiscuous interfaces** — a sniffer, or a bridge.
* **Regular files under `/dev`** — a place to keep things where nobody looks.

**Fileless execution is the one to care about.** A process running from `memfd_create`
has no file to hash, no package to own it, and nothing for `pkg-integrity` to verify —
it is the technique modern Linux malware converged on precisely because it defeats
every check that starts by looking at a file. chkrootkit 0.59 added a test for it and
**that test cannot fire**: `ls -alR /proc/*/exe | grep "^\\/memfd:.*?\\(deleted\\)"`
anchors `^` to a line beginning `lrwxrwxrwx 1 root root 0 …`, and `.*?` is a PCRE lazy
quantifier that plain `grep` reads as `.*` followed by a literal `?`. Verified against a
synthetic line of exactly the right shape: it matches neither the original pattern nor
the anchor-stripped one. The idea is right, so it is implemented here properly.

## The measured floor

On the reference desktop: **0** memfd processes, **0** promiscuous interfaces, **0**
regular files under `/dev`, and **0** unowned listener binaries. Two processes are
running deleted binaries and neither is a finding at High — one is package-owned
(upgraded in place), one is a self-updating AppImage in `~/.local/bin`.

The socket check is the one with a real coverage limit, and it is reported rather than
hidden: mapping a listening socket to the process holding it means reading
`/proc/<pid>/fd`, which an ordinary user cannot do for anyone else's processes.
Unprivileged on the reference machine, **9 of 26 listening sockets resolved** — the
other 17 belong to root or other users. Reporting "no unowned listeners" from a third
of the data would be a clean result over an unasked question.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from . import CRITICAL, HIGH, LOW, MEDIUM, CheckResult, Finding, is_directory

# Locations a running binary should not have come from. Same list as the persistence
# checks use, and for the same reason: /opt and /usr/local are where the FHS puts
# software the package manager did not install, so they are not on it.
SUSPECT_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/var/lib/",
                "/var/cache/", "/var/spool/")

# Legitimately full of things that are not device nodes.
DEV_EXEMPT = ("shm", "pts", "mqueue", "hugepages")

IFF_PROMISC = 0x100


def run(backend, ctx) -> CheckResult:
    res = CheckResult(name="processes", title="Running processes")
    _executables(backend, ctx, res)
    _listeners(backend, ctx, res)
    _promiscuous(ctx, res)
    _dev_files(ctx, res)
    return res


def _suspect(path: str) -> str:
    for prefix in SUSPECT_DIRS:
        if path.startswith(prefix):
            return prefix.rstrip("/")
    return ""


def _pids(root: Path) -> list[str]:
    try:
        return sorted((e for e in os.listdir(root / "proc") if e.isdigit()), key=int)
    except OSError:
        return []


def _exe(root: Path, pid: str) -> str:
    try:
        return os.readlink(root / f"proc/{pid}/exe")
    except OSError:
        return ""


def _cmdline(root: Path, pid: str) -> str:
    try:
        raw = (root / f"proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return " ".join(raw.decode("utf-8", "replace").split("\0")).strip()


# ------------------------------------------------------- memfd and deleted binaries


def _executables(backend, ctx, res: CheckResult) -> None:
    root = ctx.root
    pids = _pids(root)
    if not pids:
        res.blind.append(("running processes",
                          "/proc could not be listed — nothing was examined", ""))
        return
    res.checked += len(pids)

    memfd: list[tuple[str, str]] = []
    deleted: dict[str, list[str]] = {}
    for pid in pids:
        target = _exe(root, pid)
        if not target:
            continue
        if target.startswith("/memfd:"):
            memfd.append((pid, target))
        elif target.endswith(" (deleted)"):
            deleted.setdefault(target[: -len(" (deleted)")], []).append(pid)

    for pid, target in memfd:
        res.findings.append(Finding(
            check="memfd-exec", subject=f"pid {pid}", severity=CRITICAL,
            detail=(f"this process is running from memory ({target}) — its executable "
                    f"was never written to disk, so there is no file to hash, no "
                    f"package that could own it and nothing for pkg-integrity to "
                    f"verify. Command: {_cmdline(root, pid) or '(unreadable)'}"),
            summary="running from memory, never touched disk",
            fix=(f"capture before it exits: cat /proc/{pid}/maps; "
                 f"cp /proc/{pid}/exe /tmp/sample-{pid} — and see the preservation "
                 f"note above")))

    if not deleted:
        return
    owners = backend.map_files_to_packages(sorted(deleted))
    stale_owned = [p for p in deleted if p in owners]

    for path, holders in sorted(deleted.items()):
        if path in owners:
            continue
        suspect = _suspect(path)
        pid = holders[0]
        if suspect:
            severity, why = HIGH, (
                f"it ran from {suspect} and then deleted itself — that combination is "
                f"how a dropper covers its tracks")
        else:
            # The reference machine's case: a self-updating AppImage in ~/.local/bin.
            # True, worth knowing, and not an alarm.
            severity, why = LOW, (
                "no package owns it, so nothing can say what it was. Usually an "
                "application that updated itself while running")
        res.findings.append(Finding(
            check="deleted-exe", subject=f"pid {pid}", severity=severity,
            detail=(f"running a binary that is no longer on disk ({path}) — {why}. "
                    f"Command: {_cmdline(root, pid) or '(unreadable)'}"),
            summary=("deleted binary from " + suspect if suspect
                     else "running a binary that is gone"),
            fix=(f"the file is still readable through the kernel: "
                 f"cp /proc/{pid}/exe /tmp/sample-{pid}")))

    if stale_owned:
        res.notes.append(
            f"{len(stale_owned)} package-owned binar(ies) were replaced by an upgrade "
            f"while still running, so those processes are executing code that is no "
            f"longer on disk. Not a finding — but restarting them is how they pick up "
            f"the fix they were upgraded for.")


# ----------------------------------------------------------------- listening sockets


def _socket_inodes(root: Path) -> dict[str, tuple[str, int]]:
    """inode -> (family, port) for every socket in a listening state."""
    out: dict[str, tuple[str, int]] = {}
    for family, rel, state in (("tcp", "proc/net/tcp", "0A"),
                               ("tcp6", "proc/net/tcp6", "0A"),
                               ("udp", "proc/net/udp", "07"),
                               ("udp6", "proc/net/udp6", "07")):
        try:
            lines = (root / rel).read_text(errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != state:
                continue
            try:
                port = int(fields[1].rsplit(":", 1)[1], 16)
            except (IndexError, ValueError):
                continue
            out[fields[9]] = (family, port)
    return out


def _fd_owners(root: Path) -> tuple[dict[str, str], int]:
    """socket inode -> pid, and how many processes would not let us look."""
    owners: dict[str, str] = {}
    denied = 0
    for pid in _pids(root):
        fd_dir = root / f"proc/{pid}/fd"
        try:
            entries = os.listdir(fd_dir)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        for fd in entries:
            try:
                target = os.readlink(fd_dir / fd)
            except OSError:
                continue
            if target.startswith("socket:["):
                owners[target[8:-1]] = pid
    return owners, denied


def _listeners(backend, ctx, res: CheckResult) -> None:
    """A service accepting connections whose binary no package installed.

    The modern replacement for rkhunter's `backdoorports.dat`, which lists port numbers.
    A port number means nothing — 4444 is as legitimate as 443 if something you
    installed is behind it. A listener nobody can account for means something whatever
    port it is on.
    """
    root = ctx.root
    sockets = _socket_inodes(root)
    if not sockets:
        return
    res.checked += len(sockets)

    owners, denied = _fd_owners(root)
    resolved = {ino: owners[ino] for ino in sockets if ino in owners}
    unresolved = len(sockets) - len(resolved)

    exes: dict[str, list[tuple[str, int]]] = {}
    for ino, pid in resolved.items():
        target = _exe(root, pid)
        if target and not target.endswith(" (deleted)"):
            exes.setdefault(target, []).append(sockets[ino])

    packaged = backend.map_files_to_packages(sorted(exes)) if exes else {}
    for path, endpoints in sorted(exes.items()):
        if path in packaged:
            continue
        where = ", ".join(f"{fam}/{port}" for fam, port in sorted(set(endpoints)))
        suspect = _suspect(path)
        res.findings.append(Finding(
            check="unowned-listener", subject=path,
            severity=HIGH if suspect else MEDIUM,
            detail=(f"listening on {where}, and no package owns the binary behind it"
                    + (f" — which runs from {suspect}, where a service binary does not "
                       f"belong" if suspect else
                       ". Vendor agents look like this too, so the question is whether "
                       "you installed it")),
            summary=f"unowned process listening on {where}",
            fix=f"identify it: ss -tlnp | grep -F {path.rsplit('/', 1)[-1]}"))

    if unresolved:
        # The honest half. Unprivileged, most listeners belong to processes whose
        # /proc/<pid>/fd this user cannot read, and a clean result over a third of the
        # data is the failure this action exists to avoid.
        res.blind.append((
            f"{unresolved} of {len(sockets)} listening socket(s)",
            f"could not be traced to a process — /proc/<pid>/fd is unreadable for "
            f"{denied} process(es) without root, so run it without --dry-run and fettle elevates for you", ""))


# --------------------------------------------------------- interfaces and /dev files


def _promiscuous(ctx, res: CheckResult) -> None:
    """Interfaces accepting every frame on the segment — excluding the ones that must.

    `/sys/class/net/<if>/flags` is a hex word and `IFF_PROMISC` is `0x100`. Read
    directly rather than through `ip`, which is worth noting because **the two do not
    agree**: on the reference machine `ip link` prints
    `<BROADCAST,MULTICAST,UP,LOWER_UP>` with no `PROMISC` while sysfs has the bit set,
    and `ip -d` reports the truth as a separate `promiscuity 2` counter. Anyone
    cross-checking this finding with `ip link` and seeing no PROMISC would reasonably
    conclude fettle was wrong.

    **Bridge ports are excluded, and skipping that exclusion makes the check useless.**
    A bridge member has to accept frames not addressed to it — that is what bridging
    *is* — so the kernel puts every port into promiscuous mode. On the reference machine
    both promiscuous interfaces are bridge ports: the physical NIC enslaved to `bridge0`
    for VMs, and a `veth` on a docker bridge. Reporting those would fire on every VM
    host and every container host in existence. `/sys/class/net/<if>/brport` exists for
    exactly the bridge ports and nothing else, which makes it a clean discriminator.

    What is left is an interface put into promiscuous mode by something that is not
    bridging — a packet capture, or a sniffer.
    """
    net = ctx.root / "sys/class/net"
    if not is_directory(net):
        return
    try:
        interfaces = sorted(p.name for p in net.iterdir())
    except OSError:
        return

    bridge_ports: list[str] = []
    for name in interfaces:
        try:
            flags = int((net / name / "flags").read_text().strip(), 16)
        except (OSError, ValueError):
            continue
        res.checked += 1
        if not flags & IFF_PROMISC:
            continue
        if is_directory(net / name / "brport"):
            bridge_ports.append(name)
            continue
        res.findings.append(Finding(
            check="promiscuous-interface", subject=name, severity=MEDIUM,
            detail=(f"{name} is in promiscuous mode, so it accepts every frame on the "
                    f"segment rather than the ones addressed to it — and it is not a "
                    f"bridge port, which is the one thing that needs this. A running "
                    f"packet capture does it too; nothing else should"),
            summary="interface is in promiscuous mode",
            fix=(f"find out what put it there: ip -d link show {name} (look at "
                 f"'promiscuity', not the flag list); ss -0 -p")))

    if bridge_ports:
        res.notes.append(
            f"{len(bridge_ports)} interface(s) are promiscuous because they are bridge "
            f"ports, which is how bridging works: {', '.join(bridge_ports)}. Not "
            f"findings, but listed so the count is auditable.")


def _dev_files(ctx, res: CheckResult) -> None:
    """Regular files where only device nodes belong.

    An old rkhunter/chkrootkit idea that is still true and still cheap: `/dev` is a
    place to keep a payload where nobody thinks to look, and legitimate regular files
    there are rare. `shm`, `pts`, `mqueue` and `hugepages` are exempt — they are
    filesystems mounted inside `/dev` that are legitimately full of non-devices.
    Measured 0 on the reference machine.
    """
    dev = ctx.root / "dev"
    if not is_directory(dev):
        return
    found: list[str] = []
    for dirpath, dirs, files in os.walk(dev):
        if Path(dirpath) == dev:
            dirs[:] = [d for d in dirs if d not in DEV_EXEMPT]
        for name in files:
            path = Path(dirpath) / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            res.checked += 1
            if stat.S_ISREG(mode):
                found.append(str(path))

    if not found:
        return
    res.findings.append(Finding(
        check="dev-regular-file", subject=f"{len(found)} file(s)", severity=MEDIUM,
        detail=(f"/dev holds device nodes, and these are ordinary files: "
                f"{', '.join(found[:5])}{' …' if len(found) > 5 else ''}. Keeping a "
                f"payload there is an old trick that works because nobody looks"),
        summary=f"{len(found)} regular file(s) under /dev",
        fix=f"look at them before removing anything: file {found[0]}"))
