"""Kernel and loader integrity — is something below userspace lying to us?

Four checks, ordered by how cheap and how certain they are. The first is nearly free and
nearly unambiguous; the last is the one an implant is actively trying to defeat.

* **`/etc/ld.so.preload`** — the file does not exist on a stock Arch, Debian or RHEL
  system, and every LD_PRELOAD rootkit family creates it. Its existence *is* the finding.
* **Loaded modules and kernel taint** — reconciled against each other, because neither
  alone says anything useful (see :func:`_taint`).
* **Hidden processes** — the direct counter to the `getdents64()` hook the June 2026 AUR
  wave used, done by asking the kernel through an interface that hook does not cover.
* **The eBPF surface** — pinned objects and loaded programs, with an honest statement of
  why a clean result here is weaker evidence than a clean result anywhere else.

Everything here is read-only and most of it needs no privilege. `/sys/fs/bpf` is the
exception: it is `drwx-----T root:root`, so an unprivileged run reports blindness about
it rather than a count of zero.
"""

from __future__ import annotations

import os
from pathlib import Path

from .. import command
from . import CRITICAL, HIGH, LOW, MEDIUM, CheckResult, Finding, is_directory

# The June 2026 AUR supply-chain wave pinned three maps with fixed names to hide PIDs,
# filenames and inodes from `getdents64`. Named here so the answer to "was I hit by that
# campaign" is one line rather than an inference from a list of pin names.
AUR_WAVE_PINS = ("hidden_pids", "hidden_names", "hidden_inodes")

# Kernel taint bits, from the kernel's own `Documentation/admin-guide/tainted-kernels`.
# Only the two that bear on module provenance are interpreted; the rest are recorded
# untouched, because "your kernel is tainted" without saying which bit and why is the
# kind of alarming non-statement this action exists to avoid.
TAINT_OOT_MODULE = 12          # 'O' — an out-of-tree module was loaded
TAINT_UNSIGNED_MODULE = 13     # 'E' — an unsigned module was loaded


def run(backend, ctx) -> CheckResult:
    res = CheckResult(name="kernel", title="Kernel and loader")
    _ld_preload(backend, ctx, res)
    _modules(ctx, res)
    _hidden_processes(ctx, res)
    _ebpf(backend, ctx, res)
    return res


# --------------------------------------------------------------------- ld.so.preload


def _ld_preload(backend, ctx, res: CheckResult) -> None:
    """`/etc/ld.so.preload` — every library listed here is loaded into every process.

    The cheapest high-value check in this action. A stock system does not have this file
    at all: measured absent on the reference desktop, and it is absent on a clean Arch,
    Debian and RHEL install. Legitimate uses exist (`libeatmydata`, some HPC shims) and
    they are rare enough that naming the file and its contents is the right output —
    a person who put it there recognises it instantly, and a person who did not has
    exactly the sentence they need.
    """
    path = ctx.root / "etc/ld.so.preload"
    res.checked += 1
    try:
        body = path.read_text(errors="replace")
    except FileNotFoundError:
        return                                     # the overwhelmingly common case
    except OSError as exc:
        res.blind.append(("/etc/ld.so.preload", f"could not be read ({exc.strerror})", ""))
        return

    libs = [ln.strip() for ln in body.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
    owners = backend.map_files_to_packages([x for x in libs if x.startswith("/")])
    described = ", ".join(f"{x} ({owners.get(x, 'no package owns it')})" for x in libs)
    res.findings.append(Finding(
        check="ld-preload", subject="/etc/ld.so.preload", severity=HIGH,
        detail=(f"this file exists, and every library it names is loaded into every "
                f"process on the system before anything else — which is how the "
                f"LD_PRELOAD family of rootkits intercepts what programs see. A stock "
                f"Arch, Debian or RHEL system does not have this file. Preloads: "
                f"{described or '(the file is empty)'}"),
        summary="/etc/ld.so.preload exists",
        fix=("read it: cat /etc/ld.so.preload, and trace each library back to something "
             "you installed deliberately before removing anything")))


# ------------------------------------------------------------------ modules and taint


def _loaded_modules(root: Path) -> list[str]:
    try:
        return [ln.split()[0] for ln in
                (root / "proc/modules").read_text(errors="replace").splitlines()
                if ln.split()]
    except OSError:
        return []


def _module_taint(root: Path, name: str) -> str:
    try:
        return (root / f"sys/module/{name}/taint").read_text().strip()
    except OSError:
        return ""


def _enforcement(root: Path) -> str:
    """Whether the kernel would actually refuse an unsigned module.

    Without this, "no unsigned modules are loaded" implies a guarantee that is not
    there. On the reference machine `sig_enforce` is `N` and Secure Boot is disabled
    with the platform in setup mode, so nothing prevents one being loaded — the clean
    result means "none right now", not "none possible".
    """
    try:
        enforce = (root / "sys/module/module/parameters/sig_enforce").read_text().strip()
    except OSError:
        enforce = "?"
    return "on" if enforce == "Y" else "off" if enforce == "N" else "unknown"


def _modules(ctx, res: CheckResult) -> None:
    root = ctx.root
    modules = _loaded_modules(root)
    res.checked += len(modules)
    if not modules:
        res.blind.append(("loaded kernel modules",
                          "/proc/modules could not be read — nothing was examined", ""))
        return

    # 'E' unsigned, 'O' out-of-tree, per module. Reading 155 one-line sysfs files costs
    # nothing; `modinfo` per module would fork 155 processes to learn the same thing.
    flagged = {m: t for m in modules if (t := _module_taint(root, m))}
    enforce = _enforcement(root)

    unsigned = sorted(m for m, t in flagged.items() if "E" in t)
    if unsigned:
        res.findings.append(Finding(
            check="unsigned-module", subject=", ".join(unsigned[:3]),
            severity=HIGH if enforce == "on" else MEDIUM,
            detail=(f"{len(unsigned)} loaded module(s) are unsigned, and module "
                    f"signature enforcement is {enforce}. An unsigned module can do "
                    f"anything the kernel can. Modules: {', '.join(unsigned)}"),
            summary=f"{len(unsigned)} unsigned module(s) loaded",
            fix="identify each: modinfo <name> — and check which package, if any, ships it"))

    _taint(root, flagged, enforce, res)


def _taint(root: Path, flagged: dict[str, str], enforce: str, res: CheckResult) -> None:
    """Reconcile `/proc/sys/kernel/tainted` against the modules actually loaded.

    **Taint is sticky and does not name its cause.** Once a bit is set it stays set until
    reboot, so it records that something happened, not that something is still there.
    Reporting `tainted != 0` as a finding would be wrong on the reference machine and on
    most machines like it: it reads **12288** — bits 12 and 13, out-of-tree and unsigned
    — while all 155 loaded modules are signed and none reports taint of its own. The
    cause was a DKMS or VMware module built, loaded and unloaded during an update.

    That is also exactly what an LKM rootkit that loaded and removed itself looks like,
    which is why the discrepancy is worth reporting — at Low, with the boring explanation
    first, and with the command that can actually settle it.
    """
    try:
        value = int((root / "proc/sys/kernel/tainted").read_text().strip())
    except (OSError, ValueError):
        res.blind.append(("kernel taint state",
                          "/proc/sys/kernel/tainted could not be read", ""))
        return

    res.checked += 1
    claims_module_taint = bool(value & (1 << TAINT_OOT_MODULE)
                               or value & (1 << TAINT_UNSIGNED_MODULE))
    if not claims_module_taint:
        return

    accounted = [m for m, t in flagged.items() if "O" in t or "E" in t]
    if accounted:
        # The taint has an owner that is still loaded. Nothing to explain.
        res.notes.append(
            f"kernel taint {value} is accounted for by loaded module(s): "
            f"{', '.join(sorted(accounted))}")
        return

    res.findings.append(Finding(
        check="unexplained-taint", subject="kernel taint",
        severity=LOW,
        detail=(f"the kernel records that an out-of-tree or unsigned module was loaded "
                f"since boot (taint {value}), and no currently loaded module accounts "
                f"for it — so whatever set it has since been unloaded. Usually a DKMS "
                f"or vendor module built and swapped during an update; it is also what "
                f"a kernel-module rootkit that removed itself would leave behind. "
                f"Module signature enforcement is {enforce}"),
        summary="no loaded module explains it",
        fix="find out what set it: journalctl -k | grep -i -E 'taint|module verification'"))


# ------------------------------------------------------------------ hidden processes


def _proc_listing(root: Path) -> set[int]:
    try:
        return {int(e) for e in os.listdir(root / "proc") if e.isdigit()}
    except OSError:
        return set()


def _cgroup_census(root: Path) -> tuple[set[int], int]:
    """Every PID the cgroup hierarchy accounts for, and how many files answered."""
    pids: set[int] = set()
    files = 0
    for dirpath, _dirs, names in os.walk(root / "sys/fs/cgroup"):
        if "cgroup.procs" not in names:
            continue
        try:
            body = (Path(dirpath) / "cgroup.procs").read_text()
        except OSError:
            continue
        files += 1
        pids.update(int(x) for x in body.split() if x.isdigit())
    return pids, files


def _hidden_processes(ctx, res: CheckResult) -> None:
    """A process the cgroup hierarchy knows about that `/proc` does not list.

    **Two independent kernel interfaces, which is the entire point.** The AUR wave's
    rootkit hooked `getdents64()` to hide PIDs from anything that reads `/proc` — and
    `ps`, `top` and `pgrep` all read `/proc`, so all of them inherit the lie. Cgroup
    membership is answered by reading `cgroup.procs` files, which does not go through
    that call at all, so a PID hidden from the directory listing is still counted there.

    **The obvious implementation of this check is unusable, and measuring said so.** The
    classic approach — walk every PID up to `pid_max` and stat `/proc/<pid>` — produced
    **6,272 false positives** on the reference desktop, because every non-leader *thread*
    answers a direct stat while `readdir` correctly lists only thread-group leaders.
    Filtering on `Tgid == Pid` fixes the correctness and leaves the cost: 2.5 million
    stat calls, **7.8 seconds**. The cgroup census gives the same answer — an exact match
    of 1046 against 1046, in **0.01 s** — needs no privilege, and holds inside a PID
    namespace (verified in a container).
    """
    root = ctx.root
    if not is_directory(root / "sys/fs/cgroup"):
        # Blind, not "not applicable", and NOT on the group. The question still
        # applies — something could be hidden from /proc here as easily as anywhere —
        # there is simply no second interface to ask. Setting `res.na` would have been
        # worse than wrong: it is a property of the whole group, so on a host without
        # cgroups it would have hidden this group's ld.so.preload and module findings
        # behind a single "not applicable" line.
        res.blind.append(("hidden processes",
                          "no cgroup hierarchy at /sys/fs/cgroup, so /proc could not "
                          "be cross-checked against a second kernel interface", ""))
        return

    listed = _proc_listing(root)
    census, files = _cgroup_census(root)
    if not listed or not files:
        res.blind.append(("hidden processes",
                          "could not read /proc or the cgroup hierarchy — the two "
                          "views could not be compared", ""))
        return

    res.checked += len(census)
    missing = census - listed
    if not missing:
        return

    # A process that exits between the two reads is in the census and gone from the
    # listing, which looks identical to one being hidden. Re-read both and keep only
    # what survives — an exiting process is gone from the census the second time too.
    second_census, _ = _cgroup_census(root)
    confirmed = sorted((missing & second_census) - _proc_listing(root))
    if not confirmed:
        return

    named = ", ".join(str(p) for p in confirmed[:6])
    res.findings.append(Finding(
        check="hidden-process", subject=f"{len(confirmed)} PID(s)", severity=CRITICAL,
        detail=(f"the cgroup hierarchy accounts for {len(confirmed)} process(es) that "
                f"do not appear in /proc: {named}. Those are two different kernel "
                f"interfaces, and hiding a process from the second is what a "
                f"getdents64 hook does — the technique the June 2026 AUR supply-chain "
                f"rootkit used. ps, top and pgrep all read /proc, so none of them would "
                f"show these either"),
        summary=f"{len(confirmed)} process(es) hidden from /proc",
        fix=(f"look them up through the interface that can still see them: "
             f"cat /proc/{confirmed[0]}/cmdline; grep -rl {confirmed[0]} "
             f"/sys/fs/cgroup --include=cgroup.procs")))


# ---------------------------------------------------------------------- eBPF surface


def _ebpf(backend, ctx, res: CheckResult) -> None:
    """Pinned BPF objects and loaded programs.

    **A clean result here is weaker evidence than a clean result anywhere else in this
    action, and the output says so.** An eBPF rootkit good enough to worry about hooks
    the `bpf()` syscall itself and hides its own programs from `bpftool`, which is the
    tool asking. Detecting that needs either a comparison against `bpftool prog show id
    N` for every id, or a memory capture — both out of scope for a maintenance tool, and
    naming the limit is more useful than implying it is not there.

    What this *can* do is catch an implant that did not bother, and answer one specific
    question exactly: the June 2026 AUR wave pinned three maps with fixed names, so
    "was I hit by that campaign" is a string comparison.
    """
    pin_dir = ctx.root / "sys/fs/bpf"
    pins: list[str] | None = None
    if not is_directory(pin_dir):
        # A true statement about pins, and not the end of the check: a program can be
        # loaded and attached without ever being pinned, so the bpftool half below still
        # has to run — or say that it could not.
        res.notes.append("no BPF filesystem is mounted at /sys/fs/bpf, so nothing is "
                         "pinned there.")
    else:
        try:
            pins = sorted(p.name for p in pin_dir.iterdir())
        except OSError:
            # `drwx-----T root:root` on the reference machine — this is the expected
            # unprivileged outcome, and it is blindness, not an empty result.
            res.blind.append(("pinned eBPF objects (/sys/fs/bpf)",
                              "needs root to read — run it without --dry-run and fettle elevates for you", ""))

    if pins is not None:
        res.checked += len(pins)
        hits = [p for p in pins if p in AUR_WAVE_PINS]
        if hits:
            res.findings.append(Finding(
                check="bpf-ioc-pin", subject=", ".join(hits), severity=CRITICAL,
                detail=(f"pinned BPF map(s) named {', '.join(hits)} — these are the "
                        f"exact names the June 2026 AUR supply-chain rootkit used to "
                        f"hide processes, filenames and inodes. This is a name match "
                        f"against a known campaign, not an inference"),
                summary="BPF maps named by a known rootkit campaign",
                fix=("do not clean up yet — capture first. bpftool map dump pinned "
                     "/sys/fs/bpf/<name>, and see the preservation note above")))
        elif pins:
            res.notes.append(
                f"{len(pins)} pinned BPF object(s): {', '.join(pins[:8])}"
                f"{' …' if len(pins) > 8 else ''}. systemd, docker and Cilium all pin "
                f"legitimately, so these are listed rather than judged.")

    if not command.which("bpftool"):
        # **The package is not called the same thing everywhere, and guessing sends the
        # reader to a shell prompt to be told it does not exist — after which they
        # conclude fettle is broken rather than that the hint was.** Measured: Arch and
        # Manjaro ship it in `bpf` (part of the `linux-tools` group; `pacman -Fx
        # bin/bpftool$` confirms), while Debian 13 and Rocky 9 both have a `bpftool`
        # package of its own. The first version of this hint said `pacman -S bpftool`,
        # which installs nothing on the machine it was written on.
        package = {"arch": "bpf"}.get(backend.name, "bpftool")
        res.blind.append((
            "loaded eBPF programs", "bpftool is not installed, so only pinned objects "
            "were examined — a program can be loaded and attached without being pinned",
            package))
        return

    proc = command.run(["bpftool", "prog", "show"], capture=True)
    if proc.returncode != 0:
        res.blind.append(("loaded eBPF programs",
                          "bpftool could not list them — it needs root, so run it without --dry-run and fettle elevates for you", ""))
        return
    loaded = [ln for ln in (proc.stdout or "").splitlines() if ln and ln[0].isdigit()]
    res.checked += len(loaded)
    if loaded:
        res.notes.append(
            f"{len(loaded)} eBPF program(s) loaded. A rootkit that hooks the bpf() "
            f"syscall can hide its own programs from this list, so a clean count here "
            f"is weaker evidence than the rest of this report — it rules out an implant "
            f"that did not bother, not one that did.")
