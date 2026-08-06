"""Kernel runtime posture — are the protections the kernel offers switched on?

Read straight out of ``/proc/sys``: no ``sysctl`` binary, so this works inside the
remote zipapp on a host with nothing installed.

**The keys here are deliberately few.** The tool that prompted this work compares 38
sysctls against a fixed profile, and on the reference machine two of its deviations
were requirements rather than defects: ``net.ipv4.conf.all.forwarding`` must be 1 on a
host running libvirt and Docker, and ``kernel.modules_disabled=1`` would leave a
workstation unable to load a module for any newly plugged-in device. A check that
flags what the machine needs to work is a check people learn to ignore.

So this axis judges only keys whose right value does not depend on what the machine is
*for*, and says out loud which ones it is declining to judge (see :data:`DECLINED`).
Fewer keys, defensible everywhere.

The redirect checks are the exception that proves the rule: they *are* role-dependent,
and rather than declining them this module computes the value actually in effect,
per interface, using the kernel's own documented combination rule. That is the whole
advantage of doing this natively — see :func:`redirect_findings`.
"""

from __future__ import annotations

from pathlib import Path

from . import HIGH, LOW, MEDIUM, AxisResult, Finding

# key -> (accepted values, severity, what it costs when unset)
#
# Accepted is a *set*, because several of these have more than one defensible answer
# and flattening that is how a preference gets reported as a defect. `fs.suid_dumpable`
# is the clearest case: 0 refuses core dumps from setuid processes and 2 writes them
# root-readable only, so both are safe and only 1 (world-readable dumps of privileged
# processes) is a finding. The reference tool wants 0 and calls 2 a deviation.
KEYS: dict[str, tuple[tuple[str, ...], str, str]] = {
    "kernel/randomize_va_space": (
        ("2",), HIGH,
        "address-space layout randomisation is off or partial, so code and data sit "
        "at predictable addresses and exploiting a memory bug gets much easier"),
    "kernel/dmesg_restrict": (
        ("1",), MEDIUM,
        "any local user can read the kernel ring buffer, which leaks addresses and "
        "hardware state useful for building an exploit"),
    "kernel/kptr_restrict": (
        ("1", "2"), MEDIUM,
        "kernel pointers are exposed through /proc, which defeats kernel ASLR"),
    "kernel/yama/ptrace_scope": (
        ("1", "2", "3"), MEDIUM,
        "any process can attach to and read the memory of any other process running "
        "as the same user — including keys and session tokens"),
    "kernel/unprivileged_bpf_disabled": (
        ("1", "2"), MEDIUM,
        "unprivileged users can load BPF programs, a large and repeatedly exploited "
        "kernel attack surface"),
    "fs/protected_symlinks": (
        ("1",), MEDIUM,
        "symlinks in world-writable directories are followed without the owner "
        "checks that stop a classic /tmp symlink attack"),
    "fs/protected_hardlinks": (
        ("1",), MEDIUM,
        "a user can hardlink to a file they cannot read, and have a privileged "
        "process open it for them"),
    "fs/suid_dumpable": (
        ("0", "2"), MEDIUM,
        "core dumps from setuid processes are written readable by the invoking user, "
        "exposing whatever secrets that privileged process held in memory"),
    "fs/protected_fifos": (
        ("1", "2"), LOW,
        "FIFOs in world-writable directories can be used to trick a privileged "
        "process into writing where it did not intend"),
    "fs/protected_regular": (
        ("1", "2"), LOW,
        "the same trick as protected_fifos, using ordinary files"),
    "net/ipv4/conf/all/accept_source_route": (
        ("0",), MEDIUM,
        "source-routed packets are accepted, letting a sender dictate the return "
        "path and bypass routing-based controls"),
    "net/ipv4/tcp_syncookies": (
        ("1",), LOW,
        "no SYN cookies, so a SYN flood can exhaust the connection backlog"),
    "net/ipv4/icmp_echo_ignore_broadcasts": (
        ("1",), LOW,
        "the host answers broadcast pings and can be used to amplify traffic at "
        "someone else"),
}

# Named so the run can say what it is NOT judging. Silence about a key the reader
# expects to see looks like a pass; this makes the scope explicit and the reasoning
# arguable, which a hidden weighting never is.
DECLINED = {
    "net.ipv4.ip_forward": "required on any host running containers, VMs or routing",
    "kernel.modules_disabled": "would stop the kernel loading a module for newly "
                               "attached hardware until the next reboot",
    "net.ipv4.conf.*.rp_filter": "strict reverse-path filtering breaks asymmetric and "
                                 "multi-homed routing, and the all/per-interface "
                                 "values combine in a way a single read misjudges",
    "kernel.sysrq": "a console-access debugging aid; distros disagree on the default "
                    "and the risk needs physical access",
    "net.core.bpf_jit_harden": "costs BPF performance, and matters most on hosts that "
                               "run the most BPF",
    "net.ipv4.conf.*.log_martians": "a logging preference, not a protection",
    "*.conf.default.*": "applies to interfaces created later, not to anything "
                        "currently running — the live per-interface values are what "
                        "this axis reports",
}


def _read(root: Path, rel: str) -> str | None:
    base = root / "proc/sys" if root != Path("/") else Path("/proc/sys")
    try:
        return (base / rel).read_text().strip()
    except OSError:
        return None


def interfaces(root: Path, family: str) -> list[str]:
    base = root / f"proc/sys/net/{family}/conf" if root != Path("/") \
        else Path(f"/proc/sys/net/{family}/conf")
    try:
        names = sorted(d.name for d in base.iterdir() if d.is_dir())
    except OSError:
        return []
    # `all` and `default` are not interfaces: `all` combines with each interface (see
    # redirect_findings) and `default` is a template for interfaces that do not exist
    # yet. `lo` cannot receive a redirect from anywhere.
    return [n for n in names if n not in ("all", "default", "lo")]


def redirect_findings(root: Path) -> list[Finding]:
    """Interfaces that are *actually* accepting ICMP redirects, per family.

    An accepted ICMP redirect lets anything that can reach the host rewrite its
    routing for a destination — a local man-in-the-middle primitive. Whether one is
    accepted is not the single ``conf/all`` value everyone reads, and the two families
    do not even agree with each other. From the kernel's own ip-sysctl documentation:

    * **IPv4** — enabled if *both* ``conf/all`` and ``conf/<iface>`` are true when
      forwarding is on for that interface, or if *either* is true when it is off.
    * **IPv6** — "enabled if local forwarding is disabled, disabled if local
      forwarding is enabled".

    Reading ``conf/all`` alone therefore misjudges this in both directions. Measured on
    the reference machine, which is why this is computed rather than assumed: **no**
    IPv4 interface accepts redirects (the reference tool flagged ``conf/default``,
    which only governs interfaces created later), while **ten** IPv6 interfaces do —
    a real exposure it reported only as a generic "differs from profile".
    """
    out: list[Finding] = []
    for family in ("ipv4", "ipv6"):
        all_on = _read(root, f"net/{family}/conf/all/accept_redirects") == "1"
        hit = []
        for iface in interfaces(root, family):
            iface_on = _read(root, f"net/{family}/conf/{iface}/accept_redirects") == "1"
            fwd = _read(root, f"net/{family}/conf/{iface}/forwarding") == "1"
            if family == "ipv4":
                effective = (all_on and iface_on) if fwd else (all_on or iface_on)
            else:
                effective = iface_on and not fwd
            if effective:
                hit.append(iface)
        if not hit:
            continue
        shown = ", ".join(hit[:6]) + (f" (+{len(hit) - 6} more)" if len(hit) > 6 else "")
        out.append(Finding(
            check=f"{family}-accept-redirects", subject=f"{len(hit)} interface(s)",
            severity=MEDIUM,
            detail=(f"accepting {family.upper()} ICMP redirects on {shown} — anything "
                    f"that can reach these interfaces can rewrite this host's route "
                    f"to a destination, which is a local man-in-the-middle primitive"),
            fix=f"sysctl -w net.{family}.conf.all.accept_redirects=0 "
                f"(and per-interface, then persist it in /etc/sysctl.d/)"))
    return out


def run(backend, ctx) -> AxisResult:
    res = AxisResult(name="kernel", title="Kernel runtime posture")
    root = ctx.root

    absent: list[str] = []
    for rel, (accepted, severity, why) in KEYS.items():
        name = rel.replace("/", ".")
        value = _read(root, rel)
        if value is None:
            # Not compiled in (yama without the LSM), or /proc/sys is masked, which is
            # normal in a container. Collapsed into one line below rather than becoming
            # a dozen findings about a kernel that never offered the knob.
            absent.append(name)
            continue
        res.checked += 1
        if value in accepted:
            continue
        res.findings.append(Finding(
            check=name, subject=name, severity=severity,
            detail=f"is {value}, wanted {' or '.join(accepted)} — {why}",
            fix=f"sysctl -w {name}={accepted[0]} (persist in /etc/sysctl.d/)"))

    redirects = redirect_findings(root)
    res.findings.extend(redirects)
    res.checked += len(interfaces(root, "ipv4")) + len(interfaces(root, "ipv6"))

    if absent:
        res.notes.append(
            f"{len(absent)} setting(s) do not exist on this kernel, so nothing above "
            f"speaks for them: {', '.join(absent[:5])}"
            + (f" (+{len(absent) - 5} more)" if len(absent) > 5 else ""))
    if not res.checked:
        res.blind.append(("kernel runtime settings were NOT checked",
                          "/proc/sys could not be read — it is commonly masked in "
                          "containers", ""))
        return res

    res.detail_rows.append("NOT JUDGED — the right value depends on what this machine "
                           "is for:")
    res.detail_rows.extend(f"  {key:<34}{why}" for key, why in DECLINED.items())
    return res
