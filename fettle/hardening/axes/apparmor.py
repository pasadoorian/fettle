"""AppArmor: is it confining anything, or is it just switched on?

"AppArmor is enabled" is the number everyone quotes and it says very little. Measured on
three ordinary installs, none of them tuned by hand:

============================  ======  =======  ========  ==========  =============
host                          loaded  enforce  complain  name-only   confined procs
============================  ======  =======  ========  ==========  =============
Manjaro desktop (wopr)           168       84         5         79         7 of 92
Debian 13 server                 106        7        23         76         **0**
Ubuntu 26.04 server              173       97         2         74         1 (chronyd)
============================  ======  =======  ========  ==========  =============

A stock Debian 13 loads 106 profiles and confines nothing that is running. `sshd`,
`systemd-resolved`, `systemd-networkd`, `ModemManager` and `udisksd` all run unconfined.
That is the fact this axis exists to surface, and no count of loaded profiles reveals it.

**The three profile modes are never added together.** `enforce` applies a policy.
`complain` logs and applies nothing. `unconfined` applies nothing either and is not a
defect: distros ship those profiles so applications can still use unprivileged user
namespaces after Ubuntu set ``kernel.apparmor_restrict_unprivileged_userns=1``. The
profile files say so themselves, e.g. ``/etc/apparmor.d/brave``::

    # This profile allows everything and only exists to give the
    # application a name instead of having the label "unconfined"

Ubuntu's own documentation is blunter: *"unconfined profiles that allow the use of user
namespaces provide a trivial bypass of the unprivileged user namespace restriction from
unconfined processes."* Those profiles are named here as **exemptions**, counted apart
from the enforcing ones, and never treated as coverage.

**What is deliberately not a finding**, each rejected on measurement rather than taste:

``profile files on disk that are not loaded``
    Filenames and profile names are different namespaces. 151 files produce 168 loaded
    profiles on wopr, 13 of which are children (``zgrep//sed``), and only 106 filenames
    match a profile name at all. The naive difference reports 45 non-problems.
``profiles in complain mode``
    The floor swings from 2 to 23 across the three hosts above, 16 of Debian's 23 come
    from ``sbuild`` alone, and every complain-mode profile file on both servers is owned
    by the ``apparmor`` package. Nobody chose complain mode; the distro shipped it.
``processes running unconfined``
    85 of wopr's 92 are the exemption stubs above. Kept only in the far narrower form
    below: unconfined *while a profile exists for that executable*, which measured 0 on
    all three hosts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import LOW, AxisResult, Finding

_TOOL = "aa-status"

#: Families where AppArmor is the shipped default, so its absence is a real regression.
#: On Arch it is opt-in and absent is simply the normal state.
_DEFAULTS_TO_APPARMOR = {"debian"}

#: Suggested when nothing is confined on a Debian-family host. Neither was installed on
#: either lab server, and a default install does not pull them in.
_PROFILE_PACKAGES = ("apparmor-profiles", "apparmor-profiles-extra")


def _enabled(root: Path) -> bool | None:
    """Whether the kernel module is on. ``None`` when the question cannot be answered."""
    try:
        return (root / "sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    except OSError:
        return None


def _in_lsm_list(root: Path) -> bool:
    try:
        return "apparmor" in (root / "sys/kernel/security/lsm").read_text()
    except OSError:
        return False


def _exemption_files(root: Path) -> int:
    """Profile files that declare ``flags=(unconfined)``, readable without root.

    Counted from disk rather than from the loaded set so the number is still available
    when the policy itself cannot be read.
    """
    n = 0
    try:
        for p in (root / "etc/apparmor.d").iterdir():
            if not p.is_file():
                continue
            try:
                if "flags=(unconfined)" in p.read_text(errors="replace"):
                    n += 1
            except OSError:
                continue
    except OSError:
        return 0
    return n


def parse_status(raw: str) -> tuple[dict[str, str], list[dict]] | None:
    """``aa-status --json`` into (profile -> mode, process entries), or None.

    Separated from the run so the shapes can be tested without a machine. Returns None
    for anything unparseable, which the caller reports as blindness rather than as an
    empty policy.
    """
    try:
        data = json.loads(raw)
        profiles = data["profiles"]
        procs = [e for v in data["processes"].values() for e in v]
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    if not isinstance(profiles, dict):
        return None
    return profiles, procs


def _running_executables(root: Path) -> dict[str, str]:
    """``{exe path: apparmor label}`` for every running process we can read.

    Needed because ``aa-status`` lists only processes that have a profile *attached*.
    On Debian 13 that list is empty while 19 processes are running, and "no confined
    processes" is a very different statement from "no processes".
    """
    out: dict[str, str] = {}
    proc = root / "proc"
    try:
        entries = list(proc.iterdir())
    except OSError:
        return out
    for p in entries:
        if not p.name.isdigit():
            continue
        try:
            exe = os.readlink(p / "exe")
            label = (p / "attr/current").read_text().strip("\x00\n").strip()
        except OSError:
            continue
        out.setdefault(exe, label or "unconfined")
    return out


def _packages_missing(backend, ctx) -> list[str]:
    """Which of the profile packages are absent. Empty list when it cannot be asked."""
    from ... import command

    if backend.name != "debian" or not command.which("dpkg-query"):
        return []
    missing = []
    for pkg in _PROFILE_PACKAGES:
        proc = command.run(["dpkg-query", "-W", "-f=${Status}", pkg],
                           capture=True, timeout=10)
        if "install ok installed" not in proc.stdout:
            missing.append(pkg)
    return missing


def run(backend, ctx) -> AxisResult:
    from ... import command

    res = AxisResult(name="apparmor", title="AppArmor")
    root = Path(getattr(ctx, "root", "/") or "/")

    # RHEL uses SELinux. Reporting "no AppArmor" there would be true and useless, and
    # would read as a finding on half the supported fleet.
    if backend.name == "rhel":
        res.na = "this is an SELinux distribution; AppArmor is not used here"
        return res

    enabled = _enabled(root)
    if not enabled or not _in_lsm_list(root):
        if backend.name in _DEFAULTS_TO_APPARMOR:
            res.checked = 1
            res.findings.append(Finding(
                check="apparmor-disabled", subject="apparmor", severity=LOW,
                summary="AppArmor is not active on a distribution that ships it on",
                detail="AppArmor is the mandatory access control this distribution "
                       "ships enabled, and it is not active here. Nothing is confined "
                       "at all, so a compromised service reaches whatever its Unix "
                       "user can reach."))
            return res
        res.na = ("AppArmor is not enabled, and this distribution does not enable it "
                  "by default")
        return res

    if not command.which(_TOOL):
        res.blind.append((f"the AppArmor policy was NOT read ({_TOOL} is missing)",
                          "the module is loaded, so something is or is not being "
                          "confined and this run cannot tell which", "apparmor"))
        return res

    # `aa-status` EXITS 0 unprivileged while printing "You do not have enough privilege
    # to read the profile set", so the status cannot be the test. The output has to
    # parse as policy before any of it is believed.
    proc = command.run([_TOOL, "--json"], capture=True, timeout=30)
    parsed = parse_status(proc.stdout)
    if parsed is None:
        why = "needs root" if os.geteuid() != 0 else \
              f"{_TOOL} --json returned nothing usable (exit {proc.returncode})"
        # No install hint here: the tool is present and the obstacle is privilege, so
        # suggesting `install apparmor` would send the reader to fix something that is
        # not broken. The hint belongs on the missing-tool branch above, and only there.
        res.blind.append(("the AppArmor policy was NOT read",
                          f"{why}; the module is loaded, so this run can say AppArmor "
                          f"is on and nothing about whether it confines anything",
                          ""))
        return res

    profiles, procs = parsed
    modes = {"enforce": 0, "complain": 0, "unconfined": 0}
    for mode in profiles.values():
        if mode in modes:
            modes[mode] += 1
    confined = sum(1 for e in procs if e.get("status") == "enforce")
    running = _running_executables(root)
    res.checked = len(profiles)

    res.notes.append(
        f"{len(profiles)} profiles loaded: {modes['enforce']} enforcing, "
        f"{modes['complain']} complain (logs only), "
        f"{modes['unconfined']} name-only")
    if modes["unconfined"]:
        res.notes.append(
            f"the {modes['unconfined']} name-only profiles are exemptions, not coverage: "
            "they exist so desktop applications can still use unprivileged user "
            "namespaces, and they confine nothing")
    if running:
        res.notes.append(f"{confined} of {len(running)} running executables are confined")

    # The finding, at LOW and deliberately firing on a stock Debian: that host really is
    # in this state, and there is a specific thing to do about it.
    if running and confined == 0:
        missing = _packages_missing(backend, ctx)
        fix = (f" {' and '.join(missing)} " +
               ("are" if len(missing) > 1 else "is") + " not installed, which is the "
               "usual reason a default install loads profiles that cover nothing "
               "currently running.") if missing else ""
        res.findings.append(Finding(
            check="apparmor-confines-nothing", subject="apparmor", severity=LOW,
            summary="AppArmor is enabled but confines no running process",
            detail=f"AppArmor is enabled with {len(profiles)} profiles loaded, and not "
                   f"one of the {len(running)} running executables is confined by it."
                   + fix))

    # Kept from the original plan and expected to be quiet: it measured 0 on all three
    # reference hosts. A process running unconfined when a profile exists for that exact
    # executable is a real misconfiguration rather than the usual state of a desktop.
    gaps = sorted(exe for exe, label in running.items()
                  if label in ("", "unconfined")
                  and (exe in profiles or os.path.basename(exe) in profiles))
    for exe in gaps:
        res.findings.append(Finding(
            check="apparmor-profile-not-applied", subject=exe, severity=LOW,
            summary="a loaded profile for this executable is not in effect",
            detail="a profile is loaded for this executable and the running process is "
                   "unconfined, so the policy that exists for it is not in effect"))

    res.detail_rows.extend(f"{mode:>10}  {name}"
                           for name, mode in sorted(profiles.items()))
    return res
