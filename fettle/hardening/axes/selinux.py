"""SELinux: what mode is it in, and does the machine agree with itself?

The sibling AppArmor axis exists because "enabled" hid "confining nothing". That headline
does not transfer. Measured on three untuned RHEL-family guests:

=====================  =========  ==================  ==================
host                   mode       confined processes  unconfined
=====================  =========  ==================  ==================
AlmaLinux 9.8          enforcing  141 of 147          6, all the login session
Rocky Linux 9.8        enforcing  140 of 146          6, all the login session
Fedora 44              enforcing  138 of 143          5, all the login session
=====================  =========  ==================  ==================

No daemon runs unconfined on a stock EL9 install, so coverage is not the question here.
Mode and configuration drift are.

**"Enabled or disabled" has five answers on RHEL 9, and two of them get confused.**

===============================  ====================================================
state                            how it is told apart
===============================  ====================================================
enforcing                        ``/sys/fs/selinux/enforce`` is 1
permissive                       ``enforce`` is 0, policy loaded
disabled at boot                 ``selinux=0`` on the kernel command line
``SELINUX=disabled`` on RHEL 9+  the config file, plus the release
runtime and config disagree      ``getenforce`` against ``SELINUX=`` in the config
===============================  ====================================================

The fourth is the one worth building for. Red Hat deprecated disabling SELinux through
``SELINUX=disabled``: on RHEL 9 the system then *"starts with SELinux enabled but with no
policy loaded"*, and the documented way to actually disable it is ``selinux=0`` on the
kernel command line. An admin who edited that file believes SELinux is off, and it is on
with no policy. Both the config file and ``getenforce`` agree with the mistaken belief.

**Boolean checks were measured and mostly rejected.** Of 17 candidate high-risk booleans,
four are on by default on every host tested (``selinuxuser_execstack``,
``unconfined_login``, ``httpd_enable_cgi``, ``nfs_export_all_rw``) and two more on Fedora.
A curated "dangerous booleans" list would fire four times on a stock EL9 host. The ones
that are off are no better: ``httpd_can_network_connect`` and ``samba_export_all_rw`` are
legitimately switched on by anyone running a reverse proxy or a Samba share, and flagging
those reports what the machine needs in order to work. The kernel-sysctl axis already
refuses that on principle.

What survives is ``semanage boolean -l``, which reports current against policy default and
measured **0 differences on all three hosts**. It needs root *and*
``policycoreutils-python-utils``, which is not installed on a stock AlmaLinux 9, so it is
reported as blindness when unavailable rather than as "nothing changed".
"""

from __future__ import annotations

from pathlib import Path

from . import LOW, MEDIUM, AxisResult, Finding

#: Backends whose distributions ship SELinux enforcing. Debian and Arch use AppArmor or
#: nothing, and reporting "no SELinux" there would be true and useless.
_SELINUX_FAMILIES = {"rhel"}

#: `semanage` lives here, and a stock AlmaLinux 9 does not install it.
_SEMANAGE_PACKAGE = "policycoreutils-python-utils"

ENFORCING, PERMISSIVE, DISABLED_BOOT, NO_POLICY, ABSENT = (
    "enforcing", "permissive", "disabled-at-boot", "no-policy", "absent")


def read_config_mode(text: str) -> str:
    """``SELINUX=`` from /etc/selinux/config, lowercased, or "" if unset.

    Comments matter: the shipped file documents every value in comments above the live
    setting, so a naive substring search finds "disabled" on a machine set to enforcing.
    """
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == "SELINUX":
            return value.strip().strip('"').lower()
    return ""


def _cmdline_disables(text: str) -> bool:
    return "selinux=0" in text.split()


def detect_state(root: Path) -> str:
    """Which of the five states this machine is in."""
    try:
        cmdline = (root / "proc/cmdline").read_text()
    except OSError:
        cmdline = ""
    if _cmdline_disables(cmdline):
        return DISABLED_BOOT

    enforce = root / "sys/fs/selinux/enforce"
    try:
        return ENFORCING if enforce.read_text().strip() == "1" else PERMISSIVE
    except OSError:
        pass
    # selinuxfs is not answering. On a machine with a policy store and a config file that
    # is the no-policy state; with neither, SELinux is simply not present.
    if (root / "etc/selinux/config").is_file():
        return NO_POLICY
    return ABSENT


def _el_version(root: Path) -> int | None:
    """Major release number, for the RHEL 9 config-file rule. None when unreadable."""
    from ...distro import parse_os_release

    raw = parse_os_release(root).get("VERSION_ID", "")
    head = raw.split(".")[0]
    return int(head) if head.isdigit() else None


def _process_labels(root: Path) -> tuple[int, int]:
    """(confined, total) over running processes that carry an SELinux label."""
    confined = total = 0
    try:
        entries = list((root / "proc").iterdir())
    except OSError:
        return 0, 0
    for p in entries:
        if not p.name.isdigit():
            continue
        try:
            label = (p / "attr/current").read_text().strip("\x00\n").strip()
        except OSError:
            continue
        if not label:
            continue
        total += 1
        # The type is the third field of user:role:type:level. `unconfined_t` is the
        # login session on every host measured, never a daemon.
        parts = label.split(":")
        if len(parts) > 2 and parts[2] != "unconfined_t":
            confined += 1
    return confined, total


def _booleans(root: Path) -> tuple[int, int]:
    """(total booleans, how many are on), read from selinuxfs without root."""
    total = on = 0
    try:
        entries = list((root / "sys/fs/selinux/booleans").iterdir())
    except OSError:
        return 0, 0
    for p in entries:
        try:
            current = p.read_text().split()[0]
        except (OSError, IndexError):
            continue
        total += 1
        if current == "1":
            on += 1
    return total, on


def changed_booleans(raw: str) -> list[str]:
    """Booleans whose current value differs from the policy default.

    Parses `semanage boolean -l -n`, whose rows look like::

        httpd_can_network_connect      (off  ,  off)  Allow httpd to network connect

    Measured 0 differences on all three reference hosts, so any hit is a deliberate change.
    """
    out = []
    for line in raw.splitlines():
        if "(" not in line or ")" not in line:
            continue
        name = line.split()[0]
        inner = line[line.index("(") + 1:line.index(")")]
        parts = [x.strip() for x in inner.split(",")]
        if len(parts) == 2 and parts[0] != parts[1]:
            out.append(f"{name} is {parts[0]}, policy default {parts[1]}")
    return out


def run(backend, ctx) -> AxisResult:
    from ... import command

    res = AxisResult(name="selinux", title="SELinux")
    root = Path(getattr(ctx, "root", "/") or "/")

    if backend.name not in _SELINUX_FAMILIES:
        res.na = ("this distribution does not use SELinux; mandatory access control is "
                  "covered by the apparmor axis")
        return res

    state = detect_state(root)
    if state == ABSENT:
        res.na = "SELinux is not present on this system"
        return res

    try:
        config_mode = read_config_mode((root / "etc/selinux/config").read_text())
    except OSError:
        config_mode = ""

    res.checked = 1

    if state == ENFORCING:
        res.notes.append("enforcing")
    elif state == PERMISSIVE:
        res.findings.append(Finding(
            check="selinux-not-enforcing", subject="selinux", severity=MEDIUM,
            summary="SELinux is permissive, so it logs violations and blocks none",
            detail="SELinux is in permissive mode. Policy is loaded and every violation "
                   "is logged, and none of them are denied, so a confined service that "
                   "is compromised is not actually contained."))
    elif state == DISABLED_BOOT:
        res.findings.append(Finding(
            check="selinux-not-enforcing", subject="selinux", severity=MEDIUM,
            summary="SELinux is disabled on the kernel command line",
            detail="selinux=0 on the kernel command line switches SELinux off entirely, "
                   "regardless of what /etc/selinux/config says. Nothing is confined."))
    elif state == NO_POLICY:
        res.findings.append(Finding(
            check="selinux-not-enforcing", subject="selinux", severity=MEDIUM,
            summary="SELinux has no policy loaded",
            detail="SELinux is present but no policy is loaded, so nothing is confined."))

    # The runtime mode can be changed with `setenforce` and does not survive a reboot,
    # so the two values disagreeing means one of them is about to surprise somebody.
    runtime_word = {ENFORCING: "enforcing", PERMISSIVE: "permissive"}.get(state, "")
    if runtime_word and config_mode in ("enforcing", "permissive") \
            and runtime_word != config_mode:
        res.findings.append(Finding(
            check="selinux-mode-mismatch", subject="selinux", severity=LOW,
            summary=f"running {runtime_word} but configured {config_mode}",
            detail=f"SELinux is running in {runtime_word} mode while "
                   f"/etc/selinux/config says {config_mode}. The running mode came from "
                   f"setenforce and does not survive a reboot, so the machine will "
                   f"change behaviour the next time it restarts."))

    # RHEL 9 stopped honouring SELINUX=disabled in this file. The machine is then neither
    # enforcing nor genuinely disabled, and the config file agrees with the admin's
    # mistaken belief that it is off.
    el = _el_version(root)
    if config_mode == "disabled" and el is not None and el >= 9:
        res.findings.append(Finding(
            check="selinux-config-disabled-el9", subject="/etc/selinux/config",
            severity=LOW,
            summary="SELINUX=disabled no longer disables SELinux on this release",
            detail="SELINUX=disabled in /etc/selinux/config was deprecated in RHEL 9. "
                   "The system boots with SELinux enabled and no policy loaded rather "
                   "than disabled, so it is neither enforcing nor off. Add selinux=0 to "
                   "the kernel command line if disabling it is really the intent."))

    if state in (ENFORCING, PERMISSIVE):
        confined, total = _process_labels(root)
        if total:
            res.notes.append(f"{confined} of {total} running processes are confined")
        b_total, b_on = _booleans(root)
        if b_total:
            res.notes.append(f"{b_total} booleans, {b_on} enabled")
        policy = (root / "sys/fs/selinux/policyvers")
        try:
            res.notes.append(f"policy version {policy.read_text().strip()}")
        except OSError:
            pass

        # Current-against-default is the one boolean question worth asking, and it needs
        # both root and a package that a stock AlmaLinux 9 does not install.
        if not command.which("semanage"):
            res.blind.append((
                "booleans were NOT compared against the policy defaults",
                "semanage is not installed, so a boolean somebody changed by hand "
                "cannot be told apart from one the policy ships that way",
                _SEMANAGE_PACKAGE))
        else:
            proc = command.run(["semanage", "boolean", "-l", "-n"],
                               capture=True, timeout=60)
            if proc.returncode != 0:
                res.blind.append((
                    "booleans were NOT compared against the policy defaults",
                    f"semanage exited {proc.returncode} (it needs root)", ""))
            else:
                changed = changed_booleans(proc.stdout)
                if changed:
                    res.findings.append(Finding(
                        check="selinux-boolean-changed", subject="booleans",
                        severity=LOW,
                        summary=f"{len(changed)} boolean(s) differ from the policy "
                                f"default",
                        detail="These booleans were changed from what the policy ships, "
                               "which widens or narrows what confined services may do: "
                               + "; ".join(changed[:8])))
                res.detail_rows.extend(changed)
    return res
