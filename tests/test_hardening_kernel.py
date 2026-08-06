"""The kernel runtime posture axis.

Most of these tests are about what the axis refuses to say. The tool that prompted
this work reports 16 sysctl deviations on the reference machine, two of which are
requirements — forwarding must be on for its containers and VMs, and disabling module
loading would strand a workstation's hotplug hardware. Being right about fewer things
is the point of the design, so the tests guard the silence as hard as the findings.
"""

from __future__ import annotations

from pathlib import Path

from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening.axes import HIGH, MEDIUM, AxisResult, kernel
from fettle.output import Output


def _ctx(root: Path) -> Context:
    return Context(output=Output(color=False), config=Config(), root=root,
                   user_home=root)


def _sysctl(root: Path, values: dict[str, str]) -> Path:
    """Build a fake /proc/sys from ``{"kernel/kptr_restrict": "2", ...}``."""
    for rel, val in values.items():
        p = root / "proc/sys" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(val + "\n")
    return root


# every judged key at a value the axis accepts — the quiet baseline to perturb
_CLEAN = {
    "kernel/randomize_va_space": "2", "kernel/dmesg_restrict": "1",
    "kernel/kptr_restrict": "2", "kernel/yama/ptrace_scope": "1",
    "kernel/unprivileged_bpf_disabled": "2", "fs/protected_symlinks": "1",
    "fs/protected_hardlinks": "1", "fs/suid_dumpable": "0",
    "fs/protected_fifos": "1", "fs/protected_regular": "1",
    "net/ipv4/conf/all/accept_source_route": "0", "net/ipv4/tcp_syncookies": "1",
    "net/ipv4/icmp_echo_ignore_broadcasts": "1",
}


def _checks(res: AxisResult) -> set[str]:
    return {f.check for f in res.findings}


def test_a_fully_hardened_kernel_reports_nothing_but_still_looked(tmp_path):
    res = kernel.run(None, _ctx(_sysctl(tmp_path, _CLEAN)))
    assert res.findings == []
    assert res.checked == len(_CLEAN)
    assert res.blind == []


def test_aslr_disabled_is_the_one_high(tmp_path):
    res = kernel.run(None, _ctx(_sysctl(tmp_path, {**_CLEAN,
                                                   "kernel/randomize_va_space": "0"})))
    found = [f for f in res.findings if f.check == "kernel.randomize_va_space"]
    assert len(found) == 1
    assert found[0].severity == HIGH
    assert "is 0, wanted 2" in found[0].detail


def test_suid_dumpable_accepts_both_safe_values(tmp_path):
    """0 refuses dumps from setuid processes and 2 writes them root-readable only.
    Both are safe; only 1 exposes them. The reference tool wants 0 and reports 2 as a
    deviation, which is a preference reported as a defect."""
    for safe in ("0", "2"):
        res = kernel.run(None, _ctx(_sysctl(tmp_path / safe,
                                            {**_CLEAN, "fs/suid_dumpable": safe})))
        assert "fs.suid_dumpable" not in _checks(res), f"{safe} should be accepted"

    res = kernel.run(None, _ctx(_sysctl(tmp_path / "bad",
                                        {**_CLEAN, "fs/suid_dumpable": "1"})))
    assert "fs.suid_dumpable" in _checks(res)


def test_role_dependent_keys_are_never_findings(tmp_path):
    """The two the reference tool gets wrong on a hypervisor. Present, set to the
    values it calls deviations, and this axis must stay silent about both."""
    res = kernel.run(None, _ctx(_sysctl(tmp_path, {
        **_CLEAN,
        "net/ipv4/ip_forward": "1",           # required by libvirt and Docker
        "kernel/modules_disabled": "0",       # 1 would strand hotplug hardware
        "net/ipv4/conf/all/rp_filter": "0",
        "kernel/sysrq": "176",
    })))
    assert res.findings == []
    # ...and it says so, rather than leaving the silence to be read as a pass
    declined = "\n".join(res.detail_rows)
    assert "net.ipv4.ip_forward" in declined
    assert "kernel.modules_disabled" in declined


def test_conf_default_is_not_treated_as_live_exposure(tmp_path):
    """`conf/default` templates interfaces that do not exist yet. The reference tool
    reported `net.ipv4.conf.default.accept_redirects` as a deviation on a machine where
    no interface was actually accepting redirects."""
    root = _sysctl(tmp_path, {**_CLEAN,
                              "net/ipv4/conf/all/accept_redirects": "0",
                              "net/ipv4/conf/default/accept_redirects": "1",
                              "net/ipv4/conf/eth0/accept_redirects": "0",
                              "net/ipv4/conf/eth0/forwarding": "0"})
    res = kernel.run(None, _ctx(root))
    assert "ipv4-accept-redirects" not in _checks(res)


# -- the per-interface redirect rule ---------------------------------------
# Kernel ip-sysctl documentation, quoted in redirect_findings():
#   IPv4 — enabled if BOTH all and <iface> are true when forwarding is on for that
#          interface, or if EITHER is true when it is off.
#   IPv6 — enabled if local forwarding is disabled, disabled if it is enabled.

def test_ipv4_redirects_need_both_values_when_the_interface_forwards(tmp_path):
    """all=1, iface=0, forwarding on -> NOT accepted. Reading conf/all alone would
    call this a finding."""
    root = _sysctl(tmp_path, {"net/ipv4/conf/all/accept_redirects": "1",
                              "net/ipv4/conf/eth0/accept_redirects": "0",
                              "net/ipv4/conf/eth0/forwarding": "1"})
    assert kernel.redirect_findings(root) == []


def test_ipv4_redirects_need_either_value_when_the_interface_does_not_forward(tmp_path):
    """all=0, iface=1, forwarding off -> accepted. Reading conf/all alone would miss
    it — the same read is wrong in both directions."""
    root = _sysctl(tmp_path, {"net/ipv4/conf/all/accept_redirects": "0",
                              "net/ipv4/conf/eth0/accept_redirects": "1",
                              "net/ipv4/conf/eth0/forwarding": "0"})
    found = kernel.redirect_findings(root)
    assert [f.check for f in found] == ["ipv4-accept-redirects"]
    assert found[0].severity == MEDIUM
    assert "eth0" in found[0].detail


def test_ipv6_redirects_are_suppressed_when_the_interface_forwards(tmp_path):
    root = _sysctl(tmp_path, {"net/ipv6/conf/eth0/accept_redirects": "1",
                              "net/ipv6/conf/eth0/forwarding": "1"})
    assert kernel.redirect_findings(root) == []


def test_ipv6_redirects_are_reported_when_it_does_not(tmp_path):
    """Found for real: ten interfaces on the reference machine, which the tool that
    prompted this work reported only as one generic "differs from profile" line."""
    root = _sysctl(tmp_path, {"net/ipv6/conf/eth0/accept_redirects": "1",
                              "net/ipv6/conf/eth0/forwarding": "0",
                              "net/ipv6/conf/wlan0/accept_redirects": "1",
                              "net/ipv6/conf/wlan0/forwarding": "0"})
    found = kernel.redirect_findings(root)
    assert len(found) == 1
    assert found[0].subject == "2 interface(s)"
    assert "eth0" in found[0].detail and "wlan0" in found[0].detail


def test_loopback_and_the_pseudo_interfaces_are_not_interfaces(tmp_path):
    """`lo` cannot receive a redirect from anywhere; `all` and `default` are not
    interfaces at all."""
    root = _sysctl(tmp_path, {"net/ipv6/conf/lo/accept_redirects": "1",
                              "net/ipv6/conf/lo/forwarding": "0",
                              "net/ipv6/conf/all/accept_redirects": "1",
                              "net/ipv6/conf/default/accept_redirects": "1"})
    assert kernel.redirect_findings(root) == []
    assert kernel.interfaces(root, "ipv6") == []


# -- absence -----------------------------------------------------------------

def test_settings_the_kernel_does_not_have_are_a_note_not_findings(tmp_path):
    """yama/ptrace_scope does not exist without the Yama LSM, and /proc/sys is largely
    masked inside containers. A dozen findings about knobs the kernel never offered is
    noise, so it is one line."""
    partial = {"kernel/randomize_va_space": "2", "kernel/dmesg_restrict": "1"}
    res = kernel.run(None, _ctx(_sysctl(tmp_path, partial)))
    assert res.findings == []
    assert res.checked == 2
    assert len(res.notes) == 1
    assert "do not exist on this kernel" in res.notes[0]


def test_an_unreadable_proc_sys_is_blind_not_clean(tmp_path):
    res = kernel.run(None, _ctx(tmp_path))       # nothing there at all
    assert res.findings == []
    assert res.blind
    assert "NOT checked" in res.blind[0][0]
