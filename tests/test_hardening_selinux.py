"""The SELinux axis: which of five states, and does the machine agree with itself?

Thresholds come from three untuned RHEL-family guests (AlmaLinux 9.8, Rocky 9.8,
Fedora 44), all of them enforcing with 0 non-default booleans. The boolean rules that
were rejected on measurement are pinned here so they are not quietly reintroduced.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from fettle.command import Proc
from fettle.hardening.axes import selinux


def _fs(tmp_path, *, enforce=None, config=None, cmdline="ro root=/dev/vda1",
        version_id="9.8", labels=(), booleans=()):
    """A fake root with only the files the axis reads."""
    (tmp_path / "proc").mkdir(exist_ok=True)
    (tmp_path / "proc/cmdline").write_text(cmdline + "\n")
    (tmp_path / "etc/selinux").mkdir(parents=True, exist_ok=True)
    if config is not None:
        (tmp_path / "etc/selinux/config").write_text(config)
    if enforce is not None:
        (tmp_path / "sys/fs/selinux").mkdir(parents=True, exist_ok=True)
        (tmp_path / "sys/fs/selinux/enforce").write_text(str(enforce))
        (tmp_path / "sys/fs/selinux/policyvers").write_text("33\n")
        bd = tmp_path / "sys/fs/selinux/booleans"
        bd.mkdir(exist_ok=True)
        for name, val in booleans:
            (bd / name).write_text(f"{val} {val}")
    for i, label in enumerate(labels, start=100):
        d = tmp_path / "proc" / str(i)
        d.mkdir(parents=True, exist_ok=True)
        (d / "attr").mkdir(exist_ok=True)
        (d / "attr/current").write_text(label)
    (tmp_path / "etc/os-release").write_text(f'ID="almalinux"\nVERSION_ID="{version_id}"\n')
    return tmp_path


_ENFORCING_CFG = "# comment mentioning disabled and permissive\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"


def _run(tmp_path, backend="rhel", semanage=None, **kw):
    root = _fs(tmp_path, **kw)
    ctx = SimpleNamespace(root=str(root), config=SimpleNamespace())
    have = semanage is not None
    with patch("fettle.command.which", return_value=have), \
         patch("fettle.command.run", return_value=Proc(0, semanage or "", "")):
        return selinux.run(SimpleNamespace(name=backend), ctx)


# -- the five states ---------------------------------------------------------
def test_enforcing_is_clean(tmp_path):
    res = _run(tmp_path, enforce=1, config=_ENFORCING_CFG)
    assert not res.findings
    assert "enforcing" in " ".join(res.notes)


def test_permissive_is_a_finding(tmp_path):
    res = _run(tmp_path, enforce=0, config="SELINUX=permissive\n")
    assert [f.check for f in res.findings] == ["selinux-not-enforcing"]
    assert res.findings[0].severity == "Medium"


def test_disabled_on_the_kernel_command_line(tmp_path):
    """selinux=0 wins over the config file, so the config file cannot be trusted."""
    res = _run(tmp_path, enforce=1, config=_ENFORCING_CFG,
               cmdline="ro root=/dev/vda1 selinux=0")
    assert [f.check for f in res.findings] == ["selinux-not-enforcing"]
    assert "kernel command line" in res.findings[0].summary


def test_selinuxfs_absent_with_a_policy_store_is_the_no_policy_state(tmp_path):
    res = _run(tmp_path, enforce=None, config="SELINUX=disabled\n")
    assert any(f.check == "selinux-not-enforcing" for f in res.findings)


def test_nothing_at_all_is_not_applicable(tmp_path):
    res = _run(tmp_path, enforce=None, config=None)
    assert res.na and not res.findings


def test_a_non_selinux_distro_points_at_the_apparmor_axis(tmp_path):
    res = _run(tmp_path, backend="debian", enforce=1, config=_ENFORCING_CFG)
    assert res.na and "apparmor" in res.na
    assert not res.findings


# -- runtime against config --------------------------------------------------
def test_runtime_and_config_disagreeing_is_a_finding(tmp_path):
    """`setenforce 0` does not survive a reboot, so the machine changes behaviour when
    it next restarts."""
    res = _run(tmp_path, enforce=0, config=_ENFORCING_CFG)
    checks = {f.check for f in res.findings}
    assert "selinux-mode-mismatch" in checks
    assert "selinux-not-enforcing" in checks, "permissive is still permissive"


def test_agreement_is_not_a_finding(tmp_path):
    res = _run(tmp_path, enforce=0, config="SELINUX=permissive\n")
    assert not [f for f in res.findings if f.check == "selinux-mode-mismatch"]


def test_the_config_parser_ignores_the_commentary(tmp_path):
    """The shipped file documents every value in comments above the live setting, so a
    substring search finds "disabled" on a machine set to enforcing."""
    assert selinux.read_config_mode(_ENFORCING_CFG) == "enforcing"
    assert selinux.read_config_mode("#SELINUX=disabled\nSELINUX=permissive\n") == "permissive"


# -- the RHEL 9 config trap --------------------------------------------------
def test_selinux_disabled_in_config_is_flagged_on_el9(tmp_path):
    """Red Hat deprecated it: the system boots enabled with no policy, which is neither
    enforcing nor off, and the config file agrees with the admin's mistaken belief."""
    res = _run(tmp_path, enforce=None, config="SELINUX=disabled\n", version_id="9.8")
    f = [x for x in res.findings if x.check == "selinux-config-disabled-el9"]
    assert len(f) == 1 and "selinux=0" in f[0].detail


def test_the_el9_rule_does_not_fire_on_el8(tmp_path):
    res = _run(tmp_path, enforce=None, config="SELINUX=disabled\n", version_id="8.9")
    assert not [x for x in res.findings if x.check == "selinux-config-disabled-el9"]


# -- posture, and the boolean rules that measurement rejected ----------------
def test_process_confinement_is_counted_not_flagged(tmp_path):
    """141 of 147 confined on stock AlmaLinux, and the 6 unconfined are the login
    session. Coverage is not the question on this platform."""
    labels = ["system_u:system_r:sshd_t:s0"] * 4 + \
             ["unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023"] * 2
    res = _run(tmp_path, enforce=1, config=_ENFORCING_CFG, labels=labels)
    assert "4 of 6 running processes are confined" in " ".join(res.notes)
    assert not res.findings


def test_booleans_are_counted_not_judged_individually(tmp_path):
    """Four high-risk-sounding booleans are ON by default on every host measured, so a
    curated dangerous list would fire four times on a stock EL9 install."""
    res = _run(tmp_path, enforce=1, config=_ENFORCING_CFG,
               booleans=[("selinuxuser_execstack", 1), ("unconfined_login", 1),
                         ("httpd_enable_cgi", 1), ("nfs_export_all_rw", 1),
                         ("httpd_can_network_connect", 0)])
    assert "5 booleans, 4 enabled" in " ".join(res.notes)
    assert not res.findings


def test_missing_semanage_is_blindness_not_no_changes(tmp_path):
    """semanage comes from policycoreutils-python-utils, which a stock AlmaLinux 9 does
    not install, so its absence must not read as "no booleans were changed"."""
    res = _run(tmp_path, enforce=1, config=_ENFORCING_CFG, semanage=None)
    assert res.blind and "NOT compared" in res.blind[0][0]
    assert res.blind[0][2] == "policycoreutils-python-utils"


def test_a_changed_boolean_is_a_finding(tmp_path):
    """Measured 0 differences on all three hosts, so any hit is a deliberate change."""
    out = ("httpd_can_network_connect      (on   ,  off)  Allow httpd to connect\n"
           "ssh_sysadm_login               (off  ,  off)  Allow ssh to sysadm login\n")
    res = _run(tmp_path, enforce=1, config=_ENFORCING_CFG, semanage=out)
    f = [x for x in res.findings if x.check == "selinux-boolean-changed"]
    assert len(f) == 1 and "httpd_can_network_connect" in f[0].detail
    assert "ssh_sysadm_login" not in f[0].detail


def test_changed_booleans_parses_the_semanage_columns():
    out = "foo   (on   ,  off)  desc\nbar   (off  ,  off)  desc\n"
    assert selinux.changed_booleans(out) == ["foo is on, policy default off"]
