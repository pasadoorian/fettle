"""The AppArmor axis: is anything confined, or is the module merely loaded?

Every threshold here comes from measuring three untuned hosts (Manjaro desktop, Debian 13
server, Ubuntu 26.04 server) rather than from what sounded reasonable. Two of the four
rules originally planned were dropped on those numbers, and the tests below pin the
reasons so they are not quietly reintroduced.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from fettle.command import Proc
from fettle.hardening.axes import apparmor


def _backend(name="debian"):
    return SimpleNamespace(name=name)


def _ctx(root="/"):
    return SimpleNamespace(root=root, config=SimpleNamespace())


def _status(profiles, procs=()):
    return json.dumps({"version": "2", "profiles": profiles,
                       "processes": {f"exe{i}": [e] for i, e in enumerate(procs)}})


def _run(*, profiles=None, procs=(), running=None, enabled=True, lsm=True,
         backend="debian", tool=True, raw=None, missing_pkgs=()):
    profiles = {"a": "enforce"} if profiles is None else profiles
    running = {"/usr/sbin/sshd": "unconfined"} if running is None else running
    out = raw if raw is not None else _status(profiles, procs)
    with patch.object(apparmor, "_enabled", return_value=enabled), \
         patch.object(apparmor, "_in_lsm_list", return_value=lsm), \
         patch.object(apparmor, "_running_executables", return_value=running), \
         patch.object(apparmor, "_packages_missing", return_value=list(missing_pkgs)), \
         patch("fettle.command.which", return_value=tool), \
         patch("fettle.command.run", return_value=Proc(0, out, "")):
        return apparmor.run(_backend(backend), _ctx())


# -- the three outcomes stay separate ----------------------------------------
def test_rhel_is_not_applicable_rather_than_a_finding():
    """RHEL uses SELinux. Reporting "no AppArmor" there is true and useless, and would
    read as a finding on half the supported fleet."""
    res = _run(backend="rhel")
    assert res.na and "SELinux" in res.na
    assert not res.findings and not res.blind


def test_arch_without_apparmor_is_not_applicable():
    """Arch ships AppArmor opt-in, so absent is the normal state, not a regression."""
    res = _run(backend="arch", enabled=False)
    assert res.na and not res.findings


def test_debian_without_apparmor_is_a_finding():
    res = _run(backend="debian", enabled=False)
    assert [f.check for f in res.findings] == ["apparmor-disabled"]


def test_unreadable_policy_is_blindness_not_an_empty_policy():
    """`aa-status` EXITS 0 unprivileged while printing "You do not have enough privilege
    to read the profile set", so the status cannot be the test."""
    res = _run(raw="apparmor module is loaded.\n")
    assert res.blind and not res.findings
    assert "NOT read" in res.blind[0][0]
    assert res.checked == 0


def test_a_missing_tool_is_blindness_too():
    res = _run(tool=False)
    assert res.blind and not res.findings


# -- the counts are never added together -------------------------------------
def test_the_three_profile_modes_are_reported_separately():
    """Measured: wopr 84 enforce / 5 complain / 79 name-only. A single "168 profiles
    loaded" hides that only 84 of them apply a policy."""
    res = _run(profiles={f"e{i}": "enforce" for i in range(84)}
                        | {f"c{i}": "complain" for i in range(5)}
                        | {f"u{i}": "unconfined" for i in range(79)},
               procs=[{"profile": "e0", "status": "enforce"}])
    note = " ".join(res.notes)
    assert "84 enforcing" in note and "5 complain" in note and "79 name-only" in note
    assert res.checked == 168


def test_name_only_profiles_are_called_exemptions_not_coverage():
    """Ubuntu's own docs: an unconfined profile is a bypass, not a restriction."""
    res = _run(profiles={"brave": "unconfined"},
               procs=[{"profile": "brave", "status": "unconfined"}])
    assert any("exemptions, not coverage" in n for n in res.notes)


def test_name_only_profiles_are_never_findings():
    """79 of them on wopr, all shipped by the apparmor package with a comment saying
    they confine nothing. Flagging them means flagging 79 deliberate decisions."""
    res = _run(profiles={f"u{i}": "unconfined" for i in range(79)},
               procs=[{"profile": "u0", "status": "enforce"}])
    assert not any(f.check == "apparmor-name-only" for f in res.findings)


def test_complain_mode_is_counted_not_flagged():
    """The floor swings 2 to 23 across three ordinary hosts, 16 of Debian's 23 from
    sbuild alone, and the apparmor package owns every one of those files."""
    res = _run(profiles={f"c{i}": "complain" for i in range(23)},
               procs=[{"profile": "c0", "status": "enforce"}])
    assert "23 complain" in " ".join(res.notes)
    assert not [f for f in res.findings if "complain" in f.check]


# -- the one finding, and it fires on a stock Debian -------------------------
def test_nothing_confined_is_a_finding_even_on_a_stock_host():
    """Debian 13 loads 106 profiles and confines none of its 19 running executables."""
    res = _run(profiles={f"p{i}": "enforce" for i in range(106)},
               procs=[],
               running={f"/usr/bin/x{i}": "unconfined" for i in range(19)})
    f = [x for x in res.findings if x.check == "apparmor-confines-nothing"]
    assert len(f) == 1
    assert "106 profiles" in f[0].detail and "19 running" in f[0].detail
    assert f[0].severity == "Low"


def test_the_finding_names_the_uninstalled_profile_packages():
    res = _run(profiles={"p": "enforce"}, procs=[],
               running={"/usr/bin/x": "unconfined"},
               missing_pkgs=["apparmor-profiles", "apparmor-profiles-extra"])
    detail = next(f.detail for f in res.findings
                  if f.check == "apparmor-confines-nothing")
    assert "apparmor-profiles" in detail and "apparmor-profiles-extra" in detail


def test_a_host_that_confines_something_gets_no_finding():
    """Ubuntu 26.04 confines chronyd and nothing else. One is not zero."""
    res = _run(profiles={"chronyd": "enforce"},
               procs=[{"profile": "chronyd", "status": "enforce"}],
               running={"/usr/sbin/chronyd": "/usr/sbin/chronyd (enforce)",
                        "/usr/bin/x": "unconfined"})
    assert not [f for f in res.findings if f.check == "apparmor-confines-nothing"]


# -- the surviving narrow form of the unconfined-process rule ----------------
def test_a_loaded_profile_that_is_not_applied_is_a_finding():
    """Measured 0 on all three hosts, so this is quiet by design rather than by luck."""
    res = _run(profiles={"/usr/sbin/nginx": "enforce"},
               procs=[{"profile": "other", "status": "enforce"}],
               running={"/usr/sbin/nginx": "unconfined"})
    assert [f.subject for f in res.findings
            if f.check == "apparmor-profile-not-applied"] == ["/usr/sbin/nginx"]


def test_an_unconfined_process_with_no_profile_is_not_a_finding():
    """Most of a desktop runs unconfined because no profile exists for it. That is the
    normal state and flagging it produces hundreds of rows."""
    res = _run(profiles={"something-else": "enforce"},
               procs=[{"profile": "something-else", "status": "enforce"}],
               running={f"/usr/bin/x{i}": "unconfined" for i in range(200)})
    assert not [f for f in res.findings if f.check == "apparmor-profile-not-applied"]


def test_parse_status_rejects_junk_rather_than_returning_empty():
    assert apparmor.parse_status("not json") is None
    assert apparmor.parse_status('{"profiles": []}') is None
    assert apparmor.parse_status('{"profiles": {"a": "enforce"}, "processes": {}}') \
        == ({"a": "enforce"}, [])


def test_the_privilege_branch_does_not_suggest_installing_what_is_present():
    """`aa-status` was found on PATH, so the obstacle is root, not a missing package.
    Suggesting an install sends the reader to fix something that is not broken."""
    res = _run(raw="apparmor module is loaded.\n", tool=True)
    assert res.blind[0][2] == ""


def test_the_missing_tool_branch_does_name_the_package():
    res = _run(tool=False)
    assert res.blind[0][2] == "apparmor"
