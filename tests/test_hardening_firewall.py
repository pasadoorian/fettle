"""The host firewall axis.

"A firewall is active" is nearly content-free — a firewall service running with an
empty ruleset filters nothing and reads as protection on every dashboard it reaches.
The tool that prompted this work reports `[ ACTIVE ]` and stops. These tests are
mostly about the three ways that can go wrong: claiming protection that is not there,
claiming absence that is not there, and claiming knowledge that needed root.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening.axes import MEDIUM, firewall
from fettle.hardening.axes import render as arender
from fettle.output import Output


def _ctx() -> Context:
    return Context(output=Output(color=False), config=Config(),
                   user_home=Path("/home/paul"))


def _fake(*, active=(), nft=None, iptables=None, have=("systemctl", "nft")):
    def which(name):
        return f"/usr/bin/{name}" if name in have else None

    def run(cmd, *, as_user=None, capture=False, timeout=None):
        argv = list(cmd)
        if argv[:2] == ["systemctl", "is-active"]:
            ok = argv[2] in active
            return command.Proc(0 if ok else 3, "active\n" if ok else "inactive\n", "")
        if argv[:2] == ["nft", "list"]:
            rc, out, err = nft
            return command.Proc(rc, out, err)
        if argv[:2] == ["iptables", "-S"]:
            rc, out, err = iptables
            return command.Proc(rc, out, err)
        return command.Proc(0, "", "")
    return which, run


def _run(**kw):
    which, run = _fake(**kw)
    with patch("fettle.command.which", side_effect=which), \
         patch("fettle.command.run", side_effect=run):
        return firewall.run(None, _ctx())


_DENIED = (1, "", "Error: Operation not permitted (you must be root)\n")
_RULES = (0, "table inet filter {\n  chain input {\n    type filter hook input\n"
             "    tcp dport 22 accept\n    drop\n  }\n}\n", "")
_EMPTY = (0, "", "")


# --------------------------------------------------------------------------

def test_an_active_service_with_no_rules_is_a_finding():
    """The case the usual "[ACTIVE]" answer gets wrong: running and filtering nothing."""
    res = _run(active=("ufw",), nft=_EMPTY)

    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.check == "empty-ruleset"
    assert f.severity == MEDIUM
    assert "ufw is running" in f.detail
    assert "filters nothing" in f.detail


def test_rules_present_is_not_a_finding_even_with_no_service_running():
    """Docker and libvirt program netfilter directly, and plenty of hosts load rules
    from a script. Reporting "no firewall" on a host with a full ruleset would be the
    same false positive this exercise exists to avoid — so rules outrank the absence
    of a managing service."""
    res = _run(active=(), nft=_RULES)

    assert res.findings == []
    assert "rule(s) in effect" in " ".join(res.notes)
    assert "loaded directly" in " ".join(res.notes)


def test_no_rules_and_no_service_is_a_finding():
    res = _run(active=(), nft=_EMPTY)
    assert [f.check for f in res.findings] == ["empty-ruleset"]
    assert "no firewall service is running" in res.findings[0].detail


def test_permission_denied_is_blind_not_an_empty_ruleset():
    """The load-bearing one. Measured on the reference machine: nft, iptables, ufw and
    firewall-cmd all refuse to be read unprivileged. "Cannot read the rules" and "there
    are no rules" are the same empty string if nobody distinguishes them, and one of
    those two answers is a critical finding."""
    res = _run(active=("ufw",), nft=_DENIED, have=("systemctl", "nft"))

    assert res.findings == []            # must NOT report an empty ruleset
    assert res.blind
    what, why, _ = res.blind[0]
    assert "ruleset was NOT checked" in what
    assert "needs root" in why
    assert "ufw" in " ".join(res.notes)  # but it still reports what it could see


def test_a_partially_blind_axis_does_not_sign_off_as_nothing_to_report():
    """Unprivileged, this axis can see that ufw is active and cannot read one rule.
    Rendering that as a bare "nothing to report" is close to the opposite of the truth,
    and it is easy to miss because the axis genuinely did run."""
    res = _run(active=("ufw",), nft=_DENIED)
    line = arender.screen([res])[0]

    assert "not checked" in line
    assert line.rstrip().endswith("(see below)")


def test_iptables_default_accept_policy_is_not_a_rule():
    """`-P INPUT ACCEPT` is the absence of filtering written down, not filtering."""
    res = _run(active=(), nft=None, have=("systemctl", "iptables"),
               iptables=(0, "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", ""))

    assert [f.check for f in res.findings] == ["empty-ruleset"]


def test_iptables_drop_policy_counts_as_filtering():
    res = _run(active=(), nft=None, have=("systemctl", "iptables"),
               iptables=(0, "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n", ""))

    assert res.findings == []
    assert "2 packet-filter rule(s)" in " ".join(res.notes)


def test_no_tool_to_read_the_ruleset_is_blind():
    res = _run(active=("firewalld",), have=("systemctl",))
    assert res.findings == []
    assert res.blind
    assert "neither nft nor iptables" in res.blind[0][1]
