"""Host firewall — is one active, and does it actually have rules?

The second half is the point. "A firewall is active" is what most audits report, and
it is nearly content-free: a firewall service that is running with an empty ruleset
filters nothing, and reads as protection on every dashboard it appears on. The tool
that prompted this work says ``Checking host based firewall [ ACTIVE ]`` and stops
there.

Two things are asked, and they need different privileges, so they are answered
separately rather than collapsed:

1. **Which management service is active?** ``systemctl is-active`` — rootless, always
   answerable where there is systemd.
2. **Are there packet-filter rules in the kernel?** ``nft list ruleset``, falling back
   to ``iptables -S``. This needs root. Measured on the reference machine: *nothing*
   here is readable unprivileged — nft, iptables, ufw and firewall-cmd all refuse.

So an unprivileged ``-H`` reports which service is running and says plainly that it
could not verify the rules. That is less than a full answer and more than a lie, and
it is strictly more than "[ACTIVE]".

One ordering rule matters: **rules in the kernel outrank the absence of a service.**
Docker and libvirt program iptables directly, and plenty of hosts load rules from a
script with no ``firewalld.service`` anywhere. Reporting "no firewall" on a host with
a full ruleset would be the same class of false positive this whole exercise exists to
avoid.
"""

from __future__ import annotations

from . import MEDIUM, AxisResult, Finding
from ... import command

# Checked in this order purely so the reported name matches what the user manages.
SERVICES = ("firewalld", "ufw", "nftables", "iptables", "ip6tables", "shorewall",
            "nftables-restore", "netfilter-persistent")

# Output that means "you are not allowed to look", as opposed to "there is nothing
# there". Distinguishing these is the whole job: they render identically as an empty
# ruleset if nobody checks.
_DENIED = ("permission denied", "must be root", "operation not permitted",
           "you need to be root", "not permitted")


def _run(argv: list[str]) -> tuple[int, str, str]:
    proc = command.run(argv, capture=True)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def active_services() -> list[str]:
    """Firewall management services systemd reports as running. Rootless."""
    if not command.which("systemctl"):
        return []
    found = []
    for name in SERVICES:
        rc, out, _ = _run(["systemctl", "is-active", name])
        if rc == 0 and out.strip() == "active":
            found.append(name)
    return found


def count_rules() -> tuple[int | None, str]:
    """``(rule count, how it was read)``. ``None`` means it could not be read.

    ``nft`` first because ufw and firewalld both ultimately program netfilter, so one
    read covers every front end rather than needing a parser per tool.
    """
    if command.which("nft"):
        rc, out, err = _run(["nft", "list", "ruleset"])
        if any(d in (out + err).lower() for d in _DENIED):
            return None, "nft (permission denied)"
        if rc == 0:
            # Chains without rules are scaffolding; a `policy drop` chain is itself
            # filtering, so it counts.
            rules = [ln for ln in out.splitlines()
                     if ln.strip() and not ln.strip().startswith(("table", "chain", "}"))]
            return len(rules), "nft list ruleset"
    if command.which("iptables"):
        rc, out, err = _run(["iptables", "-S"])
        if any(d in (out + err).lower() for d in _DENIED):
            return None, "iptables (permission denied)"
        if rc == 0:
            # `-P CHAIN ACCEPT` is the default-accept policy, which is the absence of
            # filtering rather than a rule. `-P CHAIN DROP` is filtering, and counts.
            rules = [ln for ln in out.splitlines()
                     if ln.startswith("-A") or (ln.startswith("-P")
                                                and not ln.endswith("ACCEPT"))]
            return len(rules), "iptables -S"
    return None, ""


def run(backend, ctx) -> AxisResult:
    res = AxisResult(name="firewall", title="Host firewall")
    services = active_services()
    rules, how = count_rules()

    if rules is None:
        res.checked = 1 if services else 0
        why = (f"reading the ruleset needs root ({how})" if how
               else "neither nft nor iptables is available to read the ruleset")
        res.blind.append(("the firewall ruleset was NOT checked",
                          f"{why} — an active firewall with an empty ruleset filters "
                          f"nothing, and this run could not tell the difference", ""))
        if services:
            res.notes.append(f"active firewall service(s): {', '.join(services)} — "
                             f"whether they have any rules loaded is unverified above")
        else:
            # Weaker than a finding: rules can be present with no managing service at
            # all (Docker and libvirt program netfilter directly), and this run cannot
            # see the rules to know.
            res.notes.append("no firewall management service is active, and the "
                             "ruleset could not be read — so this says nothing about "
                             "whether packets are being filtered")
        return res

    res.checked = 1
    if rules:
        managed = f", managed by {', '.join(services)}" if services else \
                  " (no management service is running — loaded directly)"
        res.notes.append(f"{rules} packet-filter rule(s) in effect{managed}")
        return res

    res.findings.append(Finding(
        check="empty-ruleset", subject="host firewall", severity=MEDIUM,
        detail=("no packet-filter rules are in effect" +
                (f", although {', '.join(services)} is running — a firewall service "
                 f"with an empty ruleset filters nothing" if services else
                 " and no firewall service is running") +
                ", so this host accepts whatever reaches it and depends entirely on "
                "network-level filtering"),
        fix="load a ruleset (ufw enable / firewall-cmd --reload / nft -f), or confirm "
            "this host is deliberately unfiltered"))
    return res
