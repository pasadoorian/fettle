"""The service-exposure axis.

The load-bearing test here is the *negative* one: a packaged service at 9.6 UNSAFE
must produce no finding. sshd scores 9.6 on a correctly configured machine because it
runs as root and opens a socket — that is its job. A check that reports it is a check
whose whole section gets skipped, which is exactly what the tool that prompted this
work does with all sixty-seven of its units.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening.axes import MEDIUM, services
from fettle.hardening.axes import render as arender
from fettle.output import Output


def _ctx(**cfg) -> Context:
    return Context(output=Output(color=False), config=Config(**cfg),
                   user_home=Path("/home/paul"))


class _Backend:
    """Answers who owns a unit file — the only backend call this axis makes."""

    def __init__(self, owners: dict[str, str]):
        self._owners = owners

    def map_files_to_packages(self, paths) -> dict[str, str]:
        return {p: self._owners[p] for p in paths if p in self._owners}


def _security_json(units) -> str:
    return json.dumps([{"unit": u, "exposure": f"{e:.1f}", "predicate": p}
                       for u, e, p in units])


def _fake(*, security: str, running="", enabled="", show="", per_unit="[]",
          missing=()):
    """Stub the four commands this axis runs. `missing` names absent binaries."""
    def which(name):
        return None if name in missing else f"/usr/bin/{name}"

    def run(cmd, *, as_user=None, capture=False):
        argv = list(cmd)
        if argv[:2] == ["systemd-analyze", "security"]:
            # With a trailing unit name it is the per-unit query, not the sweep.
            tail = [a for a in argv[2:] if not a.startswith("-")]
            return command.Proc(0, per_unit if tail else security, "")
        if argv[:2] == ["systemctl", "list-units"]:
            return command.Proc(0, running, "")
        if argv[:2] == ["systemctl", "list-unit-files"]:
            return command.Proc(0, enabled, "")
        if argv[:2] == ["systemctl", "show"]:
            return command.Proc(0, show, "")
        return command.Proc(0, "", "")
    return which, run


def _run(backend, ctx, **kw):
    which, run = _fake(**kw)
    with patch("fettle.command.which", side_effect=which), \
         patch("fettle.command.run", side_effect=run):
        return services.run(backend, ctx)


# --------------------------------------------------------------------------

def test_a_packaged_service_at_maximum_exposure_is_not_a_finding():
    """The anti-false-positive guard, and the reason this axis is not a score dump.

    sshd genuinely scores 9.6 UNSAFE on a healthy machine. Reporting that is how a
    security check trains its reader to stop looking.
    """
    res = _run(
        _Backend({"/usr/lib/systemd/system/sshd.service": "openssh"}), _ctx(),
        security=_security_json([("sshd.service", 9.6, "UNSAFE")]),
        running="sshd.service loaded active running OpenSSH\n",
        show="Id=sshd.service\nFragmentPath=/usr/lib/systemd/system/sshd.service\n")

    assert res.findings == []
    assert res.checked == 1               # and it did look
    assert res.na == "" and res.blind == []


def test_an_unpackaged_service_at_high_exposure_is_a_finding():
    """Found for real on the reference machine: two runZero agent units under
    /etc/systemd/system, owned by no package, running as root with host networking."""
    res = _run(
        _Backend({}), _ctx(),
        security=_security_json([("rumble-agent-abc.service", 9.6, "UNSAFE")]),
        running="rumble-agent-abc.service loaded active running agent\n",
        show="Id=rumble-agent-abc.service\n"
             "FragmentPath=/etc/systemd/system/rumble-agent-abc.service\n",
        per_unit=json.dumps([
            {"set": False, "name": "PrivateNetwork=", "exposure": "0.5",
             "description": "Service has access to the host's network"},
            {"set": False, "name": "User=", "exposure": "0.4",
             "description": "Service runs as root user"},
            {"set": True, "name": "ProtectHome=", "exposure": "0.0",
             "description": "already set — must not be named"},
        ]))

    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.check == "unpackaged-service"
    assert f.subject == "rumble-agent-abc.service"
    assert f.severity == MEDIUM
    assert "no package owns its unit file" in f.detail
    # names what to do about it, worst-weighted first
    assert "access to the host's network" in f.detail
    assert "already set" not in f.detail
    assert "systemctl cat" in f.fix


def test_an_unpackaged_but_well_confined_service_is_not_a_finding():
    """The finding is exposure *and* provenance. An unpackaged unit that is properly
    sandboxed is not something to raise — otherwise this becomes "you installed
    software", which is not a security check."""
    res = _run(
        _Backend({}), _ctx(),
        security=_security_json([("tidy.service", 1.2, "PROTECTED")]),
        running="tidy.service loaded active running tidy\n",
        show="Id=tidy.service\nFragmentPath=/etc/systemd/system/tidy.service\n")

    assert res.findings == []


def test_units_that_are_neither_running_nor_enabled_are_excluded():
    """A unit that exists but never runs is not exposure. This filter is what takes
    the reference machine from 67 units to 37, and from 42 UNSAFE to 18."""
    res = _run(
        _Backend({}), _ctx(),
        security=_security_json([("live.service", 9.6, "UNSAFE"),
                                 ("dormant.service", 9.9, "UNSAFE")]),
        running="live.service loaded active running live\n",
        show="Id=live.service\nFragmentPath=/etc/systemd/system/live.service\n")

    assert res.checked == 1
    assert [f.subject for f in res.findings] == ["live.service"]


def test_an_enabled_but_not_running_unit_still_counts():
    """Socket-activated daemons are enabled and idle; they are still exposure."""
    res = _run(
        _Backend({}), _ctx(),
        security=_security_json([("later.service", 9.6, "UNSAFE")]),
        enabled="later.service enabled enabled\n",
        show="Id=later.service\nFragmentPath=/etc/systemd/system/later.service\n")

    assert res.checked == 1
    assert [f.subject for f in res.findings] == ["later.service"]


def test_no_systemd_is_not_applicable_rather_than_blind():
    """A host with no systemd has no unit files to be exposed. That is a different
    statement from "fettle could not look", and rendering it as blindness would send
    the reader hunting for a tool to install that they do not want."""
    res = _run(_Backend({}), _ctx(), security="", missing=("systemctl",))

    assert res.na == "this host does not use systemd"
    assert res.blind == []
    assert res.findings == []


def test_systemd_present_but_not_booted_is_blind_not_clean():
    """The container case: systemctl exists, systemd is not the running init. This
    must never render as "no exposed services"."""
    res = _run(_Backend({}), _ctx(), security="")     # empty output, exit 0

    assert res.blind
    assert "NOT checked" in res.blind[0][0]
    assert res.findings == []
    assert res.checked == 0


def test_unparseable_output_is_blind():
    res = _run(_Backend({}), _ctx(), security="not json at all")
    assert res.blind
    assert res.findings == []


def test_the_posture_note_says_a_high_score_is_not_a_defect():
    """Without this sentence the note reads as "18 things are wrong"."""
    res = _run(
        _Backend({"/usr/lib/systemd/system/sshd.service": "openssh"}), _ctx(),
        security=_security_json([("sshd.service", 9.6, "UNSAFE")]),
        running="sshd.service loaded active running OpenSSH\n",
        show="Id=sshd.service\nFragmentPath=/usr/lib/systemd/system/sshd.service\n")

    note = " ".join(res.notes)
    assert "1 unsafe" in note
    assert "not by itself a defect" in note


def test_the_review_table_goes_to_the_report_not_the_screen():
    res = _run(
        _Backend({"/usr/lib/systemd/system/sshd.service": "openssh"}), _ctx(),
        security=_security_json([("sshd.service", 9.6, "UNSAFE")]),
        running="sshd.service loaded active running OpenSSH\n",
        show="Id=sshd.service\nFragmentPath=/usr/lib/systemd/system/sshd.service\n")

    assert any("openssh" in row for row in res.detail_rows)
    assert not any("openssh" in line for line in arender.screen([res]))
    assert any("openssh" in line for line in arender.report_body([res]))


def test_template_units_never_reach_the_batch_query():
    """`systemctl show` fails the ENTIRE batch on a template name — exits 1 and prints
    nothing — and `list-unit-files --state=enabled` returns `getty@.service` on an
    ordinary desktop. See the consequence test below."""
    assert services.is_template("getty@.service")
    assert services.is_template("user@.service")
    assert not services.is_template("user@1000.service")   # an instance, not a template
    assert not services.is_template("sshd.service")


def test_a_blanked_attribution_does_not_turn_every_service_into_a_finding():
    """The failure this axis exists to avoid, reached from the other direction.

    If the owner lookup comes back empty, every service at high exposure looks
    unpackaged — eighteen false findings on the reference machine, from the one axis
    built to not do that. So a batch that returns nothing is retried per unit.
    """
    calls = []

    def which(name):
        return f"/usr/bin/{name}"

    def run(cmd, *, as_user=None, capture=False):
        argv = list(cmd)
        if argv[:2] == ["systemd-analyze", "security"]:
            tail = [a for a in argv[2:] if not a.startswith("-")]
            return command.Proc(0, "[]" if tail else _security_json(
                [("sshd.service", 9.6, "UNSAFE"), ("cups.service", 9.6, "UNSAFE")]), "")
        if argv[:2] == ["systemctl", "list-units"]:
            return command.Proc(0, "sshd.service loaded active running x\n"
                                   "cups.service loaded active running y\n", "")
        if argv[:2] == ["systemctl", "list-unit-files"]:
            return command.Proc(0, "", "")
        if argv[:2] == ["systemctl", "show"]:
            units = [a for a in argv[2:] if a.endswith(".service")]
            calls.append(tuple(units))
            if len(units) > 1:            # the batch: aborted, as systemd really does
                return command.Proc(1, "", "Failed to get properties")
            u = units[0]
            return command.Proc(0, f"Id={u}\nFragmentPath=/usr/lib/systemd/system/{u}\n",
                                "")
        return command.Proc(0, "", "")

    owners = {f"/usr/lib/systemd/system/{u}": p
              for u, p in (("sshd.service", "openssh"), ("cups.service", "cups"))}
    with patch("fettle.command.which", side_effect=which), \
         patch("fettle.command.run", side_effect=run):
        res = services.run(_Backend(owners), _ctx())

    assert res.findings == []                 # both are packaged, and were seen to be
    assert len(calls) == 3                    # one failed batch, then one per unit


def test_the_per_unit_fallback_only_runs_when_the_batch_failed():
    """It is a recovery path, not the normal one — 37 extra subprocesses per run would
    be a real cost to pay for nothing."""
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        argv = list(cmd)
        calls.append(tuple(argv))
        return command.Proc(0, "Id=a.service\nFragmentPath=/lib/systemd/system/a.service\n"
                               "\nId=b.service\nFragmentPath=/lib/systemd/system/b.service\n",
                            "")

    with patch("fettle.command.run", side_effect=run):
        out = services._fragment_paths(["a.service", "b.service"])

    assert len(out) == 2
    assert len(calls) == 1


def test_a_long_unit_name_does_not_wrap_one_word_per_line():
    """Measured: a 56-character unit name pushed the detail into a four-column gutter
    and rendered one word per line for twenty lines."""
    from fettle.hardening.axes import HIGH, AxisResult, Finding

    res = AxisResult(name="services", title="t", checked=1, findings=[Finding(
        check="c", subject="rumble-agent-4b7a89f3-5659-48e1-bfb9-e9787dae3cf6.service",
        detail="exposure 9.6 UNSAFE, and no package owns its unit file — something "
               "outside the package manager installed a service", severity=HIGH)])

    body = arender.screen([res])[2:]           # skip the tally and the subject line
    assert all(len(line.split()) > 1 for line in body if line.strip())
