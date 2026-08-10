"""Boot persistence — the first real compromise check (M1.2).

The measured floor this is calibrated against, from the reference desktop on
2026-08-10: **482 real unit files across the three system directories, 480 of them
package-owned.** The two that are not are runZero Explorer agents installed on purpose.
A check that reports two explicable things on a healthy machine is usable; the same
check without the symlink exclusion reports 41, and without the location rule grades
both agents High and prints a preservation banner over them.

Every threshold here exists because a simpler version of it was wrong on that machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fettle.backends.base import Context
from fettle.compromise import HIGH, LOW, MEDIUM, persistence
from fettle.config import Config
from fettle.output import Output

# The June 2026 AUR supply-chain wave's persistence, as reported by CSA: Restart=always,
# dropped in /etc/systemd/system, payload under /var/lib. Quiet — one binary, no sockets.
AUR_WAVE_UNIT = """\
[Unit]
Description=System Update Helper

[Service]
Type=simple
ExecStart=/var/lib/systemd-helper/updated
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
"""

# The shape of the two legitimate findings on the reference machine.
VENDOR_AGENT_UNIT = """\
[Unit]
Description=runZero Explorer

[Service]
ExecStart=/opt/rumble/bin/rumble-agent-4b7a89f3
User=root
Restart=always
"""


class _Backend:
    """Package ownership, controlled per test rather than asked of the real host."""

    name = "arch"

    def __init__(self, owned=()):
        self._owned = {str(p): "somepkg" for p in owned}

    def map_files_to_packages(self, paths):
        return {p: self._owned[p] for p in map(str, paths) if p in self._owned}


def _ctx(root: Path) -> Context:
    return Context(output=Output(color=False), config=Config(), root=root,
                   user_home=root, dry_run=True)


def _unit(root: Path, name: str, body: str, *, where="etc/systemd/system") -> Path:
    directory = root / where
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body)
    return path


# ------------------------------------------------------- the reason this check exists


def test_finds_the_aur_wave_unit_shape(tmp_path):
    _unit(tmp_path, "systemd-helper.service", AUR_WAVE_UNIT)
    (tmp_path / "var/lib/systemd-helper").mkdir(parents=True)
    (tmp_path / "var/lib/systemd-helper/updated").write_text("payload")

    res = persistence.run(_Backend(), _ctx(tmp_path))

    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.severity == HIGH
    assert "/var/lib" in finding.detail
    assert "Restart=always" in finding.detail       # context, printed
    assert "AUR" in finding.detail                  # the campaign is named


def test_the_services_axis_does_not_find_that_unit(tmp_path, monkeypatch):
    """The regression this milestone exists to close, proved rather than asserted.

    `hardening-audit`'s services axis already reports unpackaged units — but only above
    an exposure score of 7.0, because there the unpackaged-ness is one input into a
    judgement about *reach*. The AUR wave's unit runs one binary and opens no sockets,
    so it scores low and is skipped. Both checks look at the same file and ask different
    questions of it, which is why the answer differs.
    """
    from fettle.hardening.axes import services

    unit_path = _unit(tmp_path, "systemd-helper.service", AUR_WAVE_UNIT)

    monkeypatch.setattr(services.command, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(services, "_run", lambda argv: (
        # systemd-analyze scores it 2.9 — quiet, which is the whole point.
        (0, '[{"unit": "systemd-helper.service", "exposure": 2.9, '
            '"predicate": "OK"}]') if "security" in argv else (0, "")))
    monkeypatch.setattr(services, "_active_units", lambda: {"systemd-helper.service"})
    monkeypatch.setattr(services, "_fragment_paths",
                        lambda units: {"systemd-helper.service": str(unit_path)})

    axis = services.run(_Backend(), _ctx(tmp_path))

    assert axis.checked == 1, "the axis did look at the unit"
    assert axis.findings == [], (
        "if this ever fails the services axis has started catching low-exposure "
        "unpackaged units, and this check's scope should be revisited")


# -------------------------------------------------------------------- what is found


def test_owned_units_are_not_findings(tmp_path):
    path = _unit(tmp_path, "sshd.service", VENDOR_AGENT_UNIT, where="usr/lib/systemd/system")
    res = persistence.run(_Backend(owned=[path]), _ctx(tmp_path))
    assert res.findings == []
    assert res.checked == 1          # looked at it, and it was fine


def test_an_unowned_unit_in_the_distro_directory_is_still_found(tmp_path):
    """All 480 units in /usr/lib/systemd/system are owned on the reference machine.

    Which makes an unowned one there a file in the distribution's own unit directory
    that the distribution did not put there — the place an implant would most want to
    be, and the reason that directory is scanned despite costing 480 stats.
    """
    _unit(tmp_path, "sysupdate.service", AUR_WAVE_UNIT, where="usr/lib/systemd/system")
    (tmp_path / "var/lib/systemd-helper").mkdir(parents=True)
    (tmp_path / "var/lib/systemd-helper/updated").touch()
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [HIGH]


def test_vendor_agent_in_opt_is_medium_not_high(tmp_path):
    """/opt is where the FHS puts software the package manager did not install.

    Grading it High would put a do-not-touch-anything banner over runZero on the
    reference machine, which is how the banner stops meaning anything.
    """
    _unit(tmp_path, "rumble-agent.service", VENDOR_AGENT_UNIT)
    (tmp_path / "opt/rumble/bin").mkdir(parents=True)
    (tmp_path / "opt/rumble/bin/rumble-agent-4b7a89f3").touch()

    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [MEDIUM]
    assert "Restart=always" in res.findings[0].detail, "still stated, just not scored"


def test_a_dead_unit_is_low_not_high(tmp_path):
    """The first live run graded this High and banner-ed it, on a healthy machine.

    The cause there was runZero renaming its binary. A unit whose target does not exist
    cannot execute anything, so it is the least dangerous state this check reports, not
    the most — severity follows what the unit could *do*.
    """
    _unit(tmp_path, "rumble-agent.service", VENDOR_AGENT_UNIT)   # target not created
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [LOW]
    assert "dead" in res.findings[0].short()


def test_symlinks_and_wants_directories_are_excluded(tmp_path):
    """41 entries versus 2 — the single biggest noise reduction in this check.

    `systemctl enable` creates both, they carry no content, and each points at a unit
    examined here on its own merits.
    """
    real = _unit(tmp_path, "real.service", VENDOR_AGENT_UNIT)
    (tmp_path / "etc/systemd/system/link.service").symlink_to(real)
    wants = tmp_path / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "real.service").symlink_to(real)

    assert [p.name for p in persistence._unit_files(tmp_path)] == ["real.service"]


def test_no_unit_directories_is_blind_not_clean(tmp_path):
    """Every supported distro uses systemd, so finding none means we could not look."""
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert res.findings == []
    assert res.blind, "an empty scan must say it could not look"
    assert not res.ran


def test_a_timer_with_no_execstart_is_reported_without_inventing_a_target(tmp_path):
    _unit(tmp_path, "backup.timer",
          "[Unit]\nDescription=x\n[Timer]\nOnCalendar=daily\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert len(res.findings) == 1
    assert res.findings[0].severity == MEDIUM
    assert "no ExecStart" in res.findings[0].detail


# ------------------------------------------------------------------ ExecStart parsing


@pytest.mark.parametrize("line,expected", [
    ("ExecStart=/usr/bin/thing", ["/usr/bin/thing"]),
    ("ExecStart=-/usr/bin/thing", ["/usr/bin/thing"]),        # ignore-failure prefix
    ("ExecStart=+/usr/bin/thing", ["/usr/bin/thing"]),        # full-privilege prefix
    ("ExecStart=@/usr/bin/thing argv0", ["/usr/bin/thing"]),  # argv[0] override
    ("ExecStart=!!/usr/bin/thing", ["/usr/bin/thing"]),
    ("ExecStart=/bin/sh -c 'curl x | sh'", ["/bin/sh"]),      # argv[0], never guessing
    ("ExecStart=", []),                                       # resets the list
    ("ExecStart=/usr/lib/%i/run", []),                        # unresolved specifier
    ("ExecStart=relative/path", []),                          # not a path we can check
    ("ExecStartPre=/usr/bin/setup", ["/usr/bin/setup"]),      # Pre/Post run too
    ("Description=ExecStart=not this", []),
])
def test_exec_target_parsing(line, expected):
    assert persistence.exec_targets(line) == expected


def test_every_suspect_directory_actually_escalates():
    """The list is the check — a typo in it silently downgrades a real finding."""
    for prefix in persistence.SUSPECT_DIRS:
        assert persistence._suspect(f"{prefix}payload") == prefix.rstrip("/")
    for ok in ("/usr/bin/x", "/opt/vendor/x", "/usr/local/bin/x", "/var/vanta/x"):
        assert persistence._suspect(ok) == "", f"{ok} is a legitimate location"
