"""The axis framework and the filesystem axis.

The framework tests are mostly about the three channels staying apart — findings vs
"could not look" vs "does not apply". Collapsing any two of those is the failure mode
this whole design exists to prevent, and it is not hypothetical: the Lynis run that
prompted the work rendered 22 unset-and-therefore-safe SSH options identically to
findings, and its own Secure Boot check reads the same whether Secure Boot is off or
undeterminable.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening import axes
from fettle.hardening.axes import HIGH, LOW, MEDIUM, AxisResult, Finding, filesystem
from fettle.hardening.axes import render as arender
from fettle.output import Output


def _ctx(root: Path, **cfg) -> Context:
    return Context(output=Output(color=False), config=Config(**cfg), root=root,
                   user_home=root)


def _fake_root(tmp_path: Path, mounts: str = "") -> Path:
    (tmp_path / "proc").mkdir(parents=True, exist_ok=True)
    (tmp_path / "proc/mounts").write_text(mounts)
    return tmp_path


def _mk(root: Path, rel: str, mode: int) -> Path:
    p = root / rel.lstrip("/")
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, mode)
    return p


def _findings(res: AxisResult, check: str) -> list[Finding]:
    return [f for f in res.findings if f.check == check]


# --------------------------------------------------------------------------
# the filesystem axis
# --------------------------------------------------------------------------

def test_world_writable_without_sticky_bit_is_a_high_finding(tmp_path):
    """The real bug this axis was built to catch.

    Measured on the machine that prompted this work: /tmp was a separate tmpfs at mode
    0777 with no sticky bit and no nosuid/nodev/noexec — any local user could delete
    another user's files there *and* drop a setuid binary. Lynis found the sticky bit
    half and filed it as a *suggestion*, below "add a legal banner to /etc/issue".
    """
    root = _fake_root(tmp_path, "tmpfs /tmp tmpfs rw,noatime 0 0\n")
    _mk(root, "/tmp", 0o777)

    res = filesystem.run(None, _ctx(root))

    found = _findings(res, "sticky-bit")
    assert len(found) == 1
    assert found[0].subject == "/tmp"
    assert found[0].severity == HIGH
    assert "delete or replace another user's files" in found[0].detail
    assert found[0].fix == "chmod +t /tmp"


def test_sticky_bit_present_is_not_a_finding(tmp_path):
    """The other half of the guard above: a correct /tmp must be silent.

    Without this, muting the check entirely would pass the test above's sibling and
    the axis would look like it worked while examining nothing.
    """
    root = _fake_root(tmp_path, "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n")
    _mk(root, "/tmp", 0o1777)

    res = filesystem.run(None, _ctx(root))

    assert _findings(res, "sticky-bit") == []
    assert res.findings == []
    assert res.checked >= 1          # and it did actually look


def test_missing_mount_options_are_reported_with_honest_severities(tmp_path):
    root = _fake_root(tmp_path, "tmpfs /tmp tmpfs rw,noatime 0 0\n")
    _mk(root, "/tmp", 0o1777)

    res = filesystem.run(None, _ctx(root))

    by_check = {f.check: f for f in res.findings}
    assert by_check["mount-nosuid"].severity == MEDIUM
    assert by_check["mount-noexec"].severity == MEDIUM
    # nodev defends against a device node on a filesystem you must be root to mount —
    # flattening it to medium alongside nosuid would erase a real difference.
    assert by_check["mount-nodev"].severity == LOW


def test_a_path_inside_another_filesystem_is_a_note_not_a_finding(tmp_path):
    """You cannot set mount options on a directory that is not a mount point.

    Reporting "/home is missing nosuid" on a single-filesystem host is advice to
    repartition dressed up as a defect — and it is what makes this class of tool
    ignorable.
    """
    root = _fake_root(tmp_path, "/dev/sda1 / ext4 rw 0 0\n")
    _mk(root, "/home", 0o755)

    res = filesystem.run(None, _ctx(root))

    assert res.findings == []
    assert len(res.notes) == 1
    assert "/home" in res.notes[0]
    assert "cannot be set independently" in res.notes[0]


def test_unreadable_mount_table_is_blind_not_clean(tmp_path):
    """Half the axis can still work, so it says precisely which half could not."""
    root = tmp_path                       # no proc/mounts at all
    _mk(root, "/tmp", 0o777)

    res = filesystem.run(None, _ctx(root))

    assert any("mount options were NOT checked" in what for what, _, _ in res.blind)
    # ...and the half that does not need the mount table still ran
    assert _findings(res, "sticky-bit")


def test_absent_paths_are_not_findings(tmp_path):
    """A path that does not exist is not a defect — /boot is absent in most containers."""
    root = _fake_root(tmp_path, "")
    res = filesystem.run(None, _ctx(root))
    assert res.findings == []


def test_extra_paths_from_config_are_additive(tmp_path):
    """Adding /srv must not silently drop the built-in list — losing /tmp because you
    asked to also watch a data mount is the surprise that makes a check useless."""
    root = _fake_root(tmp_path, "")
    _mk(root, "/tmp", 0o777)
    _mk(root, "/srv", 0o777)

    res = filesystem.run(None, _ctx(root, hardening={"filesystem_paths": ["/srv"]}))

    subjects = {f.subject for f in _findings(res, "sticky-bit")}
    assert subjects == {"/tmp", "/srv"}


def test_world_writable_outside_the_shared_set_is_still_flagged(tmp_path):
    """A sticky bit makes /tmp acceptable; it does not make /srv acceptable."""
    root = _fake_root(tmp_path, "")
    _mk(root, "/srv", 0o1777)

    res = filesystem.run(None, _ctx(root, hardening={"filesystem_paths": ["/srv"]}))

    found = _findings(res, "world-writable")
    assert [f.subject for f in found] == ["/srv"]


@pytest.mark.parametrize("raw,want", [
    ("tmpfs /tmp tmpfs rw 0 0", {"/tmp": {"rw"}}),
    ("tmpfs /var/lib/x\\040y tmpfs rw 0 0", {"/var/lib/x y": {"rw"}}),
])
def test_mount_table_parsing(tmp_path, raw, want):
    root = _fake_root(tmp_path, raw + "\n")
    assert filesystem.read_mounts(root) == want


def test_the_last_mount_of_a_path_wins(tmp_path):
    """A later mount shadows an earlier one; reading the first reports options that
    nothing is currently using."""
    root = _fake_root(tmp_path,
                      "old /tmp tmpfs rw,nosuid 0 0\nnew /tmp tmpfs rw,noexec 0 0\n")
    assert filesystem.read_mounts(root)["/tmp"] == {"rw", "noexec"}


# --------------------------------------------------------------------------
# the framework
# --------------------------------------------------------------------------

def _only(root: Path, name: str) -> Context:
    """A context running just one axis — so a framework test does not shell out to the
    real systemd, and does not need editing every time an axis is added."""
    others = [a for a in axes.ALL_AXIS_NAMES if a != name]
    return _ctx(root, hardening={"disable_axes": others})


def test_an_axis_that_raises_is_blind_not_clean(tmp_path, monkeypatch):
    """A bug in one axis must not read as that axis having nothing to report — and
    must not take the others down, which is the flaw that prompted the redesign."""
    def _boom(backend, ctx):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(filesystem, "run", _boom)
    results = axes.run_all(None, _only(_fake_root(tmp_path), "filesystem"))

    assert len(results) == 1
    assert results[0].findings == []
    assert results[0].blind
    assert "kaboom" in results[0].blind[0][1]


def test_disable_axes_switches_one_off(tmp_path):
    root = _fake_root(tmp_path)
    assert [r.name for r in axes.run_all(None, _only(root, "filesystem"))] == \
        ["filesystem"]
    every = _ctx(root, hardening={"disable_axes": list(axes.ALL_AXIS_NAMES)})
    assert axes.run_all(None, every) == []


def test_a_typo_in_disable_axes_is_reported(tmp_path):
    """Silently disabling nothing is the same class of surprise as silently disabling
    everything — the user asked for something and got no answer either way."""
    cfg = Config(hardening={"disable_axes": ["filesytem"]})
    assert axes.unknown_disabled(cfg) == ["filesytem"]
    assert axes.unknown_disabled(Config(hardening={"disable_axes": ["binary"]})) == []


def test_excludes_are_counted_so_the_run_can_say_what_it_hid(tmp_path):
    res = AxisResult(name="filesystem", title="t", checked=2, findings=[
        Finding(check="sticky-bit", subject="/tmp", detail="d"),
        Finding(check="mount-nodev", subject="/home", detail="d"),
    ])
    dropped = axes.apply_excludes([res], ["mount-*"], [])
    assert dropped == 1
    assert [f.check for f in res.findings] == ["sticky-bit"]

    res2 = AxisResult(name="filesystem", title="t", checked=1, findings=[
        Finding(check="sticky-bit", subject="/tmp", detail="d")])
    assert axes.apply_excludes([res2], [], ["/tmp"]) == 1
    assert res2.findings == []


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def test_an_axis_that_passed_still_prints(tmp_path):
    """A section that vanishes when it passes is indistinguishable from one that never
    ran — which is the invariant, applied to the rendering layer."""
    res = AxisResult(name="filesystem", title="Filesystem hygiene", checked=7)
    line = arender.screen([res])[0]
    assert "Filesystem hygiene" in line
    assert "nothing to report" in line
    assert "7 checked" in line


def test_a_blind_axis_does_not_render_as_a_pass():
    res = AxisResult(name="ssh", title="SSH configuration",
                     blind=[("sshd config was NOT checked", "needs root", "")])
    line = arender.screen([res])[0]
    assert "not checked" in line
    assert "nothing to report" not in line


def test_not_applicable_is_its_own_answer():
    """Neither a finding nor blindness: the question does not arise on this host."""
    res = AxisResult(name="ssh", title="SSH configuration", na="no sshd is installed")
    line = arender.screen([res])[0]
    assert "not applicable" in line
    assert "no sshd is installed" in line


def test_findings_render_worst_first():
    res = AxisResult(name="filesystem", title="t", checked=3, findings=[
        Finding(check="c", subject="/low", detail="d", severity=LOW),
        Finding(check="c", subject="/high", detail="d", severity=HIGH),
        Finding(check="c", subject="/med", detail="d", severity=MEDIUM),
    ])
    # [0] is the axis tally line, [1] the table header; the rows follow.
    lines = arender.screen([res])
    assert lines[1].split() == ["SEVERITY", "SUBJECT", "FINDING"]
    assert [ln.split()[1] for ln in lines[2:]] == ["/high", "/med", "/low"]
