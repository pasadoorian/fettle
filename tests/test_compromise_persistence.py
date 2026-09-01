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

import os
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


# `chmod 000` denies nothing to uid 0, so every test below whose mechanism is an
# unreadable directory is meaningless as root — it would assert blindness on a run that
# could see everything. CI runs as an ordinary user and exercises them; a `sudo pytest`
# or a root container skips them and says so, rather than failing for a reason that has
# nothing to do with the code. This is the same trap that made five tests pass only on
# the developer's machine during the QA pass.
needs_unprivileged = pytest.mark.skipif(
    os.geteuid() == 0,
    reason="permission-denial tests are meaningless as root (chmod 000 does not apply)")


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


# ------------------------------------------------------------------ scheduled jobs
#
# The asymmetry these tests exist to pin: `/etc/cron.d` is package-managed, so "no
# package owns this" is a signal there; `/var/spool/cron` and `~/.config/systemd/user`
# are not, so the same test applied to them would flag every user crontab and every user
# unit on every machine.

TIMESHIFT_CRON = """\
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=""

0 * * * * root timeshift --check --scripted
"""


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def test_unowned_system_cron_is_a_finding(tmp_path):
    """The real one on the reference machine: timeshift writes this at runtime."""
    _write(tmp_path, "etc/cron.d/timeshift-hourly", TIMESHIFT_CRON)
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [MEDIUM]
    assert "timeshift --check --scripted" in res.findings[0].detail


def test_owned_system_cron_is_not(tmp_path):
    path = _write(tmp_path, "etc/cron.d/0hourly", "01 * * * * root run-parts /etc/cron.hourly\n")
    res = persistence.run(_Backend(owned=[path]), _ctx(tmp_path))
    assert res.findings == []


def test_a_cron_job_running_from_a_suspect_location_is_high(tmp_path):
    _write(tmp_path, "etc/cron.d/update", "@reboot root /var/tmp/.sysd/agent\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [HIGH]
    assert "/var/tmp" in res.findings[0].detail


def test_user_crontabs_are_never_judged_on_ownership(tmp_path):
    """Applying the ownership test here would flag every user crontab ever created."""
    _write(tmp_path, "var/spool/cron/paulda", "0 3 * * * /usr/local/bin/backup.sh\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert res.findings == [], "a normal user crontab is not a finding"
    assert any("per-user crontab" in n for n in res.notes), "but it IS reported"
    assert any("backup.sh" in row for row in res.detail_rows)


def test_a_user_crontab_running_from_tmp_is_a_finding(tmp_path):
    _write(tmp_path, "var/spool/cron/paulda", "*/5 * * * * /dev/shm/.x/beacon\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [HIGH]
    assert "/dev/shm" in res.findings[0].detail


@needs_unprivileged
def test_an_unreadable_spool_is_blind_not_empty(tmp_path):
    """Debian ships /var/spool/cron 0730 root:crontab.

    Reporting zero scheduled jobs on a host that has them, because the directory could
    not be opened, is the failure this project is named for.
    """
    spool = tmp_path / "var/spool/cron"
    spool.mkdir(parents=True)
    (spool / "root").write_text("0 3 * * * /usr/bin/thing\n")
    spool.chmod(0o000)
    try:
        res = persistence.run(_Backend(), _ctx(tmp_path))
        assert res.blind, "an unreadable spool must say so"
        assert any("could not be read" in why for _, why, _ in res.blind)
    finally:
        spool.chmod(0o755)


def test_a_missing_spool_is_not_blind(tmp_path):
    """Absent means there are none. Only present-and-unreadable is blindness."""
    _write(tmp_path, "etc/cron.d/x", "0 * * * * root /usr/bin/thing\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert not [b for b in res.blind if "crontab" in b[0] or "at" in b[0]]


def test_at_jobs_are_reported_by_existing(tmp_path):
    _write(tmp_path, "var/spool/atd/a0000101b2c3d4", "#!/bin/sh\n/tmp/payload\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert any("at` job" in n for n in res.notes)


# --------------------------------------------------------------------- user units


USER_UNIT = """\
[Unit]
Description=user helper
[Service]
ExecStart={target}
Restart=always
"""


def test_a_user_unit_is_not_a_finding_just_for_being_unowned(tmp_path, monkeypatch):
    """No package ever owns a unit in ~/.config — judging on ownership flags them all."""
    _fake_user(tmp_path, monkeypatch)
    _write(tmp_path, "home/real/.config/systemd/user/sync.service",
           USER_UNIT.format(target="/usr/local/bin/sync"))
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert res.findings == []
    assert res.checked >= 1, "it was still examined"
    assert any("sync.service" in row for row in res.detail_rows)


def test_a_user_unit_running_from_a_suspect_location_is_high(tmp_path, monkeypatch):
    """The non-root branch of the June 2026 AUR wave."""
    _fake_user(tmp_path, monkeypatch)
    _write(tmp_path, "home/real/.config/systemd/user/updater.service",
           USER_UNIT.format(target="/var/lib/systemd-helper/updated"))
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.severity for f in res.findings] == [HIGH]
    assert res.findings[0].subject.startswith("real:")
    assert "/var/lib" in res.findings[0].detail


@needs_unprivileged
def test_an_unreadable_home_is_blind_not_clean(tmp_path, monkeypatch):
    _fake_user(tmp_path, monkeypatch)
    directory = tmp_path / "home/real/.config/systemd/user"
    directory.mkdir(parents=True)
    directory.chmod(0o000)
    try:
        res = persistence.run(_Backend(), _ctx(tmp_path))
        assert any("user services" in what for what, _, _ in res.blind)
    finally:
        directory.chmod(0o755)


def _fake_user(root: Path, monkeypatch) -> None:
    """One real user with a home, plus the noise accounts a real box carries."""
    import pwd

    (root / "home/real").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(pwd, "getpwall", lambda: [
        pwd.struct_passwd(("real", "x", 1000, 1000, "", "/home/real", "/bin/bash")),
        pwd.struct_passwd(("nixbld1", "x", 1101, 1101, "", "/var/empty",
                           "/usr/sbin/nologin")),
    ])


# ---------------------------------------------------------------- crontab parsing


@pytest.mark.parametrize("line,has_user,expected", [
    ("0 * * * * root timeshift --check", True, ["timeshift --check"]),
    ("0 * * * * /usr/bin/backup", False, ["/usr/bin/backup"]),
    ("@reboot root /var/lib/x/agent", True, ["/var/lib/x/agent"]),
    ("@daily /usr/bin/thing", False, ["/usr/bin/thing"]),
    ("# 0 * * * * root disabled", True, []),
    ("SHELL=/bin/bash", True, []),
    ('MAILTO=""', True, []),
    ("", True, []),
    ("0 * * *", True, []),                       # too few fields to be a schedule
])
def test_cron_command_parsing(line, has_user, expected):
    from fettle.compromise import cron

    assert cron.commands(line, has_user_field=has_user) == expected


@pytest.mark.parametrize("command,expected", [
    ("/usr/bin/backup --daily", "/usr/bin/backup"),
    ("timeshift --check", ""),                   # bare name: not resolved against PATH
    ("sudo /usr/bin/thing", "/usr/bin/thing"),   # wrappers stepped over
    ("/usr/bin/env FOO=1 /opt/x/run", "/opt/x/run"),
    ("nice -n 19 /var/tmp/x", "/var/tmp/x"),
])
def test_cron_argv0(command, expected):
    from fettle.compromise import cron

    assert cron.argv0(command) == expected


# ------------------------------------------------- the interpreter-difference guard
#
# These exist because CI failed on a commit that was green locally, and the cause was
# neither the code nor the test being wrong on its own terms: `Path.is_dir()` raises
# EACCES on python 3.11-3.13 and returns False on 3.14. wopr runs 3.14; CI runs the
# other three. A test that only exercises the real filesystem is therefore a test whose
# meaning depends on which interpreter runs it — so the strict behaviour is simulated
# here, and the same scenario is pinned on every version.


def _strict_isdir(monkeypatch):
    """`os.path.isdir` that behaves like python 3.11-3.13's `Path.is_dir()`.

    Those versions call `self.stat()` and swallow only what `pathlib._ignore_error`
    covers — ENOENT, ENOTDIR, EBADF, ELOOP. EACCES is not in that list, so it
    propagates. 3.14 replaced the whole thing with `os.path.isdir()`, which swallows
    everything. Mirroring the ignore-list exactly matters: a simulation that also raised
    on a missing path would fail the test for a reason CI never saw.
    """
    import errno
    import os

    ignored = {errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP}
    real = os.path.isdir

    def strict(path):
        try:
            os.stat(path)
        except OSError as exc:
            if exc.errno not in ignored:
                raise
            return False
        return real(path)

    monkeypatch.setattr(os.path, "isdir", strict)


@needs_unprivileged
def test_unreadable_spool_under_the_strict_isdir_of_older_pythons(tmp_path, monkeypatch):
    """The exact scenario that failed CI and passed here.

    On Debian `/var/spool/cron` is `0730 root:crontab`, so an unprivileged run probes
    `/var/spool/cron/crontabs` through a directory it cannot search. Before the fix that
    raised out of the whole persistence group, `run_all` caught it, and the group was
    reported blind — meaning a Debian user got *no* persistence findings rather than the
    ones this check can produce without root.
    """
    _write(tmp_path, "etc/cron.d/timeshift-hourly", TIMESHIFT_CRON)
    spool = tmp_path / "var/spool/cron"
    spool.mkdir(parents=True)
    (spool / "root").write_text("0 3 * * * /usr/bin/thing\n")
    spool.chmod(0o000)
    _strict_isdir(monkeypatch)
    try:
        res = persistence.run(_Backend(), _ctx(tmp_path))
    finally:
        spool.chmod(0o755)

    # It did not raise, it still produced the findings it could see...
    assert [f.severity for f in res.findings] == [MEDIUM]
    # ...and it said what it could not see.
    assert any("could not be read" in why for _, why, _ in res.blind)


@needs_unprivileged
def test_nested_unreadable_directories_are_reported_once(tmp_path):
    """Naming `/var/spool/cron/crontabs` when `/var/spool/cron` is already unreadable
    says the same thing twice, and implies we know the nested one exists."""
    from fettle.compromise import cron

    spool = tmp_path / "var/spool/cron"
    spool.mkdir(parents=True)
    spool.chmod(0o000)
    try:
        blocked = cron.unreadable(tmp_path, cron.USER_CRON_DIRS)
    finally:
        spool.chmod(0o755)
    assert len(blocked) == 1
    assert blocked[0].endswith("var/spool/cron")


def test_the_filesystem_predicates_never_raise(monkeypatch):
    """The contract, asserted directly so it does not depend on the interpreter."""
    import os

    from fettle.compromise import is_directory, is_regular_file

    def boom(_path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os.path, "isdir", boom)
    monkeypatch.setattr(os.path, "isfile", boom)
    assert is_directory("/anything") is False
    assert is_regular_file("/anything") is False


# ------------------------------------------- widened 2026-09-01: sockets, paths, drop-ins


SOCKET_UNIT = """\
[Unit]
Description=Listener

[Socket]
ListenStream=4444
Accept=no

[Install]
WantedBy=sockets.target
"""

PATH_UNIT = """\
[Unit]
Description=Watcher

[Path]
PathExists=/tmp/.trigger
Unit=payload.service
"""


def test_an_unowned_socket_unit_is_found(tmp_path):
    """`.socket` persists with no always-running process, so nothing looks odd in ps."""
    _unit(tmp_path, "backdoor.socket", SOCKET_UNIT)
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-unit"]
    assert [f.subject for f in found] == ["backdoor.socket"]
    assert "when something connects" in found[0].detail


def test_an_unowned_path_unit_is_found(tmp_path):
    """`.path` fires on a filesystem event, which no process listing shows either."""
    _unit(tmp_path, "watcher.path", PATH_UNIT)
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-unit"]
    assert [f.subject for f in found] == ["watcher.path"]
    assert "when a file appears" in found[0].detail


def test_socket_and_path_units_are_not_described_as_timers(tmp_path):
    """The old wording said "a timer, or a unit that only orders others" for every unit
    with no ExecStart. Naming the actual trigger is the point of scanning these."""
    _unit(tmp_path, "backdoor.socket", SOCKET_UNIT)
    _unit(tmp_path, "watcher.path", PATH_UNIT)
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-unit"]
    # Asserted before the negative below, so this cannot pass by finding nothing at all.
    assert len(found) == 2
    details = " ".join(f.detail for f in found)
    assert "a timer" not in details


def test_a_packaged_socket_unit_is_silent(tmp_path):
    path = _unit(tmp_path, "cups.socket", SOCKET_UNIT)
    res = persistence.run(_Backend(owned=[path]), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-unit"] == []


# ------------------------------------------------------------------- drop-in overrides


def _dropin(root: Path, unit: str, name: str, body: str,
            *, where="etc/systemd/system") -> Path:
    directory = root / where / f"{unit}.d"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body)
    return path


def test_an_unowned_dropin_is_found_and_names_the_unit_it_changes(tmp_path):
    """A drop-in hijacks a unit a package owns without touching the unit's own file."""
    _dropin(tmp_path, "sshd.service", "override.conf",
            "[Service]\nExecStartPost=/usr/local/bin/notify\n")
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-dropin"]
    assert len(found) == 1
    assert found[0].subject == "sshd.service.d/override.conf"
    assert "sshd.service" in found[0].summary
    assert "systemctl cat sshd.service" in found[0].fix


def test_a_dropin_running_from_a_suspect_directory_is_high(tmp_path):
    _dropin(tmp_path, "sshd.service", "10-hijack.conf",
            "[Service]\nExecStart=\nExecStart=/dev/shm/.x/payload\n")
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-dropin"]
    assert [f.severity for f in found] == [HIGH]
    assert "/dev/shm" in found[0].detail


def test_an_ordinary_unowned_dropin_admits_it_could_be_systemctl_edit(tmp_path):
    """No host measured has had `systemctl edit` run on it, so the floor of 0 unowned
    drop-ins does not cover the case where an admin made one. Say so in the finding."""
    _dropin(tmp_path, "docker.service", "override.conf",
            "[Service]\nLimitNOFILE=infinity\n")
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-dropin"]
    assert [f.severity for f in found] == [MEDIUM]
    assert "systemctl edit" in found[0].detail


def test_a_packaged_dropin_is_silent(tmp_path):
    path = _dropin(tmp_path, "sshd.service", "50-distro.conf",
                   "[Service]\nRestart=always\n")
    res = persistence.run(_Backend(owned=[path]), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-dropin"] == []


def test_the_dropin_scan_does_not_pick_up_wants_symlinks(tmp_path):
    """`.wants/` holds what `systemctl enable` creates. Only `.d/` holds real content."""
    real = _unit(tmp_path, "real.service", "[Service]\nExecStart=/usr/bin/true\n")
    wants = tmp_path / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True)
    (wants / "real.service").symlink_to(real)
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-dropin"] == []


def test_the_dropin_finding_shows_what_the_override_sets(tmp_path):
    """"An unowned file exists" is not actionable; what it changes is."""
    _dropin(tmp_path, "nginx.service", "override.conf",
            "# a comment\n[Service]\nUser=root\nEnvironment=DEBUG=1\n")
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-dropin"]
    assert "User=root" in found[0].detail
    assert "Environment=DEBUG=1" in found[0].detail
    assert "a comment" not in found[0].detail
    assert "[Service]" not in found[0].detail


# ------------------------------------------- P2: boot and login execution, not units


def _script(root: Path, rel: str, name: str, body: str = "#!/bin/sh\ntrue\n") -> Path:
    directory = root / rel
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(body)
    return path


@pytest.mark.parametrize("rel,phrase", [
    ("usr/lib/systemd/system-generators", "generator"),
    ("etc/init.d", "SysV"),
    ("etc/profile.d", "login shell"),
    ("etc/update-motd.d", "SSH login"),
    ("etc/xdg/autostart", "desktop session"),
])
def test_an_unowned_startup_script_is_found_and_says_what_runs_it(tmp_path, rel, phrase):
    """"An unowned file" is not actionable. What runs it, and when, is."""
    _script(tmp_path, rel, "evil")
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-startup-script"]
    assert len(found) == 1
    assert found[0].severity == MEDIUM
    assert phrase in found[0].detail


def test_a_packaged_startup_script_is_silent(tmp_path):
    path = _script(tmp_path, "etc/profile.d", "distro.sh")
    res = persistence.run(_Backend(owned=[path]), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-startup-script"] == []


def test_rc_local_is_not_a_finding_when_it_cannot_run(tmp_path):
    """AlmaLinux 9 ships /etc/rc.local without the execute bit. It is inert, and
    reporting it would fire on a stock install for no reason."""
    path = _script(tmp_path, "etc", "rc.local")
    path.chmod(0o644)
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-startup-script"] == []


def test_an_executable_unowned_rc_local_is_a_finding(tmp_path):
    path = _script(tmp_path, "etc", "rc.local")
    path.chmod(0o755)
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-startup-script"]
    assert [f.subject for f in found] == ["/etc/rc.local"]


def test_an_owned_executable_rc_local_is_silent(tmp_path):
    path = _script(tmp_path, "etc", "rc.local")
    path.chmod(0o755)
    res = persistence.run(_Backend(owned=[path]), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-startup-script"] == []


def test_rc_dirs_are_not_scanned_because_they_hold_only_symlinks(tmp_path):
    """Debian 13 has 63 entries under /etc/rc*.d and not one regular file. Every one
    points into /etc/init.d, which is scanned, so this would only rename each finding."""
    real = _script(tmp_path, "etc/init.d", "ssh")
    rc2 = tmp_path / "etc/rc2.d"
    rc2.mkdir(parents=True)
    (rc2 / "S01ssh").symlink_to(real)
    found = [f for f in persistence.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-startup-script"]
    assert [f.subject for f in found] == ["/etc/init.d/ssh"]


def test_run_motd_d_is_not_scanned(tmp_path):
    """fwupd writes /run/motd.d/85-fwupd at runtime and no package owns it, on both the
    reference desktop and Debian 13. The test's answer is known before it runs."""
    _script(tmp_path, "run/motd.d", "85-fwupd")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-startup-script"] == []


def test_etc_profile_itself_is_not_scanned(tmp_path):
    """/etc/profile is owned by NO package on Debian 13 and Ubuntu 26.04: dpkg-query -S
    exits 1 and base-files does not list it. A rule covering it would have fired on half
    the hosts measured, on a file every Linux system has."""
    (tmp_path / "etc").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc/profile").write_text("export PATH=/usr/bin\n")
    (tmp_path / "etc/bash.bashrc").write_text("PS1='$ '\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-startup-script"] == []


def test_startup_script_symlinks_are_skipped(tmp_path):
    real = _script(tmp_path, "opt", "vendor-hook")
    d = tmp_path / "etc/profile.d"
    d.mkdir(parents=True)
    (d / "vendor.sh").symlink_to(real)
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-startup-script"] == []
