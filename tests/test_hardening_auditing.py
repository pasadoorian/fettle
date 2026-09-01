"""The auditing axis: will a change to the startup locations leave any record?

Calibrated against four hosts measured 2026-09-01, and every rule here exists because a
simpler version of it fires on a stock install of something:

* **auditd is not installed at all on Debian 13 or Ubuntu 26.04.** "auditd is not running"
  would fire on every Debian-family host for a package the distribution never shipped.
* **A stock AlmaLinux 9 runs auditd with zero rules loaded.** Its `audit.rules` holds four
  non-comment lines, all of them buffer and failure-mode settings, so "no rules loaded"
  is the shipped RHEL default.
* **`/etc/audit/rules.d` is mode 0750 on AlmaLinux and 0755 on Manjaro**, so an
  unprivileged run is blind on one and not the other, and blind must never render as
  "nothing is configured".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening.axes import LOW, MEDIUM, auditing
from fettle.output import Output

# Exactly what `auditctl -l` printed on fettle-alma9 after loading three watches, copied
# from the terminal rather than written from memory. auditctl accepts `-w` and then warns
# "Old style watch rules are slower", which is why the axis suggests the -F dir= form.
REAL_AUDITCTL_L = """\
-w /etc/systemd/system -p wa -k startup_persist
-w /usr/lib/systemd/system -p wa -k startup_persist
-w /etc/init.d -p wa -k startup_persist
"""

# The form Paul's own /etc/audit/rules.d/50-persistence.rules uses, and the one auditctl
# recommends. Both spellings appear in the wild, so both are parsed.
DIR_FORM = """\
-a always,exit -F dir=/etc/systemd/system/ -F perm=wa -F key=systemd_persist
-a always,exit -F dir=/usr/lib/systemd/system/ -F perm=wa -F key=systemd_persist
"""


class _Backend:
    def __init__(self, name="arch"):
        self.name = name


def _ctx(root: Path) -> Context:
    return Context(output=Output(color=False), config=Config(), root=root,
                   user_home=root, dry_run=True)


def _rules(root: Path, name: str, body: str) -> Path:
    d = root / "etc/audit/rules.d"
    d.mkdir(parents=True, exist_ok=True)
    path = d / name
    path.write_text(body)
    return path


class _Cmd:
    """Stands in for fettle.command, with per-test unit states and auditctl output."""

    def __init__(self, *, tools=("auditctl", "systemctl"), enabled="enabled",
                 active="active", listing="No rules\n", rc=0):
        self._tools, self._enabled, self._active = tools, enabled, active
        self._listing, self._rc = listing, rc

    def which(self, name):
        return f"/usr/sbin/{name}" if name in self._tools else None

    def run(self, argv, capture=False, timeout=None, **kw):
        class P:
            pass
        p = P()
        if argv[0] == "systemctl":
            p.returncode, p.stdout = 0, (
                self._enabled if argv[1] == "is-enabled" else self._active) + "\n"
        else:
            p.returncode, p.stdout = self._rc, self._listing
        p.stderr = ""
        return p


@pytest.fixture
def cmd(monkeypatch):
    def install(c):
        from fettle import command as real
        for attr in ("which", "run"):
            monkeypatch.setattr(real, attr, getattr(c, attr))
        return c
    return install


# ------------------------------------------------------------------- the parser


def test_the_w_form_is_parsed():
    """Real output from fettle-alma9, not a guess at the format."""
    assert auditing.watched_paths(REAL_AUDITCTL_L) == {
        "/etc/systemd/system", "/usr/lib/systemd/system", "/etc/init.d"}


def test_the_dir_form_is_parsed():
    """The form auditctl recommends and Paul's own rules file uses."""
    assert auditing.watched_paths(DIR_FORM) == {
        "/etc/systemd/system", "/usr/lib/systemd/system"}


def test_no_rules_parses_to_nothing_watched():
    assert auditing.watched_paths("No rules\n") == set()


def test_a_trailing_slash_does_not_make_a_path_look_unwatched():
    """`-F dir=` conventionally carries one and `-w` does not, and they mean the same."""
    assert auditing.watched_paths("-w /etc/init.d/ -p wa") == {"/etc/init.d"}


# -------------------------------------------------- unreadable is not the same as empty


def test_an_unreadable_rules_directory_is_blindness_not_an_empty_result(tmp_path):
    """The trap this axis was written around.

    /etc/audit/rules.d is 0750 root:root on AlmaLinux 9. The first pass of the
    measurement counted Permission denied as zero rules files, which reads as "nothing is
    configured" when the truth is "this run could not look".
    """
    d = tmp_path / "etc/audit/rules.d"
    d.mkdir(parents=True)
    (d / "audit.rules").write_text("-D\n")
    d.chmod(0o000)
    try:
        res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    finally:
        d.chmod(0o755)
    assert any("were NOT read" in what for what, _, _ in res.blind)


def test_rules_files_reports_readability_separately(tmp_path):
    d = tmp_path / "etc/audit/rules.d"
    d.mkdir(parents=True)
    (d / "50-persistence.rules").write_text("-w /etc/init.d -p wa\n")
    assert auditing.rules_files(tmp_path) == (["50-persistence.rules"], True)


def test_an_absent_directory_reads_as_readable_and_empty(tmp_path):
    """Absent is a real answer: nothing is configured. Only denied is blindness."""
    assert auditing.rules_files(tmp_path) == ([], True)


# ------------------------------------------------------------------- what fires, and where


def test_debian_without_auditd_is_not_applicable(tmp_path, cmd):
    """auditd is not installed on a stock Debian 13 or Ubuntu 26.04. Reporting it as a
    problem would fire on every Debian-family host for a package never shipped."""
    cmd(_Cmd(tools=("systemctl",)))
    res = auditing.run(_Backend("debian"), _ctx(tmp_path))
    assert res.na and "does not install it by default" in res.na
    assert res.findings == []


def test_rhel_without_auditd_is_a_finding(tmp_path, cmd):
    """RHEL ships it installed and enabled, so its absence there is a real regression."""
    cmd(_Cmd(tools=("systemctl",)))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    assert [f.check for f in res.findings] == ["auditd-not-installed"]
    assert res.findings[0].severity == LOW


def test_rules_written_but_auditd_not_running_is_the_reference_desktop(tmp_path, cmd):
    """wopr on 2026-09-01: audit 4.2.1-1 installed, 50-persistence.rules with four
    watches, auditd disabled and inactive. Somebody wrote the policy and nothing applies
    it, which is the one state where the machine's own config proves the intent."""
    _rules(tmp_path, "50-persistence.rules",
           "-a always,exit -F dir=/etc/systemd/system/ -F perm=wa -F key=systemd_persist\n"
           "-a always,exit -F dir=/usr/lib/systemd/system/ -F perm=wa -F key=systemd_persist\n"
           "-a always,exit -F dir=/etc/init.d/ -F perm=wa -F key=init_persist\n"
           "-a always,exit -F dir=/run/motd.d/ -F perm=wa -F key=motd_persist\n")
    cmd(_Cmd(enabled="disabled", active="inactive"))
    res = auditing.run(_Backend("arch"), _ctx(tmp_path))
    assert [f.check for f in res.findings] == ["auditd-configured-but-not-running"]
    assert res.findings[0].severity == MEDIUM
    assert "4 watch directive(s)" in res.findings[0].detail
    assert "disabled" in res.findings[0].detail          # it will not start at boot either


def test_no_rules_loaded_on_a_running_auditd_reports_the_missing_paths(tmp_path, cmd):
    """A stock AlmaLinux 9: auditd active, audit.rules present, auditctl -l says "No
    rules". Fires at Low deliberately, the same way the AppArmor axis fires on a stock
    Debian: the host really is in this state and there is a specific thing to do."""
    _rules(tmp_path, "audit.rules", "-D\n-b 8192\n-f 1\n")
    cmd(_Cmd(listing="No rules\n"))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    assert [f.check for f in res.findings] == ["auditd-startup-paths-unwatched"]
    assert res.findings[0].severity == LOW
    assert "4 startup location(s)" in res.findings[0].summary


def test_the_suggested_rule_uses_the_form_auditctl_does_not_call_slow(tmp_path, cmd):
    """auditctl prints "Old style watch rules are slower" for every -w it accepts.
    Suggesting the slow form would be telling the reader to do the thing the tool warns
    about, which was caught by running it rather than by reading the manual."""
    _rules(tmp_path, "audit.rules", "-D\n")
    cmd(_Cmd(listing="No rules\n"))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    fix = res.findings[0].fix
    assert "-F dir=" in fix and "perm=wa" in fix
    assert "-w /" not in fix


def test_partially_watched_reports_only_what_is_missing(tmp_path, cmd):
    """Verified live: three watches loaded on fettle-alma9 produced "watching 3 path(s)"
    and one missing location, not four."""
    _rules(tmp_path, "audit.rules", "-D\n")
    cmd(_Cmd(listing=REAL_AUDITCTL_L))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    assert len(res.findings) == 1
    assert "1 startup location(s)" in res.findings[0].summary
    assert "/etc/update-motd.d" in res.findings[0].detail


def test_the_arch_spelling_of_the_motd_directory_counts(tmp_path, cmd):
    """Paul's own rules file watches /run/motd.d, which is where Arch puts it. Demanding
    /etc/update-motd.d specifically would report a watched path as unwatched."""
    _rules(tmp_path, "audit.rules", "-D\n")
    cmd(_Cmd(listing=REAL_AUDITCTL_L + "-w /run/motd.d -p wa -k motd_persist\n"))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    assert res.findings == []


def test_everything_watched_is_silent(tmp_path, cmd):
    _rules(tmp_path, "audit.rules", "-D\n")
    listing = "".join(f"-w {p} -p wa -k k\n" for p, _ in auditing.WATCH_PATHS)
    cmd(_Cmd(listing=listing))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    assert res.findings == []
    assert any("watching 4 path(s)" in n for n in res.notes)


def test_auditctl_refusing_privilege_is_blindness_not_zero_watches(tmp_path, cmd):
    """auditctl -l exits 4 unprivileged. Treating that as "watching nothing" would
    report every path unwatched on any run that was not root."""
    _rules(tmp_path, "audit.rules", "-D\n")
    cmd(_Cmd(listing="You must be root to run this program.\n", rc=4))
    res = auditing.run(_Backend("rhel"), _ctx(tmp_path))
    assert res.findings == []
    assert any("loaded audit rules were NOT read" in what for what, _, _ in res.blind)


def test_configured_watches_counts_both_spellings(tmp_path):
    _rules(tmp_path, "a.rules", "-w /etc/init.d -p wa -k x\n# comment\n")
    _rules(tmp_path, "b.rules", "-a always,exit -F dir=/etc/systemd/system/ -F perm=wa\n")
    assert auditing.configured_watches(tmp_path) == 2
