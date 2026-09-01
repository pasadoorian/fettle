"""The startup inventory and the baseline diff.

The governing constraint, and the reason most of these tests exist: **the baseline
enriches, it never gates.** If the first run happens on a machine that is already
compromised, the implant is recorded as normal. A design where the baseline decided what
got reported would then go permanently quiet about it, and the machine that most needed
the check would be the one that said least.

So `test_the_baseline_never_silences_an_ownership_finding` is the important one here. The
rest guard the pieces that make it usable.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from fettle.backends.base import Context
from fettle.compromise import MEDIUM, baseline, persistence
from fettle.config import Config
from fettle.output import Output

UNIT = "[Service]\nExecStart=/usr/bin/true\n"


class _Backend:
    name = "arch"

    def __init__(self, owned=()):
        self._owned = {str(p): "somepkg" for p in owned}

    def map_files_to_packages(self, paths):
        return {p: self._owned[p] for p in map(str, paths) if p in self._owned}


def _ctx(root: Path, *, dry_run=False) -> Context:
    """user_home is the scratch root, so the real ~/.fettle is never touched."""
    return Context(output=Output(color=False), config=Config(), root=root,
                   user_home=root, dry_run=dry_run)


def _unit(root: Path, name: str, body: str = UNIT) -> Path:
    d = root / "etc/systemd/system"
    d.mkdir(parents=True, exist_ok=True)
    path = d / name
    path.write_text(body)
    return path


def _notes(res) -> str:
    return " ".join(res.notes)


# ----------------------------------------------------------- the governing constraint


def test_the_baseline_never_silences_an_ownership_finding(tmp_path):
    """An implant present when the baseline was taken is still unowned, so it is still
    reported. This is the poisoned-baseline case and the whole design turns on it."""
    _unit(tmp_path, "implant.service")
    first = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f.check for f in first.findings if f.check == "unowned-unit"] \
        == ["unowned-unit"]

    # Second run: the file is now in the baseline, i.e. "known". It must still be a
    # finding, because nothing about it became sanctioned by being recorded.
    second = persistence.run(_Backend(), _ctx(tmp_path))
    found = [f for f in second.findings if f.check == "unowned-unit"]
    assert [f.subject for f in found] == ["implant.service"]
    assert "0 new" in _notes(second)          # and it is correctly not reported as new


# ------------------------------------------------------------------- the first run


def test_the_first_run_says_it_recorded_a_baseline_not_that_nothing_changed(tmp_path):
    """"Baseline recorded, N entries" and "nothing changed" are different statements."""
    _unit(tmp_path, "a.service")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    notes = _notes(res)
    assert "startup baseline recorded" in notes
    assert "nothing to compare against" in notes
    assert "0 new, 0 modified" not in notes


def test_the_baseline_file_is_owner_only_from_the_start(tmp_path):
    """Same reasoning as the run-log fix: create-then-chmod leaves a window, and an
    interrupted run leaves the file readable permanently."""
    _unit(tmp_path, "a.service")
    persistence.run(_Backend(), _ctx(tmp_path))
    store = tmp_path / ".fettle" / baseline.FILENAME
    assert store.is_file()
    assert stat.S_IMODE(store.stat().st_mode) == 0o600


def test_dry_run_writes_no_baseline_and_says_so(tmp_path):
    _unit(tmp_path, "a.service")
    res = persistence.run(_Backend(), _ctx(tmp_path, dry_run=True))
    assert not (tmp_path / ".fettle" / baseline.FILENAME).exists()
    assert "--dry-run does not write one" in _notes(res)


# --------------------------------------------------- the one finding nothing else sees


def test_a_package_owned_file_edited_in_place_is_found(tmp_path):
    """No ownership test can ever see this: dbus.service still belongs to dbus after
    somebody rewrites its ExecStart."""
    path = _unit(tmp_path, "dbus.service")
    backend = _Backend(owned=[path])
    persistence.run(backend, _ctx(tmp_path))                    # baseline
    path.write_text("[Service]\nExecStart=/tmp/.x/payload\n")
    res = persistence.run(backend, _ctx(tmp_path))

    found = [f for f in res.findings if f.check == "startup-file-changed"]
    assert len(found) == 1
    assert found[0].severity == MEDIUM
    assert "still belongs to somepkg" in found[0].detail
    assert [f for f in res.findings if f.check == "unowned-unit"] == [], \
        "the ownership test correctly says nothing; only the baseline can see this"


def test_backdating_the_mtime_does_not_hide_a_change(tmp_path):
    """`touch -r reference victim` backdates an mtime in one command and cannot forge a
    sha256, which is why entries compare on content."""
    path = _unit(tmp_path, "dbus.service")
    backend = _Backend(owned=[path])
    before = path.stat()
    persistence.run(backend, _ctx(tmp_path))
    path.write_text("[Service]\nExecStart=/tmp/.x/payload\n")
    os.utime(path, (before.st_atime, before.st_mtime))          # the backdate

    res = persistence.run(backend, _ctx(tmp_path))
    assert [f.check for f in res.findings if f.check == "startup-file-changed"] \
        == ["startup-file-changed"]


def test_an_unchanged_machine_reports_no_changes(tmp_path):
    _unit(tmp_path, "a.service")
    backend = _Backend(owned=[tmp_path / "etc/systemd/system/a.service"])
    persistence.run(backend, _ctx(tmp_path))
    res = persistence.run(backend, _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "startup-file-changed"] == []
    assert "0 new, 0 modified" in _notes(res)


# ------------------------------------------------------------------- the enrichment


def test_a_file_that_arrived_since_the_baseline_says_so_on_the_existing_finding(tmp_path):
    """One finding, not two. The ownership check already reports it; the baseline adds
    when it turned up."""
    keep = _unit(tmp_path, "known.service")
    backend = _Backend(owned=[keep])
    persistence.run(backend, _ctx(tmp_path))
    _unit(tmp_path, "implant.service")

    res = persistence.run(backend, _ctx(tmp_path))
    found = [f for f in res.findings if f.check == "unowned-unit"]
    assert [f.subject for f in found] == ["implant.service"]
    assert "arrived since" in found[0].detail
    assert len([f for f in res.findings if "implant" in f.subject]) == 1
    # The first live run read "…a unit that only orders others It was not here…",
    # because not every detail string ends in punctuation.
    assert "others It was not" not in found[0].detail
    assert ". It was not here" in found[0].detail


def test_a_file_present_at_baseline_is_not_described_as_new(tmp_path):
    _unit(tmp_path, "implant.service")
    persistence.run(_Backend(), _ctx(tmp_path))
    res = persistence.run(_Backend(), _ctx(tmp_path))
    found = [f for f in res.findings if f.check == "unowned-unit"]
    assert "arrived since" not in found[0].detail


# ------------------------------------------------------------------- inventory and report


def test_the_inventory_summarises_on_screen_and_lists_in_the_report(tmp_path):
    _unit(tmp_path, "a.service")
    (tmp_path / "etc/profile.d").mkdir(parents=True)
    (tmp_path / "etc/profile.d/x.sh").write_text("true\n")
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert "startup inventory:" in _notes(res)
    assert any("a.service" in row for row in res.detail_rows)
    assert any("x.sh" in row for row in res.detail_rows)


def test_run_systemd_system_is_inventoried_though_it_is_not_ownership_checked(tmp_path):
    """Generator output that nothing owns by construction. Excluded from the ownership
    test because its answer is known in advance, and listed here so the reader can judge."""
    d = tmp_path / "run/systemd/system"
    d.mkdir(parents=True)
    (d / "netplan-ovs-cleanup.service").write_text(UNIT)
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-unit"] == []
    assert any("netplan-ovs-cleanup" in row and "generated" in row
               for row in res.detail_rows)


def test_removed_files_go_to_the_report_and_are_not_findings(tmp_path):
    """A package removal produces these in bulk and none of them is a risk.

    Two units, one removed, which is what an uninstall looks like. A machine with *no*
    startup files left is a `--root` pointed somewhere wrong, and `_system_units` already
    reports that as blindness rather than as an empty inventory.
    """
    gone = _unit(tmp_path, "gone.service")
    stays = _unit(tmp_path, "stays.service")
    backend = _Backend(owned=[gone, stays])
    persistence.run(backend, _ctx(tmp_path))
    gone.unlink()

    res = persistence.run(_Backend(owned=[stays]), _ctx(tmp_path))
    assert [f for f in res.findings if "gone.service" in f.subject] == []
    assert any("removed since" in row and "gone.service" in row
               for row in res.detail_rows)
    assert "1 gone" in _notes(res)


# ------------------------------------------------------------------- damaged baselines


def test_a_corrupt_baseline_is_retaken_rather_than_half_compared(tmp_path):
    _unit(tmp_path, "a.service")
    persistence.run(_Backend(), _ctx(tmp_path))
    store = tmp_path / ".fettle" / baseline.FILENAME
    store.write_text("{ not json")

    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert "startup baseline recorded" in _notes(res)
    assert baseline.load(store) is not None, "and a usable one replaced it"


def test_a_future_version_is_not_compared_against(tmp_path):
    store = tmp_path / ".fettle" / baseline.FILENAME
    store.parent.mkdir(parents=True)
    store.write_text(json.dumps({"version": baseline.VERSION + 1, "entries": {}}))
    assert baseline.load(store) is None


def test_an_unwritable_baseline_is_reported_as_blindness(tmp_path, monkeypatch):
    """It cannot say what changed and neither will the next run, which is a blind spot
    rather than a clean comparison."""
    _unit(tmp_path, "a.service")
    monkeypatch.setattr(baseline, "save", lambda *a, **kw: False)
    res = persistence.run(_Backend(), _ctx(tmp_path))
    assert any("were NOT compared" in what for what, _, _ in res.blind)


def test_an_unreadable_file_is_not_reported_as_modified(tmp_path):
    """An empty digest on either side means unreadable, and comparing it against a real
    hash would report every unreadable file as changed on every run."""
    old = {"/x": {"class": "unit", "sha256": "", "package": "p", "mtime": 0}}
    new = {"/x": {"class": "unit", "sha256": "abc", "package": "p", "mtime": 0}}
    assert baseline.compare(old, new)["changed"] == []


def test_losing_a_package_owner_is_noted(tmp_path):
    old = {"/x": {"class": "unit", "sha256": "a", "package": "somepkg", "mtime": 0}}
    new = {"/x": {"class": "unit", "sha256": "a", "package": "", "mtime": 0}}
    assert baseline.compare(old, new)["lost_owner"] == ["/x"]
