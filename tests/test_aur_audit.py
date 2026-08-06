"""AUR audit (`-A`) — the update.sh-style health/metrics table."""

import json
import time
from unittest.mock import patch

from fettle import command
from fettle.aur import audit
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


def _ctx(tmp_path, cfg=None):
    return Context(output=Output(color=False), config=cfg or Config(),
                   sudo_user="paul", user_home=tmp_path)


def _run(tmp_path, *, foreign, results, cfg=None, capsys=None):
    with patch("fettle.command.run") as run, \
         patch("fettle.aur.audit.aur_meta.fetch_info", return_value=results):
        run.return_value.stdout = "\n".join(foreign)
        audit.run(_ctx(tmp_path, cfg))
    return capsys.readouterr().out if capsys else ""


def test_table_has_header_and_metrics(tmp_path, capsys):
    now = time.time()
    results = [
        {"Name": "old-pkg", "Maintainer": "alice", "LastModified": now - 500 * 86400,
         "OutOfDate": None, "NumVotes": 42},
        {"Name": "fresh-pkg", "Maintainer": "bob", "LastModified": now - 3 * 86400,
         "OutOfDate": None, "NumVotes": 7},
    ]
    out = _run(tmp_path, foreign=["old-pkg", "fresh-pkg"], results=results, capsys=capsys)
    assert "PACKAGE" in out and "VOTES" in out and "AGE(d)" in out
    assert "42" in out  # votes surfaced
    assert "RECENTLY-CHANGED" in out          # fresh-pkg is within aur_recent_days
    # oldest-first ordering: old-pkg's row precedes fresh-pkg's
    assert out.index("old-pkg") < out.index("fresh-pkg")


def test_flags_orphan_and_out_of_date(tmp_path, capsys):
    now = time.time()
    results = [
        {"Name": "orphan", "Maintainer": None, "LastModified": now, "NumVotes": 1},
        {"Name": "ood", "Maintainer": "bob", "OutOfDate": 111, "LastModified": now, "NumVotes": 1},
    ]
    out = _run(tmp_path, foreign=["orphan", "ood"], results=results, capsys=capsys)
    assert "ORPHAN" in out
    assert "OUT-OF-DATE" in out and "FLAGGED" in out


def test_not_found_and_report_written(tmp_path, capsys):
    results = [{"Name": "present", "Maintainer": "bob", "LastModified": time.time(),
                "NumVotes": 3, "Description": "a handy tool", "URL": "https://example.org"}]
    out = _run(tmp_path, foreign=["present", "ghost"], results=results, capsys=capsys)
    assert "NOT FOUND IN AUR" in out and "ghost" in out
    d = tmp_path / ".fettle/reports/local"
    report = list(d.glob("aur-audit-*.txt"))[0].read_text()
    assert "AUR audit" in report and "present" in report
    import json
    data = json.loads(list(d.glob("aur-audit-*.json"))[0].read_text())["data"]
    p = next(p for p in data["packages"] if p["name"] == "present")   # structured rows
    assert p["description"] == "a handy tool"     # captured for the report, not the .txt
    assert p["homepage"] == "https://example.org"
    assert "ghost" in data["not_found_in_aur"]                   # keeps the missing set


def test_reverse_dependents_flags_and_removal_candidates(tmp_path, capsys):
    import json

    from fettle.command import Proc
    now = time.time()
    results = [
        {"Name": "lib-leftover", "Maintainer": "a", "LastModified": now - 400 * 86400, "NumVotes": 5},
        {"Name": "used-lib", "Maintainer": "b", "LastModified": now - 400 * 86400, "NumVotes": 5},
        {"Name": "opt-only", "Maintainer": "c", "LastModified": now - 400 * 86400, "NumVotes": 5},
    ]
    foreign = ["lib-leftover", "used-lib", "opt-only"]
    qi = ("Name            : lib-leftover\nRequired By     : None\nOptional For    : None\n"
          "\nName            : used-lib\nRequired By     : someapp\nOptional For    : None\n"
          "\nName            : opt-only\nRequired By     : None\nOptional For    : someapp\n")
    ql = ("lib-leftover /usr/lib/libleftover.so\nlib-leftover /usr/lib/libleftover.so.1\n"
          "used-lib /usr/lib/libused.so\nopt-only /usr/bin/opt-only\n")

    def fake_run(cmd, **kw):
        if "-Qmq" in cmd:
            return Proc(0, "\n".join(foreign))
        if "-Qi" in cmd:
            return Proc(0, qi)
        if "-Ql" in cmd:
            return Proc(0, ql)
        return Proc(0, "")

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.aur.audit.aur_meta.fetch_info", return_value=results):
        audit.run(_ctx(tmp_path))
    out = capsys.readouterr().out
    assert "NO-DEPENDENTS" in out and "Candidates for removal" in out
    # The removal command is stated once at the top of the section, not repeated under
    # every candidate — 59 of them on a real host made the list twice as long as its
    # content.
    assert "remove with: sudo pacman -Rns <package name>" in out
    assert out.count("sudo pacman -Rns") == 1
    assert "lib-leftover" in out

    d = tmp_path / ".fettle/reports/local"
    data = json.loads(list(d.glob("aur-audit-*.json"))[0].read_text())["data"]
    pkgs = {p["name"]: p for p in data["packages"]}
    # unused library -> NO-DEPENDENTS + LIB, is a removal candidate
    assert "NO-DEPENDENTS" in pkgs["lib-leftover"]["flags"] and "LIB" in pkgs["lib-leftover"]["flags"]
    assert pkgs["lib-leftover"]["is_library"] is True
    # used library -> has a dependent, NOT flagged, NOT a candidate
    assert pkgs["used-lib"]["required_by"] == ["someapp"]
    assert "NO-DEPENDENTS" not in pkgs["used-lib"]["flags"]
    # optional-only -> weaker flag, not a removal candidate
    assert "NO-HARD-DEPS" in pkgs["opt-only"]["flags"]
    assert "NO-DEPENDENTS" not in pkgs["opt-only"]["flags"]
    assert [c["name"] for c in data["removal_candidates"]] == ["lib-leftover"]


def test_maintainer_change_section(tmp_path, capsys):
    snap = tmp_path / ".cache/fettle/aur-maintainers.json"
    snap.parent.mkdir(parents=True)
    snap.write_text('{"pkg": "alice"}')
    results = [{"Name": "pkg", "Maintainer": "mallory", "LastModified": time.time(), "NumVotes": 1}]
    out = _run(tmp_path, foreign=["pkg"], results=results, capsys=capsys)
    assert "Maintainer changes since last run" in out
    assert "[REVIEW BEFORE UPGRADE] pkg: alice -> mallory" in out


def test_audit_has_no_ioc_findings(tmp_path, capsys):
    """-A is health-only: even a known-bad name yields no COMPROMISED alert here."""
    results = [{"Name": "evil-pkg", "Maintainer": "baduser", "LastModified": time.time(),
                "NumVotes": 1}]
    out = _run(tmp_path, foreign=["evil-pkg"], results=results, capsys=capsys)
    assert "malicious" not in out.lower() and "compromised" not in out.lower()


def test_offline_rpc_reports_no_data(tmp_path, capsys):
    _run(tmp_path, foreign=["pkg"], results=None)  # fetch_info None => offline
    assert "AUR RPC returned no data" in capsys.readouterr().err


def test_maintainer_snapshot_unreadable_does_not_crash(tmp_path):
    # B6: a root-owned aur-maintainers.json must not crash a later user run.
    by_name = {"pkg": {"Name": "pkg", "Maintainer": "alice"}}
    snap = tmp_path / ".cache/fettle/aur-maintainers.json"
    snap.parent.mkdir(parents=True)
    snap.write_text('{"pkg": "bob"}')  # a real prior snapshot
    with patch("pathlib.Path.read_text", side_effect=PermissionError):
        changes, first_run = audit._maintainer_changes(by_name, _ctx(tmp_path))
    assert changes == []  # degraded (couldn't read baseline) rather than raised
    # An unreadable baseline is not a comparison — it must not be reported as "none".
    assert first_run is True


def test_summary_carries_what_was_found(tmp_path, capsys):
    """Measured on a real 77-package host: 9 packages absent from the AUR and 4 flagged
    out-of-date, all summarised as "AUR audit of 77 package(s)". "No longer exists
    upstream" is exactly what a package deleted for malware looks like from here."""
    info = [{"Name": "good", "Maintainer": "alice", "LastModified": time.time(),
             "NumVotes": 10},
            {"Name": "stale", "Maintainer": "bob", "LastModified": time.time(),
             "NumVotes": 3, "OutOfDate": 1}]
    ctx = _ctx(tmp_path)
    with patch("fettle.aur.common.foreign_packages",
               return_value=["good", "stale", "vanished"]), \
         patch("fettle.aur.meta.fetch_info", return_value=info), \
         patch("fettle.command.run", return_value=command.Proc(0, "", "")):
        audit.run(ctx)
    ctx.output.print_summary()
    out = capsys.readouterr()
    assert "1 no longer in the AUR" in out.out
    assert "1 flagged out-of-date" in out.out
    assert "vanished" in out.err          # and warned about by name


def test_rpc_failure_is_not_silent_in_the_summary(tmp_path, capsys):
    ctx = _ctx(tmp_path)
    with patch("fettle.aur.common.foreign_packages", return_value=["a", "b"]), \
         patch("fettle.aur.meta.fetch_info", return_value=None):
        audit.run(ctx)
    ctx.output.print_summary()
    assert "did NOT run" in capsys.readouterr().out


def test_maintainer_baseline_is_not_shared_with_pkg_audit(tmp_path):
    """One file was shared with pkg-audit's AUR provider, and both read *and rewrote*
    it — so a maintainer takeover was reported once, by whichever action ran first, and
    was invisible to the other. `fettle -P` then `fettle -A` and -A said "none"."""
    from fettle.supplychain.aur_source import AURSource
    by_name = {"pkg": {"Name": "pkg", "Maintainer": "alice"}}
    ctx = _ctx(tmp_path)
    # pkg-audit establishes its baseline first...
    with patch("fettle.aur.common.foreign_packages", return_value=["pkg"]), \
         patch("fettle.aur.meta.query_info", return_value=[by_name["pkg"]]), \
         patch("fettle.aur.common.ioc_feed") as feed:
        feed.return_value.bad_packages.return_value = set()
        feed.return_value.bad_accounts.return_value = set()
        feed.return_value.bad_npm.return_value = set()
        AURSource().findings(ctx)
    # ...and aur-audit must still see its own first run, not an already-consumed diff.
    changes, first_run = audit._maintainer_changes(by_name, ctx)
    assert first_run is True and changes == []
    assert (tmp_path / ".cache/fettle/aur-maintainers-pkgaudit.json").is_file()
    assert (tmp_path / ".cache/fettle/aur-maintainers-audit.json").is_file()


# -- the mark has to match the words -------------------------------------------
def _summary_mark(tmp_path, capsys, foreign, info, snapshot=None):
    """Run the audit and return the summary line's leading mark."""
    if snapshot is not None:
        p = tmp_path / ".cache/fettle"
        p.mkdir(parents=True, exist_ok=True)
        (p / "aur-maintainers-audit.json").write_text(json.dumps(snapshot))
    ctx = _ctx(tmp_path)
    with patch("fettle.aur.common.foreign_packages", return_value=foreign), \
         patch("fettle.aur.meta.fetch_info", return_value=info), \
         patch("fettle.command.run", return_value=command.Proc(0, "", "")):
        audit.run(ctx)
    ctx.output.print_summary()
    cap = capsys.readouterr()
    line = next(ln for ln in (cap.out + cap.err).splitlines() if "AUR audit of" in ln)
    return line.strip()[0], line


def test_vanished_package_does_not_get_a_green_tick(tmp_path, capsys):
    """The bug: `✓ AUR audit of 79 package(s) — 9 no longer in the AUR`, exit 0.

    A package that disappeared from the AUR is what a package deleted for malware looks
    like from here, and it was being reported under a green tick.
    """
    info = [{"Name": "good", "Maintainer": "alice", "LastModified": time.time()}]
    mark, line = _summary_mark(tmp_path, capsys, ["good", "vanished"], info)
    assert mark == "!", line
    assert "1 no longer in the AUR" in line


def test_clean_audit_still_gets_a_green_tick(tmp_path, capsys):
    """The other half: a warning that fires every run is not a warning."""
    info = [{"Name": "good", "Maintainer": "alice", "LastModified": time.time()}]
    mark, line = _summary_mark(tmp_path, capsys, ["good"], info)
    assert mark == "✓", line


def test_out_of_date_alone_stays_green(tmp_path, capsys):
    """Standing states are counted in the text but do not raise the mark: on a real
    79-package host 7 are flagged out-of-date more or less permanently, and warning on
    that every run is how a warning stops being read."""
    info = [{"Name": "stale", "Maintainer": "bob", "LastModified": time.time(),
             "OutOfDate": 1}]
    mark, line = _summary_mark(tmp_path, capsys, ["stale"], info)
    assert mark == "✓", line
    assert "flagged out-of-date" in line


def test_maintainer_takeover_raises_the_mark(tmp_path, capsys):
    """The other event-shaped signal: the package changed hands since the last run."""
    info = [{"Name": "good", "Maintainer": "mallory", "LastModified": time.time()}]
    mark, line = _summary_mark(tmp_path, capsys, ["good"], info,
                               snapshot={"good": "alice"})
    assert mark == "!", line
    assert "maintainer change" in line
