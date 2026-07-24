"""AUR audit (`-A`) — the update.sh-style health/metrics table."""

import time
from unittest.mock import patch

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
    assert "sudo pacman -Rns lib-leftover" in out

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
        changes = audit._maintainer_changes(by_name, _ctx(tmp_path))
    assert changes == []  # degraded (couldn't read baseline) rather than raised
