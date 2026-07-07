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
    results = [{"Name": "present", "Maintainer": "bob", "LastModified": time.time(), "NumVotes": 3}]
    out = _run(tmp_path, foreign=["present", "ghost"], results=results, capsys=capsys)
    assert "NOT FOUND IN AUR" in out and "ghost" in out
    report = (tmp_path / "aur-audit.txt").read_text()
    assert "AUR audit" in report and "present" in report


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
