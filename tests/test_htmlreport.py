"""RH1: HTML dashboard build + one-off JSON backfill."""

import json
import os
from types import SimpleNamespace

from fettle import htmlreport
from fettle.config import Config


def _ctx(home, sudo_user=None):
    return SimpleNamespace(user_home=home, sudo_user=sudo_user, config=Config())


def _write_report_json(base, host, tool, ts, data):
    d = base / ".fettle/reports" / host
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{tool}-{ts}.json").write_text(json.dumps(
        {"schema": "fettle.report/1", "tool": tool, "host": host,
         "timestamp": ts, "fettle_version": "0.12.0", "data": data}))


# -- name parsing ------------------------------------------------------------
def test_parse_name_splits_tool_and_timestamp():
    assert htmlreport._parse_name("hardening-audit-20260721-152641") == \
        ("hardening-audit", "20260721-152641")
    assert htmlreport._parse_name("run-20260721-152637-1") == \
        ("run", "20260721-152637")
    assert htmlreport._parse_name("weird") == ("weird", "")


# -- collect -----------------------------------------------------------------
def test_collect_groups_by_host(tmp_path):
    _write_report_json(tmp_path, "local", "pkg-audit", "20260721-010101",
                       {"findings": []})
    _write_report_json(tmp_path, "web-01", "hardening-audit", "20260721-020202",
                       {"band_tally": {"Critical": 1}})
    got = htmlreport.collect(tmp_path / ".fettle")
    assert set(got) == {"local", "web-01"}
    assert got["web-01"]["reports"][0]["tool"] == "hardening-audit"


def test_collect_newest_first(tmp_path):
    for ts in ("20260721-010101", "20260721-030303", "20260721-020202"):
        _write_report_json(tmp_path, "local", "pkg-audit", ts, {})
    entries = htmlreport.collect(tmp_path / ".fettle")["local"]["reports"]
    assert [e["timestamp"] for e in entries] == \
        ["20260721-030303", "20260721-020202", "20260721-010101"]


# -- build -------------------------------------------------------------------
def test_build_writes_0600_html_with_hosts(tmp_path):
    _write_report_json(tmp_path, "local", "hardening-audit", "20260721-010101",
                       {"band_tally": {"Critical": 1}})
    _write_report_json(tmp_path, "ec3", "pkg-audit", "20260721-020202",
                       {"findings": []})
    path = htmlreport.build(_ctx(tmp_path))
    assert path == tmp_path / ".fettle/report.html"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    text = path.read_text()
    assert text.startswith("<!doctype html>")
    assert "local" in text and "ec3" in text
    assert "hardening-audit" in text and "pkg-audit" in text


def test_build_escapes_untrusted_content(tmp_path):
    # a package name with HTML must be escaped, never injected
    _write_report_json(tmp_path, "local", "pkg-audit", "20260721-010101",
                       {"note": "<script>alert(1)</script>"})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_build_empty_tree_still_valid_html(tmp_path):
    (tmp_path / ".fettle").mkdir()
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert text.startswith("<!doctype html>") and "fettle report" in text


# -- backfill ----------------------------------------------------------------
def test_backfill_converts_txt_only_reports(tmp_path):
    d = tmp_path / ".fettle/reports/bifrost"
    d.mkdir(parents=True)
    (d / "pkg-audit-20260721-010101.txt").write_text("pkg-audit report\nno findings\n")
    ld = tmp_path / ".fettle/logs/bifrost"
    ld.mkdir(parents=True)
    (ld / "run-20260721-010101.txt").write_text("session transcript\n")

    n = htmlreport.backfill(_ctx(tmp_path))
    assert n == 2
    rep = json.loads((d / "pkg-audit-20260721-010101.json").read_text())
    assert rep["tool"] == "pkg-audit" and rep["host"] == "bifrost"
    assert rep["backfilled"] is True and "no findings" in rep["data"]["text"]
    log = json.loads((ld / "run-20260721-010101.json").read_text())
    assert log["schema"] == "fettle.log/1" and "transcript" in log
    assert oct(os.stat(d / "pkg-audit-20260721-010101.json").st_mode & 0o777) == "0o600"


def test_backfill_is_idempotent_and_nondestructive(tmp_path):
    d = tmp_path / ".fettle/reports/local"
    d.mkdir(parents=True)
    txt = d / "aur-audit-20260721-010101.txt"
    txt.write_text("original")
    (d / "aur-audit-20260721-010101.json").write_text('{"existing": true}')

    assert htmlreport.backfill(_ctx(tmp_path)) == 0        # skips existing json
    assert json.loads((d / "aur-audit-20260721-010101.json").read_text()) == \
        {"existing": True}                                 # not overwritten
    assert txt.read_text() == "original"                   # txt untouched
