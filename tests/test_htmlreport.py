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
                       {"band_tally": {"Critical": 1},
                        "packages": [{"package": "x", "band": "Critical", "score": 18,
                                      "binaries": 1, "has_privileged": False,
                                      "checks": {"relro": 1}}]})
    _write_report_json(tmp_path, "ec3", "pkg-audit", "20260721-020202",
                       {"findings": [{"severity": "WARN", "source": "apt",
                                      "package": "p", "detail": "d"}]})
    path = htmlreport.build(_ctx(tmp_path))
    assert path == tmp_path / ".fettle/report.html"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    text = path.read_text()
    assert text.startswith("<!doctype html>")
    assert "local" in text and "ec3" in text
    assert "hardening-audit" in text and "pkg-audit" in text


def test_build_escapes_untrusted_content(tmp_path):
    # a package name with HTML must be escaped, never injected into the page
    _write_report_json(tmp_path, "local", "pkg-audit", "20260721-010101",
                       {"findings": [{"severity": "CRIT", "source": "aur",
                                      "package": "<script>alert(1)</script>",
                                      "detail": "evil"}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "<script>alert(1)</script>" not in text     # never raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


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


# -- RH2: dashboard + per-type rendering -------------------------------------
def test_dashboard_and_controls_present(tmp_path):
    _write_report_json(tmp_path, "local", "hardening-audit", "20260721-010101",
                       {"band_tally": {"Critical": 1, "High": 2},
                        "scan": {"analyzed": 4000}, "packages": []})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert 'class="dashboard"' in text and 'class="card"' in text
    assert 'id="q"' in text and 'id="hostf"' in text and 'id="typef"' in text
    assert "b-Critical" in text and "1 Critical" in text     # band chip


def test_hardening_renders_scored_table(tmp_path):
    _write_report_json(tmp_path, "web", "hardening-audit", "20260721-010101", {
        "band_tally": {"Critical": 1, "Low": 40},
        "scan": {"analyzed": 100},
        "packages": [{"package": "xorg-server", "band": "Critical", "score": 18.0,
                      "binaries": 2, "has_privileged": True,
                      "checks": {"relro": 2, "canary": 2}},
                     {"package": "quiet", "band": "Low", "score": 1.0,
                      "binaries": 1, "has_privileged": False, "checks": {}}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "xorg-server" in text and "relro=2, canary=2" in text
    assert "quiet" not in text                    # Low not tabled
    assert "40 Medium/Low package(s)" in text


def test_findings_render_with_severity_pills(tmp_path):
    _write_report_json(tmp_path, "local", "aur-ioc-scan", "20260721-010101",
                       {"findings": [{"severity": "CRIT", "source": "aur",
                                      "package": "evil", "detail": "bad feed"}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "sev-CRIT" in text and "evil" in text and "bad feed" in text


def test_aur_audit_links_name_and_shows_software(tmp_path):
    _write_report_json(tmp_path, "local", "aur-audit", "20260721-010101",
                       {"packages": [
                           {"name": "yay", "maintainer": "jdoe", "age_days": 5,
                            "votes": 900, "flags": "",
                            "description": "AUR helper", "homepage": "https://github.com/x/yay"},
                           {"name": "evil", "maintainer": "m", "age_days": 1,
                            "votes": 0, "flags": "",
                            "description": "sneaky", "homepage": "javascript:alert(1)"}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert '<th>software</th>' in text                             # new column
    assert 'href="https://aur.archlinux.org/packages/yay"' in text  # name links to AUR
    assert "AUR helper" in text                                    # description shown
    assert 'href="https://github.com/x/yay"' in text               # safe homepage linked
    assert "javascript:alert(1)" not in text                       # unsafe URL blocked


def test_aur_audit_renders_removal_candidates(tmp_path):
    _write_report_json(tmp_path, "local", "aur-audit", "20260723-010101", {
        "packages": [{"name": "webkit2gtk", "maintainer": "a", "age_days": 1, "votes": 9,
                      "flags": "NO-DEPENDENTS LIB", "description": "", "homepage": ""}],
        "removal_candidates": [{"name": "webkit2gtk", "is_library": True}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "Candidates for removal" in text
    assert "sudo pacman -Rns webkit2gtk" in text
    assert 'href="https://aur.archlinux.org/packages/webkit2gtk"' in text   # AUR link reused
    assert "verify before removing" in text.lower()                          # the caveat


def test_findings_link_only_aur_packages(tmp_path):
    _write_report_json(tmp_path, "local", "pkg-audit", "20260721-010101",
                       {"findings": [
                           {"severity": "WARN", "source": "aur", "package": "aurpkg",
                            "detail": "d"},
                           {"severity": "WARN", "source": "apt", "package": "aptpkg",
                            "detail": "d"}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert 'href="https://aur.archlinux.org/packages/aurpkg"' in text   # aur -> linked
    assert "packages/aptpkg" not in text                               # apt -> plain text


def test_aur_audit_escapes_html_in_name_and_desc(tmp_path):
    _write_report_json(tmp_path, "local", "aur-audit", "20260721-010101",
                       {"packages": [{"name": "p<b>", "maintainer": "m", "age_days": 1,
                                      "votes": 0, "flags": "",
                                      "description": "<script>x</script>", "homepage": ""}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "<b>" not in text and "<script>x</script>" not in text       # escaped
    assert "&lt;script&gt;" in text


def test_upgrade_check_renders_verdict(tmp_path):
    _write_report_json(tmp_path, "ec3", "upgrade-check", "20260721-010101",
                       {"safety_verdict": "caution", "failure_likelihood": "medium",
                        "summary": "kernel bump", "must_do_before": ["snapshot"],
                        "recommendation": "proceed-with-care"})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "v-caution" in text and "CAUTION" in text
    assert "snapshot" in text and "proceed-with-care" in text


def test_log_transcript_renders(tmp_path):
    d = tmp_path / ".fettle/logs/ec1"
    d.mkdir(parents=True)
    (d / "run-20260721-010101.json").write_text(json.dumps(
        {"schema": "fettle.log/1", "tool": "run", "host": "ec1",
         "timestamp": "20260721-010101", "argv": ["-a"], "exit_code": 0,
         "transcript": "clean + update done"}))
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "run logs" in text and "clean + update done" in text


def test_bad_payload_never_breaks_the_page(tmp_path):
    # a structurally-wrong hardening payload falls back to a <pre> dump, no crash
    _write_report_json(tmp_path, "local", "hardening-audit", "20260721-010101",
                       {"packages": "not-a-list"})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert text.startswith("<!doctype html>")     # rendered fine anyway


# -- empty-report filtering --------------------------------------------------
def test_empty_reports_are_hidden(tmp_path):
    _write_report_json(tmp_path, "ec3", "obsolete-pkgs", "20260721-010101",
                       {"packages": []})                       # empty -> hidden
    _write_report_json(tmp_path, "ec3", "pkg-audit", "20260721-020202",
                       {"findings": [{"severity": "CRIT", "source": "apt",
                                      "package": "real", "detail": "d"}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "pkg-audit" in text and "real" in text              # non-empty shown
    assert "obsolete-pkgs" not in text                          # empty hidden
    assert "1 empty report(s) hidden" in text                   # noted


def test_is_empty_predicate():
    e = htmlreport._is_empty
    assert e({"tool": "obsolete-pkgs", "data": {"packages": []}})
    assert not e({"tool": "obsolete-pkgs", "data": {"packages": ["x"]}})
    assert e({"tool": "aur-ioc-scan", "data": {"findings": []}})
    assert e({"tool": "alien-pkgs", "data": {"text": "\n"}})     # blank backfill
    assert not e({"tool": "upgrade-check", "data": {"safety_verdict": "safe"}})
    assert e({"schema": "fettle.log/1", "transcript": "   "})    # blank log


def test_host_with_only_empty_reports_is_dropped(tmp_path):
    _write_report_json(tmp_path, "quiet-host", "obsolete-pkgs", "20260721-010101",
                       {"packages": []})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    # no host <section> for a host whose every report is empty (and no logs)
    assert 'data-host="quiet-host"' not in text


# -- group name is not a host asset ------------------------------------------
def test_group_name_rendered_as_group_run_not_host(tmp_path):
    from fettle.config import Config
    _write_report_json(tmp_path, "ec1", "pkg-audit", "20260722-010101",
                       {"findings": [{"severity": "WARN", "source": "apt",
                                      "package": "p", "detail": "d"}]})
    ld = tmp_path / ".fettle/logs/bifrost-lab"
    ld.mkdir(parents=True)
    (ld / "run-20260722-020202.json").write_text(json.dumps(
        {"schema": "fettle.log/1", "tool": "run", "host": "bifrost-lab",
         "timestamp": "20260722-020202", "argv": ["remote", "bifrost-lab", "-a"],
         "exit_code": 0, "transcript": "group summary: 4 ok"}))
    cfg = Config()
    cfg.remote = {"groups": {"bifrost-lab": ["ec1", "ec2"]}}
    text = htmlreport.build(SimpleNamespace(user_home=tmp_path, sudo_user=None,
                                            config=cfg)).read_text()
    assert 'data-host="ec1"' in text                       # real host still shown
    assert '<div class="card"><h3>bifrost-lab</h3>' not in text   # NOT a host card
    assert '<option value="bifrost-lab">' not in text      # NOT in the host filter
    assert "group runs" in text and 'data-type="group-run"' in text
    # tiny summary: argv label + pass badge, NOT the full transcript
    assert "fettle remote bifrost-lab -a" in text
    assert 'class="badge b-ok"' in text
    assert "group summary: 4 ok" not in text               # transcript not dumped here


def test_no_group_config_treats_all_as_hosts(tmp_path):
    # without a group config, a logs/<name> dir is still a host (unchanged behavior)
    ld = tmp_path / ".fettle/logs/somehost"
    ld.mkdir(parents=True)
    (ld / "run-20260722-010101.json").write_text(json.dumps(
        {"schema": "fettle.log/1", "tool": "run", "host": "somehost",
         "timestamp": "20260722-010101", "transcript": "hi"}))
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert 'data-host="somehost"' in text and "group runs" not in text


# -- friendly section labels + run-log argv hint -----------------------------
def test_section_headers_are_friendly_with_name_in_parens(tmp_path):
    _write_report_json(tmp_path, "ec3", "pkg-audit", "20260722-010101",
                       {"findings": [{"severity": "WARN", "source": "apt",
                                      "package": "p", "detail": "d"}]})
    ld = tmp_path / ".fettle/logs/ec3"
    ld.mkdir(parents=True)
    (ld / "run-20260722-020202.json").write_text(json.dumps(
        {"schema": "fettle.log/1", "tool": "run", "host": "ec3",
         "timestamp": "20260722-020202", "argv": ["remote", "ec3", "-H"],
         "exit_code": 0, "transcript": "no hardening deviations"}))
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "Package Supply-Chain Audit" in text and "(pkg-audit)" in text
    assert "Session Transcripts" in text and "(run logs)" in text
    # each run-log summary is labeled by what it ran
    assert "fettle remote ec3 -H" in text


def test_report_entry_shows_producing_command(tmp_path):
    d = tmp_path / ".fettle/reports/ec1"
    d.mkdir(parents=True)
    (d / "hardening-audit-20260722-010101.json").write_text(json.dumps(
        {"schema": "fettle.report/1", "tool": "hardening-audit", "host": "ec1",
         "timestamp": "20260722-010101", "command": "fettle -H",
         "data": {"packages": [{"package": "p", "score": 5, "band": "High",
                                "binaries": [], "checks": {}}]}}))
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert 'class="cmdtag"' in text and "fettle -H" in text   # the exact command shown
