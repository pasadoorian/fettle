"""RH1: HTML dashboard build + one-off JSON backfill."""

# stale-flag-ok: `aur-ioc-scan` is a stored REPORT type that still renders,
# even though the command was retired in v0.73.0.
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


def _recent(hours_ago: int = 1) -> str:
    """A report timestamp relative to now, in fettle's `YYYYMMDD-HHMMSS` form.

    Any test that means "this host reported **recently**" has to generate its fixture
    rather than hardcode one, because the dashboard's staleness rule compares against
    the wall clock: `[reports] stale_days` defaults to 7, so a hardcoded date passes
    for exactly a week after whoever wrote it, then fails forever. That is not
    hypothetical — `test_a_clean_host_says_OK` pinned 2026-08-05 and started failing on
    2026-08-12, seven days later, with no code change to blame.

    The other fixtures in this file hardcode deliberately old dates and are fine: they
    either assert the staleness warning itself or do not touch it.
    """
    from datetime import datetime, timedelta

    return (datetime.now() - timedelta(hours=hours_ago)).strftime("%Y%m%d-%H%M%S")


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
    # A band tally with an EMPTY package list cannot happen in real data — and a host
    # whose only report has nothing in it is now hidden, so the fixture has to carry a
    # package or there is (correctly) no card to assert on.
    _write_report_json(tmp_path, "local", "hardening-audit", "20260721-010101",
                       {"band_tally": {"Critical": 1, "High": 2},
                        "scan": {"analyzed": 4000},
                        "packages": [{"package": "openssl", "band": "Critical",
                                      "score": 18, "bins": 2, "missing": ["relro"]}]})
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


def test_advisories_render_pending_and_fixable(tmp_path):
    _write_report_json(tmp_path, "local", "advisory-check", "20260724-010101", {
        "findings": [
            {"source": "arch", "package": "djvulibre", "installed_version": "3.5-1",
             "status": "pending_fix", "severity": "High", "cves": ["CVE-2025-53367"],
             "fixed_version": None, "group_id": "AVG-2907",
             "url": "https://security.archlinux.org/AVG-2907"},
            {"source": "arch", "package": "poppler", "installed_version": "22-1",
             "status": "fixed_available", "severity": "Critical", "cves": ["CVE-1"],
             "fixed_version": "22-2", "group_id": "AVG-2812", "url": "https://x"}],
        "uncovered": {"arch": ["yay"]}, "manjaro": True})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "Pending fixes" in text and "Fix available" in text
    assert "djvulibre" in text and "CVE-2025-53367" in text          # pending
    assert "poppler" in text and 'b-Critical' in text                 # banded severity
    assert "Not covered by the arch tracker" in text and "yay" in text
    assert "sync lag" in text                                          # Manjaro note


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


# -- host cards: only for hosts that have something to show -------------------
def test_empty_host_directories_are_hidden_and_counted(tmp_path):
    """Eight of these on the QA machine, each rendering a card reading
    "no reports / latest: -" — left behind by fetch-backs that found nothing and by
    lab guests whose DHCP address moved."""
    _write_report_json(tmp_path, "real-host", "pkg-audit", "20260721-010101",
                       {"findings": [{"source": "aur", "package": "x",
                                      "question": "KNOWN_BAD", "severity": "CRIT",
                                      "detail": "d"}]})
    (tmp_path / ".fettle/reports" / "ghost-host").mkdir(parents=True)
    (tmp_path / ".fettle/logs" / "another-ghost").mkdir(parents=True)
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "real-host" in text
    assert "ghost-host" not in text and "another-ghost" not in text
    assert "2 empty hidden" in text              # hidden, not disappeared


def test_pkg_integrity_has_a_renderer(tmp_path):
    """Split out of sys-audit in v0.72.0 and built from the same `Scan`, so the
    payload shape is identical — but it was never registered, and five reports
    rendered as a raw JSON dump."""
    assert htmlreport._RENDERERS.get("pkg-integrity") is htmlreport._render_sysaudit
    _write_report_json(tmp_path, "h1", "pkg-integrity", "20260721-010101",
                       {"categories": ["Package file integrity"],
                        "level_counts": {"error": 1},
                        "text": "[error] Package Integrity: 3 file(s) differ"})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "Package file integrity" in text
    assert '"level_counts"' not in text          # not a raw JSON dump


# -- the host card is a verdict across ALL audits, not a hardening tally ------
def _card(tmp_path):
    import re
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    m = re.search(r'<div class="card"[^>]*><h3>(.*?)</h3>(.*?)</div></div>', text, re.S)
    return re.sub(r"<[^>]*>", " ", m.group(2)) if m else ""


def test_card_verdict_covers_every_audit_not_just_hardening(tmp_path):
    """It showed hardening bands only — an opt-in audit every desktop has bands in —
    so a host with files failing integrity or unpatched Criticals showed no chip."""
    _write_report_json(tmp_path, "h1", "pkg-integrity", "20260805-010101",
                       {"categories": ["x"], "level_counts": {"error": 3},
                        "text": "3 file(s) differ"})
    body = _card(tmp_path)
    assert "High" in body and "package file integrity" in body


def test_card_uses_only_the_newest_report_of_each_type(tmp_path):
    """Five retained advisory-check reports put the same CVEs on the card five
    times — noise pretending to be scale."""
    for ts in ("20260801-010101", "20260802-010101", "20260803-010101"):
        _write_report_json(tmp_path, "h1", "advisory-check", ts,
                           {"findings": [{"severity": "High", "package": "openssl",
                                          "source": "arch"}]})
    assert _card(tmp_path).count("with a known CVE") == 1


def test_card_normalises_pre_v080_severity_names(tmp_path):
    """Reports written before the scales were unified are on disk forever, so `WARN`
    is normalised on read rather than rendered next to `Medium` as if different."""
    _write_report_json(tmp_path, "h1", "pkg-audit", "20260805-010101",
                       {"findings": [{"severity": "WARN", "package": "p",
                                      "source": "aur", "question": "KNOWN_BAD",
                                      "detail": "d"}]})
    body = _card(tmp_path)
    assert "1 Medium" in body and "Warn" not in body


def test_card_flags_a_host_that_stopped_reporting(tmp_path):
    """No data is not good news — the fleet-level form of the invariant. A silent
    host looked exactly like one that reported clean this morning."""
    _write_report_json(tmp_path, "h1", "pkg-audit", "20200101-010101",
                       {"findings": [{"severity": "Low", "package": "p",
                                      "source": "aur", "question": "q",
                                      "detail": "d"}]})
    assert "has not reported in" in _card(tmp_path)


def test_a_clean_host_says_OK(tmp_path):
    _write_report_json(tmp_path, "h1", "sys-audit", _recent(),
                       {"categories": ["Secure Boot"], "level_counts": {"ok": 4},
                        "text": "[ok] Secure Boot: Enabled"})
    body = _card(tmp_path)
    assert "OK" in body


# -- delta: what changed since the last day you looked ------------------------
def _two_days(tmp_path, tool, old_data, new_data):
    _write_report_json(tmp_path, "h1", tool, "20260801-120000", old_data)
    _write_report_json(tmp_path, "h1", tool, "20260805-120000", new_data)
    return htmlreport.build(_ctx(tmp_path)).read_text()


def _find(pkg, sev="High"):
    return {"severity": sev, "source": "arch", "package": pkg,
            "question": "KNOWN_BAD", "detail": "d"}


def test_delta_reports_new_and_resolved(tmp_path):
    """Showing what went away matters as much as what arrived — "you fixed it" must
    not render the same as "it was never there"."""
    text = _two_days(tmp_path, "pkg-audit",
                     {"findings": [_find("gone1"), _find("gone2"), _find("stays")]},
                     {"findings": [_find("stays"), _find("brand-new")]})
    assert "+1 new" in text and "-2 resolved" in text
    assert "brand-new" in text and "gone1" in text        # named in the badge tooltip


def test_delta_baseline_is_a_previous_DAY_not_the_previous_report(tmp_path):
    """Three runs in an hour would otherwise reset the baseline and show an empty
    delta right after you fixed something."""
    for hh in ("090000", "100000", "110000"):
        _write_report_json(tmp_path, "h1", "pkg-audit", f"20260805-{hh}",
                           {"findings": [_find(f"p{hh}")]})
    # all same-day -> no earlier day to compare against -> no delta claimed
    assert "new</span>" not in htmlreport.build(_ctx(tmp_path)).read_text()
    _write_report_json(tmp_path, "h1", "pkg-audit", "20260801-120000",
                       {"findings": [_find("old")]})
    assert "+1 new" in htmlreport.build(_ctx(tmp_path)).read_text()


def test_count_only_types_report_a_count_delta_with_an_honest_tooltip(tmp_path):
    """sys-audit and pkg-integrity store no per-finding identity, so "3 -> 1" is all
    they can honestly say."""
    text = _two_days(tmp_path, "sys-audit",
                     {"categories": ["c"], "level_counts": {"error": 1}, "text": "t"},
                     {"categories": ["c"], "level_counts": {"error": 4}, "text": "t"})
    assert "more finding(s) than" in text
    assert 'title=" (since' not in text                   # never an empty tooltip


def test_dates_in_the_delta_are_formatted(tmp_path):
    text = _two_days(tmp_path, "pkg-audit", {"findings": [_find("a")]},
                     {"findings": [_find("b")]})
    assert "since 2026-08-01" in text and "since 20260801" not in text


def test_severity_filter_is_offered(tmp_path):
    _write_report_json(tmp_path, "h1", "pkg-audit", "20260805-120000",
                       {"findings": [_find("a")]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert 'id="sevf"' in text and "High and above" in text
    assert 'data-sev="3"' in text                          # entry tagged for the filter


def test_wide_report_content_can_be_reached(tmp_path):
    """Reported from a real run: the "Fix available" table showed only the severity
    badge and the CVSS vector — package, versions, CVEs and links were all present in
    the HTML but unreachable, because `section.host` clips and nothing scrolled. The
    44-character CVSS vector was what forced the first column that wide.

    Content that exists but cannot be reached is the layout form of the bug this whole
    QA pass is about.
    """
    _write_report_json(tmp_path, "h1", "advisory-check", "20260805-120000",
                       {"findings": [{"source": "osv", "package": "cryptography",
                                      "installed_version": "41.0.7",
                                      "fixed_version": "42.0.0", "severity": "High",
                                      "cves": ["CVE-2023-50782"], "status": "fixable",
                                      "environment": "/home/p/src/x/venv",
                                      "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                      "url": "https://osv.dev/x", "group_id": "GHSA-x"}]})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    # the vector is reference detail: available on hover, not eating a column
    assert 'title="CVSS CVSS:3.1/' in text
    assert "<br><span class=muted" not in text
    # and a body that overflows can be scrolled rather than silently clipped
    assert ".body{padding:.3rem .7rem .75rem;overflow-x:auto}" in text
    for cell in ("cryptography", "41.0.7", "42.0.0", "CVE-2023-50782",
                 "/home/p/src/x/venv"):
        assert cell in text


# -- hyperlinks: every name and identifier goes to its own authority -----------
def test_advisory_identifiers_link_to_the_right_authority():
    """Three schemes appear in the CVE column. GHSA advisories frequently have no NVD
    entry, so sending them to NVD would dead-end."""
    assert "nvd.nist.gov/vuln/detail/CVE-2023-50782" in \
        htmlreport._advisory_link("CVE-2023-50782")
    assert "github.com/advisories/GHSA-3ww4-gg4f-jr7f" in \
        htmlreport._advisory_link("GHSA-3ww4-gg4f-jr7f")
    # Ubuntu's own page carries the per-release fix status, which NVD does not.
    assert "ubuntu.com/security/CVE-2024-57857" in \
        htmlreport._advisory_link("UBUNTU-CVE-2024-57857")
    assert "security.archlinux.org/AVG-2313" in htmlreport._advisory_link("AVG-2313")
    assert "<a" not in htmlreport._advisory_link("SOMETHING-ELSE-1")   # no guessing


def test_arch_advisory_packages_link_to_the_REPO_not_the_aur():
    """advisory-check's `arch` rows come from security.archlinux.org, which tracks
    core/extra. An AUR link on `arch/apr` would 404; the AUR packages are the ones in
    the tracker's own "not covered" list."""
    assert "archlinux.org/packages/?name=apr" in htmlreport._pkg_link("apr", source="arch")
    assert "aur.archlinux.org" not in htmlreport._pkg_link("apr", source="arch")
    assert "aur.archlinux.org/packages/brave-bin" in \
        htmlreport._pkg_link("brave-bin", source="aur")


def test_language_packages_link_by_ecosystem():
    assert "pypi.org/project/certifi" in \
        htmlreport._pkg_link("certifi", source="osv", ecosystem="PyPI")
    assert "npmjs.com/package/left-pad" in \
        htmlreport._pkg_link("left-pad", source="osv", ecosystem="npm")
    # No ecosystem recorded (a pre-v0.82.0 report) -> plain text, never a guess.
    assert "<a" not in htmlreport._pkg_link("certifi", source="osv")


def test_uncovered_packages_link_to_the_aur_and_advise_a_live_flag(tmp_path):
    _write_report_json(tmp_path, "h1", "advisory-check", "20260805-120000",
                       {"findings": [], "uncovered": {"arch": ["brave-bin"]}})
    text = htmlreport.build(_ctx(tmp_path)).read_text()
    assert "aur.archlinux.org/packages/brave-bin" in text
    assert "-I</code>" not in text            # retired in v0.73.0


def test_pkg_audit_links_every_source_not_just_the_aur(tmp_path):
    _write_report_json(tmp_path, "h1", "pkg-audit", "20260805-120000",
                       {"findings": [{"severity": "Medium", "source": "apt",
                                      "package": "curl", "question": "STALE",
                                      "detail": "d"}]})
    assert "packages.debian.org/curl" in htmlreport.build(_ctx(tmp_path)).read_text()


# -- multi-environment findings expand to real paths --------------------------
def _adv_multi(tmp_path, pairs):
    _write_report_json(tmp_path, "h1", "advisory-check", "20260805-120000",
                       {"findings": [
                           {"source": "osv", "package": "pip", "severity": "High",
                            "installed_version": v, "environment": e,
                            "fixed_version": "26.2", "cves": ["CVE-2025-1"],
                            "status": "fixable", "url": "https://osv.dev/x",
                            "group_id": "GHSA-x", "ecosystem": "PyPI"}
                           for e, v in pairs]})
    return htmlreport.build(_ctx(tmp_path)).read_text()


def test_multiple_environments_expand_to_their_paths(tmp_path):
    """It said "4 environments" with the paths in a `title` tooltip — which cannot be
    copied, cannot be reached on a touch device, and would not have held the 44 paths
    of the largest real group anyway."""
    text = _adv_multi(tmp_path, [("/srv/a/venv", "23.2.1"), ("/srv/b/venv", "25.0")])
    assert '<details class="envs"><summary>2 environments' in text
    assert "/srv/a/venv" in text and "/srv/b/venv" in text
    assert "title=\"/srv" not in text                  # not hidden in a tooltip


def test_environments_are_listed_oldest_version_first(tmp_path):
    """Which ones are furthest behind is what turns a count into a work queue."""
    text = _adv_multi(tmp_path, [("/srv/new/venv", "26.1.1"),
                                 ("/srv/old/venv", "23.2.1"),
                                 ("/srv/mid/venv", "24.0")])
    body = text[text.index("<pre>", text.index('class="envs"')):]
    assert body.index("/srv/old") < body.index("/srv/mid") < body.index("/srv/new")


def test_version_order_is_numeric_not_lexical():
    """String order ranks `10.0` below `9.0` and `6.8.0-99` above `6.8.0-124` — the
    trap the kernel code documents."""
    v = ["1.26.20", "2.5.0", "9.0", "10.0", "23.2.1"]
    assert sorted(v, key=htmlreport._vkey) == ["1.26.20", "2.5.0", "9.0", "10.0",
                                               "23.2.1"]


def test_a_single_environment_needs_no_expander(tmp_path):
    text = _adv_multi(tmp_path, [("/srv/only/venv", "23.2.1")])
    assert "/srv/only/venv" in text and 'class="envs"' not in text


def test_the_filter_does_not_reach_inside_an_entry(tmp_path):
    """The expanders are nested <details>. The severity filter walks entry-level ones
    only — otherwise filtering would collapse or reveal them as a side effect."""
    text = _adv_multi(tmp_path, [("/srv/a/venv", "1.0"), ("/srv/b/venv", "2.0")])
    assert "querySelectorAll('details[data-host]')" in text


# -- hardening axes on the dashboard (v0.120.0) ------------------------------
#
# The axes shipped in v0.111.0-0.116.1 but nothing on the dashboard knew about them:
# the card rendered only the binary packages, the severity filter ranked only the
# binary bands, and the host verdict counted only those bands. A machine whose one
# finding was a world-writable /tmp therefore read as clean — the same
# silence-reads-as-a-pass failure the audit itself exists to prevent, in a different
# surface.

def _axes_data(*, packages=None, findings=None, blind=(), na=""):
    return {
        "band_tally": {}, "scan": {}, "packages": packages or [],
        "axes": [{
            "axis": "filesystem", "title": "Filesystem hygiene", "checked": 7,
            "not_applicable": na,
            "tally": {}, "notes": [],
            "findings": findings if findings is not None else [{
                "check": "sticky-bit", "subject": "/tmp", "severity": "High",
                "summary": "world-writable (0777) with no sticky bit",
                "detail": "world-writable (0777) with no sticky bit — any local user "
                          "can delete or replace another user's files here",
                "fix": "chmod +t /tmp"}],
            "not_checked": [{"what": w, "why": y, "package": ""} for w, y in blind],
        }],
    }


def test_axis_findings_render_on_the_hardening_card():
    html = htmlreport._render_hardening(_axes_data())
    assert "world-writable (0777) with no sticky bit" in html
    assert "chmod +t /tmp" in html
    assert "filesystem" in html
    assert ">High<" in html


def test_the_long_detail_is_not_what_the_table_shows():
    """`summary` is the label; the sentence explaining why belongs in the saved text
    report, not in a table cell."""
    html = htmlreport._render_hardening(_axes_data())
    assert "another user's files" not in html


def test_a_report_with_only_axis_findings_is_not_hidden():
    """`_is_empty` tested `packages` alone, so a run whose findings all came from the
    filesystem/kernel/ssh axes vanished from the dashboard entirely."""
    entry = {"tool": "hardening-audit", "data": _axes_data()}
    assert htmlreport._is_empty(entry) is False


def test_an_axis_that_could_not_look_also_keeps_the_report_visible():
    """Blindness is not emptiness. A card that disappears because every axis was blind
    tells the reader nothing was wrong."""
    entry = {"tool": "hardening-audit",
             "data": _axes_data(findings=[],
                                blind=[("the SSH config was NOT checked", "needs root")])}
    assert htmlreport._is_empty(entry) is False
    assert "NOT checked" in htmlreport._render_hardening(entry["data"])


def test_a_genuinely_empty_hardening_report_is_still_hidden():
    entry = {"tool": "hardening-audit", "data": {"packages": [], "axes": []}}
    assert htmlreport._is_empty(entry) is True


def test_axis_findings_rank_for_the_severity_filter():
    """Without this a host whose only finding is a High axis result filters out as
    "nothing above Low"."""
    entry = {"tool": "hardening-audit", "data": _axes_data()}
    assert htmlreport._entry_rank(entry) == htmlreport._SEV_RANK["High"]


def test_axis_findings_reach_the_host_verdict():
    lines = htmlreport._host_problems(
        {"reports": [{"tool": "hardening-audit", "data": _axes_data()}], "logs": []}, stale_days=7)
    joined = " ".join(text for _, text in lines)
    assert "system hardening finding" in joined
    assert any(rank == htmlreport._SEV_RANK["High"] for rank, _ in lines)


def test_an_axis_verdict_is_not_capped_like_the_binary_bands():
    """The binary bands are capped at rank 2 because every real desktop has
    Critical-band packages, so uncapped they would make every host red forever. An axis
    finding is the opposite: specific, rare and actionable."""
    lines = htmlreport._host_problems({"reports": [
        {"tool": "hardening-audit",
         "data": {**_axes_data(),
                  "axes": [{**_axes_data()["axes"][0],
                            "findings": [{"check": "x", "subject": "/tmp",
                                          "severity": "Critical", "summary": "s",
                                          "detail": "d", "fix": ""}]}]}}], "logs": []},
        stale_days=7)
    assert any(rank == htmlreport._SEV_RANK["Critical"] for rank, _ in lines)


def test_a_pre_axes_report_still_renders():
    """Reports written before v0.111.0 have no `axes` key at all, and stored reports
    are forever."""
    old = {"band_tally": {"High": 2}, "scan": {"analyzed": 100},
           "packages": [{"band": "High", "score": 9, "package": "p", "binaries": 1,
                         "checks": {"relro": 1}, "has_privileged": False}]}
    html = htmlreport._render_hardening(old)
    assert "High" in html
    assert htmlreport._is_empty({"tool": "hardening-audit", "data": old}) is False


def test_legacy_lowercase_severities_normalise():
    """v0.111.0-0.119.0 wrote "high"/"medium"/"low" before the scale was unified."""
    data = _axes_data(findings=[{"check": "c", "subject": "/tmp", "severity": "high",
                                 "summary": "s", "detail": "d", "fix": ""}])
    assert htmlreport._entry_rank({"tool": "hardening-audit", "data": data}) == \
        htmlreport._SEV_RANK["High"]
    assert ">High<" in htmlreport._render_hardening(data)
