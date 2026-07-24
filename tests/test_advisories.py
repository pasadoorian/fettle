"""Distro advisory / CVE tracking (PLAN.md §19) — DB cache, Arch provider, check."""

import json
from types import SimpleNamespace
from unittest.mock import patch

from fettle.advisories import base, check, db
from fettle.advisories.arch_source import ArchAdvisorySource
from fettle.config import Config
from fettle.output import Output


# -- SQLite cache ------------------------------------------------------------
def test_db_roundtrip_and_last_updated(tmp_path):
    conn = db.connect(tmp_path / "adv.db")
    rows = [("arch", "AVG-1", "vim", "Fixed", "High", "1-1", "1-2",
             '["CVE-1"]', None, "http://x", "Fixed")]
    db.replace_source(conn, "arch", rows, now=1000)
    assert db.last_updated(conn, "arch") == 1000
    got = db.all_rows(conn, "arch")
    assert len(got) == 1 and got[0][1] == "vim" and got[0][5] == "1-2" and got[0][9] == "Fixed"
    # replace is a full swap for that source
    db.replace_source(conn, "arch", [], now=2000)
    assert db.all_rows(conn, "arch") == [] and db.last_updated(conn, "arch") == 2000


def test_db_schema_mismatch_rebuilds(tmp_path):
    p = tmp_path / "adv.db"
    conn = db.connect(p)
    db.replace_source(conn, "arch", [("arch", "A", "p", "Fixed", "Low", "", "1",
                                      "[]", None, "", "Fixed")], now=1)
    conn.execute("PRAGMA user_version=999")   # simulate an old/foreign schema
    conn.commit()
    conn.close()
    conn2 = db.connect(p)                     # reopen -> version mismatch -> rebuilt
    assert db.all_rows(conn2, "arch") == []


# -- Arch classification -----------------------------------------------------
def _arch_with_vercmp(mapping):
    """An ArchAdvisorySource whose _vercmp returns mapping[(a,b)]."""
    src = ArchAdvisorySource()
    src._vercmp = lambda a, b: mapping.get((a, b))
    return src


def test_classify_vulnerable_is_pending():
    src = ArchAdvisorySource()
    assert src._classify("1.0", "Vulnerable", None) == (base.PENDING_FIX, None)


def test_classify_fixed_behind_is_fix_available():
    src = _arch_with_vercmp({("1.0", "1.2"): -1})
    assert src._classify("1.0", "Fixed", "1.2") == (base.FIXED_AVAILABLE, "1.2")


def test_classify_fixed_uptodate_is_skipped():
    src = _arch_with_vercmp({("1.2", "1.2"): 0})
    assert src._classify("1.2", "Fixed", "1.2") == (None, None)


def test_classify_not_affected_is_skipped():
    assert ArchAdvisorySource()._classify("1.0", "Not affected", "1.2") == (None, None)


# -- Arch refresh + findings (mock the network + pacman/vercmp) --------------
class _Resp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()

    def read(self, *a):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_AVGS = [
    {"name": "AVG-1", "packages": ["djvulibre"], "status": "Vulnerable",
     "severity": "High", "affected": "3.5-1", "fixed": None,
     "issues": ["CVE-2025-1"], "advisories": []},
    {"name": "AVG-2", "packages": ["poppler"], "status": "Fixed", "severity": "Critical",
     "affected": "22-1", "fixed": "22-2", "issues": ["CVE-1", "CVE-2"], "advisories": ["ASA-1"]},
    {"name": "AVG-3", "packages": ["bash"], "status": "Fixed", "severity": "Low",
     "affected": "5-1", "fixed": "5-2", "issues": ["CVE-3"], "advisories": []},
]


def test_refresh_then_findings(tmp_path):
    conn = db.connect(tmp_path / "adv.db")
    src = ArchAdvisorySource()
    with patch("fettle.advisories.arch_source.urllib.request.urlopen",
               lambda *a, **k: _Resp(_AVGS)):
        assert src.refresh(conn) == 3            # 3 packages across 3 AVGs

    installed = {"djvulibre": "3.5-1", "poppler": "22-1", "bash": "5-2"}

    def fake_run(cmd, **kw):
        if cmd[:2] == ["pacman", "-Q"] and len(cmd) == 2:
            return SimpleNamespace(stdout="\n".join(f"{k} {v}" for k, v in installed.items()))
        if cmd[0] == "vercmp":
            a, b = cmd[1], cmd[2]
            return SimpleNamespace(stdout="-1" if a < b else ("0" if a == b else "1"))
        return SimpleNamespace(stdout="")

    with patch("fettle.command.run", side_effect=fake_run):
        found = {f.package: f for f in src.findings(None, conn)}
    # djvulibre: Vulnerable, no fix -> pending
    assert found["djvulibre"].status == base.PENDING_FIX
    assert found["djvulibre"].cves == ["CVE-2025-1"]
    # poppler: installed 22-1 < fixed 22-2 -> fix available, Critical, ASA attached
    assert found["poppler"].status == base.FIXED_AVAILABLE
    assert found["poppler"].fixed_version == "22-2" and found["poppler"].advisory_id == "ASA-1"
    # bash: installed 5-2 == fixed 5-2 -> patched, not a finding
    assert "bash" not in found


def test_refresh_network_failure_returns_minus_one(tmp_path):
    conn = db.connect(tmp_path / "adv.db")

    def boom(*a, **k):
        raise OSError("offline")
    with patch("fettle.advisories.arch_source.urllib.request.urlopen", boom):
        assert ArchAdvisorySource().refresh(conn) == -1


# -- filters (§19.8) ---------------------------------------------------------
def _f(pkg, sev, status=base.FIXED_AVAILABLE, cls="Fixed"):
    return base.AdvisoryFinding(source="arch", package=pkg, installed_version="1",
                                status=status, severity=sev, distro_class=cls)


def test_filters_severity_packages_classes():
    findings = [_f("a", "Critical"), _f("b", "Low"), _f("evil-bin", "High"),
                _f("c", "High", cls="Unknown")]
    cfg = {"severity_threshold": "High", "exclude_packages": ["evil-*"],
           "exclude_classes": ["Unknown"]}
    out = [f.package for f in check._apply_filters(findings, cfg)]
    assert out == ["a"]        # b dropped (Low<High), evil-bin (glob), c (class Unknown)


# -- check.run end-to-end with a stub provider -------------------------------
class _StubProvider:
    source = "arch"

    def is_present(self, ctx):
        return True

    def refresh(self, conn):
        return 2

    def findings(self, ctx, conn):
        return [_f("poppler", "Critical"),
                base.AdvisoryFinding(source="arch", package="djvulibre",
                                     installed_version="3.5-1", status=base.PENDING_FIX,
                                     severity="High", cves=["CVE-2025-1"], distro_class="Vulnerable")]

    def uncovered(self, ctx):
        return ["yay", "some-git"]


def _ctx(tmp_path, cfg=None):
    return SimpleNamespace(config=cfg or Config(), user_home=tmp_path, sudo_user=None,
                           output=Output(color=False), dry_run=False, root=str(tmp_path))


def test_check_run_writes_report(tmp_path, capsys):
    with patch("fettle.advisories.check._providers", lambda: [_StubProvider()]):
        check.run(_ctx(tmp_path))
    out = capsys.readouterr().out
    assert "Pending fixes" in out and "djvulibre" in out
    assert "Fix available" in out and "poppler" in out
    assert "NOT covered by the arch tracker" in out and "yay" in out
    d = tmp_path / ".fettle/reports/local"
    data = json.loads(list(d.glob("advisory-check-*.json"))[0].read_text())["data"]
    assert data["counts"] == {"pending": 1, "fixed_available": 1}
    assert data["uncovered"]["arch"] == ["yay", "some-git"]


def test_check_run_no_provider_warns(tmp_path, capsys):
    class _Absent(_StubProvider):
        def is_present(self, ctx):
            return False
    with patch("fettle.advisories.check._providers", lambda: [_Absent()]):
        check.run(_ctx(tmp_path))
    cap = capsys.readouterr()
    assert "no advisory provider" in (cap.out + cap.err).lower()


# -- Debian provider (M2) ----------------------------------------------------
def test_debian_classify_release():
    from fettle.advisories.debian_source import DebianAdvisorySource
    d = DebianAdvisorySource()
    # open -> pending
    assert d._classify_release({"status": "open", "urgency": "high"}) == ("pending", None, "high")
    # resolved with a real fix -> fixable
    assert d._classify_release({"status": "resolved", "fixed_version": "2-1",
                                "urgency": "medium"}) == ("fixable", "2-1", "medium")
    # resolved, fixed_version "0", no nodsa -> not affected (skip)
    assert d._classify_release({"status": "resolved", "fixed_version": "0",
                                "urgency": "unimportant"}) is None
    # resolved, no fix, nodsa -> pending, tagged nodsa (won't-fix)
    assert d._classify_release({"status": "resolved", "fixed_version": "0",
                                "nodsa": "too intrusive", "urgency": "low"}) == ("pending", None, "nodsa")
    # undetermined -> skip
    assert d._classify_release({"status": "undetermined"}) is None


_DEB_DATA = {
    "openssl": {
        "CVE-A": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1",
                                            "urgency": "high"}}},
        "CVE-B": {"releases": {"bookworm": {"status": "open", "urgency": "unimportant"}}},
    },
    "curl": {  # a different suite only -> ignored for bookworm
        "CVE-C": {"releases": {"sid": {"status": "open", "urgency": "high"}}},
    },
}


def test_debian_refresh_filters_to_running_suite(tmp_path):
    from fettle.advisories.debian_source import DebianAdvisorySource
    conn = db.connect(tmp_path / "adv.db")
    src = DebianAdvisorySource()
    src._suite = lambda ctx=None: "bookworm"
    with patch("fettle.advisories.debian_source.urllib.request.urlopen",
               lambda *a, **k: _Resp(_DEB_DATA)):
        n = src.refresh(conn)
    assert n == 2                                   # only the two bookworm entries
    pkgs = sorted(r[1] for r in db.all_rows(conn, "debian"))
    assert pkgs == ["openssl", "openssl"] and "curl" not in pkgs


def test_debian_findings_uses_dpkg_compare(tmp_path):
    from fettle.advisories.debian_source import DebianAdvisorySource
    conn = db.connect(tmp_path / "adv.db")
    src = DebianAdvisorySource()
    src._suite = lambda ctx=None: "bookworm"
    with patch("fettle.advisories.debian_source.urllib.request.urlopen",
               lambda *a, **k: _Resp(_DEB_DATA)):
        src.refresh(conn)
    installed = {"openssl": "3.0.9-1"}              # behind the 3.0.11-1 fix

    def fake_run(cmd, **kw):
        if cmd[:2] == ["dpkg-query", "-W"]:
            return SimpleNamespace(stdout="\n".join(f"{k} {v}" for k, v in installed.items()))
        if cmd[:2] == ["dpkg", "--compare-versions"]:   # 3.0.9-1 lt 3.0.11-1 -> true
            return SimpleNamespace(returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    with patch("fettle.command.run", side_effect=fake_run):
        found = {f.cves[0]: f for f in src.findings(None, conn)}
    assert found["CVE-A"].status == base.FIXED_AVAILABLE and found["CVE-A"].fixed_version == "3.0.11-1"
    assert found["CVE-B"].status == base.PENDING_FIX and found["CVE-B"].distro_class == "unimportant"


def test_debian_is_present_debian_only():
    from fettle.advisories.debian_source import DebianAdvisorySource
    d = DebianAdvisorySource()
    with patch("fettle.advisories.debian_source.command.which", return_value=True):
        with patch.object(d, "_osrel", return_value={"ID": "debian"}):
            assert d.is_present(None) is True
        with patch.object(d, "_osrel", return_value={"ID": "ubuntu", "ID_LIKE": "debian"}):
            assert d.is_present(None) is False       # Ubuntu -> M3 provider, not this one


# -- Ubuntu provider (M3, OVAL) ----------------------------------------------
class _RawResp:
    def __init__(self, raw):
        self._raw = raw

    def read(self, *a):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_OVAL = """<oval_definitions>
 <definition class="vulnerability"><metadata>
   <reference source="Package" ref_id="openssl" />
   <advisory>
     <cve href="https://ubuntu.com/security/CVE-2024-1" priority="critical">CVE-2024-1</cve>
     <cve href="https://ubuntu.com/security/CVE-2024-2" priority="low">CVE-2024-2</cve>
   </advisory></metadata>
   <criteria>
     <criterion comment="(CVE-2024-1) openssl package in noble was vulnerable but has been fixed (note: '3.0.13-1')." />
     <criterion comment="(CVE-2024-2) openssl package in noble was vulnerable but has been fixed (note: '3.0.12-1')." />
   </criteria>
 </definition>
</oval_definitions>"""


def test_ubuntu_refresh_parses_oval_with_severity(tmp_path):
    import bz2

    from fettle.advisories.ubuntu_source import UbuntuAdvisorySource
    conn = db.connect(tmp_path / "adv.db")
    src = UbuntuAdvisorySource()
    src._codename = lambda ctx=None: "noble"
    with patch("fettle.advisories.ubuntu_source.urllib.request.urlopen",
               lambda *a, **k: _RawResp(bz2.compress(_OVAL.encode()))):
        assert src.refresh(conn) == 2
    rows = {r[0]: r for r in db.all_rows(conn, "ubuntu")}  # keyed by group_id (CVE)
    assert rows["CVE-2024-1"][3] == "Critical" and rows["CVE-2024-1"][5] == "3.0.13-1"
    assert rows["CVE-2024-2"][3] == "Low"


def test_ubuntu_findings_flags_critical(tmp_path):
    import bz2

    from fettle.advisories.ubuntu_source import UbuntuAdvisorySource
    conn = db.connect(tmp_path / "adv.db")
    src = UbuntuAdvisorySource()
    src._codename = lambda ctx=None: "noble"
    with patch("fettle.advisories.ubuntu_source.urllib.request.urlopen",
               lambda *a, **k: _RawResp(bz2.compress(_OVAL.encode()))):
        src.refresh(conn)

    def fake_run(cmd, **kw):
        if cmd[:2] == ["dpkg-query", "-W"]:
            return SimpleNamespace(stdout="openssl 3.0.10-1")     # behind both fixes
        if cmd[:2] == ["dpkg", "--compare-versions"]:
            return SimpleNamespace(returncode=0)                  # installed < fixed
        return SimpleNamespace(stdout="", returncode=0)

    with patch("fettle.command.run", side_effect=fake_run):
        found = {f.cves[0]: f for f in src.findings(None, conn)}
    assert found["CVE-2024-1"].severity == "Critical"            # Ubuntu can be Critical
    assert found["CVE-2024-1"].status == base.FIXED_AVAILABLE and found["CVE-2024-1"].fixed_version == "3.0.13-1"


def test_ubuntu_osv_pending_via_shared_client(tmp_path):
    from fettle.advisories import db, osv
    from fettle.advisories.ubuntu_source import UbuntuAdvisorySource
    conn = db.connect(tmp_path / "adv.db")
    src = UbuntuAdvisorySource()
    src._installed = lambda: {"dovecot": "1:2.3.21+dfsg1-2ubuntu6"}
    src._osv_ecosystem = lambda ctx=None: "Ubuntu:24.04:LTS"
    rec = {"id": "UBUNTU-CVE-2026-0394", "aliases": ["CVE-2026-0394"],
           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
                        {"type": "Ubuntu", "score": "medium"}],
           "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "dovecot"},
                         "ranges": [{"events": [{"introduced": "0"}]}]}]}   # no fix -> pending
    with patch.object(osv, "querybatch",
                      return_value=[[{"id": "UBUNTU-CVE-2026-0394", "modified": "m"}]]), \
         patch.object(osv, "record", return_value=rec):
        rows = src._osv_pending(conn)
    assert len(rows) == 1
    r = rows[0]
    assert r[2] == "dovecot" and r[3] == "pending"
    assert r[4] == "Medium"                              # native Ubuntu priority, not CVSS
    assert r[7] == '["CVE-2026-0394"]' and r[11].startswith("CVSS")   # cvss carried too


def test_ubuntu_is_present_ubuntu_only():
    from fettle.advisories.ubuntu_source import UbuntuAdvisorySource
    u = UbuntuAdvisorySource()
    with patch("fettle.advisories.ubuntu_source.command.which", return_value=True):
        with patch.object(u, "_osrel", return_value={"ID": "ubuntu"}):
            assert u.is_present(None) is True
        with patch.object(u, "_osrel", return_value={"ID": "debian"}):
            assert u.is_present(None) is False


# -- OSV client + language provider (M4) -------------------------------------
_OSV_REC = {
    "id": "GHSA-xxxx", "aliases": ["CVE-2024-9"],
    "database_specific": {"severity": "HIGH"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                  "ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}]}],
}


def test_osv_classify_fixable_vs_pending():
    from fettle.advisories import osv
    assert osv.classify(_OSV_REC, "PyPI", "2.25.0") == ("fixable", "2.31.0")
    no_fix = {"affected": [{"package": {"ecosystem": "PyPI", "name": "x"},
                            "ranges": [{"events": [{"introduced": "0"}]}]}]}
    assert osv.classify(no_fix, "PyPI", "1.0") == ("pending", None)
    assert osv.classify(_OSV_REC, "npm", "2.25.0") is None      # ecosystem mismatch -> skip


def test_osv_severity_shows_both():
    from fettle.advisories import osv
    band, cvss = osv.severity(_OSV_REC)
    assert band == "High" and cvss.startswith("CVSS:3.1/")


def test_osv_record_caches_incrementally(tmp_path):
    from fettle.advisories import db, osv
    conn = db.connect(tmp_path / "adv.db")
    calls = []

    class _R:
        def __init__(self, b):
            self._b = b

        def read(self, *a):
            return self._b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_open(req, *a, **k):
        calls.append(getattr(req, "full_url", req))
        return _R(json.dumps(_OSV_REC).encode())

    with patch("fettle.advisories.osv.urllib.request.urlopen", fake_open):
        r1 = osv.record(conn, "GHSA-xxxx", "2024-01-01")   # fetch + cache
        r2 = osv.record(conn, "GHSA-xxxx", "2024-01-01")   # same modified -> cache hit
        osv.record(conn, "GHSA-xxxx", "2024-06-01")        # changed modified -> refetch
    assert r1["id"] == r2["id"] == "GHSA-xxxx"
    assert len(calls) == 2                                  # not 3 — the middle one was cached


def test_osv_language_provider_refresh_and_findings(tmp_path):
    from fettle.advisories import base, db, osv
    from fettle.advisories.osv_source import OsvLanguageSource
    conn = db.connect(tmp_path / "adv.db")
    src = OsvLanguageSource()
    src._installed = lambda: [("PyPI", "requests", "2.25.0"), ("PyPI", "clean-pkg", "1.0")]
    with patch.object(osv, "querybatch",
                      return_value=[[{"id": "GHSA-xxxx", "modified": "2024-01-01"}], []]), \
         patch.object(osv, "record", return_value=_OSV_REC):
        assert src.refresh(conn) == 1                       # only the vulnerable one
    f = src.findings(None, conn)
    assert len(f) == 1
    assert f[0].source == "osv" and f[0].package == "requests"
    assert f[0].status == base.FIXED_AVAILABLE and f[0].fixed_version == "2.31.0"
    assert f[0].severity == "High" and f[0].cvss.startswith("CVSS:")
    assert f[0].cves == ["CVE-2024-9"]


def test_osv_dedups_same_cve_across_databases():
    from fettle.advisories.osv import dedup_rows as _dedup
    # same package + CVE from GHSA (High) and PYSEC (Unknown) -> keep the High one
    ghsa = ("osv", "GHSA-x", "ecdsa", "pending", "High", "0.19.2", None,
            '["CVE-2024-23342"]', None, "u1", "PyPI", "CVSS:3.1/...")
    pysec = ("osv", "PYSEC-1", "ecdsa", "pending", "Unknown", "0.19.2", None,
             '["CVE-2024-23342"]', None, "u2", "PyPI", "")
    out = _dedup([pysec, ghsa])
    assert len(out) == 1 and out[0][4] == "High" and out[0][1] == "GHSA-x"


# -- update-flow security gate (best-effort, §19.8) --------------------------
def test_gate_proceeds_when_no_cache(tmp_path):
    # no advisories.db present -> never blocks a routine update
    assert check.security_gate(_ctx(tmp_path)) is True


def test_gate_confirms_on_critical(tmp_path):
    findings = [_f("openssl", "Critical")]
    with patch("fettle.advisories.check._providers",
               lambda: [type("P", (_StubProvider,), {"findings": lambda s, c, conn: findings})()]):
        ctx = _ctx(tmp_path, Config())
        db.connect(db.db_path(ctx)).close()
        ctx.assume_yes = False
        ctx.confirm = lambda *a, **k: False          # user says no
        assert check.security_gate(ctx) is False     # -> abort
        ctx.confirm = lambda *a, **k: True           # user says yes
        assert check.security_gate(ctx) is True


def test_gate_no_critical_proceeds(tmp_path):
    findings = [_f("vim", "High")]                   # High, not Critical -> no gate
    with patch("fettle.advisories.check._providers",
               lambda: [type("P", (_StubProvider,), {"findings": lambda s, c, conn: findings})()]):
        ctx = _ctx(tmp_path, Config())
        db.connect(db.db_path(ctx)).close()
        ctx.assume_yes = False
        ctx.confirm = lambda *a, **k: False          # would abort IF asked
        assert check.security_gate(ctx) is True       # not asked -> proceeds


def test_gate_under_assume_yes_never_blocks(tmp_path):
    findings = [_f("openssl", "Critical")]
    with patch("fettle.advisories.check._providers",
               lambda: [type("P", (_StubProvider,), {"findings": lambda s, c, conn: findings})()]):
        ctx = _ctx(tmp_path, Config())
        db.connect(db.db_path(ctx)).close()
        ctx.assume_yes = True
        ctx.confirm = lambda *a, **k: False          # must NOT be consulted
        assert check.security_gate(ctx) is True


def test_update_action_aborts_when_gate_false():
    from unittest.mock import MagicMock

    from fettle import actions
    backend, ctx = MagicMock(), MagicMock()
    ctx.dry_run = False
    with patch("fettle.advisories.check.security_gate", return_value=False):
        actions._update(backend, ctx)
    backend.update_system.assert_not_called()        # gate aborted -> no upgrade
    with patch("fettle.advisories.check.security_gate", return_value=True):
        actions._update(backend, ctx)
    backend.update_system.assert_called_once()


# -- CLI dispatch ------------------------------------------------------------
def test_cli_routes_advisory_subcommands():
    from fettle import cli
    with patch("fettle.advisories.check.run") as run, \
         patch("fettle.advisories.check.update") as upd:
        assert cli._main(["advisory-check", "--no-config"]) == 0
        assert cli._main(["advisory-update", "--no-config"]) == 0
    run.assert_called_once()
    upd.assert_called_once()
