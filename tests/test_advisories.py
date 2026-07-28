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

    def refresh(self, conn, ctx=None):
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
    assert data["counts"] == {"pending": 1, "fixed_available": 1,
                              "pending_occurrences": 1, "fixed_available_occurrences": 1}
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
        rows = src._osv_pending(conn, floor=0)           # no floor -> keep the Medium one
    assert len(rows) == 1
    r = rows[0]
    assert r[2] == "dovecot" and r[3] == "pending"
    assert r[4] == "Medium"                              # native Ubuntu priority, not CVSS
    assert r[7] == '["CVE-2026-0394"]' and r[11].startswith("CVSS")   # cvss carried too
    # the severity floor drops it: Medium (rank 2) < High (rank 3)
    with patch.object(osv, "querybatch",
                      return_value=[[{"id": "UBUNTU-CVE-2026-0394", "modified": "m"}]]), \
         patch.object(osv, "record", return_value=rec):
        from fettle.advisories.base import severity_rank
        assert src._osv_pending(conn, floor=severity_rank("High")) == []


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
    src._installed = lambda ctx: [("PyPI", "requests", "2.25.0", "venvA"),
                                  ("PyPI", "clean-pkg", "1.0", "venvA")]
    with patch.object(osv, "querybatch",
                      return_value=[[{"id": "GHSA-xxxx", "modified": "2024-01-01"}], []]), \
         patch.object(osv, "record", return_value=_OSV_REC):
        assert src.refresh(conn) == 1                       # only the vulnerable one
    f = src.findings(None, conn)
    assert len(f) == 1
    # stored env-qualified, split back out for grouping
    assert f[0].source == "osv" and f[0].package == "requests"
    assert f[0].environment == "venvA"
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


def test_osv_dedup_tolerates_short_rows_on_collision():
    # OVAL rows are 11-element (no cvss yet); a same-(pkg,cve) tie must NOT IndexError
    from fettle.advisories.osv import dedup_rows
    r1 = ("ubuntu", "CVE-1", "openssl", "fixable", "High", "", "3-1",
          '["CVE-1"]', None, "u", "high")           # 11 elements, no cvss
    r2 = ("ubuntu", "CVE-1", "openssl", "fixable", "High", "", "3-1",
          '["CVE-1"]', None, "u", "high")
    assert len(dedup_rows([r1, r2])) == 1            # collapses, no crash


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


# -- OSV language scan targets UNMANAGED environments only -------------------
# Regression guard. This provider used to enumerate the running interpreter's
# packages, which on a distro box is the package-manager-owned system
# site-packages: it re-reported packages the arch/debian providers already cover
# (judging them by PyPI rather than the distro's own verdict) while missing every
# venv on the machine. wopr: 264 scanned, 100% pacman-owned, 36 venvs invisible.
def _fake_venv(root, name, pkgs, *, marker="pyvenv.cfg"):
    """Build a venv-shaped tree with real .dist-info metadata."""
    env = root / name
    sp = env / "lib/python3.14/site-packages"
    sp.mkdir(parents=True)
    if marker:
        (env / marker).write_text("home = /usr/bin\n")
    for pkg, ver in pkgs.items():
        d = sp / f"{pkg}-{ver}.dist-info"
        d.mkdir()
        (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {pkg}\nVersion: {ver}\n")
    return env


def _osv_ctx(tmp_path, **adv):
    from fettle.backends.base import Context
    from fettle.config import Config
    from fettle.output import Output
    cfg = Config()
    cfg.advisories = adv
    return Context(output=Output(color=False), config=cfg, user_home=tmp_path)


def test_language_scan_finds_project_venvs_under_configured_roots(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    root = tmp_path / "src"
    _fake_venv(root / "SploitScan", "venv", {"requests": "2.25.0"})
    _fake_venv(root / "bifrost", ".venv", {"jinja2": "3.0.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[str(root)], venv_depth=3)
    got = {(name, ver, env) for _eco, name, ver, env in OsvLanguageSource()._pip(ctx)}
    # labelled by PROJECT, not by the venv dir's own name ("venv"/".venv")
    assert ("requests", "2.25.0", "SploitScan") in got
    assert ("jinja2", "3.0.0", "bifrost") in got


def test_language_scan_ignores_distro_managed_site_packages(tmp_path):
    """A site-packages dir that is NOT part of an environment must not be scanned
    — that is the distro providers' territory and caused duplicate findings."""
    from fettle.advisories.osv_source import OsvLanguageSource
    root = tmp_path / "src"
    # same shape, but no pyvenv.cfg => not an environment we own
    _fake_venv(root / "distro", "lib-tree", {"ecdsa": "0.19.2"}, marker=None)
    ctx = _osv_ctx(tmp_path, venv_roots=[str(root)], venv_depth=3)
    assert OsvLanguageSource()._pip(ctx) == []


def test_language_scan_finds_uv_and_pipx_apps(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    _fake_venv(tmp_path / ".local/share/uv/tools", "ruff", {"ruff": "0.1.0"})
    _fake_venv(tmp_path / ".local/share/pipx/venvs", "httpie", {"httpie": "3.0.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[])       # no project roots: tools only
    got = {(name, env) for _eco, name, _v, env in OsvLanguageSource()._pip(ctx)}
    assert ("ruff", "ruff") in got and ("httpie", "httpie") in got


def test_venv_search_is_depth_bounded(tmp_path):
    """An unbounded $HOME walk took >120s on a real machine; depth must be honoured."""
    from fettle.advisories.osv_source import OsvLanguageSource
    deep = tmp_path / "src/a/b/c/d/e"
    _fake_venv(deep, "venv", {"requests": "2.25.0"})
    shallow = _osv_ctx(tmp_path, venv_roots=[str(tmp_path / "src")], venv_depth=2)
    assert OsvLanguageSource()._pip(shallow) == []
    deep_ctx = _osv_ctx(tmp_path, venv_roots=[str(tmp_path / "src")], venv_depth=9)
    assert OsvLanguageSource()._pip(deep_ctx) != []


def test_default_depth_reaches_nested_project_venvs(tmp_path):
    """Default depth must reach a venv nested like src/<topic>/<repo>/<sub>/venv —
    real research trees put them there (src/fortinet/exploits/CVE_*/.../venv), and
    the previous default of 3 silently missed them."""
    from fettle.advisories.osv_source import OsvLanguageSource
    _fake_venv(tmp_path / "src/topic/repo/sub", "venv", {"requests": "2.25.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[str(tmp_path / "src")])   # no venv_depth set
    found = OsvLanguageSource()._pip(ctx)
    assert [name for _eco, name, _v, _env in found] == ["requests"]


def test_same_package_in_two_venvs_stays_two_findings(tmp_path):
    """Env is part of the identity: the same vulnerable package in two venvs is
    two things to fix, and dedup keys on the package name."""
    from fettle.advisories.osv_source import OsvLanguageSource
    root = tmp_path / "src"
    _fake_venv(root / "toolA", "venv", {"requests": "2.25.0"})
    _fake_venv(root / "toolB", "venv", {"requests": "2.25.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[str(root)], venv_depth=3)
    envs = sorted(env for *_x, env in OsvLanguageSource()._pip(ctx))
    assert envs == ["toolA", "toolB"]


def test_node_scan_reads_unmanaged_trees_without_npm(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    mods = tmp_path / ".bun/install/global/node_modules"
    (mods / "left-pad").mkdir(parents=True)
    (mods / "left-pad/package.json").write_text('{"name":"left-pad","version":"1.0.0"}')
    (mods / "@scope/thing").mkdir(parents=True)
    (mods / "@scope/thing/package.json").write_text('{"name":"@scope/thing","version":"2.0.0"}')
    got = {(n, v, e) for _eco, n, v, e in OsvLanguageSource()._npm(_osv_ctx(tmp_path))}
    assert ("left-pad", "1.0.0", "bun") in got
    assert ("@scope/thing", "2.0.0", "bun") in got     # scoped packages handled


# -- grouping: one package in many venvs is ONE problem, N places to fix -----
# The unmanaged-language scan reports per environment, so replication (not
# severity) is what makes the report unreadable: a real run produced 212 findings
# for 16 packages, urllib3 alone accounting for 80. A severity floor barely helps
# (209 of those 212 were High), so reporting groups instead.
def _envf(pkg, env, ver="1.0", sev="High", cves=("CVE-1",), fixed="2.0", status=None):
    from fettle.advisories import base
    return base.AdvisoryFinding(
        source="osv", package=pkg, environment=env, installed_version=ver,
        status=status or base.FIXED_AVAILABLE, severity=sev, cves=list(cves),
        fixed_version=fixed)


def test_group_collapses_same_package_across_environments():
    got = check._group([_envf("urllib3", e) for e in ("alpha", "beta", "gamma")])
    assert len(got) == 1
    f, envs = got[0]
    assert f.package == "urllib3"
    assert [e for e, _v in envs] == ["alpha", "beta", "gamma"]


def test_group_merges_differing_installed_versions_behind_one_fix():
    """Keyed on the REMEDIATION, not the installed version: "upgrade pip to 26.1.2"
    is one action whether a venv sits on 24.0 or 25.2. Keying on the installed
    version fragmented that single action into 34 lines on real data."""
    got = check._group([_envf("pip", "dfir", ver="25.2", fixed="26.1.2"),
                        _envf("pip", "cve-maker", ver="24.0", fixed="26.1.2")])
    assert len(got) == 1
    f, envs = got[0]
    assert dict(envs) == {"dfir": "25.2", "cve-maker": "24.0"}   # per-env version kept
    assert check._installed_summary(f, envs) == "24.0…25.2 (2 versions)"


def test_group_keeps_different_fix_targets_apart():
    """Different fix versions ARE different remediations — must not merge."""
    got = check._group([_envf("pip", "a", fixed="26.1.2"),
                        _envf("pip", "b", fixed="25.3")])
    assert len(got) == 2


def test_group_keeps_different_cves_apart():
    got = check._group([_envf("pillow", "a", cves=("CVE-1",)),
                        _envf("pillow", "a", cves=("CVE-2",))])
    assert len(got) == 2


def test_group_leaves_os_findings_untouched():
    """Distro findings have no environment; grouping must be a no-op for them."""
    got = check._group([_envf("bash", ""), _envf("curl", "")])
    assert len(got) == 2 and all(envs == [] for _f_, envs in got)


def test_render_lists_environments_and_reports_occurrences():
    findings = [_envf("urllib3", f"env{i}") for i in range(28)]
    lines, data = check._render(findings, {}, False, ["osv"])
    text = "\n".join(lines)
    assert "Fix available — installed trails a security fix (1)" in text
    assert "28 occurrences across 28 environment(s)" in text     # nothing vanished
    assert "in 28 environments: env0 (1.0)" in text
    assert "(+18 more)" in text                                   # 10 shown, rest summarized
    assert data["counts"] == {"pending": 0, "fixed_available": 1,
                              "pending_occurrences": 0, "fixed_available_occurrences": 28}
    assert len(data["findings"]) == 28            # JSON keeps every occurrence


def test_render_single_environment_reads_naturally():
    lines, _d = check._render([_envf("requests", "SploitScan")], {}, False, ["osv"])
    text = "\n".join(lines)
    assert "in SploitScan (1.0)" in text and "environments:" not in text
    assert "occurrences across" not in text        # nothing was collapsed


# -- environment labels must be unique --------------------------------------
# The label is part of a finding's identity: rows are cached as "env:package" and
# deduplicated on that name, so two environments sharing a label silently collapse
# and a real finding disappears. Both collision shapes occur on a real tree.
def test_two_venvs_in_one_project_get_distinct_labels(tmp_path):
    """venv-fettle-dev and venv-fettle-web both label as their parent, 'fettle'."""
    from fettle.advisories.osv_source import OsvLanguageSource
    proj = tmp_path / "src/fettle"
    _fake_venv(proj, "venv-dev", {"requests": "2.25.0"})
    _fake_venv(proj, "venv-web", {"jinja2": "3.0.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[str(tmp_path / "src")])
    labels = {env for *_x, env in OsvLanguageSource()._pip(ctx)}
    assert len(labels) == 2, f"labels collapsed: {labels}"


def test_same_dirname_in_different_projects_gets_distinct_labels(tmp_path):
    """src/cisa-kev/venv vs src/cvetool/cisa-kev/venv — different projects."""
    from fettle.advisories.osv_source import OsvLanguageSource
    _fake_venv(tmp_path / "src/cisa-kev", "venv", {"requests": "2.25.0"})
    _fake_venv(tmp_path / "src/cvetool/cisa-kev", "venv", {"jinja2": "3.0.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[str(tmp_path / "src")])
    found = OsvLanguageSource()._pip(ctx)
    labels = {env for *_x, env in found}
    assert len(labels) == 2, f"labels collapsed: {labels}"
    assert len(found) == 2                      # neither package was lost


def test_labels_stay_short_when_unambiguous(tmp_path):
    """Widening only kicks in on a collision — the common case stays readable."""
    from fettle.advisories.osv_source import OsvLanguageSource
    _fake_venv(tmp_path / "src/SploitScan", "venv", {"requests": "2.25.0"})
    _fake_venv(tmp_path / "src/ALEAPP", "venv", {"jinja2": "3.0.0"})
    ctx = _osv_ctx(tmp_path, venv_roots=[str(tmp_path / "src")])
    assert {env for *_x, env in OsvLanguageSource()._pip(ctx)} == {"SploitScan", "ALEAPP"}


# -- cargo / crates.io -------------------------------------------------------
# `cargo install`ed crates are compiled from source into ~/.cargo/bin: unsigned,
# and invisible to every OS package manager. Read from cargo's own install index,
# not from the binary names in ~/.cargo/bin (a crate's binaries need not share its
# name -- flutter_rust_bridge_codegen installs a differently-named binary).
def _crates(tmp_path, keys):
    import json as _json
    d = tmp_path / ".cargo"
    d.mkdir(parents=True, exist_ok=True)
    (d / ".crates2.json").write_text(
        _json.dumps({"installs": {k: {"bins": []} for k in keys}}))


_REGISTRY = "(registry+https://github.com/rust-lang/crates.io-index)"


def test_cargo_registry_install_is_enumerated(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    _crates(tmp_path, [f"ripgrep 14.1.0 {_REGISTRY}"])
    assert OsvLanguageSource()._cargo(_osv_ctx(tmp_path)) == [
        ("crates.io", "ripgrep", "14.1.0", "cargo")]


def test_cargo_source_kind_is_visible_in_the_label(tmp_path):
    """A path/git install is a source checkout whose version need not be the
    published release of that name — a finding against it must be readable as such,
    not presented as a registry match."""
    from fettle.advisories.osv_source import OsvLanguageSource
    _crates(tmp_path, [
        f"a 1.0.0 {_REGISTRY}",
        "b 2.0.0 (path+file:///home/u/.cache/yay/x/src/b)",
        "c 3.0.0 (git+https://github.com/o/c#abc123)",
    ])
    got = {name: env for _eco, name, _v, env in
           OsvLanguageSource()._cargo(_osv_ctx(tmp_path))}
    assert got == {"a": "cargo", "b": "cargo(path)", "c": "cargo(git)"}


def test_cargo_absent_index_yields_nothing(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    assert OsvLanguageSource()._cargo(_osv_ctx(tmp_path)) == []


def test_cargo_malformed_index_does_not_crash(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    d = tmp_path / ".cargo"
    d.mkdir(parents=True)
    (d / ".crates2.json").write_text("{not json")
    assert OsvLanguageSource()._cargo(_osv_ctx(tmp_path)) == []
    (d / ".crates2.json").write_text('{"installs": "wrong type"}')
    assert OsvLanguageSource()._cargo(_osv_ctx(tmp_path)) == []


def test_cargo_skips_unparseable_keys(tmp_path):
    from fettle.advisories.osv_source import OsvLanguageSource
    _crates(tmp_path, ["nameonly", f"good 1.0.0 {_REGISTRY}"])
    assert [n for _e, n, _v, _env in
            OsvLanguageSource()._cargo(_osv_ctx(tmp_path))] == ["good"]


def test_cargo_feeds_the_shared_installed_list(tmp_path):
    """It must reach _installed(), or the crates are enumerated and never queried."""
    from fettle.advisories.osv_source import OsvLanguageSource
    _crates(tmp_path, [f"ripgrep 14.1.0 {_REGISTRY}"])
    ctx = _osv_ctx(tmp_path, venv_roots=[])
    ecos = {eco for eco, *_rest in OsvLanguageSource()._installed(ctx)}
    assert "crates.io" in ecos
