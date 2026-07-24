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
             '["CVE-1"]', None, "http://x")]
    db.replace_source(conn, "arch", rows, now=1000)
    assert db.last_updated(conn, "arch") == 1000
    got = db.all_rows(conn, "arch")
    assert len(got) == 1 and got[0][1] == "vim" and got[0][5] == "1-2"
    # replace is a full swap for that source
    db.replace_source(conn, "arch", [], now=2000)
    assert db.all_rows(conn, "arch") == [] and db.last_updated(conn, "arch") == 2000


def test_db_schema_mismatch_rebuilds(tmp_path):
    p = tmp_path / "adv.db"
    conn = db.connect(p)
    db.replace_source(conn, "arch", [("arch", "A", "p", "Fixed", "Low", "", "1",
                                      "[]", None, "")], now=1)
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
    assert "NOT covered by the tracker" in out and "yay" in out
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
