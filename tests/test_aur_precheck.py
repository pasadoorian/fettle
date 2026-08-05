"""Install-time AUR precheck — ports tests/unit/test_aur_precheck.bats to pytest.

The CRIT/WARN line strings are a contract consumed by yay-init.lua's parser, so
these assertions pin the exact substrings the way the bats suite did.
"""

import json
import time

import pytest

from fettle.aur import precheck


def _records():
    now = time.time()
    old, recent, ood = now - 500 * 86400, now - 5 * 86400, now - 50 * 86400
    return [
        {"Name": "orphan-pkg", "Maintainer": None,      "LastModified": recent, "OutOfDate": None},
        {"Name": "stale-pkg",  "Maintainer": "alice",   "LastModified": old,    "OutOfDate": None},
        {"Name": "ood-pkg",    "Maintainer": "bob",     "LastModified": recent, "OutOfDate": ood},
        {"Name": "evil-pkg",   "Maintainer": "baduser", "LastModified": recent, "OutOfDate": None},
        {"Name": "good-pkg",   "Maintainer": "carol",   "LastModified": recent, "OutOfDate": None},
    ]


def _fake_ioc_fetch(url, timeout=20.0):
    # (text, status). 404 is normal: campaigns publish different list types, so an
    # absent list is "missing", not a gap in coverage.
    if url.endswith("packages.txt"):        # covers packages.txt (not -extra)
        return "evil-pkg\nchaos-rat-bin\n", "ok"
    if url.endswith("accounts.json"):
        return json.dumps({"accounts": {"baduser": {}}}), "ok"
    return "", "missing"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A sandbox HOME with an allowlist and a single IOC campaign."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("AUR_IOC_CAMPAIGNS", "c1")
    monkeypatch.setenv("AUR_PRECHECK_MAX_AGE_DAYS", "365")
    monkeypatch.delenv("AUR_PRECHECK", raising=False)
    allow = tmp_path / ".config/yay/allowlist.txt"
    allow.parent.mkdir(parents=True)
    allow.write_text("mailspring\n")
    monkeypatch.setattr("fettle.aur.ioc._fetch", _fake_ioc_fetch)
    return tmp_path


def _run(pkg, *, records=None):
    """Run the precheck with mocked RPC; return captured advisory lines."""
    out = []
    online = records if records is not None else _records()
    monkeypatch_target = "fettle.aur.meta.fetch_info"
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(monkeypatch_target, lambda pkgs, **kw: online)
        precheck.check([pkg], emit=out.append)
    return out


def test_scan_splits_crit_and_warn(env):
    # AP1: scan() returns (crit, warn) with the prefixes stripped — the gate's input.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        crit, warn = precheck.scan(["evil-pkg", "orphan-pkg", "good-pkg"])
    assert any("evil-pkg" in c for c in crit)              # known-compromised -> CRIT
    assert any("orphan-pkg" in w for w in warn)            # orphaned -> WARN
    assert not any("good-pkg" in x for x in crit + warn)   # clean -> nothing
    assert not any(c.startswith("CRIT ") for c in crit)    # prefix stripped


def test_flags_orphaned(env):
    assert any("WARN orphan-pkg is ORPHANED" in ln for ln in _run("orphan-pkg"))


def test_flags_out_of_date(env):
    assert any("WARN ood-pkg is flagged OUT-OF-DATE" in ln for ln in _run("ood-pkg"))


def test_flags_stale_past_threshold(env):
    out = _run("stale-pkg")
    assert any("WARN stale-pkg PKGBUILD last updated" in ln for ln in out)
    assert any("stale" in ln for ln in out)


def test_loud_compromised_name_and_maintainer(env):
    out = _run("evil-pkg")
    assert any("CRIT evil-pkg is on the KNOWN-COMPROMISED package list" in ln for ln in out)
    assert any("CRIT evil-pkg is maintained by KNOWN-MALICIOUS account 'baduser'" in ln
               for ln in out)


def test_flags_missing_from_aur(env):
    assert any("WARN ghost-pkg was NOT found in the AUR" in ln for ln in _run("ghost-pkg"))


def test_silent_for_clean_package(env):
    assert _run("good-pkg") == []


def test_silent_for_allowlisted_package(env):
    assert _run("mailspring") == []


def test_offline_rpc_distinct_from_not_found(env):
    out = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: None)
        precheck.check(["orphan-pkg"], emit=out.append)
    assert any("could not reach the AUR RPC" in ln for ln in out)
    assert not any("NOT found in the AUR" in ln for ln in out)


def test_compromised_list_from_cache_when_offline(env):
    # Prime the IOC cache with an online run, then go offline (RPC gone) and
    # confirm the known-compromised CRIT still fires from the cached list.
    _run("evil-pkg")  # seeds the on-disk IOC cache
    out = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: None)
        mp.setattr("fettle.aur.ioc._fetch",
                   lambda url, timeout=20.0: ("", "unreachable"))  # network down
        precheck.check(["evil-pkg"], emit=out.append)
    assert any("CRIT evil-pkg is on the KNOWN-COMPROMISED package list" in ln for ln in out)


def test_main_exit_status_reflects_a_critical(env):
    """It returned 0 unconditionally. The yay hook reads stdout and discards the
    status (verified in its source), so a real one costs the hook nothing and makes
    `fettle aur-precheck foo && yay -S foo` mean what it looks like it means."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        assert precheck.main(["evil-pkg"]) == 1        # KNOWN-COMPROMISED
        assert precheck.main(["good-pkg"]) == 0


def test_bare_main_scans_all_installed_foreign(env, capsys):
    # No args -> enumerate installed foreign packages and scan them all.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.precheck._installed_foreign",
                   lambda: ["evil-pkg", "good-pkg"])
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        rc = precheck.main([])
    out = capsys.readouterr().out
    assert rc == 1                                    # evil-pkg is KNOWN-COMPROMISED
    assert "scanning 2 installed" in out
    assert "KNOWN-COMPROMISED" in out          # evil-pkg flagged in the batch


def test_bare_main_no_foreign_packages(env, capsys):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.precheck._installed_foreign", lambda: [])
        rc = precheck.main([])
    assert rc == 0
    assert "no foreign/AUR packages installed" in capsys.readouterr().out


def test_bare_main_clean_reports_no_issues(env, capsys):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.precheck._installed_foreign", lambda: ["good-pkg"])
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        precheck.main([])
    assert "no issues found." in capsys.readouterr().out


def test_master_toggle_disables(env, monkeypatch):
    monkeypatch.setenv("AUR_PRECHECK", "false")
    out = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        precheck.check(["evil-pkg"], emit=out.append)
    assert out == []


def test_main_double_dash_takes_literal_package_names(env):
    # B7: everything after `--` is a package name; stray flags before it drop, but
    # names are never silently lost.
    seen = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.precheck.check", lambda pkgs, **kw: seen.extend(pkgs))
        precheck.main(["--no-color", "--", "good-pkg"])
    assert seen == ["good-pkg"]


# -- the malware gate must not pass silently when its lists are blind ---------
class _BlindIOC:
    """IoC feeds unreachable: the lists come back EMPTY."""
    stale: list = []
    unavailable = ["aur-infected/packages.txt"]
    degraded = True

    def __init__(self, **_kw):
        pass

    def bad_packages(self):
        return set()

    def bad_accounts(self):
        return set()


def test_unreadable_ioc_feeds_are_announced(env):
    """Measured before the fix: with a cold cache and an unreachable feed host,
    `bad_packages()` returned set(), `degraded` was True, and the precheck emitted
    nothing — so a compromised package would have been built in silence. This is the
    install-time gate, so it matters more here than anywhere else."""
    lines = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.precheck.aur_ioc.IOC", _BlindIOC)
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        precheck.check(["good-pkg"], emit=lines.append)
    assert any("NOT checked against the known-compromise lists" in ln for ln in lines)
    assert any(ln.startswith("WARN ") for ln in lines)   # the hook parses WARN lines


def test_world_writable_allowlist_is_ignored(env, tmp_path):
    """An allowlist entry suppresses a CRITICAL malware warning, so the file is a
    trust boundary — fettle's TOML config has refused world-writable files since day
    one, and this was the softer way to silence the same alarm."""
    allow = tmp_path / "allowlist.txt"
    allow.write_text("evil-pkg\n")
    allow.chmod(0o666)
    lines = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("YAY_ALLOWLIST_FILE", str(allow))
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        precheck.check(["evil-pkg"], emit=lines.append)
    assert any("world-writable" in ln and "IGNORING" in ln for ln in lines)
    assert any("KNOWN-COMPROMISED" in ln for ln in lines)   # not suppressed


def test_safe_allowlist_still_suppresses(env, tmp_path):
    allow = tmp_path / "allowlist.txt"
    allow.write_text("evil-pkg\n")
    allow.chmod(0o644)
    lines = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("YAY_ALLOWLIST_FILE", str(allow))
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        precheck.check(["evil-pkg"], emit=lines.append)
    assert lines == []
