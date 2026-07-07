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
    if url.endswith("packages.txt"):        # covers packages.txt (not -extra)
        return "evil-pkg\nchaos-rat-bin\n"
    if url.endswith("accounts.json"):
        return json.dumps({"accounts": {"baduser": {}}})
    return ""


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
        mp.setattr("fettle.aur.ioc._fetch", lambda url, timeout=20.0: "")  # network down
        precheck.check(["evil-pkg"], emit=out.append)
    assert any("CRIT evil-pkg is on the KNOWN-COMPROMISED package list" in ln for ln in out)


def test_main_always_returns_zero(env):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        assert precheck.main(["evil-pkg"]) == 0


def test_master_toggle_disables(env, monkeypatch):
    monkeypatch.setenv("AUR_PRECHECK", "false")
    out = []
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("fettle.aur.meta.fetch_info", lambda pkgs, **kw: _records())
        precheck.check(["evil-pkg"], emit=out.append)
    assert out == []
