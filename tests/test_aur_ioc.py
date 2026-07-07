import json
import os
from unittest.mock import patch

from fettle.aur.ioc import DEFAULT_NPM_SEED, IOC


def _ioc(tmp_path, **kw):
    return IOC(cache_dir=tmp_path / "ioc", campaigns=["c1"], ttl=100, **kw)


def _backdate(cache_dir, seconds):
    """Age every cached file by `seconds` so the TTL check sees it as stale."""
    for fp in cache_dir.iterdir():
        st = fp.stat()
        os.utime(fp, (st.st_atime - seconds, st.st_mtime - seconds))


def test_bad_packages_merges_and_strips_comments(tmp_path):
    text = "# comment\nevil-pkg\n\nother-pkg\n"
    with patch("fettle.aur.ioc._fetch", return_value=text):
        pkgs = _ioc(tmp_path).bad_packages()
    assert pkgs == {"evil-pkg", "other-pkg"}


def test_bad_accounts_parses_json(tmp_path):
    payload = json.dumps({"accounts": {"baduser": {}, "eviluser": {}}})
    with patch("fettle.aur.ioc._fetch", return_value=payload):
        assert _ioc(tmp_path).bad_accounts() == {"baduser", "eviluser"}


def test_cache_hit_avoids_refetch(tmp_path):
    with patch("fettle.aur.ioc._fetch", return_value="pkg-a\n") as m:
        ioc = _ioc(tmp_path)
        ioc.bad_npm()
        first = m.call_count
        ioc.bad_npm()  # within TTL -> served from disk
    assert m.call_count == first  # no additional fetch


def test_stale_cache_refetches(tmp_path):
    with patch("fettle.aur.ioc._fetch", return_value="pkg-a\n") as m:
        _ioc(tmp_path).bad_npm()
        n1 = m.call_count
        _backdate(tmp_path / "ioc", 10_000)  # older than the 100s TTL
        _ioc(tmp_path).bad_npm()
    assert m.call_count > n1


def test_bad_npm_seeds_when_feed_empty(tmp_path):
    # Offline with no npm IOC list -> fall back to the seed, never silently empty.
    with patch("fettle.aur.ioc._fetch", return_value=""):
        assert _ioc(tmp_path).bad_npm() == set(DEFAULT_NPM_SEED)


def test_failed_fetch_falls_back_to_stale(tmp_path):
    with patch("fettle.aur.ioc._fetch", return_value="pkg-a\n"):
        _ioc(tmp_path).bad_npm()  # seed cache
    _backdate(tmp_path / "ioc", 10_000)
    with patch("fettle.aur.ioc._fetch", return_value=""):  # network down
        pkgs = _ioc(tmp_path).bad_npm()
    assert pkgs == {"pkg-a"}  # stale cache used rather than "clean"
