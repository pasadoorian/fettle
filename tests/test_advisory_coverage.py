"""Incomplete upstream data cannot acquire a current/clean cache stamp."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fettle.advisories import db, osv
from fettle.advisories.osv_source import OsvLanguageSource
from fettle.advisories.debian_source import DebianAdvisorySource
from fettle.command import Proc
from fettle.config import Config


def test_osv_pagination_keeps_query_alignment():
    queries = [{"package": {"ecosystem": "PyPI", "name": n}, "version": "1"}
               for n in ("first", "second")]
    responses = [{"results": [{"vulns": [{"id": "A"}], "next_page_token": "next"},
                               {"vulns": [{"id": "B"}]}]},
                 {"results": [{"vulns": [{"id": "C"}]}]}]
    with patch.object(osv, "_post", side_effect=responses) as post:
        assert osv.querybatch(queries) == [[{"id": "A"}, {"id": "C"}], [{"id": "B"}]]
    assert post.call_args.args[1] == {"queries": [{**queries[0], "page_token": "next"}]}


@pytest.mark.parametrize("response", [{}, {"results": []}, {"results": [None]},
                                      {"results": [{"error": "failed"}]}])
def test_osv_rejects_incomplete_batch(response):
    with patch.object(osv, "_post", return_value=response), pytest.raises(ValueError):
        osv.querybatch([{"version": "1"}])


def test_missing_record_preserves_old_source_and_timestamp(tmp_path):
    conn = db.connect(tmp_path / "cache.db")
    src = OsvLanguageSource()
    row = ("osv", "old", "/env:pkg", "pending", "High", "1", None, "[]", None, "", "", "", "PyPI")
    db.replace_source(conn, "osv", [row], now=100)
    src._installed = lambda ctx: [("PyPI", "pkg", "1", "/env")]
    with patch.object(osv, "querybatch", return_value=[[{"id": "new"}]]), \
         patch.object(osv, "record", return_value=None):
        assert src.refresh(conn) == -1
    assert db.last_updated(conn, "osv") == 100
    assert db.all_rows(conn, "osv")[0][0] == "old"
    conn.close()


def test_language_inventory_change_invalidates_fresh_cache(tmp_path):
    conn = db.connect(tmp_path / "cache.db")
    src = OsvLanguageSource()
    inventory = [("PyPI", "pkg", "1", "/env")]
    src._installed = lambda ctx: inventory
    assert src.needs_refresh(conn, None)
    with patch.object(osv, "querybatch", return_value=[[]]):
        src.refresh(conn)
    assert not src.needs_refresh(conn, None)
    inventory[0] = ("PyPI", "pkg", "2", "/env")
    assert src.needs_refresh(conn, None)
    conn.close()


def test_language_roots_and_user_site_follow_invoker(tmp_path, monkeypatch):
    home = tmp_path / "invoker"
    env = home / "src/project/.venv"
    sp = env / "lib/python3.11/site-packages"
    sp.mkdir(parents=True)
    (env / "pyvenv.cfg").touch()
    user = home / ".local/lib/python3.12/site-packages"
    user.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(tmp_path / "root"))
    ctx = SimpleNamespace(user_home=home, config=Config())
    paths = {p for _, p in OsvLanguageSource()._environments(ctx)}
    assert paths == {sp, user}


def test_apt_inventory_uses_source_versions_and_only_installed_packages():
    with patch("fettle.command.run", return_value=Proc(0, "libfoo 1.0 installed\nremoved 2 config-files\n", "")) as run:
        assert DebianAdvisorySource()._installed() == {"libfoo": "1.0"}
    assert "${source:Version}" in run.call_args.args[0][-1]


def test_osv_record_matching_uses_package_name():
    rec = {"affected": [
        {"package": {"ecosystem": "PyPI", "name": "other"}, "ranges": [{"events": [{"fixed": "9"}]}]},
        {"package": {"ecosystem": "PyPI", "name": "target"}, "ranges": []}]}
    assert osv.classify(rec, "PyPI", "1", "target") == ("pending", None)
