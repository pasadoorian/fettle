"""RP1: central report storage — per-host dirs, timestamps, 0600, rotation."""

import datetime as dt
import os
from types import SimpleNamespace

from fettle import reports
from fettle.config import Config


def _ctx(home, cfg=None, sudo_user=None):
    return SimpleNamespace(user_home=home, sudo_user=sudo_user,
                           config=cfg or Config())


def _at(y=2026, mo=7, d=21, h=6, mi=45, s=30):
    return dt.datetime(y, mo, d, h, mi, s)


# -- location & layout -------------------------------------------------------
def test_local_report_lands_in_reports_local(tmp_path):
    p = reports.write_report("hardening-audit", "body", _ctx(tmp_path), now=_at())
    assert p == tmp_path / ".fettle/reports/local/hardening-audit-20260721-064530.txt"
    assert p.read_text() == "body\n"


def test_remote_host_gets_its_own_subdir(tmp_path):
    p = reports.write_report("pkg-audit", "x", _ctx(tmp_path), host="foo", now=_at())
    assert p.parent == tmp_path / ".fettle/reports/foo"


def test_host_tag_sanitized_and_defaults_to_local():
    assert reports.host_tag(None) == "local"
    assert reports.host_tag("local") == "local"
    assert reports.host_tag("user@web-01.example.com") == "user_web-01.example.com"
    assert reports.host_tag("../etc") == "etc"       # path chars stripped
    assert reports.host_tag("///") == "local"        # nothing left -> local


def test_body_gets_trailing_newline_once(tmp_path):
    p1 = reports.write_report("aur-audit", "no newline", _ctx(tmp_path), now=_at())
    p2 = reports.write_report("aur-audit", "has newline\n", _ctx(tmp_path),
                              now=_at(s=31))
    assert p1.read_text() == "no newline\n"
    assert p2.read_text() == "has newline\n"


# -- permissions -------------------------------------------------------------
def test_report_is_0600_and_dirs_are_0700(tmp_path):
    p = reports.write_report("pkg-audit", "secret pkg names", _ctx(tmp_path), now=_at())
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    for d in (tmp_path / ".fettle", tmp_path / ".fettle/reports",
              tmp_path / ".fettle/reports/local"):
        assert oct(os.stat(d).st_mode & 0o777) == "0o700"


# -- timestamping / no clobber -----------------------------------------------
def test_same_second_writes_do_not_clobber(tmp_path):
    a = reports.write_report("aur-audit", "one", _ctx(tmp_path), now=_at())
    b = reports.write_report("aur-audit", "two", _ctx(tmp_path), now=_at())
    assert a != b
    assert a.read_text() == "one\n" and b.read_text() == "two\n"


# -- rotation ----------------------------------------------------------------
def test_keeps_newest_n_per_type(tmp_path):
    ctx = _ctx(tmp_path)  # default keep = 5
    for i in range(8):
        reports.write_report("hardening-audit", f"run{i}", ctx, now=_at(mi=i))
    d = tmp_path / ".fettle/reports/local"
    kept = sorted(d.glob("hardening-audit-*.txt"))
    assert len(kept) == 5                      # newest 5 of 8
    assert kept[-1].read_text() == "run7\n"    # most recent retained
    assert not any("run0" in f.read_text() for f in kept)  # oldest gone


def test_rotation_is_per_type_and_per_host(tmp_path):
    ctx = _ctx(tmp_path)
    for i in range(6):
        reports.write_report("hardening-audit", f"h{i}", ctx, now=_at(mi=i))
        reports.write_report("pkg-audit", f"p{i}", ctx, now=_at(mi=i))
        reports.write_report("hardening-audit", f"r{i}", ctx, host="foo", now=_at(mi=i))
    loc = tmp_path / ".fettle/reports/local"
    foo = tmp_path / ".fettle/reports/foo"
    assert len(list(loc.glob("hardening-audit-*.txt"))) == 5   # local hardening
    assert len(list(loc.glob("pkg-audit-*.txt"))) == 5         # local pkg (untouched)
    assert len(list(foo.glob("hardening-audit-*.txt"))) == 5   # foo hardening (separate)


def test_prune_returns_removed_and_survives_missing():
    # prune on a nonexistent dir must not raise
    from pathlib import Path
    assert reports.prune(Path("/nonexistent-xyz"), "x", 5) == []


# -- config ------------------------------------------------------------------
def test_keep_from_config(tmp_path):
    cfg = Config()
    cfg.reports = {"keep": 2}
    ctx = _ctx(tmp_path, cfg)
    for i in range(5):
        reports.write_report("aur-audit", f"{i}", ctx, now=_at(mi=i))
    assert len(list((tmp_path / ".fettle/reports/local").glob("aur-audit-*.txt"))) == 2


def test_dir_override_from_config(tmp_path):
    cfg = Config()
    cfg.reports = {"dir": str(tmp_path / "custom")}
    reports.write_report("pkg-audit", "x", _ctx(tmp_path, cfg), now=_at())
    assert (tmp_path / "custom/reports/local").is_dir()


def test_malformed_config_falls_back_to_defaults(tmp_path):
    cfg = Config()
    cfg.reports = {"keep": "lots"}          # not an int
    ctx = _ctx(tmp_path, cfg)
    for i in range(7):
        reports.write_report("aur-audit", f"{i}", ctx, now=_at(mi=i))
    # default keep = 5
    assert len(list((tmp_path / ".fettle/reports/local").glob("aur-audit-*.txt"))) == 5
    cfg.reports = "garbage"                  # not even a dict
    p = reports.write_report("aur-audit", "ok", ctx, now=_at(mi=59))
    assert p.exists()


def test_logs_dir_mirrors_reports_layout(tmp_path):
    d = reports.logs_dir(_ctx(tmp_path), host="foo")
    assert d == tmp_path / ".fettle/logs/foo"
    assert oct(os.stat(d).st_mode & 0o777) == "0o700"


# -- RP2: legacy-note behavior ----------------------------------------------
class _Out:
    def __init__(self):
        self.notes = []

    def note(self, m):
        self.notes.append(m)


def test_legacy_note_fires_once_when_old_reports_present(tmp_path):
    (tmp_path / "hardening-audit.txt").write_text("old")   # pre-0.11 report in $HOME
    out = _Out()
    ctx = SimpleNamespace(user_home=tmp_path, sudo_user=None, config=Config(), output=out)
    reports.write_report("hardening-audit", "new", ctx, now=_at())
    reports.write_report("hardening-audit", "new2", ctx, now=_at(s=31))
    hits = [n for n in out.notes if "reports now live under" in n]
    assert len(hits) == 1                                  # exactly once, not per write
    assert (tmp_path / ".fettle/.reports-migrated").exists()


def test_no_legacy_note_without_old_reports(tmp_path):
    out = _Out()
    ctx = SimpleNamespace(user_home=tmp_path, sudo_user=None, config=Config(), output=out)
    reports.write_report("pkg-audit", "x", ctx, now=_at())
    assert not any("reports now live" in n for n in out.notes)


def test_prune_known_rotates_every_report_type(tmp_path):
    d = tmp_path / ".fettle/reports/foo"
    d.mkdir(parents=True)
    for base in ("hardening-audit", "pkg-audit"):
        for i in range(7):
            (d / f"{base}-2026072{i}-000000.txt").write_text(str(i))
    reports.prune_known(d, 5)
    assert len(list(d.glob("hardening-audit-*.txt"))) == 5
    assert len(list(d.glob("pkg-audit-*.txt"))) == 5
