"""RJ1: JSON siblings for reports + logs — envelope, rotation, toggle."""

import datetime as dt
import json
import os
from types import SimpleNamespace

from fettle import reports
from fettle.config import Config


def _ctx(home, cfg=None, sudo_user=None):
    return SimpleNamespace(user_home=home, sudo_user=sudo_user, config=cfg or Config())


def _at(mi=45, s=30):
    return dt.datetime(2026, 7, 21, 6, mi, s)


def _json_of(txt_path):
    return json.loads(txt_path.with_suffix(".json").read_text())


# -- envelope ----------------------------------------------------------------
def test_json_sibling_written_with_envelope(tmp_path):
    txt = reports.write_report("pkg-audit", "the body", _ctx(tmp_path), now=_at())
    js = txt.with_suffix(".json")
    assert js.exists()
    env = json.loads(js.read_text())
    assert env["schema"] == "fettle.report/1"
    assert env["tool"] == "pkg-audit"
    assert env["host"] == "local"
    assert env["timestamp"] == "20260721-064530"
    assert env["fettle_version"]                      # non-empty version string
    assert env["data"] == {"text": "the body"}        # fallback when no structure


def test_structured_data_is_stored_verbatim(tmp_path):
    data = {"findings": [{"severity": "CRIT", "package": "evil"}], "count": 1}
    txt = reports.write_report("aur-ioc-scan", "text", _ctx(tmp_path),
                               host="web-01", now=_at(), data=data)
    env = _json_of(txt)
    assert env["host"] == "web-01"
    assert env["data"] == data                        # structured payload, not text


def test_json_sibling_is_0600(tmp_path):
    txt = reports.write_report("aur-audit", "x", _ctx(tmp_path), now=_at())
    assert oct(os.stat(txt.with_suffix(".json")).st_mode & 0o777) == "0o600"


# -- toggle ------------------------------------------------------------------
def test_json_disabled_by_config(tmp_path):
    cfg = Config()
    cfg.reports = {"json": False}
    txt = reports.write_report("pkg-audit", "x", _ctx(tmp_path, cfg), now=_at())
    assert txt.exists() and not txt.with_suffix(".json").exists()


def test_json_toggle_accepts_string_falsey(tmp_path):
    cfg = Config()
    cfg.reports = {"json": "off"}
    txt = reports.write_report("pkg-audit", "x", _ctx(tmp_path, cfg), now=_at())
    assert not txt.with_suffix(".json").exists()


# -- rotation keeps txt+json together ----------------------------------------
def test_rotation_removes_json_siblings_too(tmp_path):
    ctx = _ctx(tmp_path)  # keep=5
    for i in range(8):
        reports.write_report("hardening-audit", f"run{i}", ctx, now=_at(mi=i))
    d = tmp_path / ".fettle/reports/local"
    assert len(list(d.glob("hardening-audit-*.txt"))) == 5
    assert len(list(d.glob("hardening-audit-*.json"))) == 5   # no orphaned json
    # every surviving txt has its json, and vice-versa
    stems_txt = {p.stem for p in d.glob("hardening-audit-*.txt")}
    stems_json = {p.stem for p in d.glob("hardening-audit-*.json")}
    assert stems_txt == stems_json


def test_same_second_writes_pair_txt_and_json(tmp_path):
    a = reports.write_report("aur-audit", "one", _ctx(tmp_path), now=_at())
    b = reports.write_report("aur-audit", "two", _ctx(tmp_path), now=_at())
    assert a != b
    assert a.with_suffix(".json").exists() and b.with_suffix(".json").exists()
    assert _json_of(a)["data"]["text"] == "one"
    assert _json_of(b)["data"]["text"] == "two"


# -- run-log JSON ------------------------------------------------------------
def test_log_json_envelope(tmp_path):
    from fettle import runlog
    d = tmp_path / ".fettle/logs/local"
    d.mkdir(parents=True)
    txt = d / "run-20260721-064530.txt"
    txt.write_text("scanning...\n✓ done\n")
    runlog._write_log_json(txt, _ctx(tmp_path), host="local",
                           argv=["-H"], exit_code=0)
    env = json.loads((d / "run-20260721-064530.json").read_text())
    assert env["schema"] == "fettle.log/1" and env["tool"] == "run"
    assert env["host"] == "local" and env["timestamp"] == "20260721-064530"
    assert env["argv"] == ["-H"] and env["exit_code"] == 0
    assert "done" in env["transcript"]
    assert oct(os.stat(d / "run-20260721-064530.json").st_mode & 0o777) == "0o600"
