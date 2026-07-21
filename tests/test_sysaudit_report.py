"""sys-audit now persists a structured report (Scan accumulation + HTML render)."""

import json
from types import SimpleNamespace

from fettle import htmlreport
from fettle.output import Output
from fettle.secure.base import Scan


def _scan():
    return Scan(output=Output(color=False))


# -- Scan accumulates structured records + text ------------------------------
def test_scan_records_status_by_category():
    s = _scan()
    s.section("Secure Boot")
    s.sub("mokutil")
    s.status("Secure Boot", "Disabled", "warn")
    s.status("Setup Mode", "No", "ok")
    s.section("TPM")
    s.status("TPM 2.0", "Present", "ok")

    assert len(s.records) == 3
    assert s.records[0] == {"category": "Secure Boot", "sub": "mokutil",
                            "label": "Secure Boot", "value": "Disabled", "level": "warn"}
    assert "Secure Boot: Disabled" in s.report_text()


def test_report_data_groups_by_category_with_counts():
    s = _scan()
    s.section("Secure Boot")
    s.status("A", "x", "warn")
    s.status("B", "y", "ok")
    s.section("TPM")
    s.status("C", "z", "error")
    data = s.report_data()
    assert [c["name"] for c in data["categories"]] == ["Secure Boot", "TPM"]
    sb = data["categories"][0]
    assert len(sb["items"]) == 2 and sb["items"][0]["label"] == "A"
    assert data["level_counts"] == {"error": 1, "warn": 1, "ok": 1, "info": 0}
    json.dumps(data)                       # serializable


# -- HTML rendering ----------------------------------------------------------
def _write(base, host, tool, ts, data):
    d = base / ".fettle/reports" / host
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{tool}-{ts}.json").write_text(json.dumps(
        {"schema": "fettle.report/1", "tool": tool, "host": host,
         "timestamp": ts, "data": data}))


def test_sysaudit_renders_categories_and_levels(tmp_path):
    _write(tmp_path, "local", "sys-audit", "20260721-010101", {
        "categories": [
            {"name": "Secure Boot", "items": [
                {"sub": "mokutil", "label": "Secure Boot", "value": "Disabled",
                 "level": "warn"}]},
            {"name": "TPM", "items": [
                {"sub": "", "label": "TPM 2.0", "value": "Present", "level": "ok"}]}],
        "level_counts": {"error": 0, "warn": 1, "ok": 1, "info": 0}})
    ctx = SimpleNamespace(user_home=tmp_path, sudo_user=None,
                          config=__import__("fettle.config", fromlist=["Config"]).Config())
    text = htmlreport.build(ctx).read_text()
    assert ">sys-audit (" in text                  # its own section
    assert "Secure Boot" in text and "TPM" in text
    assert "sev-WARN" in text and "v-safe" in text   # level pills
    assert "Disabled" in text and "Present" in text


def test_sysaudit_empty_is_hidden():
    assert htmlreport._is_empty({"tool": "sys-audit", "data": {"categories": []}})
    assert not htmlreport._is_empty(
        {"tool": "sys-audit", "data": {"categories": [{"name": "x", "items": []}]}})
