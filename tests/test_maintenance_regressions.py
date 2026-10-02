"""Observable regressions from the October maintenance review."""

import datetime as dt
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fettle import actions, htmlreport, reports
from fettle.backends.arch import ArchBackend
from fettle.backends.base import Context, Result
from fettle.backends.debian import DebianBackend
from fettle.command import Proc
from fettle.config import Config, load
from fettle.output import BLIND, FAILED, FOUND, Output


@pytest.mark.parametrize("action", ["rebuild_check", "firmware_check"])
def test_missing_check_tool_is_not_a_clean_summary(action, tmp_path, capsys):
    ctx = Context(Output(color=False), Config(), root=tmp_path, dry_run=True)
    with patch("fettle.command.which", return_value=False):
        actions.run([action], ArchBackend(), ctx)
    assert ctx.output.failures_of(BLIND)
    assert "nothing to report" not in capsys.readouterr().out


def test_failed_backend_result_sets_failure_even_after_a_warning(monkeypatch, capsys):
    ctx = Context(Output(color=False), Config())

    def handler(backend, ctx):
        ctx.output.summary_warn("partial result")
        return Result(ok=False, summary="query failed")

    monkeypatch.setitem(actions.HANDLERS, "rebuild_check", handler)
    actions.run(["rebuild_check"], None, ctx)
    assert ctx.output.failures_of(FAILED)
    assert "query failed" in capsys.readouterr().out


def test_backend_failure_does_not_duplicate_a_recorded_finding(monkeypatch):
    ctx = Context(Output(color=False), Config())

    def handler(backend, ctx):
        ctx.output.summary_fail("existing finding", kind=FOUND)
        return Result(ok=False)

    monkeypatch.setitem(actions.HANDLERS, "rebuild_check", handler)
    actions.run(["rebuild_check"], None, ctx)
    assert len(ctx.output.failures_of(FAILED, BLIND, FOUND)) == 1
    assert not ctx.output.failures_of(FAILED)


@pytest.mark.parametrize("backend", [DebianBackend, ArchBackend])
def test_failed_resolver_cannot_report_an_empty_success(backend):
    ctx = Context(Output(color=False), Config())
    with patch("fettle.command.which", return_value=True), \
         patch("fettle.command.run", return_value=Proc(2, "", "resolver failed")):
        tx = backend().pending_transaction(ctx, sync=False)
    assert not tx.ok and not tx.items
    assert any("failed" in note for note in tx.notes)


@pytest.mark.parametrize("value", ['"update"', "123", "true", '["update", 12]'])
def test_bad_action_list_defaults_without_discarding_valid_settings(tmp_path, value):
    path = tmp_path / "config.toml"
    path.write_text(f"auto_rebuild = true\ndefault_actions = {value}\n")
    cfg, warnings = load(path)
    assert cfg.auto_rebuild is True
    assert cfg.default_actions == Config().default_actions
    assert any("default_actions" in warning for warning in warnings)


def test_bad_nested_settings_keep_valid_siblings_and_do_not_leak_values(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('auto_rebuild = true\n[reports]\nkeep = "private-value"\njson = false\n'
                    '[updaters]\narch = "not-a-table"\n')
    cfg, warnings = load(path)
    assert cfg.auto_rebuild is True and cfg.reports["json"] is False
    assert "keep" not in cfg.reports and "arch" not in cfg.updaters
    assert any("reports.keep" in warning for warning in warnings)
    assert any("updaters.arch" in warning for warning in warnings)
    assert all("private-value" not in warning for warning in warnings)


@pytest.mark.parametrize("keep", [1, 10])
def test_same_second_retention_keeps_the_last_report_and_its_json(tmp_path, keep):
    ctx = SimpleNamespace(user_home=tmp_path, sudo_user=None,
                          config=Config(reports={"keep": keep}))
    now = dt.datetime(2026, 10, 1, 12, 0)
    for i in range(13):
        last = reports.write_report("probe", f"run {i}", ctx, now=now, data={"run": i})
        assert last.exists(), "writing a report must not prune the report just written"
    files = list(last.parent.glob("probe-*.txt"))
    assert len(files) == keep
    assert last.read_text().strip() == "run 12"
    assert json.loads(last.with_suffix(".json").read_text())["data"] == {"run": 12}


@pytest.mark.parametrize("payload", [[], None, "wrong", 1,
                                     {"timestamp": [], "tool": {}}, {"data": []}])
def test_malformed_envelopes_do_not_break_collection(tmp_path, payload):
    path = tmp_path / "probe-20261001-120000.json"
    path.write_text(json.dumps(payload))
    entries = htmlreport._host_entries(tmp_path)
    assert entries == []
