"""Behavior checks for adjacent failures found during maintenance."""

import asyncio
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from fettle import cli, reports, runlog
from fettle.config import Config
from fettle.web.guard import LocalOriginGuard
from fettle.web import runner


@pytest.mark.parametrize("kind", ["http", "websocket"])
@pytest.mark.parametrize("host,origin,allowed", [
    ("localhost", "http://localhost", True),
    ("[::1]:8080", "http://[::1]:8080", True),
    ("127.0.0.1:8080", "http://127.0.0.1:8080", True),
    ("127.0.0.1:8080", "http://evil.example", False),
    ("127.0.0.1:8080", "http://127.0.0.1:9000", False),
    ("evil.example", "http://evil.example", False),
    ("localhost", "null", False),
    ("localhost", "http://[bad", False),
    ("", "http://localhost", False),
])
def test_guard_checks_host_and_origin_before_app(kind, host, origin, allowed):
    calls, sent = [], []

    async def app(scope, receive, send):
        calls.append(scope)

    async def send(event):
        sent.append(event)

    scope = {"type": kind, "scheme": "http",
             "headers": [(b"host", host.encode()), (b"origin", origin.encode())]}
    asyncio.run(LocalOriginGuard(app)(scope, None, send))
    assert bool(calls) is allowed
    if not allowed:
        assert sent[0].get("status", sent[0].get("code")) in (403, 1008)


def test_guard_rejects_websocket_without_origin():
    async def app(*args):
        pytest.fail("untrusted handshake reached the app")

    async def send(event):
        assert event == {"type": "websocket.close", "code": 1008}

    asyncio.run(LocalOriginGuard(app)({"type": "websocket", "scheme": "ws",
                                     "headers": [(b"host", b"localhost")]}, None, send))


@pytest.mark.parametrize("code", [0, 3])
def test_main_records_actual_noninteractive_exit(monkeypatch, code):
    seen = []
    monkeypatch.setattr(runlog, "maybe_record", lambda argv: None)
    monkeypatch.setattr(runlog, "start_nontty_log", lambda argv:
                        SimpleNamespace(close=lambda **kw: seen.append(kw["exit_code"])))
    monkeypatch.setattr(cli, "_main", lambda argv: code)
    assert cli.main(["-d"]) == code
    assert seen == [code]


def test_simultaneous_report_writers_keep_distinct_complete_pairs(tmp_path):
    ctx = SimpleNamespace(user_home=tmp_path, config=Config(reports={"keep": 30}), sudo_user=None)
    import datetime
    now = datetime.datetime(2026, 10, 2)

    def write(i):
        return reports.write_report("probe", str(i), ctx, now=now, data={"i": i})

    with ThreadPoolExecutor(max_workers=6) as pool:
        paths = list(pool.map(write, range(25)))
    assert len(set(paths)) == 25
    for path in paths:
        assert json.loads(path.with_suffix(".json").read_text())["data"]["i"] == int(path.read_text())
        assert path.stat().st_mode & 0o777 == 0o600


def test_report_storage_refuses_symlinked_host_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / ".fettle/reports"
    target.mkdir(parents=True)
    (target / "local").symlink_to(outside, target_is_directory=True)
    ctx = SimpleNamespace(user_home=tmp_path, config=Config(), sudo_user=None)
    with pytest.raises(OSError, match="symlink"):
        reports.write_report("probe", "private", ctx)
    assert not list(outside.iterdir())


def test_runner_refuses_overlapping_runs_and_cleans_up_after_cancel(tmp_path):
    async def scenario():
        ready = asyncio.Event()
        marker = tmp_path / "survived"
        # A harmless child would publish a marker if left running after cancellation.
        child = "import time,pathlib;time.sleep(1);pathlib.Path(%r).touch()" % str(marker)
        script = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);print('ready',flush=True);time.sleep(20)" % child
        task = asyncio.create_task(runner.run_action([], lambda line: ready.set(),
                                                     cmd=[sys.executable, "-c", script]))
        await asyncio.wait_for(ready.wait(), 3)
        with pytest.raises(RuntimeError, match="already running"):
            await runner.run_action([], print, cmd=[sys.executable, "-c", "print('bad')"])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(1.1)
        assert not marker.exists()
        assert await runner.run_action([], lambda line: None,
                                       cmd=[sys.executable, "-c", "print('ok')"]) == 0

    asyncio.run(scenario())
