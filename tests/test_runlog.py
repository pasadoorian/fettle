"""RP3: run-logger — ANSI cleaning, config gating, guards, non-tty tee, host tag."""

import io
import os
from types import SimpleNamespace
from unittest.mock import patch

from fettle import runlog
from fettle.config import Config


# -- ANSI / CR cleaning ------------------------------------------------------
def test_clean_strips_colour_and_cursor_codes():
    raw = b"\x1b[32m\xe2\x9c\x93\x1b[0m done\x1b[1;31m!\x1b[0m"
    assert runlog.clean(raw) == b"\xe2\x9c\x93 done!"


def test_clean_collapses_carriage_return_progress():
    # a progress bar redraw: "10%\r50%\r100%\n" -> keep only the final text
    assert runlog.clean(b"10%\r50%\r100%\n") == b"10%50%100%\n"
    assert runlog.clean(b"line\r\nnext\r\n") == b"line\nnext\n"


def test_clean_strips_osc_title_sequences():
    assert runlog.clean(b"\x1b]0;my title\x07hello") == b"hello"


# -- enabled gate ------------------------------------------------------------
def test_enabled_defaults_true_and_respects_config():
    assert runlog._enabled(Config()) is True                 # no [reports] -> on
    cfg = Config()
    cfg.reports = {"log": False}
    assert runlog._enabled(cfg) is False
    cfg.reports = {"log": "off"}
    assert runlog._enabled(cfg) is False
    cfg.reports = {"log": "true"}
    assert runlog._enabled(cfg) is True
    cfg.reports = "garbage"
    assert runlog._enabled(cfg) is True                      # malformed -> on


# -- host tag from argv ------------------------------------------------------
def test_log_host_local_by_default():
    assert runlog.log_host(["-a"]) == "local"
    assert runlog.log_host([]) == "local"


def test_log_host_reads_remote_target():
    assert runlog.log_host(["remote", "web-01", "-a"]) == "web-01"
    # skips --ssh-arg / -J value pairs before the host
    assert runlog.log_host(["remote", "--ssh-arg", "-p2222", "-J", "jump", "foo", "-H"]) == "foo"


# -- guards: record/tee must no-op in tests & when guarded -------------------
def test_maybe_record_noops_in_test_env():
    # conftest sets FETTLE_TEST=1 -> _skip() true regardless of tty
    with patch("sys.stdin") as si, patch("sys.stdout") as so:
        si.isatty.return_value = True
        so.isatty.return_value = True
        assert runlog.maybe_record(["-a"]) is None


def test_maybe_record_noops_when_not_a_tty(monkeypatch):
    monkeypatch.delenv("FETTLE_TEST", raising=False)   # even outside test mode…
    with patch("sys.stdin") as si, patch("sys.stdout") as so:
        si.isatty.return_value = False                 # …a pipe never records
        so.isatty.return_value = True
        assert runlog.maybe_record(["-a"]) is None
    monkeypatch.setenv("FETTLE_TEST", "1")


def test_start_nontty_log_noops_in_test_env():
    assert runlog.start_nontty_log(["-a"]) is None     # FETTLE_TEST guard


def test_is_active_reflects_guard(monkeypatch):
    monkeypatch.setenv(runlog.GUARD, "1")
    assert runlog.is_active() is True
    monkeypatch.delenv(runlog.GUARD)
    assert runlog.is_active() is False


# -- non-tty tee actually writes an ANSI-stripped log ------------------------
def test_nontty_log_tees_and_finalizes(tmp_path, monkeypatch):
    monkeypatch.delenv("FETTLE_TEST", raising=False)
    cfg = Config()
    ctxlike = SimpleNamespace(user_home=tmp_path, sudo_user=None, config=cfg)
    path, directory = runlog._new_log(ctxlike, "local")
    log = runlog._NonTtyLog(path, directory, ctxlike)
    try:
        print("\x1b[32mhello\x1b[0m world")            # coloured -> stripped in file
    finally:
        log.close()
    monkeypatch.setenv("FETTLE_TEST", "1")
    assert path.read_text().strip().endswith("hello world")
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_tee_passes_writes_through_and_logs():
    sink = io.StringIO()
    logf = io.BytesIO()
    tee = runlog._Tee(sink, logf)
    tee.write("\x1b[1mbold\x1b[0m\n")
    assert sink.getvalue() == "\x1b[1mbold\x1b[0m\n"    # terminal keeps colour
    assert logf.getvalue() == b"bold\n"                 # file is clean
