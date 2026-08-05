"""`fettle upgrade-check` command wiring (UC4) — all API calls mocked."""

from unittest.mock import patch

from fettle.ai.snapshot import Snapshot
from fettle.ai.upgrade_check import Result
from fettle.cli import main as cli_main


class _Backend:
    def __init__(self, pending):
        self._pending = pending

    def pending_upgrades(self, ctx):
        return self._pending


def _snap():
    return Snapshot("Manjaro", "6.12", "sys", [("linux", "6.12", "6.18")])


def test_up_to_date(capsys):
    with patch("fettle.cli.detect", return_value=_Backend([])):
        rc = cli_main(["upgrade-check", "--no-config"])
    assert rc == 0
    assert "up to date" in capsys.readouterr().out


def test_snapshot_json_round_trip():
    snap = Snapshot("Arch", "6.14", "inxi text", [("linux", "6.13", "6.14"),
                                                  ("mesa", "1", "2")])
    back = Snapshot.from_json(snap.to_json())
    assert back.distro == "Arch" and back.kernel == "6.14" and back.inxi == "inxi text"
    assert back.pending == [("linux", "6.13", "6.14"), ("mesa", "1", "2")]  # tuples


def test_collect_emits_only_json_no_api_call(capsys):
    with patch("fettle.cli.detect", return_value=_Backend([("linux", "6.12", "6.18")])), \
         patch("fettle.ai.snapshot.gather", return_value=_snap()), \
         patch("fettle.ai.upgrade_check.analyze") as analyze:
        rc = cli_main(["upgrade-check", "--collect", "--no-config"])
    out = capsys.readouterr().out
    assert rc == 0
    analyze.assert_not_called()               # collection never contacts the API
    parsed = Snapshot.from_json(out)          # stdout is exactly one JSON object
    assert parsed.distro == "Manjaro"
    assert parsed.pending == [("linux", "6.12", "6.18")]


def test_no_key_shows_package_list(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with patch("fettle.cli.detect", return_value=_Backend([("linux", "6.12", "6.18")])), \
         patch("fettle.ai.snapshot.gather", return_value=_snap()):
        rc = cli_main(["upgrade-check", "--no-config"])
    cap = capsys.readouterr()
    # The check did NOT run. It used to exit 0 with no summary, so "no key" was
    # indistinguishable from a clean verdict to anything downstream.
    assert rc == 1
    assert "no API key" in cap.err
    assert "linux  6.12 -> 6.18" in cap.out
    assert "did NOT run" in cap.out + cap.err


def test_happy_path_renders_and_saves(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    result = Result(
        safety_verdict="caution", failure_likelihood="medium",
        summary="Kernel bump.", must_do_before=["snapshot /"],
        should_do_after=["reboot"], watch_items=[{"package": "linux", "concern": "kernel"}],
        recommendation="proceed-with-care",
        sources=[{"title": "t", "url": "https://forum.manjaro.org/x"}],
        usage={"input_tokens": 1000, "output_tokens": 200, "web_searches": 2})
    with patch("fettle.cli.detect", return_value=_Backend([("linux", "6.12", "6.18")])), \
         patch("fettle.ai.snapshot.gather", return_value=_snap()), \
         patch("fettle.ai.upgrade_check.analyze", return_value=result):
        rc = cli_main(["upgrade-check", "--no-config"])
    cap = capsys.readouterr()
    out = cap.out + cap.err
    assert rc == 0
    assert "Verdict: CAUTION" in out
    assert "snapshot /" in out and "reboot" in out
    assert "linux: kernel" in out
    assert "forum.manjaro.org" in out
    assert "web search(es)" in out
    d = tmp_path / ".fettle/reports/local"
    saved = list(d.glob("upgrade-check-*.txt"))[0].read_text()
    assert "Verdict: CAUTION" in saved and "Recommendation: proceed-with-care" in saved
    import json
    data = json.loads(list(d.glob("upgrade-check-*.json"))[0].read_text())["data"]
    assert data["safety_verdict"] == "caution"       # Result serialized to JSON
    assert data["recommendation"] == "proceed-with-care"


def test_analysis_unavailable_falls_back(capsys, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with patch("fettle.cli.detect", return_value=_Backend([("linux", "6.12", "6.18")])), \
         patch("fettle.ai.snapshot.gather", return_value=_snap()), \
         patch("fettle.ai.upgrade_check.analyze", return_value=None):
        rc = cli_main(["upgrade-check", "--no-config"])
    cap = capsys.readouterr()
    assert rc == 1                      # could not run != a clean bill of health
    assert "unavailable" in cap.err and "linux  6.12 -> 6.18" in cap.out
    assert "were NOT assessed" in cap.out + cap.err


# -- the verdict reaches the digest, and only a broken check fails the run ---
def _verdict_run(capsys, monkeypatch, verdict):
    from fettle.ai.upgrade_check import Result
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    res = Result(safety_verdict=verdict, failure_likelihood="low", summary="s",
                 must_do_before=["pacman -Syu --ignore linux"], recommendation="proceed")
    with patch("fettle.cli.detect", return_value=_Backend([("linux", "6.12", "6.18")])), \
         patch("fettle.ai.snapshot.gather", return_value=_snap()), \
         patch("fettle.ai.upgrade_check.analyze", return_value=res), \
         patch("fettle.reports.write_report", return_value="/dev/null"):
        rc = cli_main(["upgrade-check", "--no-config"])
    cap = capsys.readouterr()
    return rc, cap.out + cap.err


def test_safe_verdict_reaches_the_summary(capsys, monkeypatch):
    rc, text = _verdict_run(capsys, monkeypatch, "safe")
    assert rc == 0
    assert "upgrade check: SAFE" in text


def test_risky_verdict_warns_but_does_not_fail_the_run(capsys, monkeypatch):
    """It is the model's opinion about an upgrade, not fettle being unable to do its
    job — and a check you asked for and got an answer from has not failed."""
    rc, text = _verdict_run(capsys, monkeypatch, "risky")
    assert rc == 0
    assert "upgrade check: RISKY" in text


def test_model_authored_commands_are_attributed(capsys, monkeypatch):
    """The system prompt asks the model for concrete commands, and web search feeds it
    forum posts anyone can write. Those lines rendered like fettle's own advice."""
    _rc, text = _verdict_run(capsys, monkeypatch, "caution")
    assert "suggested by the model — verify before running" in text
    assert "pacman -Syu --ignore linux" in text
