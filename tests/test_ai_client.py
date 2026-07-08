"""urllib Anthropic client (UC3) — auth, key redaction, pause_turn loop."""

from fettle.ai import client
from fettle.config import Config


def test_redact_key_shows_last4_only():
    assert client.redact_key("sk-ant-api03-ABCDwxyz") == "sk-ant-…wxyz"
    assert client.redact_key("") == "(unset)"
    assert client.redact_key(None) == "(unset)"


def test_resolve_auth_env_wins(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env")
    assert client.resolve_auth(Config(ai_api_key="sk-cfg")) == ("env", "sk-env")


def test_resolve_auth_config_fallback(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert client.resolve_auth(Config(ai_api_key="sk-cfg")) == ("config", "sk-cfg")


def test_resolve_auth_none(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert client.resolve_auth(Config()) is None


def test_messages_continues_through_pause_turn():
    turns = [
        {"stop_reason": "pause_turn",
         "content": [{"type": "web_search_tool_result"}]},
        {"stop_reason": "end_turn",
         "content": [{"type": "web_search_tool_result"},
                     {"type": "text", "text": "{}"}]},
    ]
    calls = []

    def runner(body, api_key, *, timeout):
        calls.append(body["messages"])
        return turns.pop(0)

    msg, searches = client.messages(
        {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
        api_key="k", runner=runner)
    assert msg["stop_reason"] == "end_turn"
    assert searches == 2                       # counted across both turns
    assert len(calls) == 2                     # re-POSTed after pause_turn
    assert calls[1][-1]["role"] == "assistant"  # prior turn appended


def test_messages_returns_none_on_failure():
    msg, searches = client.messages(
        {"model": "m", "messages": []}, api_key="k",
        runner=lambda body, key, *, timeout: None)
    assert msg is None and searches == 0


def test_debug_diag_explains_exhausted_continuations(capsys):
    client.set_debug(True)
    try:
        msg, _ = client.messages(
            {"model": "m", "messages": [{"role": "user", "content": "hi"}]},
            api_key="k", max_continuations=1,
            runner=lambda body, key, *, timeout: {
                "stop_reason": "pause_turn",
                "content": [{"type": "web_search_tool_result"}]})
    finally:
        client.set_debug(False)
    assert msg["stop_reason"] == "pause_turn"      # never finished
    assert "exhausted" in capsys.readouterr().err  # and said so
