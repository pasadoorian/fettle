"""Upgrade Checker request build, JSON extraction, and the hallucination guard."""

import json
from unittest.mock import patch

from fettle.ai import upgrade_check as uc
from fettle.ai.snapshot import Snapshot
from fettle.config import Config


def _snap():
    return Snapshot(distro="Manjaro", kernel="6.12", inxi="System: ...",
                    pending=[("linux", "6.12", "6.18"), ("nvidia", "550", "560")])


def test_build_payload_shape():
    p = uc.build_payload(_snap(), model="claude-sonnet-5", effort="medium",
                         allow_web=True, max_uses=5)
    assert p["model"] == "claude-sonnet-5"
    assert p["output_config"]["effort"] == "medium"
    assert p["thinking"] == {"type": "adaptive"}
    tool = p["tools"][0]
    assert tool["type"] == "web_search_20260209" and tool["max_uses"] == 5
    assert "bbs.archlinux.org" in tool["allowed_domains"]
    assert "linux  6.12 -> 6.18" in p["messages"][0]["content"]


def test_build_payload_no_web():
    p = uc.build_payload(_snap(), model="m", effort="low", allow_web=False, max_uses=5)
    assert "tools" not in p


def test_extract_json_from_text_and_fence():
    assert uc._extract_json({"content": [{"type": "text", "text": '{"a": 1}'}]}) == {"a": 1}
    fenced = {"content": [{"type": "text", "text": 'Here:\n```json\n{"a": 2}\n```'}]}
    assert uc._extract_json(fenced) == {"a": 2}
    assert uc._extract_json({"content": [{"type": "text", "text": "no json"}]}) is None


def test_validate_drops_hallucinated_packages_and_bad_sources():
    data = {
        "safety_verdict": "caution", "failure_likelihood": "medium", "summary": "s",
        "watch_items": [
            {"package": "linux", "concern": "kernel bump"},      # real
            {"package": "made-up-pkg", "concern": "invented"},   # NOT in pending
        ],
        "sources": [
            {"title": "ok", "url": "https://bbs.archlinux.org/x"},   # allowed
            {"title": "bad", "url": "https://randomblog.example/x"},  # off-domain
        ],
    }
    r = uc._validate(data, _snap())
    assert [w["package"] for w in r.watch_items] == ["linux"]
    assert r.dropped_watch_items == 1
    assert len(r.sources) == 1 and "archlinux.org" in r.sources[0]["url"]


def test_validate_normalizes_bad_enums():
    r = uc._validate({"safety_verdict": "banana", "failure_likelihood": "???"}, _snap())
    assert r.safety_verdict == "caution" and r.failure_likelihood == "medium"


def test_analyze_happy_path(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    result_json = json.dumps({
        "safety_verdict": "caution", "failure_likelihood": "medium",
        "summary": "Kernel and driver both bump.",
        "must_do_before": ["snapshot /"], "should_do_after": ["reboot"],
        "watch_items": [{"package": "nvidia", "concern": "rebuild DKMS"}],
        "recommendation": "proceed-with-care",
        "sources": [{"title": "t", "url": "https://forum.manjaro.org/x"}],
    })
    fake_msg = {"stop_reason": "end_turn",
                "content": [{"type": "text", "text": result_json}],
                "usage": {"input_tokens": 1200, "output_tokens": 300}}
    with patch("fettle.ai.upgrade_check.client.messages", return_value=(fake_msg, 3)):
        r = uc.analyze(_snap(), config=Config())
    assert r.safety_verdict == "caution"
    assert r.watch_items[0]["package"] == "nvidia"
    assert r.usage == {"input_tokens": 1200, "output_tokens": 300, "web_searches": 3}


def test_analyze_no_key_returns_none(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert uc.analyze(_snap(), config=Config()) is None


def test_analyze_refusal_returns_none(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with patch("fettle.ai.upgrade_check.client.messages",
               return_value=({"stop_reason": "refusal", "content": []}, 0)):
        assert uc.analyze(_snap(), config=Config()) is None
