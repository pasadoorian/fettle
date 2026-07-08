"""Upgrade Checker — ask Claude whether a pending upgrade is safe.

Builds a grounded, token-frugal request (real package list + system facts, web
search restricted to distro forums, concise structured JSON), calls the urllib
client, then applies a **deterministic hallucination guard**: any flagged package
that isn't actually in the pending list is dropped, and off-domain sources are
removed. Returns ``None`` on any failure so the caller degrades to the plain diff.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field

from . import client

# Trusted sources the model may search / cite (grounding, not random blogs).
# NOTE: every domain here must be reachable by Anthropic's web-search crawler —
# the API 400s the whole request if `allowed_domains` names one it can't fetch.
# askubuntu.com and reddit.com block the crawler, so they're excluded (leaving
# them in was the Ubuntu-VM 400). ubuntuforums.org/ubuntu.com/launchpad.net still
# cover the Ubuntu side; the Arch/Manjaro forums cover those distros.
ALLOWED_DOMAINS = (
    "bbs.archlinux.org", "wiki.archlinux.org", "archlinux.org",
    "forum.manjaro.org", "forums.manjaro.org",
    "ubuntuforums.org", "ubuntu.com", "launchpad.net",
)

_VERDICTS = ("safe", "caution", "risky")
_LIKELIHOODS = ("low", "medium", "high")

_SCHEMA_HINT = """{
  "safety_verdict": "safe" | "caution" | "risky",
  "failure_likelihood": "low" | "medium" | "high",
  "summary": "<=2 sentence plain-language summary",
  "must_do_before": ["concrete action or command", ...],
  "should_do_after": ["concrete action or command", ...],
  "watch_items": [{"package": "<name from the pending list>", "concern": "..."}, ...],
  "recommendation": "one line: proceed / proceed-with-care / hold",
  "sources": [{"title": "...", "url": "https://..."}, ...]
}"""

_SYSTEM = (
    "You are a Linux upgrade-safety advisor. You are given the packages that WOULD "
    "be upgraded on a machine plus its hardware/software profile. Judge whether "
    "running this upgrade now is safe.\n\n"
    "Rules:\n"
    "- Ground every claim in the provided package list or a cited forum source. "
    "Search the distro's official forums (Arch BBS, Manjaro, Ubuntu Forums, "
    "Launchpad) for KNOWN issues with the specific "
    "packages/versions upgrading — prioritize kernel, GPU driver, glibc, systemd, "
    "mesa, the desktop environment, and python.\n"
    "- If you find no evidence of problems, say the upgrade looks routine. Do NOT "
    "invent risks, bugs, versions, or package names. Only reference packages that "
    "appear in the provided pending list.\n"
    "- Be specific and actionable: concrete commands/steps, not 'be careful'. Keep "
    "watch_items to genuinely high-signal packages; don't echo the whole list.\n"
    "- Cite a source URL for any specific claim.\n"
    "- Output ONLY one JSON object matching this schema, no prose:\n" + _SCHEMA_HINT
)


@dataclass
class Result:
    safety_verdict: str
    failure_likelihood: str
    summary: str
    must_do_before: list = field(default_factory=list)
    should_do_after: list = field(default_factory=list)
    watch_items: list = field(default_factory=list)
    recommendation: str = ""
    sources: list = field(default_factory=list)
    dropped_watch_items: int = 0  # hallucination-guard drops (transparency)
    usage: dict = field(default_factory=dict)


def build_payload(snapshot, *, model: str, effort: str,
                  allow_web: bool, max_uses: int) -> dict:
    payload = {
        "model": model,
        # Roomy: adaptive thinking tokens count toward the output budget, so a
        # tight cap truncates the response before the JSON verdict is emitted
        # (stop_reason "max_tokens", no parseable object). The verdict is small;
        # we only pay for tokens actually used.
        "max_tokens": 8000,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": effort},
        "system": _SYSTEM,
        "messages": [{"role": "user",
                      "content": snapshot.as_prompt() + "\n\nAssess this upgrade."}],
    }
    if allow_web:
        payload["tools"] = [{
            "type": "web_search_20260209", "name": "web_search",
            "max_uses": max_uses, "allowed_domains": list(ALLOWED_DOMAINS),
        }]
    return payload


def _extract_json(msg: dict) -> dict | None:
    text = "".join(b.get("text", "") for b in msg.get("content", [])
                   if b.get("type") == "text").strip()
    if not text:
        return None
    for candidate in (text, text[text.find("{"):text.rfind("}") + 1]):
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except ValueError:
            continue
    return None


def _domain_ok(url: str) -> bool:
    host = urllib.parse.urlparse(url).netloc.lower()
    return any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def _validate(data: dict, snapshot) -> Result:
    pending = {n.lower() for n, _o, _new in snapshot.pending}
    kept, dropped = [], 0
    for item in data.get("watch_items") or []:
        pkg = str(item.get("package", "")).lower()
        # A hallucination guard: the model can only warn about packages that are
        # actually upgrading. Drop anything not in the real pending set.
        if pending and pkg not in pending:
            dropped += 1
            continue
        kept.append(item)
    sources = [s for s in (data.get("sources") or [])
               if isinstance(s, dict) and _domain_ok(str(s.get("url", "")))]
    verdict = data.get("safety_verdict")
    likelihood = data.get("failure_likelihood")
    return Result(
        safety_verdict=verdict if verdict in _VERDICTS else "caution",
        failure_likelihood=likelihood if likelihood in _LIKELIHOODS else "medium",
        summary=str(data.get("summary", "")).strip(),
        must_do_before=list(data.get("must_do_before") or []),
        should_do_after=list(data.get("should_do_after") or []),
        watch_items=kept,
        recommendation=str(data.get("recommendation", "")).strip(),
        sources=sources,
        dropped_watch_items=dropped,
    )


def format_report(result: "Result") -> str:
    """Full plain-text report (for the screen body and ~/upgrade-check.txt)."""
    lines = [f"Verdict: {result.safety_verdict.upper()}  "
             f"(failure likelihood: {result.failure_likelihood})"]
    if result.summary:
        lines += ["", result.summary]
    if result.must_do_before:
        lines += ["", "Before upgrading:"] + [f"  - {s}" for s in result.must_do_before]
    if result.should_do_after:
        lines += ["", "After upgrading:"] + [f"  - {s}" for s in result.should_do_after]
    if result.watch_items:
        lines += ["", "Watch:"] + [f"  - {w.get('package')}: {w.get('concern')}"
                                   for w in result.watch_items]
    if result.recommendation:
        lines += ["", f"Recommendation: {result.recommendation}"]
    if result.sources:
        lines += ["", "Sources:"] + [f"  - {s.get('title', '')}: {s.get('url', '')}"
                                     for s in result.sources]
    if result.dropped_watch_items:
        lines += ["", f"({result.dropped_watch_items} model-flagged item(s) dropped: "
                  "not in the actual upgrade set)"]
    return "\n".join(lines)


def analyze(snapshot, *, config, allow_web: bool = True) -> Result | None:
    """Run the check. Returns ``None`` if unauthenticated, refused, or on any
    failure — the caller then falls back to showing the plain package diff."""
    auth = client.resolve_auth(config)
    if auth is None:
        return None
    _, api_key = auth
    payload = build_payload(
        snapshot,
        model=getattr(config, "ai_model", "claude-sonnet-5"),
        effort=getattr(config, "ai_effort", "medium"),
        allow_web=allow_web,
        max_uses=getattr(config, "ai_max_web_searches", 5),
    )
    msg, searches = client.messages(payload, api_key=api_key)
    if msg is None:
        return None  # client._diag already explained the HTTP/network failure
    stop = msg.get("stop_reason")
    if stop == "refusal":
        client._diag("model declined the request (stop_reason=refusal)")
        return None
    data = _extract_json(msg)
    if data is None:
        hint = ("response hit max_tokens before finishing — raise max_tokens"
                if stop == "max_tokens" else
                "response was still mid-turn (web search not finished)"
                if stop == "pause_turn" else
                f"no JSON verdict in the reply (stop_reason={stop})")
        client._diag(hint)
        return None
    result = _validate(data, snapshot)
    usage = msg.get("usage") or {}
    result.usage = {"input_tokens": usage.get("input_tokens", 0),
                    "output_tokens": usage.get("output_tokens", 0),
                    "web_searches": searches}
    return result
