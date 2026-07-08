"""Minimal Anthropic ``/v1/messages`` client over ``urllib`` — no SDK dependency.

Keeps fettle zero-dep: handles auth, the POST, server-tool ``pause_turn``
continuation, and light retry by hand. Returns the final message dict, or
``None`` on any failure so the Upgrade Checker can degrade to a plain package
diff when the model is unavailable/unauthorized/offline. Non-streaming with a
generous timeout (a single bounded request, not a UI) — simpler and robust.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"

# When on, the client explains *why* a request failed (HTTP status + error body,
# network error, or an exhausted pause_turn loop) on stderr. The CLI flips it via
# `upgrade-check --verbose`; kept off the runner signature so test runners stay
# simple. Never prints the payload or the API key.
_DEBUG = False


def set_debug(on: bool) -> None:
    global _DEBUG
    _DEBUG = on


def _diag(msg: str) -> None:
    if _DEBUG:
        print(f"  [ai] {msg}", file=sys.stderr)


def redact_key(key: str | None) -> str:
    """Display form for --print-config: a prefix + last-4 hint, never the secret."""
    if not key:
        return "(unset)"
    return f"sk-ant-…{key[-4:]}" if len(key) >= 4 else "sk-ant-…****"


def resolve_auth(config) -> tuple[str, str] | None:
    """Return ``(source, api_key)`` or ``None``. ``ANTHROPIC_API_KEY`` wins over
    the config file's ``ai_api_key`` (which sits behind fettle's config gate)."""
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return ("env", env)
    cfg_key = getattr(config, "ai_api_key", "") or ""
    if cfg_key:
        return ("config", cfg_key)
    return None


def _post(payload: dict, api_key: str, *, timeout: float) -> dict | None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(API_URL, data=data, method="POST", headers={
        "x-api-key": api_key,
        "anthropic-version": API_VERSION,
        "content-type": "application/json",
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https)
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:800]
            except OSError:
                pass
            _diag(f"HTTP {exc.code} {exc.reason}: {body}")
            if exc.code in (429, 500, 529) and attempt < 2:
                _diag(f"retrying after backoff (attempt {attempt + 2}/3)")
                time.sleep(2 ** attempt)  # backoff on rate-limit / overload
                continue
            return None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            _diag(f"request failed: {exc!r}")
            return None
    return None


def messages(payload: dict, *, api_key: str, timeout: float = 300.0,
             runner=_post, max_continuations: int = 8) -> tuple[dict | None, int]:
    """POST a Messages request, continuing through ``pause_turn`` (server tools).

    Returns ``(final_message | None, web_search_count)``. ``runner`` is injected
    for tests. The long default timeout covers adaptive thinking + web search;
    ``max_continuations`` covers many forum searches on a large upgrade set.
    """
    convo = list(payload["messages"])
    body = dict(payload)
    searches = 0
    msg = None
    for _ in range(max_continuations + 1):
        body["messages"] = convo
        msg = runner(body, api_key, timeout=timeout)
        if msg is None:
            return None, searches
        searches += sum(1 for b in msg.get("content", [])
                        if b.get("type") == "web_search_tool_result")
        if msg.get("stop_reason") == "pause_turn":
            convo = convo + [{"role": "assistant", "content": msg.get("content", [])}]
            continue
        return msg, searches
    _diag(f"exhausted {max_continuations} pause_turn continuations "
          f"({searches} web searches so far); response never finished")
    return msg, searches  # ran out of continuations — return what we have
