"""AUR RPC v5 client — replaces ``aur_query_rpc`` (curl) + the ``jq`` parsing.

Pure stdlib (urllib + json). POSTs the package list so a large set doesn't blow
the URL-length limit, and degrades to ``[]`` on any network/parse failure so
callers never mistake "offline" for "all clear".
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

RPC_URL = "https://aur.archlinux.org/rpc/v5/info"


def query_info(packages, *, timeout: float = 30.0) -> list[dict]:
    """Return the AUR RPC ``results`` list for ``packages`` (``[]`` on failure)."""
    pkgs = [p for p in packages if p]
    if not pkgs:
        return []
    data = urllib.parse.urlencode([("arg[]", p) for p in pkgs]).encode()
    req = urllib.request.Request(RPC_URL, data=data, headers={"User-Agent": "fettle"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https URL)
            payload = json.load(resp)
    except (OSError, ValueError):
        return []
    results = payload.get("results")
    return results if isinstance(results, list) else []
