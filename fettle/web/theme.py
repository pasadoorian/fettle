"""Reuse the HTML report's terminal styling in the web UI (pure stdlib)."""

from __future__ import annotations

from .. import htmlreport


def head_html() -> str:
    """The ``<style>`` block for the dark terminal look, reused verbatim from the
    ``fettle report`` dashboard so the web UI matches it."""
    return f"<style>{htmlreport._STYLE}</style>"
