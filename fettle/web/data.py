"""Read model for the web UI — the same JSON reports/logs the HTML dashboard uses.

Pure stdlib and read-only (no nicegui, no subprocess): a thin adapter over
``htmlreport.collect`` / ``reports`` so pages call functions instead of globbing.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from .. import htmlreport, reports
from ..config import Config


def _ctxlike(user_home=None, config=None):
    return SimpleNamespace(user_home=user_home or Path.home(),
                           sudo_user=None, config=config or Config())


def base_dir(*, user_home=None, config=None) -> Path:
    """Where reports/logs live — ``[reports] dir`` or ``~/.fettle``."""
    return reports._settings(_ctxlike(user_home, config))[0]


def collect(base=None, **kw) -> dict:
    """``{host: {"reports": [envelope...], "logs": [envelope...]}}`` newest-first —
    the whole read model, straight from the stored JSON envelopes.

    Pass ``base`` (a path) to read a specific tree; tests pass a scratch dir so the
    real ``~/.fettle`` is never touched.
    """
    tree = Path(base) if base is not None else base_dir(**kw)
    return htmlreport.collect(tree)


def hosts(base=None, **kw) -> list[str]:
    """The hosts that have any stored reports/logs, sorted."""
    return sorted(collect(base, **kw))
