"""Read model for the web UI — the same JSON reports/logs the HTML dashboard uses.

Pure stdlib and read-only (no nicegui, no subprocess): a thin adapter over
``htmlreport`` / ``reports`` so pages call functions instead of globbing, and so the
web UI serves the *same* live-generated dashboard the ``fettle report`` command
writes to disk.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from .. import htmlreport, reports
from ..config import Config
from ..config import load as _load_config


def _config():
    """The user's real config (for `[reports] dir` + remote group names), or
    defaults. Never hard-fails — config.load already degrades to defaults."""
    try:
        from ..cli import DEFAULT_CONFIG
        cfg, _ = _load_config(DEFAULT_CONFIG)
        return cfg
    except Exception:
        return Config()


def _ctxlike(user_home=None, config=None):
    return SimpleNamespace(
        user_home=user_home or Path.home(), sudo_user=None,
        config=config if config is not None else _config())


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


def run_history(base=None, *, limit: int = 100, **kw) -> list[dict]:
    """Every stored run-log across all hosts, newest first (capped at ``limit``).
    Each item: ``{host, timestamp, argv, exit_code, transcript}`` from the
    ``fettle.log/1`` envelopes the CLI already writes (incl. web-triggered runs)."""
    tree = collect(base, **kw)
    rows: list[dict] = []
    for host, groups in tree.items():
        for e in groups.get("logs", []):
            payload = e.get("data") if isinstance(e.get("data"), dict) else {}
            rows.append({
                "host": host,
                "timestamp": e.get("timestamp", ""),
                "argv": e.get("argv"),
                "exit_code": e.get("exit_code"),
                "transcript": (e.get("transcript") or payload.get("transcript")
                               or payload.get("text") or ""),
            })
    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows[:limit]


def remote_groups(config=None) -> dict[str, list[str]]:
    """Configured ``[remote.groups.<name>]`` as ``{name: [hosts...]}`` (empty if
    none). Read-only view for the UI to list what `fettle remote <group>` targets."""
    from .. import remote
    groups = remote.remote_groups(config if config is not None else _config())
    return {name: list(g.hosts) for name, g in groups.items()}


def report_html(base=None, *, user_home=None, config=None, now=None) -> str:
    """The full dashboard HTML, live-generated from current data (no disk write) —
    identical to ``fettle report``'s output, so the web UI mirrors it exactly."""
    ctx = _ctxlike(user_home, config)
    tree = Path(base) if base is not None else None
    return htmlreport.render_page(ctx, base=tree, now=now)
