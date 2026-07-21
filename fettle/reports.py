"""Central report/log storage under ``~/.fettle/{reports,logs}/<host>/``.

Every report is timestamped (never clobbered), ``0600``, owned by the invoking
user, and rotated to keep the newest N per ``(host, type)``. ``<host>`` is
``local`` for a local run or the target hostname for a remote-driven one, so each
host keeps its own independent history.

This module owns the *file plumbing* only — callers pass a rendered text body.
Keeping generation separate from storage is deliberate: a future JSON/HTML phase
swaps what goes in the body without touching any of this.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path

from .util import chown_to_user

DEFAULT_KEEP = 5
_BASE = ".fettle"
_TS_FMT = "%Y%m%d-%H%M%S"
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
REPORT_SCHEMA = "fettle.report/1"


def _settings(ctx) -> tuple[Path, int]:
    """(base dir, keep) from ``[reports]`` config, with safe fallbacks."""
    cfg = getattr(ctx, "config", None)
    r = getattr(cfg, "reports", None)
    r = r if isinstance(r, dict) else {}
    raw_dir = r.get("dir")
    base = (Path(os.path.expanduser(str(raw_dir))) if raw_dir
            else _user_home(ctx) / _BASE)
    try:
        keep = max(1, int(r.get("keep", DEFAULT_KEEP)))  # always keep >=1 (this run)
    except (TypeError, ValueError):
        keep = DEFAULT_KEEP
    return base, keep


def _user_home(ctx) -> Path:
    return getattr(ctx, "user_home", None) or Path.home()


def host_tag(host: str | None) -> str:
    """Filesystem-safe subdir name for a host; ``local`` for a local run."""
    if not host or host == "local":
        return "local"
    # sub unsafe chars, then strip leading/trailing "_"/"." so a host like
    # "../etc" can't escape the dir and ".."/"." can't name a parent/self.
    tag = _UNSAFE.sub("_", host).strip("_.")
    if not tag or tag in (".", ".."):
        return "local"
    return tag


def _dir(ctx, kind: str, host: str) -> Path:
    """Ensure ``<base>/<kind>/<host>`` exists as 0700, owned by the user."""
    base, _ = _settings(ctx)
    target = base / kind / host_tag(host)
    sudo_user = getattr(ctx, "sudo_user", None)
    base.mkdir(parents=True, exist_ok=True)
    for level in (base, base / kind, target):
        try:
            level.mkdir(exist_ok=True)
        except OSError:
            pass
        try:
            os.chmod(level, 0o700)
        except OSError:
            pass
        chown_to_user(level, sudo_user)  # never leave a root-owned dir in ~
    return target


def reports_dir(ctx, host: str = "local") -> Path:
    return _dir(ctx, "reports", host)


def logs_dir(ctx, host: str = "local") -> Path:
    return _dir(ctx, "logs", host)


def _timestamp(now) -> str:
    return (now or _dt.datetime.now()).strftime(_TS_FMT)


def _stem(directory: Path, name: str, ts: str) -> Path:
    """`<name>-<ts>` path stem (no extension), disambiguated on the `.txt` sibling
    if two writes land in the same second. The `.txt` and `.json` share this stem
    so rotation treats them as one unit."""
    base = directory / f"{name}-{ts}"
    if not base.with_suffix(".txt").exists():
        return base
    i = 1
    while (directory / f"{name}-{ts}-{i}.txt").exists():
        i += 1
    return directory / f"{name}-{ts}-{i}"


def _json_enabled(ctx) -> bool:
    """`[reports] json` — write a JSON sibling for each report (default on)."""
    cfg = getattr(ctx, "config", None)
    r = getattr(cfg, "reports", None)
    r = r if isinstance(r, dict) else {}
    val = r.get("json", True)
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() not in ("false", "0", "no", "off")


def _secure(path: Path, ctx) -> None:
    """0600 + chown to the invoking user (the whole ~/.fettle tree is owner-only)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    chown_to_user(path, getattr(ctx, "sudo_user", None))


def envelope(name: str, host: str, ts: str, *, data=None, body: str = "") -> dict:
    """The JSON document wrapping a report: metadata + structured ``data`` (or a
    ``{"text": body}`` fallback so every file still has a machine-readable form)."""
    from . import __version__
    return {
        "schema": REPORT_SCHEMA,
        "tool": name,
        "host": host_tag(host),
        "timestamp": ts,
        "fettle_version": __version__,
        "data": data if data is not None else {"text": body},
    }


# report basenames that used to be written straight into $HOME (pre-0.11).
_LEGACY_NAMES = ("aur-audit", "aur-ioc-scan", "pkg-audit", "hardening-audit",
                 "upgrade-check", "alien-pkgs", "obsolete-pkgs")


def maybe_legacy_note(ctx) -> None:
    """Once ever, if pre-0.11 ``~/<name>.txt`` reports are lying around, tell the
    user reports moved (and leave the old files untouched). A marker under the
    base dir suppresses the note on subsequent runs."""
    out = getattr(ctx, "output", None)
    if out is None:
        return
    home = _user_home(ctx)
    try:
        legacy = [f"~/{n}.txt" for n in _LEGACY_NAMES if (home / f"{n}.txt").exists()]
        legacy += [f"~/{f.name}" for f in home.glob("upgrade-check-*.txt")]
    except OSError:
        return
    if not legacy:
        return
    base, _ = _settings(ctx)
    marker = base / ".reports-migrated"
    try:
        if marker.exists():
            return
    except OSError:
        return
    sample = legacy[0] + (f" (and {len(legacy) - 1} more)" if len(legacy) > 1 else "")
    out.note(f"reports now live under {base}/reports/<host>/ — your old "
             f"{sample} is left as-is; delete it when you're ready")
    try:
        base.mkdir(parents=True, exist_ok=True)
        os.chmod(base, 0o700)
        marker.write_text("")
        os.chmod(marker, 0o600)  # keep the whole ~/.fettle tree owner-only
        chown_to_user(base, getattr(ctx, "sudo_user", None))
        chown_to_user(marker, getattr(ctx, "sudo_user", None))
    except OSError:
        pass


def write_report(name: str, body: str, ctx, *, host: str = "local", now=None,
                 data=None) -> Path:
    """Write ``~/.fettle/reports/<host>/<name>-<ts>.txt`` (0600, chowned, rotated),
    plus a ``.json`` sibling (unless ``[reports] json = false``). ``data`` is the
    structured payload for the JSON; when omitted it falls back to the text body.
    Returns the ``.txt`` path."""
    maybe_legacy_note(ctx)
    directory = reports_dir(ctx, host)
    ts = _timestamp(now)
    stem = _stem(directory, name, ts)
    txt = stem.with_suffix(".txt")
    txt.write_text(body if body.endswith("\n") else body + "\n")
    _secure(txt, ctx)
    if _json_enabled(ctx):
        js = stem.with_suffix(".json")
        js.write_text(json.dumps(envelope(name, host, ts, data=data, body=body),
                                 indent=2) + "\n")
        _secure(js, ctx)
    _, keep = _settings(ctx)
    prune(directory, name, keep)
    return txt


def prune_known(directory: Path, keep: int) -> None:
    """Rotate every known report type in ``directory`` to the newest ``keep``.
    Used after pulling a batch of reports back from a remote host."""
    for name in _LEGACY_NAMES:
        prune(directory, name, keep)


def prune(directory: Path, name: str, keep: int) -> list[Path]:
    """Keep only the newest ``keep`` ``<name>-<ts>`` entries, removing each older
    entry's ``.txt`` **and** its ``.json`` sibling together.

    Names sort chronologically (the timestamp is fixed-width), so the oldest are
    the lexicographically-first. Returns the ``.txt`` paths removed.
    """
    files = sorted(directory.glob(f"{name}-[0-9]*.txt"))
    doomed = files[:-keep] if keep > 0 else files
    removed = []
    for old in doomed:
        try:
            old.unlink()
            removed.append(old)
        except OSError:
            pass
        try:
            old.with_suffix(".json").unlink()  # sibling (may not exist)
        except OSError:
            pass
    return removed
