"""AUR source provider — the Package Supply Chain view of installed AUR packages.

Answers the question-set for foreign (AUR/manual) packages using the AUR RPC and
the lenucksi IOC feed, and detects maintainer changes across runs (the "Atomic
Arch" re-adoption tell). This is the normalized replacement for update.sh's
``aur_audit`` (-A) and the package/account/npm parts of ``aur_scan`` (-S).
Host-persistence indicators from the old -S belong to System Supply Chain (sys-audit).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .. import command
from ..aur import ioc as aur_ioc
from ..aur import meta as aur_meta
from ..util import matches_any
from .base import (
    KNOWN_BAD,
    STALE_OR_ABANDONED,
    UNVERIFIED_PUBLISHER,
    Finding,
    Severity,
    SourceProvider,
)

_JS_CACHE_SUBDIRS = (".npm", ".bun", ".cache/yarn", ".local/share/pnpm", ".cache/pnpm")


class AURSource(SourceProvider):
    source = "aur"
    coverage = "orphan / out-of-date / stale / known-bad via AUR RPC + lenucksi IOC feed"

    def is_present(self, ctx) -> bool:
        return bool(self._foreign(ctx))

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _foreign(ctx) -> list[str]:
        names = command.run(["pacman", "-Qmq"], capture=True).stdout.split()
        return [n for n in names if not matches_any(n, ctx.config.exclude_foreign)]

    def _ioc(self, ctx) -> aur_ioc.IOC:
        return aur_ioc.IOC(
            cache_dir=ctx.user_home / ".cache/fettle/ioc",
            campaigns=ctx.config.aur_ioc_campaigns,
            ttl=ctx.config.aur_ioc_cache_ttl,
        )

    # -- the audit -----------------------------------------------------------
    def findings(self, ctx) -> list[Finding]:
        foreign = self._foreign(ctx)
        if not foreign:
            return []
        results = aur_meta.query_info(foreign)
        by_name = {r.get("Name"): r for r in results if r.get("Name")}
        now = time.time()
        max_age = ctx.config.aur_max_age_days
        out: list[Finding] = []

        # Package-level metadata questions.
        for name in foreign:
            r = by_name.get(name)
            if r is None:
                out.append(Finding(Severity.WARN, self.source, name, STALE_OR_ABANDONED,
                                    "not present in AUR (deleted/renamed) — investigate"))
                continue
            if r.get("Maintainer") is None:
                out.append(Finding(Severity.WARN, self.source, name, UNVERIFIED_PUBLISHER,
                                    "orphaned (no maintainer)"))
            if r.get("OutOfDate"):
                out.append(Finding(Severity.WARN, self.source, name, STALE_OR_ABANDONED,
                                    "flagged out-of-date in the AUR"))
            last = r.get("LastModified")
            if isinstance(last, (int, float)):
                age = int((now - last) // 86400)
                if age > max_age:
                    out.append(Finding(Severity.LOW, self.source, name, STALE_OR_ABANDONED,
                                       f"last updated {age} days ago"))

        # IOC cross-references (the KNOWN_BAD question).
        ioc = self._ioc(ctx)
        bad_pkgs = ioc.bad_packages()
        for name in foreign:
            if name in bad_pkgs:
                out.append(Finding(Severity.CRIT, self.source, name, KNOWN_BAD,
                                   "on a known-malicious package list — REMOVE/INVESTIGATE"))
        bad_accounts = ioc.bad_accounts()
        for name, r in by_name.items():
            m = r.get("Maintainer")
            if m and m in bad_accounts:
                out.append(Finding(Severity.CRIT, self.source, name, KNOWN_BAD,
                                   f"maintained by a known-malicious account ({m})"))
        for name, path in self._js_cache_hits(ioc.bad_npm(), ctx.user_home):
            out.append(Finding(Severity.CRIT, self.source, name, KNOWN_BAD,
                               f"malicious JS package trace under {path}"))

        # Maintainer-change / re-adoption tell (state diff across runs).
        out.extend(self._maintainer_changes(by_name, ctx))
        return out

    def _maintainer_changes(self, by_name, ctx) -> list[Finding]:
        snap_path = ctx.user_home / ".cache/fettle/aur-maintainers.json"
        current = {n: (r.get("Maintainer") or "ORPHAN") for n, r in by_name.items()}
        previous: dict[str, str] = {}
        if snap_path.is_file():
            try:
                previous = json.loads(snap_path.read_text())
            except ValueError:
                previous = {}
        changes = []
        for name, maint in current.items():
            old = previous.get(name)
            if old is not None and old != maint:
                changes.append(Finding(Severity.WARN, self.source, name, UNVERIFIED_PUBLISHER,
                                       f"maintainer changed {old} -> {maint} (review before upgrade)"))
        if not ctx.dry_run:
            try:
                snap_path.parent.mkdir(parents=True, exist_ok=True)
                snap_path.write_text(json.dumps(current))
            except OSError:
                pass
        return changes

    @staticmethod
    def _js_cache_hits(names, home: Path):
        if not names:
            return []
        lowered = {n.lower() for n in names}
        hits: list[tuple[str, str]] = []
        for sub in _JS_CACHE_SUBDIRS:
            root = home / sub
            if not root.is_dir():
                continue
            base_depth = len(root.parts)
            for dirpath, dirnames, filenames in os.walk(root):
                if len(Path(dirpath).parts) - base_depth >= 6:
                    dirnames[:] = []  # prune deeper than 6 levels
                    continue
                for entry in (*dirnames, *filenames):
                    el = entry.lower()
                    for n in lowered:
                        if n in el:
                            hits.append((n, str(Path(dirpath) / entry)))
        return hits
