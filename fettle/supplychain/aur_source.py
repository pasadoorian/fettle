"""AUR source provider — the Package Supply Chain view of installed AUR packages.

Answers the question-set for foreign (AUR/manual) packages using the AUR RPC and
the lenucksi IOC feed, and detects maintainer changes across runs (the "Atomic
Arch" re-adoption tell). This backs the cross-distro ``pkg-audit`` command (the
normalized-``Finding`` umbrella). The Arch-specific ``aur-audit`` (-A) health
table and ``aur-ioc-scan`` (-S) live in ``fettle/aur/{audit,ioc_scan}.py`` and
share the low-level helpers in ``fettle/aur/common.py``.
"""

from __future__ import annotations

import json
import time

from ..aur import common as aur_common
from ..aur import meta as aur_meta
from .base import (
    KNOWN_BAD,
    STALE_OR_ABANDONED,
    UNVERIFIED_PUBLISHER,
    Finding,
    Severity,
    SourceProvider,
)


class AURSource(SourceProvider):
    source = "aur"
    coverage = "orphan / out-of-date / stale / known-bad via AUR RPC + lenucksi IOC feed"

    def is_present(self, ctx) -> bool:
        return bool(aur_common.foreign_packages(ctx))

    # -- the audit -----------------------------------------------------------
    def findings(self, ctx) -> list[Finding]:
        foreign = aur_common.foreign_packages(ctx)
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
        ioc = aur_common.ioc_feed(ctx)
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
        for name, path in aur_common.js_cache_hits(ioc.bad_npm(), ctx.user_home):
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
