"""AUR source provider — the Package Supply Chain view of installed AUR packages.

Answers the question-set for foreign (AUR/manual) packages using the AUR RPC and
the lenucksi IOC feed, and detects maintainer changes across runs (the "Atomic
Arch" re-adoption tell). This backs the cross-distro ``pkg-audit`` command (the
normalized-``Finding`` umbrella). The Arch-specific ``aur-audit`` (-A) health
table lives in ``fettle/aur/audit.py`` (the IoC scanner it once named was retired
in v0.73.0; its checks are here). Old path: ``fettle/aur/{audit,ioc_scan}.py`` and
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
    UNVERIFIABLE,
    UNVERIFIED_PUBLISHER,
    Finding,
    Severity,
    SourceProvider,
)


class AURSource(SourceProvider):
    source = "aur"
    coverage = ("orphan / out-of-date / stale / known-bad via AUR RPC + lenucksi IOC "
                "feeds; reports when a feed could not be read, so a quiet result is "
                "never mistaken for a clean one")

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
                out.append(Finding(Severity.MEDIUM, self.source, name, STALE_OR_ABANDONED,
                                    "not present in AUR (deleted/renamed) — investigate"))
                continue
            if r.get("Maintainer") is None:
                out.append(Finding(Severity.MEDIUM, self.source, name, UNVERIFIED_PUBLISHER,
                                    "orphaned (no maintainer)"))
            if r.get("OutOfDate"):
                out.append(Finding(Severity.MEDIUM, self.source, name, STALE_OR_ABANDONED,
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
                out.append(Finding(Severity.CRITICAL, self.source, name, KNOWN_BAD,
                                   "on a known-malicious package list — REMOVE/INVESTIGATE"))
        bad_accounts = ioc.bad_accounts()
        for name, r in by_name.items():
            m = r.get("Maintainer")
            if m and m in bad_accounts:
                out.append(Finding(Severity.CRITICAL, self.source, name, KNOWN_BAD,
                                   f"maintained by a known-malicious account ({m})"))
        for name, path in aur_common.js_cache_hits(ioc.bad_npm(), ctx.user_home):
            out.append(Finding(Severity.CRITICAL, self.source, name, KNOWN_BAD,
                               f"malicious JS package trace under {path}"))

        # Coverage of the IoC half, inherited from `aur-ioc-scan` (retired) when
        # retired in v0.73.0. Without it, folding -I into -P would have silently
        # undone the fix that sweep landed: the malware check reporting "nothing
        # matched" while the feeds it matches against were never read. -P runs on
        # every `fettle -a`, so this is the copy that matters.
        if ioc.unavailable:
            out.append(Finding(
                Severity.MEDIUM, self.source, "ioc-feeds", UNVERIFIABLE,
                "could not be fetched: " + ", ".join(sorted(set(ioc.unavailable)))
                + " — a package compromised in a campaign published since would NOT "
                "have been seen"))
        if ioc.stale:
            out.append(Finding(
                Severity.MEDIUM, self.source, "ioc-feeds", UNVERIFIABLE,
                "served from an out-of-date cache: "
                + ", ".join(sorted(set(ioc.stale)))))

        # Maintainer-change / re-adoption tell (state diff across runs).
        out.extend(self._maintainer_changes(by_name, ctx))
        return out

    def _maintainer_changes(self, by_name, ctx) -> list[Finding]:
        from ..util import chown_to_user

        # Its own baseline. Shared with aur-audit until v0.66.0, where whichever ran
        # first consumed the diff and rewrote the file, so the other always reported
        # "no changes" — losing exactly the maintainer-takeover signal both exist to
        # catch. The legacy path is still read as a one-time fallback.
        snap_path = ctx.user_home / ".cache/fettle/aur-maintainers-pkgaudit.json"
        if not snap_path.is_file():
            legacy = ctx.user_home / ".cache/fettle/aur-maintainers.json"
            if legacy.is_file():
                snap_path = legacy
        current = {n: (r.get("Maintainer") or "ORPHAN") for n, r in by_name.items()}
        previous: dict[str, str] = {}
        if snap_path.is_file():
            # OSError too: an earlier elevated run may have left this root-owned,
            # so a later unprivileged read must degrade, not crash.
            try:
                previous = json.loads(snap_path.read_text())
            except (OSError, ValueError):
                previous = {}
        changes = []
        for name, maint in current.items():
            old = previous.get(name)
            if old is not None and old != maint:
                changes.append(Finding(Severity.MEDIUM, self.source, name, UNVERIFIED_PUBLISHER,
                                       f"maintainer changed {old} -> {maint} (review before upgrade)"))
        if not ctx.dry_run:
            try:
                snap_path = ctx.user_home / ".cache/fettle/aur-maintainers-pkgaudit.json"
                snap_path.parent.mkdir(parents=True, exist_ok=True)
                snap_path.write_text(json.dumps(current))
                # Chown back so a root run doesn't leave a file the user can't read.
                chown_to_user(snap_path.parent, ctx.sudo_user)
                chown_to_user(snap_path, ctx.sudo_user)
            except OSError:
                pass
        return changes
