"""Snap source provider — the Package Supply Chain view of installed snaps.

Snaps come from the Snap Store with a publisher (verified accounts show a ✓ / **)
and a confinement level. This provider answers who publishes each snap
(`UNVERIFIED_PUBLISHER`, `UNOFFICIAL_SOURCE` for sideloaded), and whether the
sandbox is weakened (`OVER_PRIVILEGED` for `classic`/`devmode`), and whether the
snap is **still published at all** (`STALE_OR_ABANDONED`) — withdrawal is what a
store does to malware, so a snap that has vanished is worth knowing about. No
malware feed exists for snaps, so `KNOWN_BAD` is not answered (see the coverage
line).
"""

from __future__ import annotations

from .. import command
from .base import (
    OVER_PRIVILEGED,
    STALE_OR_ABANDONED,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
    UNVERIFIED_PUBLISHER,
    Finding,
    Severity,
    SourceProvider,
    still_upstream,
)


class SnapSource(SourceProvider):
    source = "snap"
    coverage = ("publisher verification (✓/**) + confinement (classic/devmode) + "
                "still-published check against the Store; no malware feed")

    def is_present(self, ctx) -> bool:
        return command.which("snap")

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        unknown: list[str] = []
        # `snap list` columns: Name Version Rev Tracking Publisher Notes
        for line in command.run(["snap", "list"], capture=True).stdout.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 6:
                continue
            name, publisher, notes = cols[0], cols[4], cols[5]
            sideloaded = publisher in ("-", "")
            if sideloaded:
                out.append(Finding(Severity.MEDIUM, self.source, name, UNOFFICIAL_SOURCE,
                                   "sideloaded snap (no Store publisher)"))
            elif not ("✓" in publisher or "**" in publisher):
                out.append(Finding(Severity.LOW, self.source, name, UNVERIFIED_PUBLISHER,
                                   f"unverified publisher '{publisher}'"))
            # Is it still published? A sideloaded snap never was, so asking would flag
            # every one of them on every run.
            if not sideloaded:
                present = still_upstream(["snap", "info", name], "no snap found")
                if present is False:
                    out.append(Finding(Severity.MEDIUM, self.source, name,
                                       STALE_OR_ABANDONED,
                                       "no longer in the Snap Store — withdrawn or "
                                       "renamed; a snap pulled for malware looks "
                                       "exactly like this"))
                elif present is None:
                    unknown.append(name)
            if "classic" in notes:
                out.append(Finding(Severity.MEDIUM, self.source, name, OVER_PRIVILEGED,
                                   "classic confinement (runs outside the sandbox)"))
            if "devmode" in notes:
                out.append(Finding(Severity.MEDIUM, self.source, name, OVER_PRIVILEGED,
                                   "devmode (sandbox enforcement disabled)"))
        if unknown:
            # One finding, not one per snap: an unreachable Store is a single fact about
            # the run, and repeating it per app would bury everything else.
            out.append(Finding(Severity.INFO, self.source, ", ".join(sorted(unknown)),
                               UNVERIFIABLE,
                               f"could not reach the Snap Store to check whether "
                               f"{len(unknown)} snap(s) are still published — not "
                               "checked, rather than checked and clean"))
        return out
