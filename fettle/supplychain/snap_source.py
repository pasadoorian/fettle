"""Snap source provider — the Package Supply Chain view of installed snaps.

Snaps come from the Snap Store with a publisher (verified accounts show a ✓ / **)
and a confinement level. This provider answers who publishes each snap
(`UNVERIFIED_PUBLISHER`, `UNOFFICIAL_SOURCE` for sideloaded), and whether the
sandbox is weakened (`OVER_PRIVILEGED` for `classic`/`devmode`). No malware feed
exists for snaps, so `KNOWN_BAD` is not answered (see the coverage line).
"""

from __future__ import annotations

from .. import command
from .base import (
    OVER_PRIVILEGED,
    UNOFFICIAL_SOURCE,
    UNVERIFIED_PUBLISHER,
    Finding,
    Severity,
    SourceProvider,
)


class SnapSource(SourceProvider):
    source = "snap"
    coverage = ("publisher verification (✓/**) + confinement (classic/devmode); "
                "no malware feed")

    def is_present(self, ctx) -> bool:
        return command.which("snap")

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        # `snap list` columns: Name Version Rev Tracking Publisher Notes
        for line in command.run(["snap", "list"], capture=True).stdout.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 6:
                continue
            name, publisher, notes = cols[0], cols[4], cols[5]
            if publisher in ("-", ""):
                out.append(Finding(Severity.WARN, self.source, name, UNOFFICIAL_SOURCE,
                                   "sideloaded snap (no Store publisher)"))
            elif not ("✓" in publisher or "**" in publisher):
                out.append(Finding(Severity.LOW, self.source, name, UNVERIFIED_PUBLISHER,
                                   f"unverified publisher '{publisher}'"))
            if "classic" in notes:
                out.append(Finding(Severity.WARN, self.source, name, OVER_PRIVILEGED,
                                   "classic confinement (runs outside the sandbox)"))
            if "devmode" in notes:
                out.append(Finding(Severity.WARN, self.source, name, OVER_PRIVILEGED,
                                   "devmode (sandbox enforcement disabled)"))
        return out
