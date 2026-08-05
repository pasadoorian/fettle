"""The normalized supply-chain model (see PLAN.md §3.8).

One :class:`Finding` format and one question-set; each :class:`SourceProvider`
(AUR/APT/Flatpak/Snap) answers what its ecosystem can, and prints a ``coverage``
line so uneven depth is explicit.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..backends.base import Context


class Severity(enum.IntEnum):
    """One severity scale, shared with the advisory side.

    Supply-chain findings used ``INFO/LOW/WARN/CRIT`` while advisories used
    ``Critical/High/Medium/Low``, and the dashboard showed both at once — with
    ``LOW: 38`` and ``Low: 510`` sitting in the same table as if they were different
    things. Nothing could sort or filter across them, which is the one job a
    fleet view has. Same words now, in the terminal and in the JSON.

    ``INFO`` is kept as a rung below Low rather than folded into it: it marks a row
    that is context, not a problem (a dangling image), and flattening that would
    inflate the Low count with things nobody needs to act on.
    """
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Display form — title case, matching the advisory vocabulary."""
        return self.name.title()


# The questions every provider answers as far as its ecosystem allows.
UNVERIFIED_PUBLISHER = "UNVERIFIED_PUBLISHER"
UNOFFICIAL_SOURCE = "UNOFFICIAL_SOURCE"
INSECURE_TRANSPORT = "INSECURE_TRANSPORT"
STALE_OR_ABANDONED = "STALE_OR_ABANDONED"
INTEGRITY_DRIFT = "INTEGRITY_DRIFT"
KNOWN_BAD = "KNOWN_BAD"
OVER_PRIVILEGED = "OVER_PRIVILEGED"
# Added for the container provider: the name you deployed does not identify a fixed
# artifact, so "the same image" is a different thing week to week and nothing records
# what actually ran.
MUTABLE_REFERENCE = "MUTABLE_REFERENCE"
# Not a property of the software but of the audit: the provider could not answer its
# questions for this item (daemon down, permission denied, tool broken). It exists so
# a failed check can never be mistaken for a clean one — returning no findings when
# you could not look is the bug this whole model is meant to prevent.
UNVERIFIABLE = "UNVERIFIABLE"


@dataclass
class Finding:
    severity: Severity
    source: str      # "aur" | "apt" | "flatpak" | "snap" | "container"
    package: str
    question: str
    detail: str


def finding_to_dict(f: "Finding") -> dict:
    """JSON-serializable form of a Finding (severity as its display label)."""
    return {"severity": f.severity.label, "source": f.source, "package": f.package,
            "question": f.question, "detail": f.detail}


class SourceProvider(abc.ABC):
    source: str = "base"
    coverage: str = ""

    @abc.abstractmethod
    def is_present(self, ctx: "Context") -> bool:
        """True if this package manager/source is in use on the host."""

    @abc.abstractmethod
    def findings(self, ctx: "Context") -> list[Finding]:
        """Return normalized findings for this source."""
