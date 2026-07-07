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
    INFO = 0
    LOW = 1
    WARN = 2
    CRIT = 3


# The seven questions every provider answers as far as its ecosystem allows.
UNVERIFIED_PUBLISHER = "UNVERIFIED_PUBLISHER"
UNOFFICIAL_SOURCE = "UNOFFICIAL_SOURCE"
INSECURE_TRANSPORT = "INSECURE_TRANSPORT"
STALE_OR_ABANDONED = "STALE_OR_ABANDONED"
INTEGRITY_DRIFT = "INTEGRITY_DRIFT"
KNOWN_BAD = "KNOWN_BAD"
OVER_PRIVILEGED = "OVER_PRIVILEGED"


@dataclass
class Finding:
    severity: Severity
    source: str      # "aur" | "apt" | "flatpak" | "snap"
    package: str
    question: str
    detail: str


class SourceProvider(abc.ABC):
    source: str = "base"
    coverage: str = ""

    @abc.abstractmethod
    def is_present(self, ctx: "Context") -> bool:
        """True if this package manager/source is in use on the host."""

    @abc.abstractmethod
    def findings(self, ctx: "Context") -> list[Finding]:
        """Return normalized findings for this source."""
