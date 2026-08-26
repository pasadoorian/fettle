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


def still_upstream(argv, absent_marker: str):
    """Does an installed item still exist in the index it came from?

    Returns **True** (still there), **False** (definitively gone), or **None** (could
    not tell) — and the third state is the entire reason this is a shared helper rather
    than two copies.

    *Withdrawn upstream* is one of the strongest supply-chain signals available, because
    removal is what a registry **does to malware**: Arch deleted `firefox-patch-bin` and
    friends after the 2025 RAT, and 1,579 packages in June 2026. fettle already asks the
    AUR this question; the store-backed ecosystems were not asked at all.

    The trap is that the question is answered over the network. A store that is merely
    unreachable makes **every** installed app look withdrawn at once — "could not look"
    rendering as "found a problem", which cries wolf exactly as badly as the reverse and
    is the failure this whole model exists to prevent. So a non-zero exit is not enough:
    the tool has to say, in as many words, that it looked and the thing was not there.
    Anything else is None and gets reported as a gap in coverage.

    Matching on the tool's own wording is fragile — it is English in someone else's
    output — but it is the only signal either tool offers, and the failure mode of a
    changed message is a finding downgraded to "could not tell", never a false alarm.
    """
    from .. import command

    proc = command.run(list(argv), capture=True)
    if proc.returncode == 0:
        return True
    text = ((proc.stdout or "") + (proc.stderr or "")).lower()
    return False if absent_marker.lower() in text else None


_UA = "fettle (package supply-chain audit)"


def still_upstream_url(url: str, *, timeout: float = 10.0):
    """HTTP sibling of :func:`still_upstream`, with the same three states.

    The extension registries answer over HTTP rather than through a CLI, but the
    contract that matters is identical: **only a definite "I looked and it is not
    there" may read as withdrawn.** A 404 is that. Everything else — a timeout, DNS
    failure, 5xx, a captive portal, a proxy, GitHub's rate limit — is None, because a
    registry that cannot be reached would otherwise report every extension you own as
    pulled at once.

    Measured 2026-08-06 against all four registries fettle talks to (Open VSX, the VS
    Code Marketplace, extensions.gnome.org, the GitHub API): each answers 200 when the
    item exists and 404 when it does not. Worth having measured — the *documented*
    Marketplace gallery endpoint returns 404 for present and absent alike, so building
    on it would have reported every VS Code extension as withdrawn.
    """
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https, fixed hosts)
            return True if 200 <= getattr(resp, "status", 200) < 300 else None
    except urllib.error.HTTPError as exc:
        return False if exc.code == 404 else None
    except Exception:                      # timeout, DNS, TLS, proxy, anything
        return None


def withdrawn_finding(source: str, package: str, detail: str) -> "Finding":
    """The standard shape for "you have it installed and it is gone upstream"."""
    return Finding(Severity.MEDIUM, source, package, STALE_OR_ABANDONED, detail)


def unverifiable_finding(source: str, names, what: str) -> "Finding":
    """One finding for a whole run's worth of unanswerable checks, never one each.

    An unreachable registry is a single fact about the run; repeating it per item would
    bury everything else the audit found.
    """
    names = sorted(names)
    return Finding(Severity.INFO, source, ", ".join(names), UNVERIFIABLE,
                   f"could not reach {what} to check whether {len(names)} item(s) are "
                   "still published — not checked, rather than checked and clean")


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


@dataclass(frozen=True)
class Examined:
    """What a provider actually looked at — so "clean" cannot render as "never ran".

    `coverage` says what a provider *can* answer. This says what it *did*, on this host,
    this run. Without it a provider that examined 24 extensions and cleared every one
    produced exactly the same output as one that never executed: its coverage sentence
    and nothing else.

    Four outcomes have to stay distinguishable, and only two of them were:

    ==========================  ==================================================
    the tool is not installed   already handled — "[x] not present on this system"
    installed, nothing to see   ``Examined(0, …)`` — "nothing to examine"
    examined N, all clean       ``Examined(N, …)`` — the case that was invisible
    could not look              already handled — an ``UNVERIFIABLE`` finding
    ==========================  ==================================================

    ``detail`` completes the sentence and is where the useful part goes: *why* there
    was nothing to report, not merely that there wasn't.
    """
    count: int
    unit: str                    # plural noun: "extensions", "images", "snaps"
    detail: str = ""


class SourceProvider(abc.ABC):
    source: str = "base"
    coverage: str = ""
    #: Set by :meth:`findings` while it works. ``None`` means this provider has not
    #: adopted the outcome line yet, and it renders exactly as it always has.
    examined: "Examined | None" = None

    @abc.abstractmethod
    def is_present(self, ctx: "Context") -> bool:
        """True if this package manager/source is in use on the host."""

    @abc.abstractmethod
    def findings(self, ctx: "Context") -> list[Finding]:
        """Return normalized findings for this source."""
