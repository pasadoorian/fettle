"""The normalized advisory model + provider ABC (PLAN.md §19.2/19.8).

One :class:`AdvisoryFinding` per (installed package, vulnerability group). Each
:class:`AdvisoryProvider` bulk-fetches its distro tracker into the shared SQLite
cache (see ``db.py``) and classifies installed packages against it — separate from
``supplychain``'s provenance-shaped ``Finding`` (this family is cve/version-shaped).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

# Distro-native severity names, worst first (Arch/Debian/Ubuntu all map onto these).
BANDS = ("Critical", "High", "Medium", "Low", "Unknown")
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

# Normalized per-package status against a vulnerability group.
FIXED_AVAILABLE = "fixed_available"   # a fix exists in a version newer than installed
PENDING_FIX = "pending_fix"           # vulnerable, no fix released yet (the tell)
UNKNOWN = "unknown"                   # affected but the fix state can't be determined


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)


@dataclass
class AdvisoryFinding:
    source: str                                  # "arch" | "debian" | "ubuntu"
    package: str
    installed_version: str
    status: str                                  # FIXED_AVAILABLE / PENDING_FIX / UNKNOWN
    severity: str                                # Critical/High/Medium/Low/Unknown
    cves: list[str] = field(default_factory=list)
    fixed_version: str | None = None
    group_id: str | None = None                  # AVG-xxxx (Arch) / CVE / OSV id
    advisory_id: str | None = None               # ASA / DSA / USN, if one exists
    distro_class: str = ""                       # native rating/status tag (for filtering)
    url: str = ""
    cvss: str = ""                               # CVSS vector (OSV) — the "second opinion"


def advisory_to_dict(f: AdvisoryFinding) -> dict:
    """JSON-serializable form of an AdvisoryFinding."""
    return {
        "source": f.source, "package": f.package,
        "installed_version": f.installed_version, "status": f.status,
        "severity": f.severity, "cves": list(f.cves),
        "fixed_version": f.fixed_version, "group_id": f.group_id,
        "advisory_id": f.advisory_id, "distro_class": f.distro_class, "url": f.url,
        "cvss": f.cvss,
    }


class AdvisoryProvider(abc.ABC):
    """One per distro. Fetches its tracker's data into the shared DB and classifies
    installed packages against it."""

    source: str = "base"

    @abc.abstractmethod
    def is_present(self, ctx) -> bool:
        """True if this distro's tracker applies to the running system."""

    @abc.abstractmethod
    def refresh(self, conn, ctx=None) -> int:
        """Bulk-fetch the tracker into ``conn`` (replacing this source's rows).
        ``ctx`` (optional) gives config access for providers that need it. Returns the
        row count stored, or ``-1`` on a fetch/parse failure (the caller keeps
        whatever was already cached — best-effort, never destructive)."""

    @abc.abstractmethod
    def findings(self, ctx, conn) -> list[AdvisoryFinding]:
        """Classify installed packages against the cached data."""

    @abc.abstractmethod
    def uncovered(self, ctx) -> list[str]:
        """Installed packages this tracker does NOT cover (AUR/manual/foreign) — for
        the honesty report so a clean result never over-reassures."""
