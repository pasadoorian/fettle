"""Flatpak source provider — the Package Supply Chain view of Flatpak apps.

Flatpak is a sandboxed-bundle ecosystem: apps come from a remote (flathub is the
curated default) and declare a permission set. This provider answers where each
app came from (`UNOFFICIAL_SOURCE` for non-flathub origins), how broad its sandbox
holes are (`OVER_PRIVILEGED` — host/home filesystem, all-devices), and whether a
remote uses plain http (`INSECURE_TRANSPORT`). No publisher-verification API and
no malware feed, so those questions are left unanswered (see the coverage line).
"""

from __future__ import annotations

from .. import command
from .base import (
    Examined,
    INSECURE_TRANSPORT,
    OVER_PRIVILEGED,
    STALE_OR_ABANDONED,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
    Finding,
    Severity,
    SourceProvider,
    still_upstream,
)

# Filesystem grants that punch broadly through the sandbox.
_BROAD_FS = {"host", "host-os", "host-etc", "home"}


def _cols(line: str) -> list[str]:
    return line.split("\t") if "\t" in line else line.split()


def _perm_field(text: str, section: str, key: str) -> list[str]:
    """Values of ``key=`` in ``[section]`` of a flatpak permissions dump (ini-like)."""
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
        elif cur == section and line.startswith(key + "="):
            return [x for x in line[len(key) + 1:].split(";") if x]
    return []


class FlatpakSource(SourceProvider):
    source = "flatpak"
    coverage = ("remote origin (flathub vs other) + sandbox permissions "
                "(filesystem/devices) + remote transport + still-offered check "
                "against the app's own remote; no malware feed")

    def is_present(self, ctx) -> bool:
        return command.which("flatpak")

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        unknown: list[str] = []
        seen = 0
        apps = command.run(["flatpak", "list", "--app", "--columns=application,origin"],
                           capture=True).stdout
        for line in apps.splitlines():
            cols = _cols(line)
            if len(cols) < 2:
                continue
            appid, origin = cols[0], cols[1]
            seen += 1
            if origin.lower() != "flathub":
                out.append(Finding(Severity.LOW, self.source, appid, UNOFFICIAL_SOURCE,
                                   f"installed from non-flathub remote '{origin}'"))
            # Is it still offered by the remote it came from? Asked against that remote
            # rather than flathub, so an app from a third-party remote is checked
            # against its own source instead of being flagged for not being on flathub.
            present = still_upstream(["flatpak", "remote-info", origin, appid],
                                     "can't find ref")
            if present is False:
                out.append(Finding(Severity.MEDIUM, self.source, appid,
                                   STALE_OR_ABANDONED,
                                   f"no longer offered by remote '{origin}' — withdrawn "
                                   "or renamed; an app pulled for malware looks exactly "
                                   "like this"))
            elif present is None:
                unknown.append(appid)
            out.extend(self._permission_findings(appid))

        remotes = command.run(["flatpak", "remotes", "--columns=name,url"], capture=True).stdout
        for line in remotes.splitlines():
            cols = _cols(line)
            if len(cols) >= 2 and cols[1].startswith("http://"):
                out.append(Finding(Severity.MEDIUM, self.source, cols[0], INSECURE_TRANSPORT,
                                   f"remote '{cols[0]}' over http: {cols[1]}"))
        if unknown:
            # One finding, not one per app: an unreachable remote is a single fact about
            # the run, and repeating it per app would bury everything else.
            out.append(Finding(Severity.INFO, self.source, ", ".join(sorted(unknown)),
                               UNVERIFIABLE,
                               f"could not reach the remote(s) to check whether "
                               f"{len(unknown)} app(s) are still offered — not checked, "
                               "rather than checked and clean"))
        self.examined = Examined(
            seen, "flatpak apps",
            "no flatpak apps installed" if not seen
            else ("all from their declared remote" if not out else ""))
        return out

    def _permission_findings(self, appid: str) -> list[Finding]:
        # `--` so an app id can never be read as an option (matches aur/audit.py).
        perms = command.run(["flatpak", "info", "--show-permissions", "--", appid],
                            capture=True).stdout
        out: list[Finding] = []
        fs = _perm_field(perms, "Context", "filesystems")
        broad = [x for x in fs if x in _BROAD_FS or x.startswith("/")]
        if broad:
            out.append(Finding(Severity.MEDIUM, self.source, appid, OVER_PRIVILEGED,
                               f"broad filesystem access: {', '.join(broad)}"))
        if "all" in _perm_field(perms, "Context", "devices"):
            out.append(Finding(Severity.MEDIUM, self.source, appid, OVER_PRIVILEGED,
                               "full device access (devices=all)"))
        return out
