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
    INSECURE_TRANSPORT,
    OVER_PRIVILEGED,
    UNOFFICIAL_SOURCE,
    Finding,
    Severity,
    SourceProvider,
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
                "(filesystem/devices) + remote transport; no malware feed")

    def is_present(self, ctx) -> bool:
        return command.which("flatpak")

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        apps = command.run(["flatpak", "list", "--app", "--columns=application,origin"],
                           capture=True).stdout
        for line in apps.splitlines():
            cols = _cols(line)
            if len(cols) < 2:
                continue
            appid, origin = cols[0], cols[1]
            if origin.lower() != "flathub":
                out.append(Finding(Severity.LOW, self.source, appid, UNOFFICIAL_SOURCE,
                                   f"installed from non-flathub remote '{origin}'"))
            out.extend(self._permission_findings(appid))

        remotes = command.run(["flatpak", "remotes", "--columns=name,url"], capture=True).stdout
        for line in remotes.splitlines():
            cols = _cols(line)
            if len(cols) >= 2 and cols[1].startswith("http://"):
                out.append(Finding(Severity.WARN, self.source, cols[0], INSECURE_TRANSPORT,
                                   f"remote '{cols[0]}' over http: {cols[1]}"))
        return out

    def _permission_findings(self, appid: str) -> list[Finding]:
        perms = command.run(["flatpak", "info", "--show-permissions", appid], capture=True).stdout
        out: list[Finding] = []
        fs = _perm_field(perms, "Context", "filesystems")
        broad = [x for x in fs if x in _BROAD_FS or x.startswith("/")]
        if broad:
            out.append(Finding(Severity.WARN, self.source, appid, OVER_PRIVILEGED,
                               f"broad filesystem access: {', '.join(broad)}"))
        if "all" in _perm_field(perms, "Context", "devices"):
            out.append(Finding(Severity.WARN, self.source, appid, OVER_PRIVILEGED,
                               "full device access (devices=all)"))
        return out
