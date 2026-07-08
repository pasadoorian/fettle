"""APT source provider — the Package Supply Chain view of Debian/Ubuntu repos.

Answers the §3.8 question-set for apt: which repositories software comes from
(official vs third-party / PPA), whether signature verification is disabled
(`[trusted=yes]`) or transport is plain http, and whether installed files still
match what the package shipped (`debsums`). APT is a signed-binary ecosystem with
no community malware feed, so `KNOWN_BAD` (Q6) is not answered — the coverage
line says so.
"""

from __future__ import annotations

import re

from .. import command
from .base import (
    INSECURE_TRANSPORT,
    INTEGRITY_DRIFT,
    UNOFFICIAL_SOURCE,
    Finding,
    Severity,
    SourceProvider,
)

# Repositories under these host suffixes are the distro's own official archives.
_OFFICIAL_SUFFIXES = (".ubuntu.com", ".debian.org", ".canonical.com")


def _host(uri: str) -> str:
    m = re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*://([^/]+)", uri)
    return m.group(1).lower() if m else ""


def _is_official(host: str) -> bool:
    return any(host == s.lstrip(".") or host.endswith(s) for s in _OFFICIAL_SUFFIXES)


def _parse_oneline(text: str, name: str):
    """Yield (uri, opts, srcfile) for one-line `deb ...` entries."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or not line.startswith("deb "):
            continue  # binary repos only (skip comments and deb-src)
        opts: dict[str, str] = {}
        if "[" in line and "]" in line:
            for kv in line[line.index("[") + 1:line.index("]")].split():
                k, _, v = kv.partition("=")
                opts[k.lower()] = v
            rest = line[line.index("]") + 1:].split()
            uri = rest[0] if rest else ""
        else:
            parts = line.split()
            uri = parts[1] if len(parts) > 1 else ""
        if uri:
            yield uri, opts, name


def _parse_deb822(text: str, name: str):
    """Yield (uri, opts, srcfile) for deb822 `.sources` stanzas."""
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line and not line[0].isspace():
                k, _, v = line.partition(":")
                fields[k.strip().lower()] = v.strip()
        if not fields or "deb" not in fields.get("types", "deb").split():
            continue
        if fields.get("enabled", "yes").lower() in ("no", "false"):
            continue
        opts: dict[str, str] = {}
        if fields.get("trusted", "").lower() in ("yes", "true"):
            opts["trusted"] = "yes"
        for uri in fields.get("uris", "").split():
            yield uri, opts, name


class AptSource(SourceProvider):
    source = "apt"
    coverage = ("3rd-party repo / PPA hygiene (source, signing, transport) + debsums "
                "file integrity; no malware feed (apt has no community IOC list)")

    def is_present(self, ctx) -> bool:
        return command.which("apt-get") or command.which("dpkg")

    def _entries(self, ctx):
        apt = ctx.root / "etc/apt"
        files = []
        if (apt / "sources.list").is_file():
            files.append(apt / "sources.list")
        srcd = apt / "sources.list.d"
        if srcd.is_dir():
            files += sorted(srcd.glob("*.list")) + sorted(srcd.glob("*.sources"))
        for f in files:
            text = f.read_text(errors="replace")
            parse = _parse_deb822 if f.suffix == ".sources" else _parse_oneline
            yield from parse(text, f.name)

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        for uri, opts, src in self._entries(ctx):
            host = _host(uri)
            label = host or uri
            third_party = bool(host) and not _is_official(host)
            if third_party:
                out.append(Finding(Severity.LOW, self.source, label, UNOFFICIAL_SOURCE,
                                   f"third-party repository {uri} ({src})"))
                # http matters for third-party repos; the official signed archives
                # ship over http by default (apt still verifies signatures), so we
                # don't flag those.
                if uri.startswith("http://"):
                    out.append(Finding(Severity.LOW, self.source, label, INSECURE_TRANSPORT,
                                       f"third-party repository over http (no TLS): {uri} ({src})"))
            if opts.get("trusted") == "yes":
                out.append(Finding(Severity.WARN, self.source, label, INSECURE_TRANSPORT,
                                   f"[trusted=yes] disables signature checks: {uri} ({src})"))
        out.extend(self._integrity())
        return out

    def _integrity(self) -> list[Finding]:
        if not command.which("debsums"):
            return []
        changed = [ln.strip() for ln in
                   command.run(["debsums", "-c"], capture=True).stdout.splitlines() if ln.strip()]
        return [Finding(Severity.WARN, self.source, "debsums", INTEGRITY_DRIFT,
                        f"modified packaged file: {ln}") for ln in changed]
