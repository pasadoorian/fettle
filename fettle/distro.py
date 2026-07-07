"""Distro detection: parse /etc/os-release and map to a :class:`PackageBackend`.

Detection uses ``ID`` first, then falls through the ``ID_LIKE`` chain, so
derivatives (Linux Mint, Pop!_OS, KDE neon, EndeavourOS, ...) resolve to their
parent family's backend with no new code.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .backends.arch import ArchBackend
from .backends.debian import DebianBackend

if TYPE_CHECKING:
    from .backends.base import PackageBackend

# os-release ID (or an ID_LIKE token) -> backend class.
_REGISTRY: dict[str, type] = {
    "arch": ArchBackend,
    "manjaro": ArchBackend,
    "endeavouros": ArchBackend,
    "debian": DebianBackend,
    "ubuntu": DebianBackend,
    "linuxmint": DebianBackend,
    "pop": DebianBackend,
}


class UnknownDistro(Exception):
    pass


def _parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def parse_os_release(root: Path = Path("/")) -> dict[str, str]:
    """Parse os-release (``/etc`` first, ``/usr/lib`` fallback) into a dict."""
    for rel in ("etc/os-release", "usr/lib/os-release"):
        path = root / rel
        if path.is_file():
            return _parse(path.read_text())
    return {}


def _id_candidates(osr: dict[str, str]) -> list[str]:
    ids: list[str] = []
    if osr.get("ID"):
        ids.append(osr["ID"].lower())
    ids.extend(token.lower() for token in osr.get("ID_LIKE", "").split())
    return ids


def detect(root: Path = Path("/"), override: str | None = None) -> "PackageBackend":
    """Return a backend instance for the running (or ``--distro``-overridden) distro."""
    known = ", ".join(sorted(_REGISTRY))
    if override:
        cls = _REGISTRY.get(override.lower())
        if cls is None:
            raise UnknownDistro(f"--distro '{override}' is not a known backend ({known})")
        return cls()

    osr = parse_os_release(root)
    for candidate in _id_candidates(osr):
        if candidate in _REGISTRY:
            return _REGISTRY[candidate]()

    pretty = osr.get("PRETTY_NAME") or osr.get("ID") or "unknown"
    raise UnknownDistro(
        f"no fettle backend for this distro ({pretty}). Known: {known}. Override with --distro."
    )
