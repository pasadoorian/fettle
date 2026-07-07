"""Debian / Ubuntu backend (apt + flatpak + snap). Actions land in M7."""

from __future__ import annotations

from .base import PackageBackend


class DebianBackend(PackageBackend):
    name = "debian"
    supported = {
        "clean", "orphans", "update", "rebuilds",
        "config_drift", "firmware", "kernels", "integrity",
        # "source_audit" arrives with M8; no python_rebuild / aur_* (Arch-only)
    }
