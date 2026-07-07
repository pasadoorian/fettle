"""Arch / Manjaro backend (pacman + yay/pamac + AUR). Actions land in M2+."""

from __future__ import annotations

from .base import PackageBackend


class ArchBackend(PackageBackend):
    name = "arch"
    supported = {
        "clean", "orphans", "update", "rebuilds", "python_rebuild",
        "config_drift", "firmware", "kernels", "aur_audit", "aur_scan",
        "integrity",
    }
