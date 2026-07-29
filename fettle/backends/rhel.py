"""RHEL / CentOS Stream / Rocky / AlmaLinux / Oracle Linux backend (dnf + rpm).

**Audit first.** This backend deliberately starts with the security half — the
cross-ecosystem package audit, the binary hardening audit and container updates — and
claims nothing else. Maintenance actions (upgrade, clean, kernels, config drift) come
in a later phase; until then ``supported`` simply omits them and ``actions.run``
reports each as unsupported rather than pretending.

That is safe because :class:`~fettle.backends.base.PackageBackend` declares no abstract
methods: capability is advertised through ``supported``, and any method left
unimplemented raises ``NotImplementedError``, which the action runner catches and
degrades into a note.

Registering the backend is worth more than it looks: the base class already returns the
distro-agnostic supply-chain providers (flatpak, snap, containers, GNOME extensions,
VS Code extensions, gh extensions), so ``fettle -P`` starts working here with no
RPM-specific code at all. **podman** is RHEL's default container runtime and the
container provider already prefers docker then podman.

Fedora is deliberately *not* claimed. It shares dnf, but its advisories come from Bodhi
as ``FEDORA-*`` rather than Red Hat's ``RHSA-*``, so a provider tuned for RHSA data
would be honest here and approximate there.
"""

from __future__ import annotations

from .base import PackageBackend


class RhelBackend(PackageBackend):
    name = "rhel"
    # Only what is actually implemented. Everything else is absent on purpose — see
    # the module docstring; a later phase adds the maintenance actions.
    supported = {
        "pkg_audit",         # via the distro-agnostic providers on the base class
        "hardening_audit",   # checksec-driven; distro-neutral apart from the baseline
        "container_update",  # podman/docker, backend-independent
    }
