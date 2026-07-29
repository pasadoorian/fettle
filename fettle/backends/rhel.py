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

import re

from .base import PackageBackend

# `rpm -Va` rows, e.g.
#   missing     /boot
#   .....UG..  g /proc
#   S.5....T.  c /etc/dnf/dnf.conf
#   S.5....T.    /usr/bin/gzip
# Anchoring the path on a leading `/` rather than splitting on whitespace keeps
# paths containing spaces intact, and makes the optional file-type marker
# unambiguous.
_VA_RE = re.compile(r"^(\S+)\s+(?:([cdglr])\s+)?(/.*)$")

# Markers whose files are EXPECTED to differ from the package: config files you
# edited, ghost files created at runtime, documentation. A modification here is
# normal operation, not tampering. A row with no marker is a packaged file —
# a binary or library — and that is the row worth alarming about.
_EXPECTED_DRIFT = {"c": "config", "g": "ghost (runtime-created)",
                   "d": "documentation", "l": "license", "r": "readme"}


class RhelBackend(PackageBackend):
    name = "rhel"
    # Only what is actually implemented. Everything else is absent on purpose — see
    # the module docstring; a later phase adds the maintenance actions.
    supported = {
        "pkg_audit",         # via the distro-agnostic providers on the base class
        "hardening_audit",   # checksec-driven; distro-neutral apart from the baseline
        "container_update",  # podman/docker, backend-independent
    }
    # NOTE: `verify_integrity` below is NOT listed here. `supported` names *pipeline
    # actions*; sys-audit's `packages` category calls the backend method directly
    # (secure/audit.py), so adding it would name an action that does not exist —
    # which is exactly what the action-registry cross-check flagged.

    def supply_chain_sources(self):
        from ..supplychain.dnf_source import DnfSource
        return [DnfSource(), *super().supply_chain_sources()]

    def verify_integrity(self, scan) -> None:
        """sys-audit's ``packages`` check — the RPM analogue of debsums/paccheck.

        ``rpm -Va`` compares every installed file against the package metadata. Two
        things about it drive this implementation:

        **Its exit code cannot detect failure.** ``rpm -Va`` exits 1 when it merely
        *finds* discrepancies, and — measured — exits **0 with no output** when the
        database is unreadable, which is byte-identical to a clean system. So the
        database is proven readable first; without that, "could not look" and "all
        verified" are the same result.

        **Most rows are expected.** Config files you edited, ghost files created at
        runtime and documentation all legitimately differ, and on a stock system they
        are the bulk of the output. Rows with no file-type marker are packaged files —
        binaries and libraries — and those are the ones worth alarming about.
        """
        scan.sub("RPM Package Verification")
        if not scan.which("rpm"):
            scan.status("rpm", "Not installed", "error")
            return

        probe, probe_rc = scan.run_text_rc(["rpm", "-q", "rpm"])
        if probe_rc != 0 or not probe.strip():
            scan.status("Package Integrity",
                        "UNKNOWN — the rpm database could not be queried; packages "
                        "were NOT verified", "error")
            return

        scan.dim("Running rpm -Va (this may take a while)...")
        # rc 0 (clean) and rc 1 (discrepancies found) are both successful runs.
        out, rc = scan.run_text_rc(["rpm", "-Va"])
        if rc > 1:
            scan.status("Package Integrity",
                        f"UNKNOWN — rpm -Va failed (exit {rc}); packages were NOT "
                        "verified", "error")
            return

        altered, expected = [], []
        for line in out.splitlines():
            m = _VA_RE.match(line.rstrip())
            if not m:
                continue
            (altered if m.group(2) is None else expected).append(line.rstrip())

        if altered:
            scan.status("Package Integrity",
                        f"{len(altered)} packaged file(s) differ from their package",
                        "error")
            scan.result("\n".join(altered[:50]))
        else:
            scan.status("Package Integrity",
                        "No packaged files altered", "ok")
        if expected:
            # Reported, not hidden — but as context, so it cannot drown the signal.
            scan.status("Expected differences",
                        f"{len(expected)} config/ghost/doc file(s) differ "
                        "(normal: you edited them, or they are created at runtime)",
                        "info")
            if scan.verbose:
                scan.result("\n".join(expected[:50]))
