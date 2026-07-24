"""Shared apt/dpkg advisory base for the Debian and Ubuntu providers.

Both classify installed SOURCE packages against cached rows the same way (dpkg for
version comparison + source mapping); only the *fetch/parse* of their tracker
differs. Subclasses implement ``is_present`` + ``refresh`` and set ``source``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .. import command
from ..distro import parse_os_release
from . import base, db


class AptAdvisorySource(base.AdvisoryProvider):
    def _osrel(self, ctx=None) -> dict:
        root = (getattr(ctx, "root", None) if ctx else None) or "/"
        try:
            return parse_os_release(Path(root))
        except Exception:
            return {}

    def _codename(self, ctx=None) -> str:
        return self._osrel(ctx).get("VERSION_CODENAME", "") or ""

    def _installed(self) -> dict[str, str]:
        proc = command.run(["dpkg-query", "-W", "-f=${source:Package} ${Version}\n"],
                           capture=True)
        out: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] not in out:
                out[parts[0]] = parts[1]
        return out

    def _behind(self, installed: str, fixed: str) -> bool:
        """True if ``installed`` < ``fixed`` per ``dpkg --compare-versions``."""
        return command.run(
            ["dpkg", "--compare-versions", installed, "lt", fixed]).returncode == 0

    def findings(self, ctx, conn) -> list[base.AdvisoryFinding]:
        installed = self._installed()
        if not installed:
            return []
        out: list[base.AdvisoryFinding] = []
        for (group_id, pkg, status, severity, _aff, fixed, cves_json,
             _adv, url, dclass, cvss) in db.all_rows(conn, self.source):
            iv = installed.get(pkg)
            if iv is None:
                continue
            if status == "pending":
                norm, fx = base.PENDING_FIX, None
            elif status == "fixable" and fixed and self._behind(iv, fixed):
                norm, fx = base.FIXED_AVAILABLE, fixed
            else:
                continue                           # patched / not applicable
            out.append(base.AdvisoryFinding(
                source=self.source, package=pkg, installed_version=iv, status=norm,
                severity=severity, cves=json.loads(cves_json) if cves_json else [],
                fixed_version=fx, group_id=group_id, distro_class=dclass, url=url,
                cvss=cvss))
        return out

    def uncovered(self, ctx) -> list[str]:
        # reliably flagging third-party/local .debs is a known limitation (noted in
        # the report); return nothing rather than a misleading "0 uncovered".
        return []
