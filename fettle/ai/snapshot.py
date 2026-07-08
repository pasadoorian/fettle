"""System snapshot for the Upgrade Checker — the payload we send to the model.

Gathers ``inxi -SCGaxxa`` (colour off), os-release, kernel, and the pending-upgrade
list into one compact, factual payload. Hardware **serials / MAC addresses / UUIDs
are redacted before anything leaves the machine** (privacy: send redacted, no
per-run prompt). Grounding the model on these real facts — rather than asking it to
recall — is the primary anti-hallucination lever (see PLAN §Phase 4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .. import command
from ..distro import parse_os_release

_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_SERIAL = re.compile(r"(?i)\bserial:\s*\S+")


def redact(text: str) -> str:
    """Strip hardware serials, MAC addresses, and UUIDs from inxi output."""
    text = _SERIAL.sub("serial: <redacted>", text)
    text = _MAC.sub("<mac>", text)
    return _UUID.sub("<uuid>", text)


@dataclass
class Snapshot:
    distro: str
    kernel: str
    inxi: str
    pending: list  # list[(name, old_ver, new_ver)]

    def as_prompt(self) -> str:
        """Compact, factual text block for the model (keeps input tokens low)."""
        lines = [f"Distribution: {self.distro}", f"Kernel: {self.kernel}", "",
                 f"Pending package upgrades ({len(self.pending)}):"]
        lines += [f"  {n}  {o} -> {new}" for n, o, new in self.pending] or ["  (none)"]
        lines += ["", "System info (inxi -SCGaxxa, redacted):",
                  self.inxi or "  (inxi not installed)"]
        return "\n".join(lines)


def gather(ctx, backend, *, root: Path = Path("/")) -> Snapshot:
    osr = parse_os_release(root)
    distro = osr.get("PRETTY_NAME") or osr.get("ID") or "unknown"
    kernel = command.run(["uname", "-r"], capture=True).stdout.strip()
    inxi = ""
    if command.which("inxi"):
        # -c 0 disables colour so the payload is clean text (no ANSI leakage).
        raw = command.run(["inxi", "-SCGaxxa", "-c", "0"], capture=True).stdout
        inxi = redact(raw.strip())
    return Snapshot(distro=distro, kernel=kernel, inxi=inxi,
                    pending=backend.pending_upgrades(ctx))
