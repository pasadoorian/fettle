"""GNOME Shell extensions — the Package Supply Chain view.

Trust model: extension JavaScript runs **inside the ``gnome-shell`` process itself**,
not in a sandbox. An enabled extension can observe and drive the entire session — every
window, keystroke path and notification — with your privileges. That is the widest
blast radius of any desktop add-on, and extensions.gnome.org review is light.

The question fettle can answer well is **attribution**: an extension under
``/usr/share`` came from a package your distro (or the AUR) built and can be traced to
a package; one under ``~/.local/share/gnome-shell/extensions`` was dropped in by hand
or by e.g.o. and nothing records where it came from.

Answers: ``UNOFFICIAL_SOURCE`` (unattributed, weighted by whether it is enabled),
``UNVERIFIABLE`` (the extension tool failed — never silently reported as clean).

Does **not** answer whether an extension's *code* is malicious; there is no IOC feed
for e.g.o., and ``coverage`` says so.
"""

from __future__ import annotations

from pathlib import Path

from .. import command
from .base import UNOFFICIAL_SOURCE, UNVERIFIABLE, Finding, Severity, SourceProvider

_TOOL = "gnome-extensions"


def _uuids(stdout: str) -> list[str]:
    """UUIDs from a bare ``gnome-extensions list`` — one per line."""
    return [ln.strip() for ln in stdout.splitlines() if ln.strip()]


def parse_details(stdout: str, uuids) -> dict[str, dict]:
    """Parse ``gnome-extensions list --details`` into ``{uuid: {field: value}}``.

    Block boundaries are taken from the *known uuid set* rather than from
    indentation: a ``Description:`` wraps onto continuation lines that carry **no**
    leading whitespace, so "unindented line starts a new extension" silently merges
    the next extension into the previous one's description.
    """
    known = set(uuids)
    out: dict[str, dict] = {}
    current = None
    for raw in stdout.splitlines():
        line = raw.strip()
        if line in known:
            current = line
            out[current] = {}
            continue
        if current is None or ":" not in raw:
            continue
        key, _, value = raw.strip().partition(":")
        key = key.strip()
        # Only real field lines are indented; a wrapped description is not, and its
        # prose can still contain a colon.
        if raw[:1].isspace() and key:
            out[current][key] = value.strip()
    return out


def _owned_by_package(path: str) -> bool | None:
    """True/False if a package manager claims ``path``, None if we cannot ask.

    None matters: "no package owns this" and "I have no way to check" must not be
    reported as the same thing.
    """
    if command.which("pacman"):
        return command.run(["pacman", "-Qo", "--", path], capture=True).returncode == 0
    if command.which("dpkg"):
        return command.run(["dpkg", "-S", "--", path], capture=True).returncode == 0
    return None


class GnomeSource(SourceProvider):
    source = "gnome"
    coverage = ("GNOME Shell extension attribution: which extensions are packaged "
                "(traceable to a package) vs dropped in by hand, and whether they are "
                "enabled. No malware/IOC feed exists for extensions.gnome.org, so "
                "this does NOT tell you whether an extension's code is malicious.")

    def is_present(self, ctx) -> bool:
        return command.which(_TOOL)

    def findings(self, ctx) -> list[Finding]:
        if not command.which(_TOOL):
            return []
        listing = command.run([_TOOL, "list"], capture=True)
        if listing.returncode != 0:
            why = (listing.stderr or listing.stdout).strip().splitlines()
            return [Finding(
                Severity.MEDIUM, self.source, _TOOL, UNVERIFIABLE,
                f"could not list extensions (exit {listing.returncode}"
                + (f": {why[0][:120]}" if why else "")
                + ") — extensions were NOT audited")]

        uuids = _uuids(listing.stdout)
        if not uuids:
            return []
        details = parse_details(
            command.run([_TOOL, "list", "--details"], capture=True).stdout, uuids)

        home = str(Path(getattr(ctx, "user_home", None) or Path.home()))
        out: list[Finding] = []
        for uuid in uuids:
            info = details.get(uuid, {})
            path = info.get("Path", "")
            enabled = info.get("Enabled", "").strip().lower() == "yes"

            # Under the user's home => hand-installed (or from e.g.o.); nothing records
            # its origin. Elsewhere, ask the package manager: a system-path extension
            # that no package owns was placed there by hand as root, which is stranger
            # still.
            if path and path.startswith(home):
                attributed = False
            else:
                owned = _owned_by_package(path) if path else None
                if owned is None:
                    continue                       # cannot tell — do not claim
                attributed = owned
            if attributed:
                continue

            where = "in your home directory" if path.startswith(home) else \
                    "in a system directory but owned by no package"
            out.append(Finding(
                Severity.MEDIUM if enabled else Severity.LOW, self.source, uuid,
                UNOFFICIAL_SOURCE,
                ("ENABLED and unattributed" if enabled else "installed but disabled")
                + f" — {where}; extension code runs inside the gnome-shell process "
                "itself, with full access to your session"))
        return out
