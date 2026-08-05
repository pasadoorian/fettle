"""VS Code / VSCodium extensions — the Package Supply Chain view.

Trust model: an extension is unsandboxed Node running with your full user privileges
— your filesystem, your shell, your SSH keys — and it auto-updates. VSCodium installs
from **Open VSX**, whose namespace vetting is materially lighter than Microsoft's
marketplace, so "who published this" is a weaker guarantee than the publisher name
suggests.

The provider reads the editor's own extension index
(``<profile>/extensions/extensions.json``), which is the only local record of *where*
each extension came from — ``metadata.source`` distinguishes a registry install
(``gallery``) from a hand-installed ``.vsix``.

Answers: ``UNOFFICIAL_SOURCE`` (sideloaded, bypassing the registry entirely),
``UNVERIFIABLE`` (the index is unreadable — never silently reported as clean).

The sideload finding describes **the copy currently installed**, not the extension's
history, so updating it from the registry clears it — measured: two extensions flagged
as ``vsix`` were re-fetched by ``codium --update-extensions`` and their index entries
became ``source: gallery``. That is the remediation, and the finding disappearing is how
you can tell it worked.

Does **not** answer whether a publisher is who they claim, or whether extension code is
malicious. Deciding that reliably needs a curated known-good publisher list per
registry, which is a maintenance burden fettle does not take on; ``coverage`` says so.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import UNOFFICIAL_SOURCE, UNVERIFIABLE, Finding, Severity, SourceProvider

# (profile dir under $HOME, human label). VS Code and VSCodium keep separate trees.
_PROFILES = (
    (".vscode-oss", "vscodium"),
    (".vscode", "vscode"),
    (".vscode-insiders", "vscode-insiders"),
)

# metadata.source values seen in the index. "gallery" = the configured registry
# (Open VSX for VSCodium, the MS marketplace for VS Code); "vsix" = a local file.
_SIDELOADED = "vsix"


def _index_paths(home: Path):
    for sub, label in _PROFILES:
        path = home / sub / "extensions/extensions.json"
        if path.is_file():
            yield path, label


def parse_index(text: str) -> list[dict] | None:
    """``extensions.json`` -> ``[{id, version, source, publisher}, …]``, or **None**
    when the file cannot be understood.

    The None/``[]`` distinction is the point: an editor with no extensions and an
    index in an unexpected format both yield "no extensions" otherwise, and the
    second one is a blind spot, not a clean result. (``json.dumps([])`` is the
    non-empty string ``"[]"``, so testing the raw text for content cannot tell them
    apart either.) Tolerant on purpose otherwise — this is the editor's internal
    file, not a public contract, so a shape change degrades to less detail.
    """
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    out = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ident = entry.get("identifier") or {}
        meta = entry.get("metadata") or {}
        ext_id = str(ident.get("id") or "").strip()
        if not ext_id:
            continue
        out.append({
            "id": ext_id,
            "version": str(entry.get("version") or ""),
            "source": str(meta.get("source") or "").strip().lower(),
            "publisher": str(meta.get("publisherDisplayName") or "").strip(),
        })
    return out


class VSCodeSource(SourceProvider):
    source = "vscode"
    coverage = ("VS Code / VSCodium extension provenance from the editor's own index: "
                "which extensions came from the configured registry vs a sideloaded "
                ".vsix. VSCodium's registry is Open VSX, whose namespace vetting is "
                "lighter than Microsoft's marketplace. Does NOT verify that a "
                "publisher is who they claim, and does NOT scan extension code.")

    def _home(self, ctx) -> Path:
        return Path(getattr(ctx, "user_home", None) or Path.home())

    def is_present(self, ctx) -> bool:
        return any(True for _ in _index_paths(self._home(ctx)))

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        for path, label in _index_paths(self._home(ctx)):
            try:
                text = path.read_text(errors="replace")
            except OSError as exc:
                out.append(Finding(
                    Severity.MEDIUM, self.source, label, UNVERIFIABLE,
                    f"could not read {path.name} ({exc.strerror or exc}) — "
                    f"{label} extensions were NOT audited"))
                continue

            exts = parse_index(text)
            if exts is None:
                # Unreadable format is a blind spot, not an empty editor.
                out.append(Finding(
                    Severity.MEDIUM, self.source, label, UNVERIFIABLE,
                    f"{path.name} was not in the expected format — {label} "
                    "extensions were NOT audited"))
                continue

            for ext in exts:
                name = f"{label}:{ext['id']}"
                if ext["source"] == _SIDELOADED:
                    claimed = (f", claiming publisher '{ext['publisher']}'"
                               if ext["publisher"] else "")
                    out.append(Finding(
                        Severity.MEDIUM, self.source, name, UNOFFICIAL_SOURCE,
                        f"installed from a local .vsix file{claimed} — it bypassed the "
                        "registry entirely, so no namespace or publisher check applied; "
                        "extensions run unsandboxed with your full user privileges. "
                        "Re-install it from the registry to clear this "
                        f"({'codium' if label.startswith('vscodium') else 'code'} "
                        "--update-extensions, or install it from the Extensions view)"))
                elif not ext["source"]:
                    out.append(Finding(
                        Severity.LOW, self.source, name, UNOFFICIAL_SOURCE,
                        "the editor's index records no install source for this "
                        "extension, so where it came from cannot be established"))
        return out
