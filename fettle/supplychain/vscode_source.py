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

from .base import (
    Examined,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
    Finding,
    Severity,
    SourceProvider,
    still_upstream_url,
    unverifiable_finding,
    withdrawn_finding,
)

# (profile dir under $HOME, human label). VS Code and VSCodium keep separate trees.
_PROFILES = (
    (".vscode-oss", "vscodium"),
    (".vscode", "vscode"),
    (".vscode-insiders", "vscode-insiders"),
)

# metadata.source values seen in the index. "gallery" = the configured registry
# (Open VSX for VSCodium, the MS marketplace for VS Code); "vsix" = a local file.
_SIDELOADED = "vsix"
_GALLERY = "gallery"

# Where a "gallery" install actually came from. VSCodium is wired to Open VSX and VS
# Code to Microsoft's marketplace; asking the wrong one would report every extension in
# the other ecosystem as withdrawn.
_OPEN_VSX = "https://open-vsx.org/api/{publisher}/{name}"
_MARKETPLACE = "https://marketplace.visualstudio.com/items?itemName={ext_id}"

# The marketplace has no usable JSON endpoint for a single extension — its documented
# gallery path answers 404 for present and absent alike (measured), so the signal is the
# store page's own status. That is a rendered web page, not an API contract, and if it
# ever starts serving 200 with a "not found" body the check would go quietly blind:
# every extension would look present and the audit would report clean having detected
# nothing. So each run first asks about an id that cannot exist. If THAT looks present,
# the discriminator is broken and the answers are thrown away as unknown rather than
# trusted. Same canary reasoning as tests/test_stale_flags.py: "found nothing" and
# "could not look" are the same shape unless you prove you can still see.
_CANARY_ID = "fettle-canary-no-such-publisher.fettle-canary-no-such-extension"


# Where to find the editor's OWN answer to "which gallery am I wired to". The profile
# directory name does NOT decide this, and assuming it does is a false-positive machine:
# measured on a real Arch box, `.vscode-oss` (Code - OSS) is patched to use Microsoft's
# marketplace, so asking Open VSX about its extensions reported `ms-vscode.cpptools` and
# `platformio.platformio-ide` as withdrawn when both are present in the gallery the
# editor actually uses — they were simply never published to Open VSX. VSCodium also
# documents a user-level override for exactly this purpose, so the user's copy is
# checked before the system one.
_USER_PRODUCT_JSON = (
    ".config/VSCodium/product.json",
    ".config/Code - OSS/product.json",
    ".config/Code/product.json",
)
_SYSTEM_PRODUCT_JSON = (
    "/usr/lib/code/product.json",
    "/usr/lib/codium/product.json",
    "/usr/share/code/resources/app/product.json",
    "/usr/share/codium/resources/app/product.json",
    "/opt/visual-studio-code/resources/app/product.json",
    "/opt/vscodium-bin/resources/app/product.json",
)

OPEN_VSX, MARKETPLACE = "openvsx", "marketplace"


def _service_url(text: str) -> str:
    try:
        data = json.loads(text)
    except ValueError:
        return ""
    gallery = data.get("extensionsGallery")
    return str(gallery.get("serviceUrl") or "") if isinstance(gallery, dict) else ""


def gallery_kind(home: Path) -> str:
    """Which registry this editor is wired to: ``OPEN_VSX``, ``MARKETPLACE``, or ``""``.

    Empty means *undetermined*, and undetermined means the removal check is skipped —
    asking the wrong registry does not produce a weaker answer, it produces a confident
    wrong one.
    """
    paths = [home / rel for rel in _USER_PRODUCT_JSON]
    paths += [Path(rel) for rel in _SYSTEM_PRODUCT_JSON]
    for path in paths:
        try:
            url = _service_url(path.read_text(errors="replace"))
        except OSError:
            continue
        if "open-vsx" in url:
            return OPEN_VSX
        if "marketplace.visualstudio.com" in url:
            return MARKETPLACE
    return ""


def _registry_url(kind: str, ext_id: str) -> str:
    """The registry URL for `ext_id` in a gallery of `kind`."""
    if kind == OPEN_VSX:
        publisher, _, name = ext_id.partition(".")
        return _OPEN_VSX.format(publisher=publisher, name=name)
    return _MARKETPLACE.format(ext_id=ext_id)


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
                ".vsix, and whether a registry install is still listed at all. VSCodium's registry is Open VSX, whose namespace vetting is "
                "lighter than Microsoft's marketplace. Does NOT verify that a "
                "publisher is who they claim, and does NOT scan extension code.")

    def _home(self, ctx) -> Path:
        return Path(getattr(ctx, "user_home", None) or Path.home())

    def is_present(self, ctx) -> bool:
        return any(True for _ in _index_paths(self._home(ctx)))

    def findings(self, ctx) -> list[Finding]:
        out: list[Finding] = []
        unknown: list[str] = []
        seen = 0
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

            # Which gallery is this editor actually wired to? Read, never inferred.
            kind = gallery_kind(self._home(ctx))
            has_gallery_installs = any(e["source"] == _GALLERY for e in exts)
            trustworthy = bool(kind)
            if not kind and has_gallery_installs:
                out.append(Finding(
                    Severity.INFO, self.source, label, UNVERIFIABLE,
                    "could not determine which extension gallery this editor uses "
                    "(no readable product.json), so its extensions were NOT checked "
                    "for removal — asking the wrong registry would report every one "
                    "of them as withdrawn"))
            elif kind == MARKETPLACE and has_gallery_installs:
                # The marketplace signal is a rendered page rather than an API contract,
                # so prove the discriminator still works before trusting any answer.
                if still_upstream_url(_registry_url(kind, _CANARY_ID)) is not False:
                    trustworthy = False
                    out.append(Finding(
                        Severity.MEDIUM, self.source, label, UNVERIFIABLE,
                        "the marketplace no longer answers 404 for an extension that "
                        "cannot exist, so a withdrawn extension is indistinguishable "
                        f"from a present one — {label} extensions were NOT checked for "
                        "removal"))

            seen += len(exts)
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
                elif ext["source"] == _GALLERY and trustworthy:
                    # Still offered by the registry it came from? Withdrawal is what a
                    # marketplace DOES to a malicious extension, and an extension runs
                    # unsandboxed with your full privileges, so this is the highest-value
                    # question in this provider.
                    present = still_upstream_url(_registry_url(kind, ext["id"]))
                    if present is False:
                        registry = ("Open VSX" if kind == OPEN_VSX
                                    else "the VS Code marketplace")
                        out.append(withdrawn_finding(
                            self.source, name,
                            f"no longer listed on {registry} — withdrawn, renamed, or "
                            "unpublished by its author. An extension pulled for malware "
                            "looks exactly like this, and it is still installed and "
                            "still running with your full user privileges"))
                    elif present is None:
                        unknown.append(name)
                if not ext["source"]:
                    out.append(Finding(
                        Severity.LOW, self.source, name, UNOFFICIAL_SOURCE,
                        "the editor's index records no install source for this "
                        "extension, so where it came from cannot be established"))
        if unknown:
            out.append(unverifiable_finding(self.source, unknown,
                                            "the extension registry"))
        self.examined = Examined(
            seen, "editor extensions",
            "no editor extensions installed" if not seen
            else ("all installed from a marketplace" if not out else ""))
        return out
