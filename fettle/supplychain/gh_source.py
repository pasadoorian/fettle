"""GitHub CLI (``gh``) extensions — the Package Supply Chain view.

Trust model: a ``gh`` extension is installed straight from **an arbitrary GitHub
repository** with no review, no signing and no registry. The part people miss is
*where it runs*: ``gh`` invokes extensions with your authenticated CLI session
available, so an extension can act as you against every repository and organisation
your token reaches. A one-line extension is a credential-exfiltration primitive.

Provenance is read from the extension directory rather than ``gh extension list``,
whose output is unstructured text with no stable contract. Each installed extension
records its origin on disk in one of two documented shapes — a ``manifest.yml`` for a
precompiled binary extension, or a git clone whose ``origin`` remote names the repo.

Answers: ``UNVERIFIED_PUBLISHER`` (who owns the repo this came from).

Does **not** answer whether the extension's code is malicious, and there is no feed
that would; ``coverage`` says so.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import UNVERIFIED_PUBLISHER, Finding, Severity, SourceProvider

# Owners whose extensions ship from the GitHub CLI project itself. Still unsandboxed,
# but attributable to the vendor you already trust for `gh` — not a third party.
_FIRST_PARTY = frozenset({"cli", "github"})

_EXT_DIR = ".local/share/gh/extensions"
# `owner: dlvhdr` in a binary extension's manifest.yml. Deliberately a line scan and
# not a YAML parse: fettle has no YAML in the standard library and this file has a
# fixed, flat shape.
_MANIFEST_RE = re.compile(r"^\s*(owner|name|host)\s*:\s*(\S+)\s*$", re.M)
# git remotes: git@github.com:owner/repo.git | https://github.com/owner/repo(.git)
_REMOTE_RE = re.compile(r"(?:github\.com[:/])([^/\s]+)/([^/\s]+?)(?:\.git)?\s*$", re.M)


def _origin_from_manifest(text: str) -> tuple[str, str]:
    fields = {k: v for k, v in _MANIFEST_RE.findall(text)}
    return fields.get("owner", ""), fields.get("name", "")


def _origin_from_git_config(text: str) -> tuple[str, str]:
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("url"):
            continue
        m = _REMOTE_RE.search(line)
        if m:
            return m.group(1), m.group(2)
    return "", ""


def extension_origin(ext_dir: Path) -> tuple[str, str]:
    """``(owner, repo)`` for an installed extension, or ``("", "")`` if unknowable."""
    manifest = ext_dir / "manifest.yml"
    if manifest.is_file():
        try:
            owner, name = _origin_from_manifest(manifest.read_text(errors="replace"))
        except OSError:
            owner, name = "", ""
        if owner:
            return owner, (name or ext_dir.name)
    cfg = ext_dir / ".git/config"
    if cfg.is_file():
        try:
            return _origin_from_git_config(cfg.read_text(errors="replace"))
        except OSError:
            return "", ""
    return "", ""


class GhSource(SourceProvider):
    source = "gh"
    coverage = ("GitHub CLI extension provenance: which GitHub repository each "
                "installed extension came from. Extensions run with your "
                "authenticated gh session available, so they can act as you against "
                "everything your token reaches. There is no registry, review or "
                "signing for them, and no IOC feed — this does NOT tell you whether "
                "an extension's code is malicious.")

    def _dir(self, ctx) -> Path:
        home = Path(getattr(ctx, "user_home", None) or Path.home())
        return home / _EXT_DIR

    def is_present(self, ctx) -> bool:
        return self._dir(ctx).is_dir()

    def findings(self, ctx) -> list[Finding]:
        root = self._dir(ctx)
        if not root.is_dir():
            return []
        out: list[Finding] = []
        for ext_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            owner, repo = extension_origin(ext_dir)
            if owner and owner.lower() in _FIRST_PARTY:
                continue                       # ships with the CLI project itself
            if owner:
                out.append(Finding(
                    Severity.WARN, self.source, ext_dir.name, UNVERIFIED_PUBLISHER,
                    f"installed from github.com/{owner}/{repo} — an arbitrary "
                    "repository with no review or signing, and it runs with your "
                    "authenticated gh session, so it can act as you anywhere your "
                    "token reaches"))
            else:
                out.append(Finding(
                    Severity.LOW, self.source, ext_dir.name, UNVERIFIED_PUBLISHER,
                    "installed, but its origin repository could not be determined "
                    "from the extension directory — provenance unknown"))
        return out
