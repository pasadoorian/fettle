"""Container images (docker / podman) — the Package Supply Chain view.

Trust model: a container image is pulled by *name*, and a name like ``:latest`` is a
mutable pointer — the bits behind it change without the name changing, so "the same
image" is a different artifact week to week and nothing on the system records what
actually ran. An image is also frozen once built: unlike a distro package, no updater
touches it, so every CVE published since its build date is still inside it.

Answers: ``MUTABLE_REFERENCE`` (``:latest``), ``STALE_OR_ABANDONED`` (image age),
``UNOFFICIAL_SOURCE`` (registry provenance), ``UNVERIFIABLE`` (the daemon could not be
queried — never silently reported as clean).

Does **not** answer what is *inside* an image. Scanning layers for vulnerable packages
is Trivy's/grype's job and would pull in the unpacking machinery fettle deliberately
avoids; ``coverage`` says so out loud.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .. import command
from ..util import matches_any
from .base import (MUTABLE_REFERENCE, STALE_OR_ABANDONED, UNOFFICIAL_SOURCE,
                   UNVERIFIABLE, Finding, Severity, SourceProvider)

# Checked in order; the first one installed is used.
RUNTIMES = ("docker", "podman")

# Registries with a known operator and a published trust story. Anything else is
# worth a second look — not because it is bad, but because you should know it is
# there. Local builds (no registry in the name) are reported as context, not flagged.
_KNOWN_REGISTRIES = frozenset({
    "docker.io", "registry-1.docker.io", "ghcr.io", "cgr.dev", "quay.io",
    "gcr.io", "registry.k8s.io", "mcr.microsoft.com", "public.ecr.aws",
    "registry.gitlab.com", "registry.access.redhat.com", "docker.elastic.co",
})

_DEFAULT_MAX_AGE_DAYS = 90
_NONE = "<none>"


def _cfg(ctx) -> tuple[int, list[str]]:
    """``(max_age_days, ignore globs)`` from ``[containers]``."""
    c = getattr(getattr(ctx, "config", None), "containers", None) or {}
    try:
        max_age = int(c.get("max_age_days", _DEFAULT_MAX_AGE_DAYS))
    except (TypeError, ValueError):
        max_age = _DEFAULT_MAX_AGE_DAYS
    return max_age, [str(p) for p in (c.get("ignore", []) or [])]


def parse_images(stdout: str) -> list[dict]:
    """One JSON object per line (``--format '{{json .}}'``); skip unparseable lines."""
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _created(value: str):
    """Parse docker's ``CreatedAt``, e.g. ``2026-06-15 10:30:30 -0400 EDT``.

    The trailing zone *abbreviation* follows the numeric offset and ``%z`` cannot
    read it, so only the first three whitespace-separated fields are used.
    """
    parts = str(value).split()
    if len(parts) < 3:
        return None
    try:
        return datetime.strptime(" ".join(parts[:3]), "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None


def _registry(repository: str) -> str:
    """Registry host in a repository name, or ``""`` when there is none.

    A bare name (``cvetool``, ``python``) is either a Docker Hub library image or a
    locally-built one — ``docker images`` cannot distinguish them, so this reports no
    registry rather than guessing.
    """
    head = repository.split("/")[0]
    if "/" in repository and ("." in head or ":" in head or head == "localhost"):
        return head
    return ""


def image_ref(repository: str, tag: str) -> str:
    return f"{repository}:{tag}" if tag and tag != _NONE else repository


class ContainerSource(SourceProvider):
    source = "container"
    coverage = ("local image inventory: mutable :latest tags, image age, registry "
                "provenance, dangling images. Does NOT scan image *contents* for "
                "vulnerable packages — use trivy/grype for that.")

    def is_present(self, ctx) -> bool:
        return any(command.which(r) for r in RUNTIMES)

    def findings(self, ctx) -> list[Finding]:
        runtime = next((r for r in RUNTIMES if command.which(r)), None)
        if runtime is None:
            return []
        proc = command.run([runtime, "images", "--format", "{{json .}}"], capture=True)
        if proc.returncode != 0:
            # The daemon is down, or the user is not in the `docker` group. Reporting
            # nothing here would look identical to "no problems found".
            why = (proc.stderr or proc.stdout).strip().splitlines()
            return [Finding(
                Severity.WARN, self.source, runtime, UNVERIFIABLE,
                f"could not list images (exit {proc.returncode}"
                + (f": {why[0][:120]}" if why else "")
                + ") — images were NOT audited")]

        max_age, ignore = _cfg(ctx)
        now = datetime.now(timezone.utc)
        out: list[Finding] = []
        for img in parse_images(proc.stdout):
            repo = str(img.get("Repository", "") or "")
            tag = str(img.get("Tag", "") or "")
            ref = image_ref(repo, tag)
            if not repo or (ignore and matches_any(ref, ignore)):
                continue

            if repo == _NONE or tag == _NONE:
                out.append(Finding(
                    Severity.INFO, self.source, str(img.get("ID", "") or ref),
                    STALE_OR_ABANDONED,
                    f"dangling image, {img.get('Size', 'unknown size')} — "
                    f"reclaim with `{runtime} image prune`"))
                continue

            if tag == "latest":
                out.append(Finding(
                    Severity.WARN, self.source, ref, MUTABLE_REFERENCE,
                    "pulled by the mutable tag ':latest' — the bits behind this name "
                    "change without the name changing, so nothing records what ran"))

            created = _created(img.get("CreatedAt", ""))
            if created is not None:
                age = (now - created).days
                if age > max_age:
                    # Harsher than the AUR "stale" reading on purpose: an AUR package
                    # still gets distro updates, whereas an image is frozen at build
                    # time and carries every CVE published since.
                    out.append(Finding(
                        Severity.WARN, self.source, ref, STALE_OR_ABANDONED,
                        f"built {age} days ago (over {max_age}); an image is frozen at "
                        "build time, so everything published since is still inside it"))

            registry = _registry(repo)
            if registry and registry not in _KNOWN_REGISTRIES:
                out.append(Finding(
                    Severity.LOW, self.source, ref, UNOFFICIAL_SOURCE,
                    f"from registry '{registry}', which is not one of the "
                    "well-known operators"))
        return out
