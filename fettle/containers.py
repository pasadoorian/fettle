"""``fettle container-update`` (``-C``) — refresh images, one decision at a time.

This is the only *state-changing* part of the container work: the audit half lives in
``supplychain/container_source.py``. Pulling an image replaces what runs on the next
`docker run`, so nothing is pulled implicitly — an image is refreshed only when policy
says so or a human says yes.

Decision order per image (first match wins)::

    auto_update = "never"      -> skip everything, no prompts
    auto_update = "always"     -> pull everything, no prompts
    matches never_update       -> skip
    matches always_update      -> pull
    otherwise                  -> ask

**Unattended runs honour config only.** Under ``--yes`` the "ask" case is *skipped*,
not auto-approved: an image you never explicitly opted into must never be pulled
without a human seeing the question. Note this deliberately bypasses
:meth:`Context.confirm`, which returns True under ``assume_yes``.

**Locally-built images are never offered.** They have no registry to refresh from, and
``docker pull cvetool:latest`` does not fail safely — it resolves to Docker Hub, a
registry that never served that image (see :func:`_local_builds`).

**Every installed runtime is used**, not just the first: a host with both docker and
podman keeps two separate image stores, and considering one while reporting a single
total makes a partial look identical to a complete one.
"""

from __future__ import annotations

from . import command
from .supplychain.container_source import (RUNTIMES, image_ref, images_argv,
                                           parse_images)
from .util import matches_any
from .output import FAILED

_NONE = "<none>"

PULL, SKIP, ASK = "pull", "skip", "ask"


def _cfg(ctx) -> dict:
    return getattr(getattr(ctx, "config", None), "containers", None) or {}


def _listed(ref: str, repo: str, patterns) -> bool:
    """Match a glob list against the full ``repo:tag`` *and* the bare repository, so
    ``never_update = ["cvetool"]`` works without having to write ``cvetool:*``."""
    patterns = [str(p) for p in (patterns or [])]
    return bool(patterns) and (matches_any(ref, patterns) or matches_any(repo, patterns))


def decide(ref: str, repo: str, cfg: dict) -> tuple[str, str]:
    """``(action, why)`` for one image — ``pull`` / ``skip`` / ``ask``."""
    mode = str(cfg.get("auto_update", "ask")).strip().lower()
    if mode == "never":
        return SKIP, "auto_update = never"
    if mode == "always":
        return PULL, "auto_update = always"
    if _listed(ref, repo, cfg.get("never_update")):
        return SKIP, "never_update"
    if _listed(ref, repo, cfg.get("always_update")):
        return PULL, "always_update"
    return ASK, "not listed"


def _local_builds(runtime: str, refs: list[str]) -> set[str]:
    """Of *refs*, the ones that were never pulled from a registry.

    An image built here has no ``RepoDigest``; every pulled one has at least one. That
    matters because "update this image" means ``<runtime> pull <ref>``, and for a bare
    name like ``cvetool:latest`` that resolves to Docker Hub — a registry which never
    served this image. Today the pull simply fails (measured: *denied / unauthorized*),
    so offering it only buys guaranteed failures. But the name is *unclaimed*, not
    reserved, and were someone to publish it, a "yes" would replace a local build with a
    stranger's image. Not offering them costs nothing: there is genuinely nothing to
    refresh.

    Best-effort — if the inspect fails we return nothing and every image stays eligible,
    which is the pre-existing behaviour rather than a new way to skip things silently.
    """
    if not refs:
        return set()
    # Both runtimes render these fields as Go slices ("[]" when empty), and each line
    # carries its own tags, so a ref the runtime cannot inspect drops out without
    # shifting the others.
    proc = command.run([runtime, "image", "inspect", "--format",
                        "{{.RepoDigests}}#{{.RepoTags}}", *refs], capture=True)
    local: set[str] = set()
    for line in (proc.stdout or "").splitlines():
        digests, _, tags = line.partition("#")
        if digests.strip() != "[]":
            continue
        for tag in tags.strip().strip("[]").split():
            if tag in refs:
                local.add(tag)
    return local


def _images(runtime: str) -> tuple[list[tuple[str, str]], str]:
    """``([(ref, repo), …], error)`` — tagged images only (dangling can't be pulled)."""
    proc = command.run(images_argv(runtime), capture=True)
    if proc.returncode != 0:
        why = (proc.stderr or proc.stdout).strip().splitlines()
        return [], (f"exit {proc.returncode}" + (f": {why[0].strip()}" if why else ""))
    seen: dict[str, str] = {}
    for img in parse_images(proc.stdout):
        repo = str(img.get("Repository", "") or "")
        tag = str(img.get("Tag", "") or "")
        if not repo or repo == _NONE or tag == _NONE:
            continue
        seen.setdefault(image_ref(repo, tag), repo)
    return sorted(seen.items()), ""


_MODES = ("ask", "always", "never")


def run(ctx) -> None:
    out = ctx.output
    runtimes = [r for r in RUNTIMES if command.which(r)]
    if not runtimes:
        out.note("no container runtime (docker/podman) found; nothing to update.")
        out.summary_add("containers: no runtime installed — nothing to update")
        return

    cfg = _cfg(ctx)
    mode = str(cfg.get("auto_update", "ask")).strip().lower()
    if mode not in _MODES:
        # A config value that does not parse must say so. `auto_update = false` is a
        # natural thing to write in TOML and reads as "never" — it silently meant
        # "ask", so a user could believe images were pinned when they were not.
        out.warn(f"[containers] auto_update = {cfg.get('auto_update')!r} is not one of "
                 f"{', '.join(_MODES)}; using 'ask'.")

    pulled: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []
    deferred: list[str] = []          # needed a human, and there wasn't one
    local: list[str] = []             # built here; no registry to refresh from
    blind: list[str] = []             # a runtime we could not read at all
    considered = 0

    # Both runtimes, not just the first. wopr has docker and podman with different
    # image sets; reading one and reporting a single total made 11 of 14 look like all
    # of them.
    for runtime in runtimes:
        tag = f"[{runtime}] " if len(runtimes) > 1 else ""
        images, err = _images(runtime)
        if err:
            # Same reasoning as the audit provider: "could not look" must not read as
            # "nothing to do".
            out.warn(f"{tag}could not list images ({err}) — no images were updated.")
            blind.append(runtime)
            continue
        if not images:
            out.note(f"{tag}no tagged images present; nothing to update.")
            continue

        considered += len(images)
        built_here = _local_builds(runtime, [ref for ref, _ in images])

        for ref, repo in images:
            if ref in built_here:
                out.note(f"{tag}{ref}: built here, not from a registry — nothing to pull")
                local.append(ref)
                continue

            action, why = decide(ref, repo, cfg)

            if action == ASK:
                if ctx.dry_run:
                    out.note(f"{tag}would ask before pulling {ref}")
                    deferred.append(ref)
                    continue
                if ctx.assume_yes:
                    # Unattended: config decides, silence does not. This must come
                    # BEFORE ctx.confirm(), which returns True under assume_yes and
                    # would pull every unlisted image.
                    out.note(f"{tag}{ref}: skipped (unattended; not in always_update)")
                    deferred.append(ref)
                    continue
                action = PULL if ctx.confirm(f"pull {tag}{ref}?", default=False) else SKIP
                why = "confirmed" if action == PULL else "declined"

            if action == SKIP:
                out.note(f"{tag}{ref}: skipped ({why})")
                skipped.append(ref)
                continue

            proc = ctx.execute([runtime, "pull", ref], quiet=True, msg=f"pulling {tag}{ref}")
            if getattr(proc, "returncode", 0) == 0:
                pulled.append(ref)
            else:
                out.warn(f"{tag}{ref}: pull failed (exit {proc.returncode})")
                failed.append(ref)

    if ctx.dry_run:
        out.note(f"dry-run: {considered} image(s) considered, nothing pulled.")
        out.summary_add(f"containers: {considered} image(s) considered (dry-run, "
                        "nothing pulled)")
        return

    bits = [f"{len(pulled)} image(s) pulled"]
    for count, label in ((failed, "failed"), (skipped, "skipped"),
                         (deferred, "left for a human"), (local, "built here")):
        if count:
            bits.append(f"{len(count)} {label}")
    line = "containers: " + ", ".join(bits)

    # A tick means "asked and answered". A pull that failed, or a runtime that could not
    # be read, is neither.
    if blind:
        names = ", ".join(blind)
        out.summary_warn(f"{line} — but {names} could NOT be read; those images "
                         "were not assessed")
    elif failed:
        out.summary_fail(f"{line} — those images were NOT updated", kind=FAILED)
    elif deferred:
        out.summary_warn(f"{line} — decisions still outstanding")
    else:
        out.summary_add(line)

    if deferred and ctx.assume_yes:
        out.next_step("container-update skipped images awaiting confirmation; run it "
                      "interactively, or list them in [containers] always_update.")
