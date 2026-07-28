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
"""

from __future__ import annotations

from . import command
from .supplychain.container_source import RUNTIMES, image_ref, parse_images
from .util import matches_any

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


def _images(runtime: str) -> tuple[list[tuple[str, str]], str]:
    """``([(ref, repo), …], error)`` — tagged images only (dangling can't be pulled)."""
    proc = command.run([runtime, "images", "--format", "{{json .}}"], capture=True)
    if proc.returncode != 0:
        why = (proc.stderr or proc.stdout).strip().splitlines()
        return [], (f"exit {proc.returncode}" + (f": {why[0][:120]}" if why else ""))
    seen: dict[str, str] = {}
    for img in parse_images(proc.stdout):
        repo = str(img.get("Repository", "") or "")
        tag = str(img.get("Tag", "") or "")
        if not repo or repo == _NONE or tag == _NONE:
            continue
        seen.setdefault(image_ref(repo, tag), repo)
    return sorted(seen.items()), ""


def run(ctx) -> None:
    out = ctx.output
    runtime = next((r for r in RUNTIMES if command.which(r)), None)
    if runtime is None:
        out.note("no container runtime (docker/podman) found; nothing to update.")
        return

    images, err = _images(runtime)
    if err:
        # Same reasoning as the audit provider: "could not look" must not read as
        # "nothing to do".
        out.warn(f"could not list images ({err}) — no images were updated.")
        return
    if not images:
        out.note("no tagged images present; nothing to update.")
        return

    cfg = _cfg(ctx)
    pulled: list[str] = []
    failed: list[str] = []
    skipped: list[str] = []
    deferred: list[str] = []          # needed a human, and there wasn't one

    for ref, repo in images:
        action, why = decide(ref, repo, cfg)

        if action == ASK:
            if ctx.dry_run:
                out.note(f"would ask before pulling {ref}")
                deferred.append(ref)
                continue
            if ctx.assume_yes:
                # Unattended: config decides, silence does not. This must come BEFORE
                # ctx.confirm(), which returns True under assume_yes and would pull
                # every unlisted image.
                out.note(f"{ref}: skipped (unattended; not in always_update)")
                deferred.append(ref)
                continue
            action = PULL if ctx.confirm(f"pull {ref}?", default=False) else SKIP
            why = "confirmed" if action == PULL else "declined"

        if action == SKIP:
            out.note(f"{ref}: skipped ({why})")
            skipped.append(ref)
            continue

        proc = ctx.execute([runtime, "pull", ref], quiet=True, msg=f"pulling {ref}")
        if getattr(proc, "returncode", 0) == 0:
            pulled.append(ref)
        else:
            out.warn(f"{ref}: pull failed (exit {proc.returncode})")
            failed.append(ref)

    if ctx.dry_run:
        out.note(f"dry-run: {len(images)} image(s) considered, nothing pulled.")
        return

    bits = [f"{len(pulled)} image(s) pulled"]
    if failed:
        bits.append(f"{len(failed)} failed")
    if skipped:
        bits.append(f"{len(skipped)} skipped")
    if deferred:
        bits.append(f"{len(deferred)} left for a human")
    out.summary_add("containers: " + ", ".join(bits))
    if deferred and ctx.assume_yes:
        out.next_step("container-update skipped images awaiting confirmation; run it "
                      "interactively, or list them in [containers] always_update.")
