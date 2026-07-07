"""Arch / Manjaro backend (pacman + yay/pamac + AUR).

M2 implements the update path (``clean`` + ``update``) at parity with the bash
``update.sh``; the remaining actions land in later milestones.
"""

from __future__ import annotations

from pathlib import Path

from .. import command
from .base import Context, PackageBackend, Result

_SYSTEM_UPDATERS = {"pacman", "pamac"}
_AUR_UPDATERS = {"yay", "pamac", "none"}


class ArchBackend(PackageBackend):
    name = "arch"
    supported = {
        "clean", "orphans", "update", "rebuilds", "python_rebuild",
        "config_drift", "firmware", "kernels", "aur_audit", "aur_scan",
        "integrity",
    }

    # -- configuration -------------------------------------------------------
    def _updaters(self, ctx: Context) -> tuple[str, str]:
        conf = {}
        if isinstance(ctx.config.updaters, dict):
            conf = ctx.config.updaters.get("arch", {}) or {}
        system = str(conf.get("system_updater", "pacman"))
        aur = str(conf.get("aur_updater", "yay"))
        if system not in _SYSTEM_UPDATERS:
            ctx.output.warn(f"invalid system_updater '{system}'; using pacman")
            system = "pacman"
        if aur not in _AUR_UPDATERS:
            ctx.output.warn(f"invalid aur_updater '{aur}'; using yay")
            aur = "yay"
        return system, aur

    # -- actions -------------------------------------------------------------
    def clean_caches(self, ctx: Context) -> Result:
        out = ctx.output
        ctx.execute(["rm", "-f", "/var/lib/pacman/db.lck"],
                    quiet=True, msg="removed stale pacman db lock")
        ctx.execute(["pacman", "-Scc", "--noconfirm"],
                    quiet=True, msg="pacman cache cleared")
        # pamac's AUR DB is per-user; run it as the user to avoid a spurious warning.
        if ctx.sudo_user and command.which("pamac"):
            ctx.execute(["pamac", "clean", "--no-confirm"], as_user=ctx.sudo_user,
                        quiet=True, msg="pamac cache cleared")
        cache_dirs = [
            ctx.user_home / ".cache/pamac",
            ctx.user_home / ".cache/yay",
            ctx.user_home / ".cache/paru",
        ]
        if ctx.sudo_user:
            cache_dirs.append(Path(f"/var/tmp/pamac-build-{ctx.sudo_user}"))
        for d in cache_dirs:
            ctx.execute(["rm", "-rf", str(d)], quiet=True, msg=f"removed {d}")
        out.summary_add("caches cleaned")
        return Result(summary="caches cleaned")

    def update_system(self, ctx: Context) -> Result:
        out = ctx.output
        system, aur = self._updaters(ctx)
        ctx.execute(["pacman-mirrors", "-f"], quiet=True, msg="mirrors refreshed")

        # pamac is all-in-one: as the AUR updater it drives the repos too.
        if aur == "pamac":
            if system != "pamac":
                out.note("AUR updater is pamac, which manages repos too — using pamac for both.")
            out.note("updating repos + AUR via pamac...")
            ctx.execute(["pamac", "update", "-a", "--enable-downgrade", "--force-refresh"],
                        as_user=ctx.sudo_user)
            out.summary_add("packages updated (pamac: repos + AUR)")
            return Result()

        if system == "pacman":
            out.note("updating official repos (pacman)...")
            ctx.execute(["pacman", "-Syuu", "--noconfirm"])
        else:  # pamac (repos only)
            out.note("updating official repos (pamac)...")
            ctx.execute(["pamac", "update", "--enable-downgrade", "--force-refresh"],
                        as_user=ctx.sudo_user)
        return Result()

    def update_extras(self, ctx: Context) -> Result:
        out = ctx.output
        system, aur = self._updaters(ctx)
        if aur == "pamac":
            return Result()  # already handled in update_system
        if aur == "none":
            out.note("skipping AUR (aur_updater: none).")
            out.summary_add(f"packages updated (repos only, via {system})")
            return Result()
        # aur == "yay"
        if not command.which("yay"):
            out.err("yay not found (aur_updater=yay). Install it, or set aur_updater to pamac/none.")
            return Result(ok=False)
        out.note("updating AUR packages (yay, with PKGBUILD review)...")
        ctx.execute(
            ["yay", "-Sua", "--devel", "--cleanafter", "--answerdiff", "None",
             "--answeredit", "None", "--diffmenu=true", "--editmenu=true"],
            as_user=ctx.sudo_user,
        )
        out.summary_add(f"packages updated (repos: {system}, AUR: yay)")
        out.next_step("check AUR packages before the next build: fettle -A -S")
        return Result()
