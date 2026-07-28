"""OSV language-ecosystem provider (PLAN.md §19.10).

Flags vulnerable **Python (PyPI)** and **Node (npm)** packages your distro does
**not** manage — venvs, uv/pipx apps, per-user installs — which no OS tracker can
see. Queries OSV.dev (via the shared ``osv`` client + SQLite record cache) and
classifies each against its ecosystem's fix state. Cross-platform.

**Scope, and why (2026-07-28).** This provider used to enumerate
``importlib.metadata.distributions()`` — the *running interpreter's* packages. On a
distro box that is the system site-packages, which is entirely package-manager
owned, so it (a) re-reported packages the arch/debian providers already cover,
judging them by PyPI version semantics rather than the distro's own verdict
(backport / not-affected), and (b) missed every venv on the machine. Every location
scanned here is unmanaged *by construction* — a venv, a uv/pipx app, or the per-user
site dir is never owned by the package manager — so there is no overlap to dedupe
and no ownership query to run.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import base, db, osv

# Prefixes owned by the OS package manager: anything under them is the distro
# providers' territory, not ours.
_SYSTEM_PREFIXES = ("/usr", "/opt", "/snap", "/var/lib/flatpak")
# Never descend into these while hunting for venvs.
_PRUNE = {"node_modules", ".git", ".cache", "__pycache__", ".mypy_cache",
          ".ruff_cache", ".tox", "site-packages"}


def _pypi_norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _under_system_prefix(path) -> bool:
    p = str(Path(path).resolve())
    return any(p == pre or p.startswith(pre + "/") for pre in _SYSTEM_PREFIXES)


def _env_label(env: Path) -> str:
    """Short, human-meaningful name for an environment. A venv is usually named
    ``venv``/``.venv``/``venv-<task>`` inside the project it belongs to, so the
    parent directory is the useful identifier (``SploitScan``, not ``venv``)."""
    name = env.name
    if name.startswith(".venv") or name == "venv" or name.startswith("venv-"):
        return env.parent.name or name
    return name


def _site_packages(env: Path) -> list[Path]:
    """``site-packages`` dirs inside a venv/tool environment (any Python version)."""
    return [p for p in env.glob("lib/python*/site-packages") if p.is_dir()]


def _find_venvs(root: Path, max_depth: int) -> list[Path]:
    """Environment dirs (those containing ``pyvenv.cfg``) under ``root``, bounded.

    Depth-bounded and prune-listed on purpose: an unbounded walk of ``$HOME`` took
    over two minutes on a real machine, which is not acceptable inside a run.
    """
    found, root = [], root.expanduser()
    if not root.is_dir():
        return found
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        if len(here.parts) - base_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _PRUNE]
        if "pyvenv.cfg" in filenames:
            found.append(here)
            dirnames[:] = []                     # don't recurse into a venv
    return found


class OsvLanguageSource(base.AdvisoryProvider):
    source = "osv"

    def is_present(self, ctx) -> bool:
        return True                              # queries OSV.dev; enumerates what's installed

    # -- fetch/classify (querybatch installed pkgs -> classified rows) --------
    def refresh(self, conn, ctx=None) -> int:
        meta, queries = [], []                   # meta[i] = (eco, name, version, env)
        for eco, name, ver, env in self._installed(ctx):
            meta.append((eco, name, ver, env))
            queries.append({"package": {"ecosystem": eco, "name": name}, "version": ver})
        if not queries:
            db.replace_source(conn, self.source, [])
            return 0
        try:
            batches = osv.querybatch(queries)
        except (OSError, ValueError):
            return -1
        rows = []
        for (eco, name, ver, env), vulns in zip(meta, batches):
            for v in vulns:
                rec = osv.record(conn, v.get("id"), v.get("modified"))
                cl = osv.classify(rec, eco, ver) if rec else None
                if cl is None:
                    continue
                status, fixed = cl
                band, cvss = osv.severity(rec)
                # The environment is part of the package identity here: the same
                # vulnerable package in three venvs is three things to fix, and
                # dedup keys on this name, so it must not collapse them.
                rows.append((self.source, v.get("id"), f"{env}:{name}", status, band,
                             ver, fixed, json.dumps(osv.cve_ids(rec)), None,
                             f"https://osv.dev/vulnerability/{v.get('id')}", eco, cvss))
        db.replace_source(conn, self.source, osv.dedup_rows(rows))
        conn.commit()                            # persist osv_vulns cached during record()
        return len(rows)

    def findings(self, ctx, conn) -> list[base.AdvisoryFinding]:
        out = []
        for (gid, pkg, status, sev, installed, fixed, cves_json, _adv, url,
             dclass, cvss) in db.all_rows(conn, self.source):
            out.append(base.AdvisoryFinding(
                source=self.source, package=pkg, installed_version=installed,
                status=(base.PENDING_FIX if status == "pending" else base.FIXED_AVAILABLE),
                severity=sev, cves=json.loads(cves_json) if cves_json else [],
                fixed_version=fixed or None, group_id=gid, distro_class=dclass,
                url=url, cvss=cvss))
        return out

    def uncovered(self, ctx) -> list[str]:
        return []

    # -- installed language packages (unmanaged environments only) -----------
    def _cfg(self, ctx) -> tuple[list[str], int]:
        adv = getattr(getattr(ctx, "config", None), "advisories", None) or {}
        roots = adv.get("venv_roots")
        if roots is None:
            roots = ["~/src"]
        return [str(r) for r in roots], int(adv.get("venv_depth", 3))

    def _home(self, ctx) -> Path:
        return Path(getattr(ctx, "user_home", None) or Path.home())

    def _environments(self, ctx) -> list[tuple[str, Path]]:
        """``(label, site-packages dir)`` for every unmanaged Python environment."""
        out: list[tuple[str, Path]] = []
        home = self._home(ctx)

        # pip install --user — unmanaged by definition (skipped if it is somehow
        # a system path, e.g. running as root with a /usr user-base).
        try:
            import site
            user = Path(site.getusersitepackages())
            if user.is_dir() and not _under_system_prefix(user):
                out.append(("user", user))
        except Exception:                        # site is absent in some embeddings
            pass

        # uv tools and pipx apps: one environment per installed application.
        for tools_dir in (home / ".local/share/uv/tools",
                          home / ".local/share/pipx/venvs",
                          home / ".local/pipx/venvs"):
            if tools_dir.is_dir():
                for env in sorted(p for p in tools_dir.iterdir() if p.is_dir()):
                    out += [(env.name, sp) for sp in _site_packages(env)]

        # project venvs under the configured roots
        roots, depth = self._cfg(ctx)
        for root in roots:
            for env in _find_venvs(Path(root).expanduser(), depth):
                out += [(_env_label(env), sp) for sp in _site_packages(env)]
        return out

    def _node_dirs(self, ctx) -> list[tuple[str, Path]]:
        """``(label, node_modules dir)`` for unmanaged Node installs. The npm global
        root is skipped when it sits under a system prefix (distro-packaged)."""
        out, home = [], self._home(ctx)
        for label, nm in (("npm-global", home / ".npm-global/lib/node_modules"),
                          ("nvm", home / ".nvm/versions/node"),
                          ("bun", home / ".bun/install/global/node_modules")):
            if label == "nvm" and nm.is_dir():
                for ver in sorted(p for p in nm.iterdir() if p.is_dir()):
                    mods = ver / "lib/node_modules"
                    if mods.is_dir():
                        out.append((f"nvm:{ver.name}", mods))
            elif nm.is_dir() and not _under_system_prefix(nm):
                out.append((label, nm))
        return out

    def _installed(self, ctx):
        return self._pip(ctx) + self._npm(ctx)

    def _pip(self, ctx):
        try:
            from importlib.metadata import distributions
        except Exception:
            return []
        seen: dict[tuple, tuple] = {}
        for label, sp in self._environments(ctx):
            try:
                dists = list(distributions(path=[str(sp)]))
            except Exception:
                continue
            for dist in dists:
                name, ver = getattr(dist, "name", None), getattr(dist, "version", None)
                if name and ver:
                    norm = _pypi_norm(name)
                    seen.setdefault((label, norm), ("PyPI", norm, ver, label))
        return list(seen.values())

    def _npm(self, ctx):
        """Read ``node_modules/*/package.json`` directly — no npm needed, and it
        works for bun/nvm trees that ``npm ls -g`` would not report."""
        seen: dict[tuple, tuple] = {}
        for label, mods in self._node_dirs(ctx):
            for pkg_dir in sorted(p for p in mods.iterdir() if p.is_dir()):
                scoped = [pkg_dir] if not pkg_dir.name.startswith("@") else \
                    sorted(p for p in pkg_dir.iterdir() if p.is_dir())
                for d in scoped:
                    try:
                        meta = json.loads((d / "package.json").read_text("utf-8", "replace"))
                    except (OSError, ValueError):
                        continue
                    name, ver = meta.get("name"), meta.get("version")
                    if name and ver:
                        seen.setdefault((label, name), ("npm", name, ver, label))
        return list(seen.values())
