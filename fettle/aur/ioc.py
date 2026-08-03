"""IOC feed fetch + TTL disk cache (lenucksi/aur-malware-check).

Replaces ``aur_fetch_bad_accounts`` / ``aur_fetch_bad_packages`` /
``aur_fetch_bad_npm`` (curl + jq). Each campaign file is cached on disk with a
TTL so a bulk audit doesn't refetch per package; a failed fetch falls back to any
stale cache rather than silently reporting "clean".
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from ..util import chown_to_user

DEFAULT_BASE = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/HEAD/data"
DEFAULT_CAMPAIGNS = ("aur-infected", "chaos-rat", "russian-spam")
DEFAULT_TTL = 21600  # 6 hours

# Known malicious JS package names, used as an offline seed when the fetched npm
# IOC list is empty (ported from update.sh's AUR_SEED_BAD_NPM) — so a JS-cache
# scan is never silently "all clear" just because the feed was unreachable.
DEFAULT_NPM_SEED = ("atomic-lockfile", "js-digest", "lockfile-js", "nextfile-js")


def _fetch(url: str, timeout: float = 20.0) -> tuple[str, str]:
    """``(text, status)`` where status is ``ok`` | ``missing`` | ``unreachable``.

    **404 is not a failure.** Campaigns publish different list types — measured
    against the live feed, ``aur-infected`` has all four files while ``chaos-rat`` and
    ``russian-spam`` have no ``packages-extra.txt`` or ``npm-packages.txt`` at all.
    Counting those absences as fetch failures marked every healthy scan as having
    incomplete coverage, which makes the warning worthless precisely when it is true.
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (fixed https base)
            return resp.read().decode("utf-8", "replace"), "ok"
    except urllib.error.HTTPError as exc:
        return "", ("missing" if exc.code == 404 else "unreachable")
    except OSError:
        return "", "unreachable"


def _nonempty(text: str) -> set[str]:
    return {
        ln.strip() for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    }


class IOC:
    """Fetches and caches the campaign IOC lists."""

    def __init__(self, *, cache_dir: Path, base: str = DEFAULT_BASE,
                 campaigns=DEFAULT_CAMPAIGNS, ttl: int = DEFAULT_TTL,
                 owner: str | None = None) -> None:
        self.cache_dir = cache_dir
        self.base = base
        self.campaigns = list(campaigns)
        self.ttl = ttl
        self.owner = owner  # chown cache files back to this user (root-run safety)
        # Feeds served from a stale cache, and feeds that could not be obtained at all.
        # A scan is only as current as its worst feed, and the caller has to be able to
        # say so instead of reporting a confident "clean".
        self.stale: list[str] = []
        self.unavailable: list[str] = []

    @property
    def degraded(self) -> bool:
        """Whether any feed was stale or missing — i.e. coverage is not current."""
        return bool(self.stale or self.unavailable)

    @staticmethod
    def _read(fp: Path) -> str:
        # OSError-safe: an earlier elevated run may have left the cache root-owned;
        # a later unprivileged read must degrade to "no cache", not crash.
        try:
            return fp.read_text()
        except OSError:
            return ""

    def _cached(self, url: str) -> str:
        """Feed text, recording **where it came from**.

        A stale cache is better than reporting "clean" — that was already the design —
        but the caller could not tell fresh data from a month-old fallback, so a scan
        against an outdated feed announced itself exactly like a current one. Provenance
        is tracked in :attr:`stale` and :attr:`unavailable` so the verdict can be
        qualified.
        """
        key = url.replace("://", "_").replace("/", "_")
        fp = self.cache_dir / key
        if fp.is_file() and (time.time() - fp.stat().st_mtime) < self.ttl:
            return self._read(fp)
        text, status = _fetch(url)
        if text:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                fp.write_text(text)
                chown_to_user(self.cache_dir, self.owner)  # don't leave root-owned
                chown_to_user(fp, self.owner)
            except OSError:
                pass
            return text
        if status == "missing":
            return ""      # this campaign simply has no such list; not a gap in coverage
        # Fetch failed — fall back to a stale cache if we have one, and say so.
        if fp.is_file():
            age_days = int((time.time() - fp.stat().st_mtime) // 86400)
            self.stale.append(f"{url.rsplit('/', 2)[-2]}/{fp.name.rsplit('_', 1)[-1]} "
                              f"({age_days}d old)")
            return self._read(fp)
        self.unavailable.append(url.rsplit("/", 2)[-2] + "/" + url.rsplit("/", 1)[-1])
        return ""

    def bad_accounts(self) -> set[str]:
        out: set[str] = set()
        for c in self.campaigns:
            try:
                data = json.loads(self._cached(f"{self.base}/campaigns/{c}/accounts.json") or "{}")
            except ValueError:
                continue
            out.update((data.get("accounts") or {}).keys())
        return out

    def bad_packages(self) -> set[str]:
        out: set[str] = set()
        for c in self.campaigns:
            for f in ("packages.txt", "packages-extra.txt"):
                out |= _nonempty(self._cached(f"{self.base}/campaigns/{c}/{f}"))
        return out

    def bad_npm(self) -> set[str]:
        out: set[str] = set()
        for c in self.campaigns:
            out |= _nonempty(self._cached(f"{self.base}/campaigns/{c}/npm-packages.txt"))
        return out or set(DEFAULT_NPM_SEED)  # never go blind: fall back to the seed
