"""Distro security-advisory / CVE tracking (PLAN.md §19).

For each installed package, surface (a) CVEs with a fix you haven't applied yet, and
(b) — the distinctive part — CVEs the package is currently vulnerable to with **no
fix released yet**. One provider per distro bulk-fetches its tracker into a shared
SQLite cache (`~/.cache/fettle/advisories.db`, rebuildable; sqlite3 is stdlib, so the
zero-dependency core holds) and classifies installed packages against it.

Opt-in: `fettle advisory-check` (never in the default `-a` set). `fettle
advisory-update` refreshes the cache. See PLAN.md §19.8 for the locked design.
"""
