"""RHEL-family advisory provider — errata from the local dnf metadata.

Covers RHEL, CentOS Stream, Rocky, AlmaLinux and Oracle Linux. Advisories come from
the repositories' own ``updateinfo`` metadata via ``dnf``: local, authoritative for the
repos you actually use, and needing no network beyond the metadata dnf already has.
It is also the only source that reflects *your* repo mix — a box on CentOS Stream and
one on the Red Hat CDN genuinely have different errata.

**Red Hat publishes no OVAL for RHEL 10 and onward** (OVAL v2 is in maintenance mode
and is not produced for new releases), so the OVAL approach used for Ubuntu does not
transfer. OSV is likewise avoided here: it carries a ``Red Hat`` ecosystem, but a probe
returned 550 records for a single kernel version because it includes RHBA/RHEA bug and
enhancement advisories — it would duplicate dnf, more noisily.

**Both dnf4 and dnf5.** RHEL 10.1 ships dnf 4.20; Fedora 44 and future RHEL ship
dnf5, whose output is a completely different shape. The two are gated on
``dnf --version`` containing the literal ``dnf5`` — not on a path check, since on a
dnf5 system dnf5 *is* ``/usr/bin/dnf`` while on RHEL 10.1 that path is a symlink to
``dnf-3``. This matters more than a normal compatibility branch: dnf5 keeps
``updateinfo`` as an alias for ``advisory``, so the dnf4 command **succeeds** there
and merely returns an unparseable shape — 19 real advisories read as zero, and the
blind-spot warning below would then wrongly announce that the repos publish no
errata.

**The blind spot this provider exists to name.** `updateinfo` only knows advisories a
repository publishes, and CentOS Stream publishes none. A real RHEL 10.1 box was
observed with **341 pending package updates and zero security advisories** — reporting
that as "no findings" would be a clean bill of health for a system a year behind. So
when there are no security advisories *and* packages are upgradable, this says the
repos carry no errata rather than implying safety.

Everything reported is ``FIXED_AVAILABLE``: `updateinfo` describes advisories that have
a fix. "Vulnerable, no fix yet" is not knowable from it and would need Red Hat's
CSAF/VEX feed.
"""

from __future__ import annotations

import json
import re

from .. import command
from ..distro import parse_os_release
from . import base, db

# os-release IDs this provider claims. Fedora is excluded on purpose: it shares dnf,
# but its advisories are Bodhi `FEDORA-*` with different severity conventions.
RHEL_IDS = frozenset({"rhel", "centos", "rocky", "almalinux", "ol"})

# `dnf updateinfo list --security` rows:
#   ALSA-2026:22715 Important/Sec. expat-2.7.3-1.el10_2.1.x86_64
# The `--with-cve` variant is deliberately NOT used: it emits three rows per advisory
# (the upstream RHSA, the CVE, and the distro's own id), which triple-counts and makes
# a CVE id look like an advisory id.
_LIST_RE = re.compile(r"^(\S+)\s+(\S+?)/Sec\.\s+(\S+)\s*$")

# `dnf updateinfo info` fields. Restricting to a KNOWN key set is what makes this
# parseable at all: the block *title* (`  Important: acl security update`) and prose
# inside Description (`  * acl: Symlink traversal ...`) both look like `Key: value`.
_FIELDS = ("Update ID", "Type", "Updated", "Bugs", "CVEs", "Description", "Severity")
_FIELD_RE = re.compile(r"^\s*(" + "|".join(_FIELDS) + r"):\s?(.*)$")
# Continuation of the previous field — used by Bugs, CVEs *and* Description.
_CONT_RE = re.compile(r"^\s+:\s?(.*)$")

# RHEL severity vocabulary -> fettle's bands. RHEL has no "High"; "Important" is its
# equivalent and must not be flattened into Medium.
_SEVERITY = {"critical": "Critical", "important": "High",
             "moderate": "Medium", "low": "Low", "none": "Unknown"}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def is_dnf5() -> bool:
    """True when ``dnf`` is dnf5.

    Detected from ``dnf --version`` output containing the literal ``dnf5``
    (``dnf5 version 5.4.2.1``), **not** from a path check: on a dnf5 system dnf5 *is*
    ``/usr/bin/dnf``, and on RHEL 10.1 ``/usr/bin/dnf`` is a symlink to ``dnf-3``.
    """
    proc = command.run(["dnf", "--version"], capture=True)
    return "dnf5" in (proc.stdout + proc.stderr).lower()


def parse_list_json(stdout: str) -> list[tuple[str, str, str]]:
    """``[(advisory, severity, nevra), …]`` from dnf5 ``advisory list --json``.

    Entries look like ``{"name": "FEDORA-…", "type": "security", "severity":
    "Important", "nevra": "libacl-2.4.0-1.fc44.x86_64", "buildtime": …}``.
    """
    try:
        data = json.loads(stdout)
    except ValueError:
        return []
    out = []
    for e in data if isinstance(data, list) else []:
        if not isinstance(e, dict):
            continue
        name, nevra = str(e.get("name") or ""), str(e.get("nevra") or "")
        if name and nevra:
            out.append((name, str(e.get("severity") or ""), nevra))
    return out


def parse_info_json(stdout: str) -> dict[str, dict]:
    """``{advisory: {"cves": [...], "severity": str}}`` from dnf5 ``advisory info
    --json``.

    CVEs are taken from structured ``references`` of type ``cve`` when present, and
    otherwise recovered by scanning reference titles and the description. That
    fallback is not belt-and-braces — on Fedora **every** reference is a ``bugzilla``
    and none is a ``cve``, yet 7 of 8 advisories name their CVE in a reference title
    or description. (It is also why ``--with-cve`` must not be used to *fetch*: on
    dnf5 that flag is a filter, and it drops every advisory lacking a cve reference.)
    """
    try:
        data = json.loads(stdout)
    except ValueError:
        return {}
    out: dict[str, dict] = {}
    for e in data if isinstance(data, list) else []:
        if not isinstance(e, dict):
            continue
        name = str(e.get("Name") or "")
        if not name:
            continue
        refs = e.get("references") or []
        cves = [str(r.get("Id") or "") for r in refs
                if isinstance(r, dict) and str(r.get("Type", "")).lower() == "cve"]
        cves = [c for c in cves if c.startswith("CVE-")]
        if not cves:
            haystack = " ".join([str(e.get("Description") or "")]
                                + [str(r.get("Title") or "") for r in refs
                                   if isinstance(r, dict)])
            cves = list(dict.fromkeys(_CVE_RE.findall(haystack)))
        out[name] = {"cves": cves, "severity": str(e.get("Severity") or "")}
    return out


def parse_list(stdout: str) -> list[tuple[str, str, str]]:
    """``[(advisory_id, severity, nevra), …]`` from ``updateinfo list --security``."""
    out = []
    for line in stdout.splitlines():
        m = _LIST_RE.match(line.rstrip())
        if m:
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


def parse_info(stdout: str) -> dict[str, dict]:
    """``{advisory_id: {"cves": [...], "severity": str, "title": str}}``.

    Blocks are separated by rules of ``=``; fields are right-aligned so their
    indentation varies, and continuation lines are ``<pad>: <value>``.
    """
    records: dict[str, dict] = {}
    cur: dict = {}
    last_key = ""

    def flush():
        uid = cur.get("Update ID", "").strip()
        if uid:
            records[uid] = {
                "cves": _CVE_RE.findall(cur.get("CVEs", "")),
                "severity": cur.get("Severity", "").strip(),
                "title": cur.get("_title", "").strip(),
            }

    for raw in stdout.splitlines():
        if set(raw.strip()) == {"="} and raw.strip():
            flush()
            cur, last_key = {}, ""
            continue
        m = _FIELD_RE.match(raw)
        if m:
            last_key = m.group(1)
            cur[last_key] = m.group(2)
            continue
        c = _CONT_RE.match(raw)
        if c and last_key:
            cur[last_key] = cur.get(last_key, "") + "\n" + c.group(1)
            continue
        # Not a field and not a continuation: the block title, which sits between two
        # `=` rules and would otherwise parse as a field (`Important: acl security
        # update`). Keep it only if we have not started collecting fields yet.
        if raw.strip() and not cur:
            cur["_title"] = raw.strip()
            last_key = ""
    flush()
    return records


def _split_nevra(nevra: str) -> tuple[str, str]:
    """``(name, evr)`` from a NEVRA.

    ``expat-2.7.3-1.el10_2.1.x86_64`` -> ``("expat", "2.7.3-1.el10_2.1")`` and
    ``openssl-libs-1:3.5.5-4.el10_2.alma.1.x86_64`` -> ``("openssl-libs",
    "1:3.5.5-4.el10_2.alma.1")``. Package names may contain hyphens, so the split
    keys on the version field starting with a digit (or an ``epoch:`` prefix).
    """
    stem = nevra.rsplit(".", 1)[0]                 # drop arch
    parts = stem.rsplit("-", 2)                    # name, [epoch:]version, release
    if len(parts) == 3 and parts[1].split(":")[-1][:1].isdigit():
        return parts[0], f"{parts[1]}-{parts[2]}"
    return stem, ""


def _nevra_name(nevra: str) -> str:
    return _split_nevra(nevra)[0]


def installed_versions() -> dict[str, str]:
    """``{name: evr}`` for every installed package, in one rpm call.

    Without this the report shows only the fix target ("-> 2.7.3-1"), which reads
    oddly next to the other providers and hides how far behind you actually are.
    """
    proc = command.run(["rpm", "-qa", "--qf", "%{NAME} %{EVR}\\n"], capture=True)
    if proc.returncode != 0:
        return {}
    out = {}
    for line in proc.stdout.splitlines():
        name, _, evr = line.partition(" ")
        if name and evr:
            out.setdefault(name.strip(), evr.strip())
    return out


class RhelAdvisorySource(base.AdvisoryProvider):
    source = "rhel"

    def _osrel(self, ctx) -> dict:
        try:
            from pathlib import Path
            return parse_os_release(Path(getattr(ctx, "root", None) or "/"))
        except Exception:
            return {}

    def is_present(self, ctx) -> bool:
        osr = self._osrel(ctx)
        ids = {osr.get("ID", "").lower(), *osr.get("ID_LIKE", "").lower().split()}
        return bool(ids & RHEL_IDS) and command.which("dnf")

    # -- fetch ---------------------------------------------------------------
    def _fetch(self) -> tuple[list, dict, bool]:
        """``(list_rows, info_by_advisory, ok)`` for whichever dnf is installed.

        The two versions are **not** interchangeable. dnf5 keeps ``updateinfo`` as an
        alias for ``advisory``, so the dnf4 command still exits 0 there — it simply
        prints a different, table-shaped format that the dnf4 regex cannot match,
        yielding zero rows with no error. That silent-empty result would then be
        reported as "these repos publish no security errata", which on a dnf5 system
        is flatly wrong.
        """
        if is_dnf5():
            listing = command.run(
                ["dnf", "advisory", "list", "--available", "--security", "--json"],
                capture=True)
            if listing.returncode != 0:
                return [], {}, False
            info = command.run(
                ["dnf", "advisory", "info", "--available", "--security", "--json"],
                capture=True)
            return (parse_list_json(listing.stdout),
                    parse_info_json(info.stdout) if info.returncode == 0 else {}, True)

        listing = command.run(["dnf", "updateinfo", "list", "--security"], capture=True)
        if listing.returncode != 0:
            return [], {}, False
        info = command.run(["dnf", "updateinfo", "info", "--security"], capture=True)
        return (parse_list(listing.stdout),
                parse_info(info.stdout) if info.returncode == 0 else {}, True)

    def refresh(self, conn, ctx=None) -> int:
        rows_in, details, ok = self._fetch()
        if not ok:
            return -1

        installed = installed_versions()
        rows = []
        for advisory, sev_word, nevra in rows_in:
            detail = details.get(advisory, {})
            band = _SEVERITY.get((detail.get("severity") or sev_word).lower(), "Unknown")
            name, fixed_evr = _split_nevra(nevra)
            rows.append((
                self.source, advisory, name, "fixable", band,
                installed.get(name, ""), fixed_evr or nevra,
                json.dumps(detail.get("cves", [])), advisory,
                f"https://access.redhat.com/errata/{advisory}"
                if advisory.startswith("RHSA") else "",
                "security",
            ))
        db.replace_source(conn, self.source, rows)
        return len(rows)

    # -- report --------------------------------------------------------------
    def findings(self, ctx, conn) -> list[base.AdvisoryFinding]:
        out = []
        for (gid, pkg, _status, sev, installed, fixed, cves_json, adv, url,
             dclass, _cvss) in db.all_rows(conn, self.source):
            out.append(base.AdvisoryFinding(
                source=self.source, package=pkg, installed_version=installed,
                status=base.FIXED_AVAILABLE, severity=sev,
                cves=json.loads(cves_json) if cves_json else [],
                fixed_version=fixed or None, group_id=gid, advisory_id=adv,
                distro_class=dclass, url=url))
        self._warn_if_blind(ctx, out)
        return out

    def _warn_if_blind(self, ctx, findings) -> None:
        """Say so when the repos carry no security errata.

        Zero advisories is ambiguous: it means "fully patched" *or* "these repos
        publish no errata". CentOS Stream is the second case, and a real RHEL 10.1 box
        showed 341 pending updates alongside zero advisories. Pending updates with no
        advisories at all is the tell.
        """
        out = getattr(ctx, "output", None)
        if findings or out is None:
            return
        pending = command.run(["dnf", "-q", "check-update"], capture=True)
        # dnf's documented exit codes: 0 = nothing to update, 100 = updates available,
        # anything else = error. 100 is success, not failure.
        if pending.returncode == 100:
            n = sum(1 for ln in pending.stdout.splitlines()
                    if ln[:1].isalnum() and len(ln.split()) >= 3)
            out.warn(
                f"no security advisories, but {n} package update(s) are pending — "
                "these repositories publish no security errata (CentOS Stream does "
                "not), so this is a blind spot, NOT a clean bill of health")

    def uncovered(self, ctx) -> list[str]:
        # Every installed package is covered as far as the repos' errata go; the
        # meaningful gap is the repo one, reported by _warn_if_blind.
        return []
