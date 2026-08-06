"""``fettle pkg-integrity`` (``-V``) — do installed files still match the package?

Split out of ``sys-audit`` in v0.72.0. It had lived there as the ``packages``
category, which put a *package* question inside the *firmware and boot chain*
scanner, and coupled a multi-second file-hashing pass to every ``-S`` run.

**What it compares against, and what that is worth.** Each package manager records a
manifest when it installs a package — pacman's MTREE in ``/var/lib/pacman/local``,
dpkg's ``.md5sums`` in ``/var/lib/dpkg/info``, rpm's file digests in the rpmdb — and
this re-reads every installed file and compares it to that record. So it answers
**"has anything changed since installation?"** It does *not* answer "was the package
authentic": the manifest came from the same package, and anything that can rewrite a
system file as root can usually rewrite the manifest too. It is a tripwire, not a
proof — useful precisely because most intruders do not bother to update the manifest.

Which is why the three outcomes are kept apart, rather than summed into "issues":

``differ``
    A packaged file whose contents no longer match. The finding.
``regenerated``
    Rewritten after install by a tool, never by a person — depmod's ``modules.*``
    index, plugin caches, mirror lists. Present on every machine, so it carries no
    information. Reported as a count, listed with ``-v``.
``not verified``
    Files that could not be read, or packages that ship no checksums. A gap in
    coverage. Counting these as findings was the bug that made the old check
    unreadable: 65 of its 82 "issues" were permission errors.
"""

from __future__ import annotations
from .output import FOUND

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .backends.base import Context, PackageBackend


def run(backend: "PackageBackend", ctx: "Context") -> None:
    from .secure.base import Scan

    out = ctx.output
    scan = Scan(output=out, root=ctx.root, verbose=out.verbose)
    try:
        backend.verify_integrity(scan)
    except NotImplementedError:
        out.warn(f"package integrity is not implemented for the {backend.name} "
                 "backend — nothing was verified.")
        out.summary_warn("pkg-integrity did NOT run — unsupported backend")
        return

    errors = [r for r in scan.records if r["level"] == "error"]
    warns = [r for r in scan.records if r["level"] == "warn"]
    if errors:
        out.summary_fail("pkg-integrity: " + "; ".join(
            f"{r['label']}: {r['value']}" for r in errors), kind=FOUND)
        out.next_step("check each file against what installed it before assuming "
                      "tampering — an upgrade interrupted mid-write looks the same.")
    if warns:
        out.summary_warn("pkg-integrity: " + "; ".join(
            f"{r['label']}: {r['value']}" for r in warns))
    if not errors and not warns:
        out.summary_add("pkg-integrity: installed files match their packages")

    _write_report(scan, ctx)


def _write_report(scan, ctx: "Context") -> None:
    from . import reports
    if not scan.records:
        return
    try:
        path = reports.write_report("pkg-integrity", scan.report_text(), ctx,
                                    data=scan.report_data())
        ctx.output.note(f"report saved to {path}")
    except OSError as exc:
        ctx.output.warn(f"could not write pkg-integrity report: {exc}")
