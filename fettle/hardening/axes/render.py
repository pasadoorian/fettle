"""Rendering for axis results — screen, saved report, and JSON.

Kept apart from :mod:`fettle.hardening.report`, which renders the binary axis: that one
is a scored per-package matrix and this one is a short list of concrete defects, and
merging them would mean one function serving two shapes badly.

**On screen the findings are a table, one per axis.** The first version printed each
finding as a wrapped prose block with its remedy underneath, which read as an essay:
five findings filled the terminal and there was no way to scan them. A table trades the
explanation for scannability, and the explanation is not lost — the saved report keeps
the full sentence and the fix for every finding, exactly as the binary axis already
shows a ranked table on screen and writes its full matrix to disk.
"""

from __future__ import annotations

import textwrap

from . import SEVERITY_ORDER, AxisResult

_WIDTH = 78
_SEV_COL = 10        # "Critical" + padding
_SUBJECT_COL = 30    # long enough for a mount point or a sysctl key


def _rank(severity: str) -> int:
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return order.get(severity, len(SEVERITY_ORDER))


def tally_line(res: AxisResult) -> str:
    """``1 High, 3 Medium`` — or a plain statement that nothing was wrong."""
    counts = res.tally()
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s)]
    if not parts:
        return f"nothing to report ({res.checked} checked)"
    return f"{', '.join(parts)}  ({res.checked} checked)"


def table(res: AxisResult) -> list[str]:
    """The findings as aligned rows, worst first, ties broken by subject.

    A subject too wide for its column takes a row of its own and the finding starts on
    the next, still in the FINDING column. Truncating instead would cut a systemd unit
    name mid-hash (`rumble-agent-4b7a89f3-5659-…`), leaving a name you cannot look up;
    letting it overflow in place shunts the finding text off the right margin and
    destroys the alignment the table exists for. Neither is worth it for the two or
    three long subjects a real run produces.
    """
    if not res.findings:
        return []
    pad = " " * (_SEV_COL + _SUBJECT_COL)
    rows = [f"{'SEVERITY':<{_SEV_COL}}{'SUBJECT':<{_SUBJECT_COL}}FINDING"]
    for f in sorted(res.findings, key=lambda x: (_rank(x.severity), x.subject)):
        wrapped = textwrap.wrap(f.short(), width=_WIDTH - len(pad)) or [""]
        if len(f.subject) < _SUBJECT_COL:
            rows.append(f"{f.severity:<{_SEV_COL}}{f.subject:<{_SUBJECT_COL}}{wrapped[0]}")
        else:
            rows.append(f"{f.severity:<{_SEV_COL}}{f.subject}")
            rows.append(pad + wrapped[0])
        rows.extend(pad + more for more in wrapped[1:])
    return rows


def screen(results: list[AxisResult]) -> list[str]:
    """What prints during the run: a heading per axis, then its table.

    An axis that ran and found nothing is *not* silent — it gets a one-line "nothing to
    report", because a section that vanishes when it passes is indistinguishable from
    one that never ran. Blindness and non-applicability say so in their own words.
    """
    lines: list[str] = []
    for res in results:
        if res.na:
            lines.append(f"{res.title}: not applicable — {res.na}")
            continue
        if not res.ran and res.blind:
            # The blind entries themselves go to Output.not_checked, which prints them
            # together at the end with an install hint. Here, just do not claim a pass.
            lines.append(f"{res.title}: not checked (see below)")
            continue
        # An axis that looked at *some* of its subjects must not sign off with a bare
        # "nothing to report" — the invariant applied to partial blindness. The firewall
        # axis is the clearest case: unprivileged it can see that ufw is active and
        # cannot read a single rule.
        partial = (f"  — plus {len(res.blind)} not checked (see below)"
                   if res.blind else "")
        lines.append(f"{res.title}: {tally_line(res)}{partial}")
        lines.extend("  " + row for row in table(res))
        for note in res.notes:
            for i, chunk in enumerate(textwrap.wrap(note, width=_WIDTH - 8)):
                lines.append(("  note: " if i == 0 else "        ") + chunk)
    return lines


def _detail_blocks(res: AxisResult) -> list[str]:
    """The long form, for the saved report: why each finding matters, and the fix."""
    lines: list[str] = []
    for f in sorted(res.findings, key=lambda x: (_rank(x.severity), x.subject)):
        lines.append(f"{f.severity}  {f.subject}  [{f.check}]")
        lines.extend("    " + line for line in textwrap.wrap(f.detail, width=_WIDTH - 4))
        if f.fix:
            lines.extend("    " + line for line in
                         textwrap.wrap(f"fix: {f.fix}", width=_WIDTH - 4))
        lines.append("")
    return lines


def report_body(results: list[AxisResult]) -> list[str]:
    """The saved-report section: the same table, then the full explanation of each
    finding, then whatever could not be looked at."""
    lines: list[str] = []
    for res in results:
        lines.append("")
        lines.append(res.title.upper())
        lines.append("-" * len(res.title))
        if res.na:
            lines.append(f"not applicable — {res.na}")
            continue
        lines.append(tally_line(res))
        if res.findings:
            lines.append("")
            lines.extend(table(res))
            lines.append("")
            lines.extend(_detail_blocks(res))
        if res.detail_rows:
            lines.append("")
            lines.extend(res.detail_rows)
        for note in res.notes:
            lines.append("")
            lines.extend(textwrap.wrap(f"note: {note}", width=_WIDTH))
        for what, why, _pkg in res.blind:
            lines.append("")
            lines.extend(textwrap.wrap(
                f"NOT CHECKED: {what}" + (f" — {why}" if why else ""), width=_WIDTH))
    return lines


def to_dict(results: list[AxisResult]) -> list[dict]:
    """Structured payload for the JSON sibling the HTML dashboard reads."""
    return [{
        "axis": r.name,
        "title": r.title,
        "checked": r.checked,
        "not_applicable": r.na,
        "tally": r.tally(),
        "findings": [{"check": f.check, "subject": f.subject, "severity": f.severity,
                      "summary": f.short(), "detail": f.detail, "fix": f.fix}
                     for f in r.findings],
        "not_checked": [{"what": w, "why": y, "package": p} for w, y, p in r.blind],
        "notes": list(r.notes),
    } for r in results]
