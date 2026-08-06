"""Rendering for axis results — screen, saved report, and JSON.

Kept apart from :mod:`fettle.hardening.report`, which renders the binary axis: that
one is a scored per-package matrix and this one is a short list of concrete defects,
and merging them would mean one function serving two shapes badly.
"""

from __future__ import annotations

import textwrap

from . import SEVERITY_ORDER, AxisResult

_WIDTH = 78
_LABEL = 10          # width of the severity column
_SUBJECT = 22        # width of the subject column


def tally_line(res: AxisResult) -> str:
    """``2 high, 1 medium  (7 checked)`` — or a plain statement that nothing was wrong."""
    counts = res.tally()
    parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s)]
    if not parts:
        return f"nothing to report ({res.checked} checked)"
    return f"{', '.join(parts)}  ({res.checked} checked)"


def _rows(res: AxisResult, *, fix: bool) -> list[str]:
    """One block per finding, worst first, ties broken by subject for a stable order."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    lines: list[str] = []
    for f in sorted(res.findings, key=lambda x: (order.get(x.severity, 9), x.subject)):
        head = f"{f.severity.upper():<{_LABEL}}{f.subject:<{_SUBJECT}}"
        body = textwrap.wrap(f.detail, width=_WIDTH - len(head)) or [""]
        lines.append(head + body[0])
        pad = " " * len(head)
        lines.extend(pad + more for more in body[1:])
        if fix and f.fix:
            lines.append(pad + f"→ {f.fix}")
    return lines


def screen(results: list[AxisResult]) -> list[str]:
    """What prints during the run: only axes with something to say.

    An axis that ran and found nothing is *not* silent — it gets a one-line "nothing
    to report", because a section that vanishes when it passes is indistinguishable
    from a section that never ran. Blindness and non-applicability say so in their own
    words rather than being dropped.
    """
    lines: list[str] = []
    for res in results:
        if res.na:
            lines.append(f"{res.title}: not applicable — {res.na}")
            continue
        if not res.ran and res.blind:
            # The blind entries themselves go to Output.not_checked, which prints
            # them together at the end with an install hint. Here, just do not claim
            # the axis passed.
            lines.append(f"{res.title}: not checked (see below)")
            continue
        lines.append(f"{res.title}: {tally_line(res)}")
        lines.extend("  " + row for row in _rows(res, fix=True))
        for note in res.notes:
            for i, chunk in enumerate(textwrap.wrap(note, width=_WIDTH - 8)):
                lines.append(("  note: " if i == 0 else "        ") + chunk)
    return lines


def report_body(results: list[AxisResult]) -> list[str]:
    """The saved-report section — the same findings, plus what could not be looked at."""
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
            lines.extend(_rows(res, fix=True))
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
                      "detail": f.detail, "fix": f.fix} for f in r.findings],
        "not_checked": [{"what": w, "why": y, "package": p} for w, y, p in r.blind],
        "notes": list(r.notes),
    } for r in results]
