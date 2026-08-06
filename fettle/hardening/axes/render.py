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
    """One block per finding, worst first, ties broken by subject for a stable order.

    A subject too wide for its column gets its own line rather than pushing the detail
    into a four-character gutter — systemd unit names run to 56 characters and the
    fixed-column version wrapped one word per line, which is unreadable.
    """
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    lines: list[str] = []
    for f in sorted(res.findings, key=lambda x: (order.get(x.severity, 9), x.subject)):
        label = f"{f.severity.upper():<{_LABEL}}"
        # Strictly less, so the column always leaves at least one space before the
        # detail: a subject of exactly _SUBJECT characters rendered as
        # "PasswordAuthenticationpassword authentication is enabled…".
        if len(f.subject) < _SUBJECT:
            head = label + f"{f.subject:<{_SUBJECT}}"
            pad = " " * len(head)
            first, rest = head, textwrap.wrap(f.detail, width=max(20, _WIDTH - len(head)))
            lines.append(first + (rest[0] if rest else ""))
            lines.extend(pad + more for more in rest[1:])
        else:
            lines.append(label + f.subject)
            pad = " " * (_LABEL + 2)
            lines.extend(pad + more for more in
                         textwrap.wrap(f.detail, width=max(20, _WIDTH - len(pad))))
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
        # An axis that looked at *some* of its subjects must not sign off with a bare
        # "nothing to report" — that is the invariant applied to partial blindness,
        # and it is easy to miss because the axis genuinely did run. The firewall axis
        # is the clearest case: unprivileged it can see that ufw is active but cannot
        # read a single rule, and "nothing to report" there is close to the opposite
        # of the truth.
        partial = (f"  — plus {len(res.blind)} not checked (see below)"
                   if res.blind else "")
        lines.append(f"{res.title}: {tally_line(res)}{partial}")
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
                      "detail": f.detail, "fix": f.fix} for f in r.findings],
        "not_checked": [{"what": w, "why": y, "package": p} for w, y, p in r.blind],
        "notes": list(r.notes),
    } for r in results]
