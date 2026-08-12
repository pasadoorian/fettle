"""Rendering for axis results — screen, saved report, and JSON.

Kept apart from :mod:`fettle.hardening.report`, which renders the binary axis: that one
is a scored per-package matrix and this one is a short list of concrete defects, and
merging them would mean one function serving two shapes badly.

**On screen the findings are ONE table across every axis, ranked worst first.** The
first version printed each finding as a wrapped prose block with its remedy underneath,
which read as an essay: five findings filled the terminal and there was no way to scan
them. The second gave every axis its own table, which scanned well for one axis and
repeated the column header four times once `compromise-check` arrived with four check
groups. One table with a GROUP column says the same thing once, and ranks across the
whole action — which is the order a reader wants it in, since "the worst thing here" is
not usually in the first group.

The per-axis tallies survive as their own lines above the table, so *"kernel: 1 Low
(1176 checked)"* is still there. They carry the coverage number, which the table cannot.

Three layout rules, each of which replaced something that looked wrong on a real run:

* **Width follows the terminal**, capped at 120 and fixed at 80 when output is not a
  TTY. The cap is because past ~120 the eye loses the row between severity and finding;
  the fixed value when piped is so a run-log does not change shape with the window that
  produced it.
* **A subject too long for its column is truncated in the middle**, keeping both ends.
  `rumble-agent-4b7a89f3…9787dae3cf6.service` stays one scannable row and stays
  distinguishable from its sibling, which differs only in the UUID. The previous
  behaviour gave a long subject its own row and left the finding text floating in the
  middle of the screen with nothing to its left.
* **The full, untruncated everything is in the saved report**, which is written at a
  fixed width and never adapts.
"""

from __future__ import annotations

import shutil
import sys
import textwrap

from . import SEVERITY_ORDER, AxisResult

_REPORT_WIDTH = 78   # the saved report: fixed, so a file does not depend on a window
_MIN_WIDTH = 60
_MAX_WIDTH = 120
_SEV_COL = 10        # "Critical" + padding
_MIN_SUBJECT = 24
_SUBJECT_SHARE = 0.45


def screen_width() -> int:
    """Columns to render into.

    Not a TTY -> 80, always. `fettle` output is captured into `~/.fettle/logs/` and
    piped into `less` and `grep`; a log whose column widths depend on how wide the
    window happened to be is a log you cannot diff against yesterday's.
    """
    try:
        if not sys.stdout.isatty():
            return 80
        columns = shutil.get_terminal_size((80, 24)).columns
    except (OSError, ValueError):           # pragma: no cover — defensive
        return 80
    return max(_MIN_WIDTH, min(_MAX_WIDTH, columns))


def truncate_middle(text: str, limit: int) -> str:
    """Keep both ends of an over-long string, and say so with an ellipsis.

    Both ends, not the head: the two unowned units on the reference machine are
    `rumble-agent-4b7a89f3-…-e9787dae3cf6.service` and
    `rumble-agent-e87f42e9-…-9848a53c857d.service`. Head-truncation renders those
    identically, which turns two findings into one indistinguishable pair.
    """
    if len(text) <= limit:
        return text
    if limit <= 1:
        return text[:limit]
    keep = limit - 1
    head = (keep + 1) // 2
    return text[:head] + "…" + text[len(text) - (keep - head):]


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


def table(results, *, width: int | None = None, group_column: bool = True) -> list[str]:
    """Every finding across every axis as one table, worst first.

    ``results`` may be a single :class:`AxisResult` or a list of them: the saved report
    renders one axis at a time under its own heading, the screen renders them together,
    and both want the same columns. A single result implies no GROUP column, since the
    heading above it already says which axis it is.

    Column widths come from the data, not from constants. A run whose subjects are all
    short does not leave half the terminal empty, and one with a 56-character unit name
    gives it room before falling back to truncation.
    """
    if isinstance(results, AxisResult):
        results, group_column = [results], False
    rows_in = [(r, f) for r in results for f in r.findings]
    if not rows_in:
        return []
    rows_in.sort(key=lambda rf: (_rank(rf[1].severity), rf[0].name, rf[1].subject))
    # A GROUP column that says the same word on every row is noise, and on a narrow
    # terminal it is noise charged to the subject's width. Dropped when every finding
    # came from one axis — which is the common case for `-H` on a tidy machine.
    group_column = group_column and len({r.name for r, _ in rows_in}) > 1

    total = (width or screen_width()) - 2
    group_col = (max(len(r.name) for r, _ in rows_in) + 2) if group_column else 0
    avail = total - _SEV_COL - group_col
    longest = max(len(f.subject) for _, f in rows_in)
    # Never narrower than its own header plus a gutter: with subjects like `/tmp` and
    # `/var` the data-driven width came out at 6, and `SUBJECT` (7) ran straight into
    # `FINDING` with no space between them.
    subject_col = min(longest + 2, max(_MIN_SUBJECT, int(avail * _SUBJECT_SHARE)))
    subject_col = max(subject_col, len("SUBJECT") + 2)
    finding_col = max(20, avail - subject_col)

    header = f"{'SEVERITY':<{_SEV_COL}}"
    if group_column:
        header += f"{'GROUP':<{group_col}}"
    header += f"{'SUBJECT':<{subject_col}}FINDING"
    rows = [header]

    pad = " " * (_SEV_COL + group_col + subject_col)
    for res, f in rows_in:
        line = f"{f.severity:<{_SEV_COL}}"
        if group_column:
            line += f"{res.name:<{group_col}}"
        # -2, not -1: a subject truncated flush to its column leaves a single
        # space before the finding, and the two run together when read quickly.
        subject = truncate_middle(f.subject, subject_col - 2)
        wrapped = textwrap.wrap(f.short(), width=finding_col) or [""]
        rows.append(line + f"{subject:<{subject_col}}{wrapped[0]}")
        rows.extend(pad + more for more in wrapped[1:])
    return rows


def screen(results: list[AxisResult]) -> list[str]:
    """What prints during the run: a coverage line per axis, then one ranked table.

    An axis that ran and found nothing is *not* silent — it gets a one-line "nothing to
    report", because a section that vanishes when it passes is indistinguishable from
    one that never ran. Blindness and non-applicability say so in their own words, and
    those lines are the only place the *coverage* number appears: the table below them
    carries findings, and findings cannot say how much was looked at.
    """
    lines: list[str] = []
    label = max((len(r.name) for r in results), default=0) + 1
    for res in results:
        name = f"{res.name + ':':<{label}}"
        if res.na:
            lines.append(f"{name} not applicable — {res.na}")
            continue
        if not res.ran and res.blind:
            # The blind entries themselves go to Output.not_checked, which prints them
            # together at the end with an install hint. Here, just do not claim a pass.
            lines.append(f"{name} not checked (see below)")
            continue
        # An axis that looked at *some* of its subjects must not sign off with a bare
        # "nothing to report" — the invariant applied to partial blindness. The firewall
        # axis is the clearest case: unprivileged it can see that ufw is active and
        # cannot read a single rule.
        partial = (f"  — plus {len(res.blind)} not checked (see below)"
                   if res.blind else "")
        lines.append(f"{name} {tally_line(res)}{partial}")

    rows = table(results)
    if rows:
        lines.append("")
        lines.extend(rows)

    # Notes last, and prefixed with the axis that raised them. They were interleaved
    # between the per-axis tables before, which put a four-line paragraph between two
    # findings and broke the scan the table exists for.
    notes = [(res, n) for res in results for n in res.notes]
    if notes:
        lines.append("")
        wrap = screen_width() - 8
        for res, note in notes:
            for i, chunk in enumerate(textwrap.wrap(f"{res.name}: {note}", width=wrap)):
                lines.append(("note: " if i == 0 else "      ") + chunk)
    return lines


def _detail_blocks(res: AxisResult) -> list[str]:
    """The long form, for the saved report: why each finding matters, and the fix."""
    lines: list[str] = []
    for f in sorted(res.findings, key=lambda x: (_rank(x.severity), x.subject)):
        lines.append(f"{f.severity}  {f.subject}  [{f.check}]")
        lines.extend("    " + line
                     for line in textwrap.wrap(f.detail, width=_REPORT_WIDTH - 4))
        if f.fix:
            lines.extend("    " + line for line in
                         textwrap.wrap(f"fix: {f.fix}", width=_REPORT_WIDTH - 4))
        lines.append("")
    return lines


def report_body(results: list[AxisResult]) -> list[str]:
    """The saved-report section: the same table, then the full explanation of each
    finding, then whatever could not be looked at.

    Rendered at a fixed width, and with **subjects never truncated** — the screen
    trades completeness for scannability and this is where the reader gets the whole
    string back.
    """
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
            lines.extend(table(res, width=_REPORT_WIDTH))
            lines.append("")
            lines.extend(_detail_blocks(res))
        if res.detail_rows:
            lines.append("")
            lines.extend(res.detail_rows)
        for note in res.notes:
            lines.append("")
            lines.extend(textwrap.wrap(f"note: {note}", width=_REPORT_WIDTH))
        for what, why, _pkg in res.blind:
            lines.append("")
            lines.extend(textwrap.wrap(
                f"NOT CHECKED: {what}" + (f" — {why}" if why else ""),
                width=_REPORT_WIDTH))
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
