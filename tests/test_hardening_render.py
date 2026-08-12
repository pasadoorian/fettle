"""Rendering the axes: the on-screen table, the saved report, and the short-label rule.

The load-bearing test here is :func:`test_every_finding_has_a_label_that_fits_a_table`.
`Finding.short()` derives its label by splitting `detail` on an em-dash, which works
because details are written as ``<what is wrong> — <why it matters>`` — and would fail
silently the moment somebody wrote one in a different shape, rendering a 140-character
paragraph into a table cell. So the rule is checked against every finding the real axes
can produce, rather than trusted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from fettle.hardening.axes import (CRITICAL, HIGH, LOW, MEDIUM, SEVERITY_ORDER,
                                   AxisResult, Finding)
from fettle.hardening.axes import certs, filesystem, kernel, render, ssh

# Wide enough to be readable at 80 columns after the SEVERITY and SUBJECT columns, and
# short enough that a row stays scannable. Two wrapped lines is the practical ceiling.
_MAX_LABEL = 80


def _every_real_finding() -> list[Finding]:
    """One of each finding the axes can emit, built from deliberately bad inputs."""
    found: list[Finding] = []

    # ssh — the axis whose details do NOT take the em-dash shape, so every one of these
    # carries an explicit summary. If that ever regresses this is what catches it.
    found += ssh.findings_for({
        "permitrootlogin": "yes", "passwordauthentication": "yes",
        "permitemptypasswords": "yes", "hostbasedauthentication": "yes",
        "ignorerhosts": "no", "gatewayports": "yes", "x11forwarding": "yes",
        "permittunnel": "ethernet", "maxauthtries": "20", "ciphers": "3des-cbc",
        "macs": "hmac-md5", "kexalgorithms": "diffie-hellman-group1-sha1",
        "hostkeyalgorithms": "ssh-dss"})
    found += ssh.findings_for({"permitrootlogin": "yes", "passwordauthentication": "no"})
    found += ssh.findings_for({"passwordauthentication": "yes"})
    return found


def test_every_finding_has_a_label_that_fits_a_table():
    findings = _every_real_finding()
    assert len(findings) >= 12, "the sample stopped covering the axis — check the inputs"
    for f in findings:
        label = f.short()
        assert label, f"{f.check} has no short form at all"
        assert len(label) <= _MAX_LABEL, (
            f"{f.check}: short form is {len(label)} chars and would fill the table:\n"
            f"  {label}\n"
            f"Give it an explicit summary= if the detail is not '<what> — <why>'.")
        assert "—" not in label, f"{f.check}: the em-dash split did not happen"


def test_the_long_detail_survives_for_the_report():
    """The table drops the explanation; the report must not. Losing it in both places
    would trade scannability for the reason to care, which is the wrong trade."""
    f = ssh.findings_for({"permitrootlogin": "yes", "passwordauthentication": "yes"})[0]
    assert len(f.detail) > len(f.short())
    assert "reachable by guessing" in f.detail
    body = render.report_body([AxisResult(name="ssh", title="SSH", checked=1,
                                          findings=[f])])
    assert any("reachable by guessing" in line for line in body)
    assert any("PermitRootLogin prohibit-password" in line for line in body)


# -- the on-screen table -----------------------------------------------------

def _res(*findings: Finding) -> AxisResult:
    return AxisResult(name="t", title="Test axis", checked=9, findings=list(findings))


def test_the_table_has_a_header_and_one_row_per_finding():
    rows = render.table(_res(
        Finding(check="a", subject="/tmp", detail="world-writable — anything", severity=HIGH),
        Finding(check="b", subject="/var", detail="mounted without nodev — meh", severity=LOW)))

    assert rows[0].split() == ["SEVERITY", "SUBJECT", "FINDING"]   # no GROUP: one axis
    assert rows[1].startswith("High")
    assert "/tmp" in rows[1] and "world-writable" in rows[1]
    assert "anything" not in rows[1]           # the why stays out of the table


def test_rows_are_ordered_worst_first():
    rows = render.table(_res(
        Finding(check="c", subject="c", detail="c", severity=LOW),
        Finding(check="a", subject="a", detail="a", severity=CRITICAL),
        Finding(check="b", subject="b", detail="b", severity=MEDIUM),
        Finding(check="d", subject="d", detail="d", severity=HIGH)))
    assert [r.split()[0] for r in rows[1:]] == ["Critical", "High", "Medium", "Low"]


def test_a_long_subject_is_truncated_in_the_middle_keeping_both_ends():
    """One scannable row beats a complete name on a row of its own.

    The previous behaviour gave an over-long subject its own row and put the finding on
    the next one, which left the finding text floating mid-screen with nothing to its
    left. Middle-truncation keeps the row intact — and keeps **both ends**, which is
    what makes the two runZero units below distinguishable: they differ only in the
    UUID, so head-truncation would render them identically. The untruncated name is in
    the saved report.
    """
    a = "rumble-agent-4b7a89f3-5659-48e1-bfb9-e9787dae3cf6.service"
    b = "rumble-agent-e87f42e9-2542-4615-891b-9848a53c857d.service"
    rows = render.table(_res(
        Finding(check="x", subject=a, detail="exposure 9.6 UNSAFE — something",
                severity=MEDIUM),
        Finding(check="x", subject=b, detail="dead unit — its binary is gone",
                severity=MEDIUM)), width=100)

    assert len(rows) == 3, "one header, one row each — nothing spilled onto a second"
    assert "…" in rows[1] and "…" in rows[2]
    assert rows[1] != rows[2], "the two units must not collapse into the same string"
    assert rows[1].startswith("Medium    rumble-agent-")      # head kept
    assert ".service" in rows[1]                              # tail kept too
    assert "exposure 9.6 UNSAFE" in rows[1]                   # on the SAME row


def test_truncation_keeps_both_ends():
    assert render.truncate_middle("abcdefghij", 20) == "abcdefghij"   # fits, untouched
    out = render.truncate_middle("abcdefghijklmnop", 9)
    assert out == "abcd…mnop"                       # 4 + ellipsis + 4 = 9
    assert render.truncate_middle("abcdef", 1) == "a"   # degenerate, still bounded


def test_width_is_stable_when_output_is_not_a_terminal():
    """A run-log whose column widths depend on the window that produced it is a log you
    cannot diff against yesterday's."""
    assert render.screen_width() == 80        # pytest captures stdout: not a TTY


def test_a_short_subject_stays_on_one_row():
    rows = render.table(_res(Finding(check="x", subject="/tmp",
                                     detail="short — why", severity=HIGH)))
    assert len(rows) == 2
    assert rows[1].startswith("High      /tmp")


def test_an_axis_with_no_findings_has_no_table():
    assert render.table(_res()) == []


# -- severity vocabulary -----------------------------------------------------

def test_the_scale_matches_the_binary_axis():
    """One vocabulary across the whole action, so a reader holds one scale and the
    dashboard can rank across both halves."""
    from fettle.hardening.score import BAND_ORDER

    assert list(SEVERITY_ORDER) == list(BAND_ORDER)


@pytest.mark.parametrize("axis_findings", [
    lambda: filesystem.run(None, _ctx_missing()).findings,
])
def test_axes_emit_only_known_severities(axis_findings):
    for f in axis_findings():
        assert f.severity in SEVERITY_ORDER


def _ctx_missing():
    from pathlib import Path
    from types import SimpleNamespace

    from fettle.config import Config
    return SimpleNamespace(root=Path("/nonexistent-for-tests"), config=Config())


def test_severity_words_are_capitalised_everywhere():
    """They were lower-case while the binary axis said Critical/High/Medium/Low, so one
    screen carried two vocabularies for the same idea."""
    assert (CRITICAL, HIGH, MEDIUM, LOW) == ("Critical", "High", "Medium", "Low")


# -- certs, whose severity depends on a clock --------------------------------

def test_certificate_labels_are_short_too():
    now = datetime(2026, 8, 7, tzinfo=timezone.utc)
    paths = [__import__("pathlib").Path("/etc/nginx/a.pem")]
    from unittest.mock import patch

    from fettle import command
    for value, want in (("Aug  1 00:00:00 2026 GMT", "expired"),
                        ((now + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT"),
                         "expires in")):
        with patch("fettle.command.run",
                   return_value=command.Proc(0, f"notAfter={value}\nsubject=CN=x\n", "")):
            found, _ = certs.findings_for(paths, now, 30)
        assert len(found) == 1
        assert want in found[0].short()
        assert len(found[0].short()) <= _MAX_LABEL


def test_kernel_labels_are_short_too():
    from pathlib import Path
    root = Path("/nonexistent")
    for f in kernel.redirect_findings(root):
        assert len(f.short()) <= _MAX_LABEL


def test_short_subjects_do_not_collapse_the_header():
    """`SUBJECT` is seven characters, and the column width comes from the data.

    With subjects like `/tmp` and `/var` the computed width was 6, so the header
    rendered as `SUBJECTFINDING` with nothing between them.
    """
    rows = render.table(_res(
        Finding(check="a", subject="/tmp", detail="world-writable — why", severity=HIGH),
        Finding(check="b", subject="/var", detail="no nodev — why", severity=LOW)))
    assert rows[0].split() == ["SEVERITY", "SUBJECT", "FINDING"]
    assert "SUBJECT " in rows[0]
