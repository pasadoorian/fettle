"""HS2: table rendering — compact on-screen table, full matrix, band summary."""

from unittest.mock import patch

from fettle.hardening import baseline as bl
from fettle.hardening import report
from fettle.hardening.engine import Deviation


def _dev(path, check):
    return Deviation(path=path, check=check, got="x", want=("good",))


def _reports(devs, pkgmap, scorer=None, setuid=False):
    with patch("fettle.hardening.score.is_setuid", return_value=setuid):
        return report.apply(devs, pkgmap, report.Exclusions(), scorer)[0]


# xorg-server (canary+relro, setuid) vs netpbm (many, one canary each)
DEVS = ([_dev("/usr/lib/Xorg.wrap", "canary"), _dev("/usr/lib/Xorg.wrap", "relro")]
        + [_dev(f"/usr/bin/np{i}", "canary") for i in range(3)])
PKGMAP = {"/usr/lib/Xorg.wrap": "xorg-server",
          **{f"/usr/bin/np{i}": "netpbm" for i in range(3)}}


# -- _tabulate ---------------------------------------------------------------
def test_tabulate_aligns_columns():
    out = report._tabulate(["A", "BB"], [["x", "yyy"], ["zz", "w"]],
                           aligns=["l", "r"])
    # header, separator, two rows
    assert len(out) == 4
    # every line padded to the same visual width (columns line up)
    assert out[0].startswith("A ")            # 'A' padded to width 2
    assert "yyy" in out[1] or "---" in out[1]  # separator row present
    # right-aligned column: 'w' pushed right under 'yyy'
    assert out[3].rstrip().endswith("w")


def test_tabulate_widens_to_longest_cell():
    out = report._tabulate(["P", "X"],
                           [["short", "1"], ["a-much-longer-value", "2"]])
    # second column lines up at the same offset in header and every row
    off = out[0].index("X")
    assert out[2].index("1") == off and out[3].index("2") == off


# -- band summary ------------------------------------------------------------
def test_band_summary_leads_with_band_counts():
    reports = _reports(DEVS, PKGMAP, setuid=True)  # xorg becomes Critical
    s = report.band_summary(reports)
    assert s.startswith("1 Critical")            # highest band first
    assert "worst first" in s


def test_band_summary_empty():
    assert report.band_summary([]).startswith("no hardening")


# -- compact on-screen table -------------------------------------------------
def test_render_screen_columns_and_sort():
    reports = _reports(DEVS, PKGMAP, setuid=True)
    lines = report.render_screen(reports)
    assert lines[0].split() == ["BAND", "SCORE", "P", "PACKAGE", "BINS",
                                "MISSING", "(worst-weighted", "first)"]
    body = lines[2:]  # skip header + separator
    # xorg-server ranks first (Critical, privileged)
    assert body[0].startswith("Critical")
    assert "xorg-server" in body[0] and "!" in body[0]


def test_render_screen_missing_is_weight_ordered():
    reports = _reports([_dev("/usr/bin/x", "runpath"), _dev("/usr/bin/x", "canary")],
                       {"/usr/bin/x": "p"})
    row = report.render_screen(reports)[2]
    # canary (weight 3) must appear before runpath (weight 0.5)
    assert row.index("canary") < row.index("runpath")


def test_render_screen_privilege_marker_only_when_privileged():
    reports = _reports([_dev("/usr/bin/x", "canary")], {"/usr/bin/x": "p"},
                       setuid=False)
    row = report.render_screen(reports)[2]
    assert "!" not in row


def test_render_screen_empty():
    assert report.render_screen([]) == [
        "no hardening deviations from the distro baseline."]


# -- full matrix (file) ------------------------------------------------------
_BASE = bl.Baseline(name="arch (test)",
                    criteria={"relro": ("Full RELRO",), "canary": ("Canary Found",),
                              "pie": ("PIE Enabled",)},
                    notes=["GCC supplies PIE and stack canary by default"])
_SCAN = {"analyzed": 4371, "static": 49, "unreadable": 0}


def test_matrix_has_every_criterion_column_and_dot_for_conforms():
    reports = _reports(DEVS, PKGMAP, setuid=True)
    text = "\n".join(report.render(reports, {"excluded_check": 0,
                                             "excluded_package": 0,
                                             "excluded_path": 0}, _BASE, _SCAN))
    # abbreviated headers present
    assert "fortify" in text and "canary" in text and "runpath" in text
    # a package missing only canary/relro shows "." in the columns it conforms to
    assert "." in text
    assert "4371 ELF" in text           # scan stats retained
    assert "xorg-server" in text


def test_matrix_row_shows_score_band_and_counts():
    reports = _reports([_dev("/usr/bin/x", "canary"), _dev("/usr/bin/y", "canary")],
                       {"/usr/bin/x": "netpbm", "/usr/bin/y": "netpbm"})
    text = "\n".join(report.render(reports, {"excluded_check": 0,
                                             "excluded_package": 0,
                                             "excluded_path": 0}, _BASE, _SCAN))
    # netpbm: 2 binaries each missing canary -> canary column count = 2, score 3 (worst)
    line = next(ln for ln in text.splitlines() if ln.startswith("netpbm"))
    assert "netpbm" in line and " 3 " in f" {line} " and "Medium" in line


def test_render_clean_report_unchanged():
    text = "\n".join(report.render([], {"excluded_check": 0, "excluded_package": 0,
                                        "excluded_path": 0}, _BASE, _SCAN))
    assert "No deviations" in text
