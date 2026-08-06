"""Reports and run-logs: where they go, who can read them, and what counts as a host.

Kept deliberately small — this row is a set of fixes, not a redesign.
"""

import os
import stat
from unittest.mock import patch

from fettle import htmlreport, runlog


# -- permissions ---------------------------------------------------------------
def test_a_run_log_is_owner_only_from_the_moment_it_exists(tmp_path):
    """It was created 0644 and only chmod'd to 0600 when the run FINISHED, so the file
    sat world-readable for the whole run — and permanently if the run was killed. The
    ~/.fettle tree is 0700 so this was defence in depth rather than an open door, but a
    tree that predates that, a restored backup or a hand-made directory has only the
    file mode left."""
    path = tmp_path / "run-x.txt"
    with runlog._open_private(path) as fh:
        fh.write(b"partial output, run still going\n")
        mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, oct(mode)


def test_the_json_sibling_is_owner_only_too(tmp_path):
    path = tmp_path / "run-x.json"
    with runlog._open_private(path, "w") as fh:
        fh.write("{}")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# -- what counts as a host -----------------------------------------------------
def _seed(base, host, *, with_data):
    d = base / "reports" / host
    d.mkdir(parents=True)
    if with_data:
        (d / "pkg-audit-20260101-000000.json").write_text(
            '{"schema":"fettle.report/1","tool":"pkg-audit","host":"h",'
            '"timestamp":"20260101-000000"}')


def test_collect_still_returns_empty_host_directories(tmp_path):
    """`collect` deliberately keeps them: the dashboard hides empty hosts and prints
    "N empty hidden" so they do not silently vanish. Filtering here would break that
    count — which is what a first attempt at this fix did."""
    _seed(tmp_path, "realhost", with_data=True)
    _seed(tmp_path, "fleet", with_data=False)
    assert set(htmlreport.collect(tmp_path)) == {"realhost", "fleet"}


def test_a_host_with_only_logs_still_counts(tmp_path):
    """Logs alone are data — a host that has run but written no report yet is real."""
    d = tmp_path / "logs" / "onlylogs"
    d.mkdir(parents=True)
    (d / "run-20260101-000000.json").write_text(
        '{"schema":"fettle.log/1","tool":"run","host":"h",'
        '"timestamp":"20260101-000000"}')
    assert "onlylogs" in htmlreport.collect(tmp_path)


def test_report_counts_only_real_hosts(tmp_path, capsys):
    from fettle import cli

    _seed(tmp_path, "a", with_data=True)
    _seed(tmp_path, "empty", with_data=False)
    with patch.object(htmlreport, "build", return_value=tmp_path / "report.html"), \
         patch("fettle.reports._settings", return_value=(tmp_path, 10)):
        cli._run_report(["--no-config"])
    assert "report for 1 host(s)" in capsys.readouterr().out
