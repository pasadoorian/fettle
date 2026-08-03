"""AUR IoC scan (`-S` / aur-ioc-scan) — installed-package indicator checks."""

from unittest.mock import patch

from fettle.aur import ioc_scan
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


class FakeIOC:
    def __init__(self, *, packages=None, accounts=None, npm=None):
        self._p, self._a, self._n = packages or set(), accounts or set(), npm or set()

    def bad_packages(self):
        return self._p

    def bad_accounts(self):
        return self._a

    def bad_npm(self):
        return self._n

    # Feed provenance: a scan is only as current as its worst feed, and the verdict
    # has to be able to say so instead of reporting a confident "clean".
    stale: list = []
    unavailable: list = []

    @property
    def degraded(self):
        return bool(self.stale or self.unavailable)


def _ctx(tmp_path):
    return Context(output=Output(color=False), config=Config(),
                   sudo_user="paul", user_home=tmp_path)


def _run(tmp_path, *, foreign, ioc, results=None, capsys):
    with patch("fettle.command.run") as run, \
         patch("fettle.aur.ioc_scan.aur_common.ioc_feed", return_value=ioc), \
         patch("fettle.aur.ioc_scan.aur_meta.query_info", return_value=results or []):
        run.return_value.stdout = "\n".join(foreign)
        ioc_scan.run(_ctx(tmp_path))
    return capsys.readouterr()


def test_flags_known_malicious_package(tmp_path, capsys):
    cap = _run(tmp_path, foreign=["evil-pkg", "good"], ioc=FakeIOC(packages={"evil-pkg"}),
               capsys=capsys)
    assert "evil-pkg" in cap.err and "known-malicious package list" in cap.err
    report = list((tmp_path / ".fettle/reports/local").glob("aur-ioc-scan-*.txt"))[0].read_text()
    assert "evil-pkg" in report


def test_flags_malicious_maintainer_account(tmp_path, capsys):
    results = [{"Name": "pkg", "Maintainer": "eviluser"}]
    cap = _run(tmp_path, foreign=["pkg"], ioc=FakeIOC(accounts={"eviluser"}),
               results=results, capsys=capsys)
    assert "known-malicious account" in cap.err and "eviluser" in cap.err


def test_flags_js_cache_trace(tmp_path, capsys):
    (tmp_path / ".npm").mkdir()
    (tmp_path / ".npm" / "atomic-lockfile").mkdir()  # matches a seed npm IOC name
    cap = _run(tmp_path, foreign=["some-pkg"], ioc=FakeIOC(npm={"atomic-lockfile"}), capsys=capsys)
    assert "malicious JS package trace" in cap.err


def test_clean_system_no_indicators(tmp_path, capsys):
    cap = _run(tmp_path, foreign=["good"], ioc=FakeIOC(packages={"other"}), capsys=capsys)
    assert "no indicators matched" in cap.out
    report = list((tmp_path / ".fettle/reports/local").glob("aur-ioc-scan-*.txt"))[0].read_text()
    assert "no indicators matched" in report


def test_no_foreign_packages(tmp_path, capsys):
    cap = _run(tmp_path, foreign=[], ioc=FakeIOC(), capsys=capsys)
    assert "no foreign (AUR) packages" in cap.out
    assert not list((tmp_path / ".fettle/reports/local").glob("aur-ioc-scan-*.txt"))  # nothing written


def test_degraded_feeds_never_report_a_clean_bill(tmp_path, capsys):
    """This action runs on every `fettle -a`, and its whole value is the answer. With
    the feeds unreachable it used to warn on stderr and then print a green "no
    indicators matched" — so a machine that was never checked looked checked."""
    ioc = FakeIOC()
    ioc.unavailable = ["aur-infected/packages.txt"]
    ctx = _ctx(tmp_path)
    with patch("fettle.command.run") as run, \
         patch("fettle.aur.ioc_scan.aur_common.ioc_feed", return_value=ioc), \
         patch("fettle.aur.ioc_scan.aur_meta.query_info", return_value=[]):
        run.return_value.stdout = "somepkg"
        ioc_scan.run(ctx)
    ctx.output.print_summary()
    cap = capsys.readouterr()
    assert "no indicators matched" not in cap.out
    assert "INCOMPLETE" in cap.err
    assert "INCOMPLETE feeds" in cap.out          # and it reaches the summary
    ioc.unavailable = []


def test_stale_cache_is_disclosed(tmp_path, capsys):
    """A laptop offline for three weeks scanned against a three-week-old feed and said
    nothing about it."""
    ioc = FakeIOC()
    ioc.stale = ["aur-infected/packages.txt (21d old)"]
    ctx = _ctx(tmp_path)
    with patch("fettle.command.run") as run, \
         patch("fettle.aur.ioc_scan.aur_common.ioc_feed", return_value=ioc), \
         patch("fettle.aur.ioc_scan.aur_meta.query_info", return_value=[]):
        run.return_value.stdout = "somepkg"
        ioc_scan.run(ctx)
    cap = capsys.readouterr()
    assert "21d old" in cap.err
    ioc.stale = []


def test_clean_scan_leaves_a_trace_in_the_summary(tmp_path, capsys):
    """"Scanned and clean" and "never ran" produced identical digests."""
    ctx = _ctx(tmp_path)
    with patch("fettle.command.run") as run, \
         patch("fettle.aur.ioc_scan.aur_common.ioc_feed", return_value=FakeIOC()), \
         patch("fettle.aur.ioc_scan.aur_meta.query_info", return_value=[]):
        run.return_value.stdout = "somepkg"
        ioc_scan.run(ctx)
    ctx.output.print_summary()
    assert "1 package(s) checked, none flagged" in capsys.readouterr().out
