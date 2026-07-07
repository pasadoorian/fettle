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
    report = (tmp_path / "aur-ioc-scan.txt").read_text()
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
    report = (tmp_path / "aur-ioc-scan.txt").read_text()
    assert "no indicators matched" in report


def test_no_foreign_packages(tmp_path, capsys):
    cap = _run(tmp_path, foreign=[], ioc=FakeIOC(), capsys=capsys)
    assert "no foreign (AUR) packages" in cap.out
    assert not (tmp_path / "aur-ioc-scan.txt").exists()  # nothing written when none installed
