from unittest.mock import patch

from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain import aur_source
from fettle.supplychain.aur_source import AURSource
from fettle.supplychain.base import KNOWN_BAD, STALE_OR_ABANDONED, UNVERIFIED_PUBLISHER, Severity


class FakeIOC:
    def __init__(self, *, packages=None, accounts=None, npm=None, **_):
        self._p, self._a, self._n = packages or set(), accounts or set(), npm or set()

    def bad_packages(self):
        return self._p

    def bad_accounts(self):
        return self._a

    def bad_npm(self):
        return self._n


def _ctx(tmp_path, cfg=None):
    return Context(output=Output(color=False), config=cfg or Config(),
                   sudo_user="paul", user_home=tmp_path)


def _run(tmp_path, *, foreign, results, ioc=None, cfg=None):
    ioc = ioc or FakeIOC()
    with patch("fettle.command.run") as run, \
         patch.object(aur_source.aur_meta, "query_info", return_value=results), \
         patch("fettle.aur.common.ioc_feed", return_value=ioc):
        run.return_value.stdout = "\n".join(foreign)
        return AURSource().findings(_ctx(tmp_path, cfg))


def test_orphan_and_out_of_date(tmp_path):
    results = [
        {"Name": "orphan-pkg", "Maintainer": None, "LastModified": 9_999_999_999},
        {"Name": "ood-pkg", "Maintainer": "bob", "OutOfDate": 123, "LastModified": 9_999_999_999},
    ]
    findings = _run(tmp_path, foreign=["orphan-pkg", "ood-pkg"], results=results)
    qs = {(f.package, f.question) for f in findings}
    assert ("orphan-pkg", UNVERIFIED_PUBLISHER) in qs
    assert ("ood-pkg", STALE_OR_ABANDONED) in qs


def test_stale_age(tmp_path):
    results = [{"Name": "old-pkg", "Maintainer": "bob", "LastModified": 0}]  # 1970 -> ancient
    findings = _run(tmp_path, foreign=["old-pkg"], results=results)
    assert any(f.question == STALE_OR_ABANDONED and "days ago" in f.detail for f in findings)


def test_known_bad_package_is_critical(tmp_path):
    results = [{"Name": "evil", "Maintainer": "bob", "LastModified": 9_999_999_999}]
    ioc = FakeIOC(packages={"evil"})
    findings = _run(tmp_path, foreign=["evil"], results=results, ioc=ioc)
    crit = [f for f in findings if f.severity >= Severity.CRIT and f.question == KNOWN_BAD]
    assert crit and crit[0].package == "evil"


def test_malicious_maintainer_account(tmp_path):
    results = [{"Name": "pkg", "Maintainer": "eviluser", "LastModified": 9_999_999_999}]
    ioc = FakeIOC(accounts={"eviluser"})
    findings = _run(tmp_path, foreign=["pkg"], results=results, ioc=ioc)
    assert any(f.severity >= Severity.CRIT and "malicious account" in f.detail for f in findings)


def test_not_found_in_aur(tmp_path):
    findings = _run(tmp_path, foreign=["ghost-pkg"], results=[])
    assert any("not present in AUR" in f.detail for f in findings)


def test_maintainer_change_detected(tmp_path):
    snap = tmp_path / ".cache/fettle/aur-maintainers.json"
    snap.parent.mkdir(parents=True)
    snap.write_text('{"pkg": "alice"}')  # prior maintainer
    results = [{"Name": "pkg", "Maintainer": "mallory", "LastModified": 9_999_999_999}]
    findings = _run(tmp_path, foreign=["pkg"], results=results)
    assert any("maintainer changed alice -> mallory" in f.detail for f in findings)


def test_clean_system_no_findings(tmp_path):
    results = [{"Name": "good", "Maintainer": "bob", "LastModified": 9_999_999_999}]
    assert _run(tmp_path, foreign=["good"], results=results) == []
