"""APT source provider — repo/PPA hygiene + debsums integrity."""

from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.apt_source import AptSource
from fettle.supplychain.base import INSECURE_TRANSPORT, INTEGRITY_DRIFT, UNOFFICIAL_SOURCE


def _ctx(root):
    return Context(output=Output(color=False), config=Config(), user_home=root, root=root)


def _write_sources(root, list_body="", sources_body=""):
    apt = root / "etc/apt"
    (apt / "sources.list.d").mkdir(parents=True)
    if list_body:
        (apt / "sources.list").write_text(list_body)
    if sources_body:
        (apt / "sources.list.d" / "extra.sources").write_text(sources_body)


def _run(root, *, debsums=None):
    """debsums=None => tool absent; else string of changed-file lines."""
    def fake_run(cmd, *, as_user=None, capture=False):
        if list(cmd)[:2] == ["debsums", "-c"]:
            return command.Proc(0, debsums or "", "")
        return command.Proc(0, "", "")

    def fake_which(name):
        return name == "debsums" and debsums is not None
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=fake_which):
        return AptSource().findings(_ctx(root))


def test_official_repo_produces_no_findings(tmp_path):
    _write_sources(tmp_path, "deb http://archive.ubuntu.com/ubuntu jammy main\n")
    assert _run(tmp_path) == []  # official archive over http is the vendor default


def test_third_party_ppa_flagged(tmp_path):
    _write_sources(tmp_path, "deb https://ppa.launchpadcontent.net/x/y/ubuntu jammy main\n")
    qs = {(f.question, f.package) for f in _run(tmp_path)}
    assert any(q == UNOFFICIAL_SOURCE for q, _ in qs)


def test_third_party_http_flags_transport(tmp_path):
    _write_sources(tmp_path, "deb http://downloads.example.com/apt stable main\n")
    findings = _run(tmp_path)
    assert any(f.question == UNOFFICIAL_SOURCE for f in findings)
    assert any(f.question == INSECURE_TRANSPORT and "http" in f.detail for f in findings)


def test_trusted_yes_disables_verification(tmp_path):
    _write_sources(tmp_path,
                   "deb [trusted=yes] https://archive.ubuntu.com/ubuntu jammy main\n")
    findings = _run(tmp_path)
    assert any(f.question == INSECURE_TRANSPORT and "trusted=yes" in f.detail for f in findings)


def test_deb822_trusted_flagged(tmp_path):
    body = ("Types: deb\n"
            "URIs: https://repo.example.org/apt\n"
            "Suites: stable\nComponents: main\nTrusted: yes\n")
    _write_sources(tmp_path, sources_body=body)
    findings = _run(tmp_path)
    assert any(f.question == INSECURE_TRANSPORT for f in findings)  # trusted=yes
    assert any(f.question == UNOFFICIAL_SOURCE for f in findings)   # non-official host


def test_debsums_reports_integrity_drift(tmp_path):
    _write_sources(tmp_path, "deb https://archive.ubuntu.com/ubuntu jammy main\n")
    findings = _run(tmp_path, debsums="/usr/bin/tampered\n/lib/x.so\n")
    drift = [f for f in findings if f.question == INTEGRITY_DRIFT]
    assert len(drift) == 2 and any("tampered" in f.detail for f in drift)


def test_no_debsums_no_integrity_findings(tmp_path):
    _write_sources(tmp_path, "deb https://archive.ubuntu.com/ubuntu jammy main\n")
    assert not any(f.question == INTEGRITY_DRIFT for f in _run(tmp_path, debsums=None))
