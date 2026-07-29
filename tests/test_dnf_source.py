"""DNF/YUM repository provenance provider.

Fixtures are real `/etc/yum.repos.d` content from a RHEL 10.1 box (CentOS Stream +
EPEL repos) — including the `$releasever` variables and `gpgcheck=0`.
"""

from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import (INSECURE_TRANSPORT, UNOFFICIAL_SOURCE,
                                     UNVERIFIABLE, Severity)
from fettle.supplychain.dnf_source import DnfSource

# Real CentOS Stream repo file — note gpgcheck=0 on all three enabled repos.
_CENTOS = """\
[centos-stream-baseos]
name=CentOS Stream 10 - BaseOS
baseurl=https://mirror.stream.centos.org/10-stream/BaseOS/x86_64/os/
gpgcheck=0
enabled=1

[centos-stream-appstream]
name=CentOS Stream 10 - AppStream
baseurl=https://mirror.stream.centos.org/10-stream/AppStream/x86_64/os/
gpgcheck=0
enabled=1
"""

# Real EPEL file: signed packages, a metalink URL, and `$releasever` variables that
# would break configparser's default interpolation.
_EPEL = """\
[epel]
name=Extra Packages for Enterprise Linux $releasever - $basearch
#baseurl=https://download.example/pub/epel/$releasever/Everything/$basearch/
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$releasever&arch=$basearch
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-$releasever_major
gpgcheck=1
repo_gpgcheck=0
enabled=1

[epel-source]
name=EPEL source
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-source-$releasever
gpgcheck=1
repo_gpgcheck=0
enabled=0
"""


def _ctx(root):
    return Context(output=Output(color=False), config=Config(), root=root)


def _tree(tmp_path, repos: dict, dnf_conf="[main]\ngpgcheck=1\n"):
    d = tmp_path / "etc/yum.repos.d"
    d.mkdir(parents=True)
    for name, text in repos.items():
        (d / name).write_text(text)
    if dnf_conf is not None:
        c = tmp_path / "etc/dnf"
        c.mkdir(parents=True, exist_ok=True)
        (c / "dnf.conf").write_text(dnf_conf)
    return tmp_path


def _run(tmp_path, repos, **kw):
    return DnfSource().findings(_ctx(_tree(tmp_path, repos, **kw)))


# -- signature checking ------------------------------------------------------
def test_gpgcheck_zero_on_an_enabled_repo_is_flagged(tmp_path):
    f = _run(tmp_path, {"centos-stream.repo": _CENTOS})
    unsigned = [x for x in f if x.question == INSECURE_TRANSPORT
                and "gpgcheck=0" in x.detail]
    assert {x.package for x in unsigned} == {"centos-stream-baseos",
                                             "centos-stream-appstream"}
    assert all(x.severity == Severity.WARN for x in unsigned)


def test_absent_gpgcheck_inherits_the_global_default(tmp_path):
    """dnf.conf ships gpgcheck=1, so a section without the key is SECURE. Treating
    absence as disabled would flag essentially every repo on every box."""
    repo = "[r]\nname=r\nbaseurl=https://mirror.stream.centos.org/x/\nenabled=1\n"
    assert _run(tmp_path, {"r.repo": repo}) == []


def test_absent_gpgcheck_with_global_off_is_flagged(tmp_path):
    repo = "[r]\nname=r\nbaseurl=https://mirror.stream.centos.org/x/\nenabled=1\n"
    f = _run(tmp_path, {"r.repo": repo}, dnf_conf="[main]\ngpgcheck=0\n")
    assert any("gpgcheck=0" in x.detail for x in f)


def test_missing_dnf_conf_assumes_checking_is_on(tmp_path):
    """Never assume a system is less safe than it is: dnf's own default is on."""
    repo = "[r]\nname=r\nbaseurl=https://mirror.stream.centos.org/x/\nenabled=1\n"
    assert _run(tmp_path, {"r.repo": repo}, dnf_conf=None) == []


def test_disabled_repo_is_reported_at_lower_severity(tmp_path):
    repo = ("[off]\nname=off\nbaseurl=https://mirror.stream.centos.org/x/\n"
            "gpgcheck=0\nenabled=0\n")
    f = _run(tmp_path, {"off.repo": repo})
    assert len(f) == 1
    assert f[0].severity == Severity.LOW and "repo is disabled" in f[0].detail


# -- transport and provenance ------------------------------------------------
def test_plain_http_is_flagged(tmp_path):
    repo = "[h]\nname=h\nbaseurl=http://vendor.example/rpm/\nenabled=1\n"
    f = _run(tmp_path, {"h.repo": repo})
    assert any(x.question == INSECURE_TRANSPORT and "plain http" in x.detail for x in f)


def test_third_party_repo_is_flagged_distro_hosts_are_not(tmp_path):
    f = _run(tmp_path, {"centos-stream.repo": _CENTOS, "epel.repo": _EPEL})
    third = {x.package for x in f if x.question == UNOFFICIAL_SOURCE}
    # EPEL is third-party on a RHEL box, exactly as a PPA is on Ubuntu.
    assert third == {"epel"}
    assert "centos-stream-baseos" not in third      # mirror.stream.centos.org is the distro


def test_disabled_third_party_repo_is_not_flagged_as_a_source(tmp_path):
    """epel-source is disabled — it contributes no packages, so it is not a source."""
    f = _run(tmp_path, {"epel.repo": _EPEL})
    assert "epel-source" not in {x.package for x in f if x.question == UNOFFICIAL_SOURCE}


# -- real-world parsing hazards ----------------------------------------------
def test_releasever_variables_do_not_break_parsing(tmp_path):
    """`$releasever`/`$basearch` and a `%` would trip configparser's default
    interpolation; the parser disables it."""
    f = _run(tmp_path, {"epel.repo": _EPEL})
    assert {x.package for x in f}                    # parsed at all
    assert "epel" in {x.package for x in f}


def test_epel_repo_gpgcheck_zero_is_deliberately_not_flagged(tmp_path):
    """EPEL ships repo_gpgcheck=0 as standard. Reporting metadata signing would be a
    finding that is true, universal and useless."""
    f = _run(tmp_path, {"epel.repo": _EPEL})
    assert not any("repo_gpgcheck" in x.detail for x in f)


def test_unparseable_repo_file_is_reported_not_skipped(tmp_path):
    f = _run(tmp_path, {"broken.repo": "this is not = [ ini\n[[[\n"})
    assert len(f) == 1 and f[0].question == UNVERIFIABLE
    assert "NOT audited" in f[0].detail


# -- presence ----------------------------------------------------------------
def test_absent_without_a_repo_dir(tmp_path):
    assert DnfSource().is_present(_ctx(tmp_path)) is False
    assert DnfSource().findings(_ctx(tmp_path)) == []


def test_present_with_a_repo_dir(tmp_path):
    assert DnfSource().is_present(_ctx(_tree(tmp_path, {}))) is True
