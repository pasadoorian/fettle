"""RHEL-family advisory provider — dnf4 `updateinfo` parsing.

Fixtures are real `dnf updateinfo` output captured from AlmaLinux 10.2 (which, unlike
CentOS Stream, publishes errata) and from a RHEL 10.1 box.
"""

from unittest.mock import patch

from fettle import command
from fettle.advisories import base
from fettle.advisories.rhel_source import (RhelAdvisorySource, _nevra_name,
                                           parse_info, parse_list)
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output

# Real `dnf updateinfo list --security` output.
_LIST = """\
Last metadata expiration check: 0:00:01 ago on Wed Jul 29 15:41:09 2026.
ALSA-2026:33124 Moderate/Sec.  coreutils-single-9.5-8.el10_2.x86_64
ALSA-2026:22715 Important/Sec. expat-2.7.3-1.el10_2.1.x86_64
ALSA-2026:33092 Moderate/Sec.  glibc-2.39-126.el10_2.alma.1.x86_64
ALSA-2026:33092 Moderate/Sec.  glibc-common-2.39-126.el10_2.alma.1.x86_64
ALSA-2026:42739 Important/Sec. libacl-2.4.0-1.el10_2.x86_64
ALSA-2026:28235 Low/Sec.       libtasn1-4.20.0-5.el10_2.x86_64
"""

# Real `dnf updateinfo info --security` output. Three traps are represented here:
# the block TITLE looks like `Key: value`; `Bugs:` and `CVEs:` both use continuation
# lines; and Description continuations contain colons of their own.
_INFO = """\
===============================================================================
  Important: acl security update
===============================================================================
  Update ID: ALSA-2026:42739
       Type: security
    Updated: 2026-07-22 11:00:33
       Bugs: 2490277 -\x20
           : 2490279 -\x20
       CVEs: CVE-2026-54369
           : CVE-2026-54370
Description: Access Control Lists (ACLs) are used to define access rights.
           :\x20
           : Security Fix(es):
           :   * acl: Symlink traversal privilege escalation (CVE-2026-54369)
           :   * acl: TOCTOU Symlink Traversal via getfacl/setfacl (CVE-2026-54370)
   Severity: Important

===============================================================================
  Important: expat security update
===============================================================================
  Update ID: ALSA-2026:22715
       Type: security
    Updated: 2026-06-04 08:56:10
       CVEs: CVE-2026-45186
Description: Expat is a C library for parsing XML documents.
   Severity: Important
"""


def _ctx(**kw):
    return Context(output=Output(color=False), config=Config(), **kw)


# -- list parsing ------------------------------------------------------------
def test_parse_list_extracts_advisory_severity_and_package():
    rows = parse_list(_LIST)
    assert len(rows) == 6                       # the metadata line is not a row
    assert rows[1] == ("ALSA-2026:22715", "Important", "expat-2.7.3-1.el10_2.1.x86_64")


def test_parse_list_keeps_one_row_per_package_of_a_shared_advisory():
    """ALSA-2026:33092 covers glibc and glibc-common — two packages, one advisory."""
    rows = [r for r in parse_list(_LIST) if r[0] == "ALSA-2026:33092"]
    assert {_nevra_name(n) for _a, _s, n in rows} == {"glibc", "glibc-common"}


# -- info parsing: the three traps -------------------------------------------
def test_parse_info_collects_multiple_cves_from_continuation_lines():
    """`CVEs:` continues on `<pad>: CVE-…` lines; keying only on `Key: value`
    silently drops every CVE after the first."""
    rec = parse_info(_INFO)["ALSA-2026:42739"]
    assert rec["cves"] == ["CVE-2026-54369", "CVE-2026-54370"]


def test_parse_info_does_not_mistake_the_block_title_for_a_field():
    """The title `  Important: acl security update` sits between two `=` rules and
    looks exactly like a field."""
    recs = parse_info(_INFO)
    assert set(recs) == {"ALSA-2026:42739", "ALSA-2026:22715"}
    assert recs["ALSA-2026:42739"]["severity"] == "Important"   # not "acl security…"


def test_parse_info_survives_colons_inside_the_description():
    """Description continuations contain `* acl: Symlink traversal …` — a colon in
    prose must not become a field."""
    rec = parse_info(_INFO)["ALSA-2026:42739"]
    assert rec["severity"] == "Important"
    assert len(rec["cves"]) == 2                # description CVEs are not duplicated


def test_parse_info_handles_an_advisory_with_no_bugs_line():
    assert parse_info(_INFO)["ALSA-2026:22715"]["cves"] == ["CVE-2026-45186"]


# -- nevra -------------------------------------------------------------------
def test_nevra_name_strips_version_release_and_arch():
    assert _nevra_name("expat-2.7.3-1.el10_2.1.x86_64") == "expat"
    assert _nevra_name("glibc-common-2.39-126.el10_2.alma.1.x86_64") == "glibc-common"
    assert _nevra_name("coreutils-single-9.5-8.el10_2.x86_64") == "coreutils-single"


# -- severity ----------------------------------------------------------------
def _refresh(conn, listing=_LIST, info=_INFO, list_rc=0):
    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:3] == ["dnf", "updateinfo", "list"]:
            return command.Proc(list_rc, listing, "")
        if c[:3] == ["dnf", "updateinfo", "info"]:
            return command.Proc(0, info, "")
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake_run):
        return RhelAdvisorySource().refresh(conn, _ctx())


def test_important_maps_to_high_not_medium(tmp_path):
    """RHEL has no "High"; `Important` is its equivalent and must not flatten."""
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")
    _refresh(conn)
    sevs = {f.package: f.severity for f in RhelAdvisorySource().findings(_ctx(), conn)}
    assert sevs["expat"] == "High"
    assert sevs["coreutils-single"] == "Medium"     # Moderate
    assert sevs["libtasn1"] == "Low"


def test_findings_carry_advisory_id_and_cves(tmp_path):
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")
    _refresh(conn)
    acl = [f for f in RhelAdvisorySource().findings(_ctx(), conn) if f.package == "libacl"][0]
    assert acl.advisory_id == "ALSA-2026:42739"
    assert acl.cves == ["CVE-2026-54369", "CVE-2026-54370"]
    assert acl.status == base.FIXED_AVAILABLE       # updateinfo only knows fixed ones


def test_refresh_reports_failure_rather_than_an_empty_result(tmp_path):
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")
    assert _refresh(conn, list_rc=1) == -1          # the ABC's "fetch failed" contract


# -- the blind spot this provider exists to name -----------------------------
def test_zero_advisories_with_pending_updates_is_reported_as_a_blind_spot(tmp_path, capsys):
    """A real RHEL 10.1 box had 341 pending updates and ZERO security advisories,
    because CentOS Stream publishes no errata. Reporting that as "no findings" would
    be a clean bill of health for a system a year behind."""
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")
    _refresh(conn, listing="Last metadata expiration check: now.\n", info="")

    def fake_run(cmd, *, as_user=None, capture=False):
        if list(cmd)[:3] == ["dnf", "-q", "check-update"]:
            # dnf exits 100 when updates ARE available — success, not failure.
            return command.Proc(100, "bash.x86_64 5.2-1 baseos\ncurl.x86_64 8.9-1 baseos\n", "")
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run):
        findings = RhelAdvisorySource().findings(_ctx(), conn)
    assert findings == []
    err = capsys.readouterr().err
    assert "blind spot" in err and "NOT a clean bill of health" in err
    assert "2 package update(s)" in err


def test_zero_advisories_and_nothing_pending_is_genuinely_quiet(tmp_path, capsys):
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")
    _refresh(conn, listing="", info="")

    def fake_run(cmd, *, as_user=None, capture=False):
        if list(cmd)[:3] == ["dnf", "-q", "check-update"]:
            return command.Proc(0, "", "")          # 0 = nothing to update
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run):
        RhelAdvisorySource().findings(_ctx(), conn)
    assert "blind spot" not in capsys.readouterr().err


# -- presence ----------------------------------------------------------------
def _present(osr, has_dnf=True, tmp_path=None):
    (tmp_path / "etc").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc/os-release").write_text(osr)
    with patch("fettle.command.which", side_effect=lambda n: has_dnf and n == "dnf"):
        return RhelAdvisorySource().is_present(_ctx(root=tmp_path))


def test_present_on_the_rhel_family(tmp_path):
    for osr in ('ID="rhel"\nID_LIKE="centos fedora"\n',
                'ID="almalinux"\nID_LIKE="rhel centos fedora"\n',
                'ID="rocky"\n', 'ID="ol"\n', 'ID="centos"\n'):
        assert _present(osr, tmp_path=tmp_path) is True, osr


def test_absent_on_other_distros_and_without_dnf(tmp_path):
    assert _present('ID="ubuntu"\nID_LIKE="debian"\n', tmp_path=tmp_path) is False
    assert _present('ID="arch"\n', tmp_path=tmp_path) is False
    assert _present('ID="rhel"\n', has_dnf=False, tmp_path=tmp_path) is False


# -- version display ---------------------------------------------------------
def test_split_nevra_handles_epoch_and_hyphenated_names():
    from fettle.advisories.rhel_source import _split_nevra
    assert _split_nevra("expat-2.7.3-1.el10_2.1.x86_64") == ("expat", "2.7.3-1.el10_2.1")
    assert _split_nevra("openssl-libs-1:3.5.5-4.el10_2.alma.1.x86_64") == (
        "openssl-libs", "1:3.5.5-4.el10_2.alma.1")
    assert _split_nevra("glibc-common-2.39-126.el10_2.alma.1.x86_64") == (
        "glibc-common", "2.39-126.el10_2.alma.1")


def test_findings_show_installed_and_fixed_versions(tmp_path):
    """Without the installed side the report reads "-> 2.7.3-1" with no "from",
    hiding how far behind the system actually is."""
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:3] == ["dnf", "updateinfo", "list"]:
            return command.Proc(0, _LIST, "")
        if c[:3] == ["dnf", "updateinfo", "info"]:
            return command.Proc(0, _INFO, "")
        if c[:2] == ["rpm", "-qa"]:
            return command.Proc(0, "expat 2.7.2-1.el10\nlibacl 2.3.9-1.el10\n", "")
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run):
        RhelAdvisorySource().refresh(conn, _ctx())
        found = {f.package: f for f in RhelAdvisorySource().findings(_ctx(), conn)}
    assert found["expat"].installed_version == "2.7.2-1.el10"
    assert found["expat"].fixed_version == "2.7.3-1.el10_2.1"
    # A package rpm doesn't report stays blank rather than guessing.
    assert found["libtasn1"].installed_version == ""


def test_rpm_query_failure_degrades_to_blank_versions():
    from fettle.advisories.rhel_source import installed_versions
    with patch("fettle.command.run", return_value=command.Proc(1, "", "no rpm")):
        assert installed_versions() == {}


# -- dnf5 --------------------------------------------------------------------
# dnf5's output is a completely different shape AND it keeps `updateinfo` as an
# alias for `advisory`, so the dnf4 command still exits 0 there and simply parses to
# nothing. That silent-empty result was then reported as "these repos publish no
# security errata" — flatly wrong on a dnf5 system. Fixtures are real Fedora 44 /
# dnf5 5.4.2.1 output.
_DNF5_LIST = """[
  {"name": "FEDORA-2026-6b9a652463", "type": "security", "severity": "Important",
   "nevra": "libacl-2.4.0-1.fc44.x86_64", "buildtime": 1783731990},
  {"name": "FEDORA-2026-daa458d11d", "type": "security", "severity": "Moderate",
   "nevra": "attr-2.6.0-1.fc44.x86_64", "buildtime": 1783731990}
]"""

# Note every reference here is a `bugzilla`, not a `cve` — that is real Fedora data,
# and it is why `--with-cve` returns nothing and cannot be used to fetch.
_DNF5_INFO = """[
  {"Name":"FEDORA-2026-daa458d11d","Title":"attr-2.6.0-1.fc44","Severity":"Moderate",
   "Type":"security","Status":"stable","Issued":1783731990,
   "Description":"rebase to v2.6.0 to fix CVE-2026-54371","Message":"",
   "references":[{"Title":"CVE-2026-54371 attr: Symlink Traversal Privilege Escalation",
                  "Id":"2494172","Type":"bugzilla",
                  "Url":"https://bugzilla.redhat.com/show_bug.cgi?id=2494172"}]},
  {"Name":"FEDORA-2026-6b9a652463","Title":"libacl","Severity":"Important",
   "Type":"security","Status":"stable","Issued":1783731990,"Description":"acl fix",
   "references":[{"Title":"ref","Id":"CVE-2026-54369","Type":"cve","Url":"u"},
                 {"Title":"ref2","Id":"CVE-2026-54370","Type":"cve","Url":"u"}]}
]"""


def test_dnf5_is_detected_from_version_output_not_a_path():
    """On a dnf5 system dnf5 IS /usr/bin/dnf, and on RHEL 10.1 /usr/bin/dnf is a
    symlink to dnf-3 — so only the version string can tell them apart."""
    from fettle.advisories.rhel_source import is_dnf5
    with patch("fettle.command.run", return_value=command.Proc(0, "dnf5 version 5.4.2.1\n", "")):
        assert is_dnf5() is True
    with patch("fettle.command.run", return_value=command.Proc(0, "4.20.0\n", "")):
        assert is_dnf5() is False


def test_dnf5_list_json_is_parsed():
    from fettle.advisories.rhel_source import parse_list_json
    rows = parse_list_json(_DNF5_LIST)
    assert len(rows) == 2
    assert rows[0] == ("FEDORA-2026-6b9a652463", "Important",
                       "libacl-2.4.0-1.fc44.x86_64")


def test_dnf5_prefers_structured_cve_references():
    from fettle.advisories.rhel_source import parse_info_json
    rec = parse_info_json(_DNF5_INFO)["FEDORA-2026-6b9a652463"]
    assert rec["cves"] == ["CVE-2026-54369", "CVE-2026-54370"]


def test_dnf5_recovers_cves_when_every_reference_is_a_bugzilla():
    """Real Fedora data: 0 of 20 references were type `cve`, yet 7 of 8 advisories
    named their CVE in a reference title or description. Without this fallback those
    findings would carry no CVE at all."""
    from fettle.advisories.rhel_source import parse_info_json
    rec = parse_info_json(_DNF5_INFO)["FEDORA-2026-daa458d11d"]
    assert rec["cves"] == ["CVE-2026-54371"]


def test_dnf5_end_to_end_produces_findings(tmp_path):
    """The regression that matters: the dnf4 regex parses dnf5 output to ZERO rows,
    silently. This asserts the dnf5 branch actually yields findings."""
    from fettle.advisories import db
    conn = db.connect(tmp_path / "a.db")

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:2] == ["dnf", "--version"]:
            return command.Proc(0, "dnf5 version 5.4.2.1\n", "")
        if c[:3] == ["dnf", "advisory", "list"]:
            return command.Proc(0, _DNF5_LIST, "")
        if c[:3] == ["dnf", "advisory", "info"]:
            return command.Proc(0, _DNF5_INFO, "")
        if c[:2] == ["rpm", "-qa"]:
            return command.Proc(0, "libacl 2.3.9-1.fc44\n", "")
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run):
        assert RhelAdvisorySource().refresh(conn, _ctx()) == 2
        found = {f.package: f for f in RhelAdvisorySource().findings(_ctx(), conn)}
    assert found["libacl"].severity == "High"            # Important -> High
    assert found["libacl"].installed_version == "2.3.9-1.fc44"
    assert found["libacl"].fixed_version == "2.4.0-1.fc44"
    assert found["attr"].cves == ["CVE-2026-54371"]      # recovered from the title


def test_dnf5_uses_advisory_not_updateinfo():
    """dnf5 aliases `updateinfo` to `advisory`, so calling the dnf4 form succeeds and
    returns an unparseable shape — the version gate must pick the JSON command."""
    seen = []

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        seen.append(c)
        if c[:2] == ["dnf", "--version"]:
            return command.Proc(0, "dnf5 version 5.4.2.1\n", "")
        return command.Proc(0, "[]", "")

    with patch("fettle.command.run", side_effect=fake_run):
        RhelAdvisorySource()._fetch()
    assert any(c[:3] == ["dnf", "advisory", "list"] for c in seen)
    assert not any("updateinfo" in c for c in seen)
    assert not any("--with-cve" in c for c in seen)      # on dnf5 it FILTERS, not enriches
