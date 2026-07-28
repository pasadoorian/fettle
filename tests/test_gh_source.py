"""GitHub CLI extension provider — origin repository of each installed extension."""

from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import UNVERIFIED_PUBLISHER, Severity
from fettle.supplychain.gh_source import GhSource, extension_origin

_EXT = ".local/share/gh/extensions"


def _ctx(home):
    return Context(output=Output(color=False), config=Config(), user_home=home)


def _binary_ext(home, name, owner, repo=None, tag="v1.0.0"):
    """A precompiled extension: gh writes a flat manifest.yml beside the binary."""
    d = home / _EXT / name
    d.mkdir(parents=True)
    (d / "manifest.yml").write_text(
        f"owner: {owner}\nname: {repo or name}\nhost: github.com\ntag: {tag}\n")
    return d


def _git_ext(home, name, url):
    """A source extension: a git clone, so the origin remote names the repo."""
    d = home / _EXT / name
    (d / ".git").mkdir(parents=True)
    (d / ".git/config").write_text(
        '[core]\n\trepositoryformatversion = 0\n'
        f'[remote "origin"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n')
    return d


def _run(home):
    return GhSource().findings(_ctx(home))


# -- origin extraction -------------------------------------------------------
def test_origin_from_binary_manifest(tmp_path):
    d = _binary_ext(tmp_path, "gh-dash", "dlvhdr", "gh-dash")
    assert extension_origin(d) == ("dlvhdr", "gh-dash")


def test_origin_from_https_git_remote(tmp_path):
    d = _git_ext(tmp_path, "gh-poi", "https://github.com/seachicken/gh-poi.git")
    assert extension_origin(d) == ("seachicken", "gh-poi")


def test_origin_from_ssh_git_remote(tmp_path):
    d = _git_ext(tmp_path, "gh-x", "git@github.com:someone/gh-x.git")
    assert extension_origin(d) == ("someone", "gh-x")


def test_origin_unknown_when_nothing_records_it(tmp_path):
    d = tmp_path / _EXT / "gh-mystery"
    d.mkdir(parents=True)
    assert extension_origin(d) == ("", "")


# -- findings ----------------------------------------------------------------
def test_third_party_extension_is_flagged_with_its_owner(tmp_path):
    _binary_ext(tmp_path, "gh-dash", "dlvhdr")
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].question == UNVERIFIED_PUBLISHER and f[0].severity == Severity.WARN
    assert "github.com/dlvhdr/gh-dash" in f[0].detail
    assert "act as you" in f[0].detail          # the token exposure is the point


def test_first_party_extensions_are_not_flagged(tmp_path):
    _binary_ext(tmp_path, "gh-copilot", "github")
    _git_ext(tmp_path, "gh-actions-cache", "https://github.com/cli/gh-actions-cache")
    assert _run(tmp_path) == []


def test_unknown_origin_is_reported_at_lower_severity(tmp_path):
    (tmp_path / _EXT / "gh-mystery").mkdir(parents=True)
    f = _run(tmp_path)
    assert len(f) == 1 and f[0].severity == Severity.LOW
    assert "could not be determined" in f[0].detail


def test_mixed_install_kinds_are_all_seen(tmp_path):
    _binary_ext(tmp_path, "gh-a", "alice")
    _git_ext(tmp_path, "gh-b", "https://github.com/bob/gh-b.git")
    (tmp_path / _EXT / "gh-c").mkdir(parents=True)
    assert {x.package for x in _run(tmp_path)} == {"gh-a", "gh-b", "gh-c"}


# -- presence ----------------------------------------------------------------
def test_absent_when_no_extension_dir(tmp_path):
    assert GhSource().is_present(_ctx(tmp_path)) is False
    assert _run(tmp_path) == []


def test_present_but_empty_is_clean(tmp_path):
    """gh installed with no extensions — a true negative, not a blind spot."""
    (tmp_path / _EXT).mkdir(parents=True)
    assert GhSource().is_present(_ctx(tmp_path)) is True
    assert _run(tmp_path) == []
