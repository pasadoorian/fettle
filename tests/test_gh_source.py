"""GitHub CLI extension provider — origin repository of each installed extension."""

from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from unittest.mock import patch

from fettle.supplychain.base import (
    STALE_OR_ABANDONED,
    UNVERIFIABLE,
    UNVERIFIED_PUBLISHER,
    Severity,
)
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


def _run(home, *, upstream=True):
    """Patched by default so the suite never touches the network — and so it never
    burns GitHub's 60/hour unauthenticated rate limit from a test run."""
    with patch("fettle.supplychain.gh_source.still_upstream_url",
               return_value=upstream):
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
    assert f[0].question == UNVERIFIED_PUBLISHER and f[0].severity == Severity.MEDIUM
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


# -- does the repository still exist? ------------------------------------------
def test_vanished_repo_is_reported(tmp_path):
    _binary_ext(tmp_path, "gh-gone", "someone", "gh-gone")
    f = _run(tmp_path, upstream=False)
    w = next(x for x in f if x.question == STALE_OR_ABANDONED)
    assert "no longer resolves" in w.detail


def test_vanished_repo_says_private_and_deleted_are_the_same_404(tmp_path):
    """Honesty about the limit of the signal: an unauthenticated request cannot tell a
    deletion from a rename from a repo going private, and a rename is routine."""
    _binary_ext(tmp_path, "gh-gone", "someone", "gh-gone")
    w = next(x for x in _run(tmp_path, upstream=False)
             if x.question == STALE_OR_ABANDONED)
    assert "made private" in w.detail and "same" in w.detail


def test_rate_limited_api_is_not_a_deletion(tmp_path):
    """GitHub allows 60 unauthenticated requests an hour. A 403 must read as "could not
    tell", never as "your extensions were removed"."""
    _binary_ext(tmp_path, "gh-a", "someone", "gh-a")
    f = _run(tmp_path, upstream=None)
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]
    assert [x for x in f if x.question == UNVERIFIABLE]


def test_unknown_origin_is_never_asked_about(tmp_path):
    """No owner/repo means no URL to ask about — it must not become a false alarm."""
    d = tmp_path / ".local/share/gh/extensions/gh-mystery"
    d.mkdir(parents=True)
    seen = []
    with patch("fettle.supplychain.gh_source.still_upstream_url",
               side_effect=lambda u, **k: seen.append(u) or True):
        GhSource().findings(_ctx(tmp_path))
    assert seen == []
