"""The packaging scripts' contract, tested from the suite rather than by tagging.

`check-tag.sh` is the first thing the release workflow runs and the only thing standing
between a typo and a release whose packages name the wrong version. That is a bad
failure in a specific way: it installs, it runs, and every bug report afterwards cites a
version that was never built. So it is a script the suite can exercise rather than a few
lines buried in YAML.

`version.sh` is the single source both the packages and the guard read, so a change to
`pyproject.toml`'s layout that broke it would silently take the rest with it.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ("install.sh", "version.sh", "check-tag.sh",
           "deb/build.sh", "rpm/build.sh", "arch/build.sh", "zipapp/build.sh")


def _run(script: str, *args: str, cwd: Path | None = None):
    return subprocess.run([str(ROOT / "packaging" / script), *args],
                          capture_output=True, text=True, cwd=cwd or ROOT)


# -- version.sh --------------------------------------------------------------

def test_version_matches_the_package():
    """The shell script and the installed package must agree, or the .deb says one
    thing and `fettle --version` says another."""
    import fettle

    out = _run("version.sh")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == fettle.__version__


def test_version_is_not_confused_by_the_ruff_section():
    """`pyproject.toml` also contains `target-version = "py311"`; a looser pattern would
    match it and hand every package the version "py311"."""
    out = _run("version.sh")
    assert out.stdout.strip() != "py311"
    assert out.stdout.count("\n") == 1, "exactly one line, no extra matches"


# -- check-tag.sh ------------------------------------------------------------

def test_a_matching_tag_passes_and_prints_the_bare_version():
    import fettle

    out = _run("check-tag.sh", f"v{fettle.__version__}")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == fettle.__version__


def test_a_mismatched_tag_fails_and_says_what_to_do():
    """The whole point. Both versions have to appear in the message, or the reader is
    left diffing two numbers they cannot see."""
    out = _run("check-tag.sh", "v99.99.99")
    assert out.returncode == 1
    assert "99.99.99" in out.stderr
    assert "pyproject.toml" in out.stderr


@pytest.mark.parametrize("tag", ["1.0.0", "release-1.0.0", "", "x1.0.0"])
def test_a_tag_that_is_not_a_version_tag_is_rejected(tag):
    """`1.0.0` without the `v` is the plausible mistake, and it must not be treated as
    a match by accident."""
    out = _run("check-tag.sh", tag)
    assert out.returncode == 1


def test_check_tag_needs_an_argument():
    out = _run("check-tag.sh")
    assert out.returncode != 0


def test_the_guard_passes_for_the_tag_the_repo_would_be_released_under():
    """Documents the pre-flight command, and fails if it ever stops working:

        packaging/check-tag.sh "v$(packaging/version.sh)"
    """
    version = _run("version.sh").stdout.strip()
    assert _run("check-tag.sh", f"v{version}").returncode == 0


# -- the scripts themselves --------------------------------------------------

@pytest.mark.parametrize("script", SCRIPTS)
def test_every_packaging_script_is_executable_and_valid_shell(script):
    """A packaging script committed without its executable bit fails only in CI, and a
    syntax error in one fails only when that distro's job runs."""
    path = ROOT / "packaging" / script
    assert path.exists(), f"{script} is missing"
    assert path.stat().st_mode & 0o111, f"{script} is not executable"

    sh = shutil.which("sh")
    if sh is None:                                   # pragma: no cover - no POSIX sh
        pytest.skip("no sh available")
    check = subprocess.run([sh, "-n", str(path)], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr


@pytest.mark.skipif(sys.platform != "linux", reason="packaging targets Linux")
def test_install_sh_produces_a_runnable_tree(tmp_path):
    """The layout all three packages share, checked once here rather than three times
    in three containers. Also proves the generated wrapper is valid shell — it is
    written by a heredoc, which is exactly where a quoting slip hides."""
    out = _run("install.sh", str(tmp_path))
    assert out.returncode == 0, out.stderr

    wrapper = tmp_path / "usr/bin/fettle"
    assert wrapper.stat().st_mode & 0o111
    assert (tmp_path / "usr/lib/fettle/fettle/cli.py").exists()
    assert (tmp_path / "usr/share/bash-completion/completions/fettle").exists()
    assert (tmp_path / "usr/share/doc/fettle/fettle.toml.example").exists()

    syntax = subprocess.run(["sh", "-n", str(wrapper)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr

    # The interpreter search is the part that has to be right on RHEL 9 and Ubuntu
    # 22.04, where `python3` is too old and a versioned name is the working one.
    text = wrapper.read_text()
    assert "python3.11" in text
    assert "3, 11" in text, "the python3 fallback must still check the version"


# -- the shared launcher template --------------------------------------------
#
# The interpreter search is the fiddly part of both launchers, and it exists because
# `python3` is 3.9 on RHEL 9 and 3.10 on Ubuntu 22.04. It lives in one template
# (packaging/wrapper.sh.in) precisely so the packaged launcher and the one in the zipapp
# archive cannot drift; these check the substitution actually produced something, since
# a sed that matched nothing fails silently and ships a launcher with a literal
# placeholder in it.

def _generated_wrappers(tmp_path):
    """The packaged launcher and the archive's, both freshly generated."""
    assert _run("install.sh", str(tmp_path)).returncode == 0
    packaged = (tmp_path / "usr/bin/fettle").read_text()

    template = (ROOT / "packaging/wrapper.sh.in").read_text()
    archive = (template
               .replace("@SETUP@", 'here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)')
               .replace("@TARGET@", '"$here/fettle.pyz"'))
    return packaged, archive


@pytest.mark.skipif(sys.platform != "linux", reason="packaging targets Linux")
def test_no_placeholder_survives_into_a_launcher(tmp_path):
    """A sed that matches nothing leaves `@SETUP@` in the shipped script, which then
    fails at run time with a syntax error nobody can place."""
    for text in _generated_wrappers(tmp_path):
        assert "@SETUP@" not in text
        assert "@TARGET@" not in text


@pytest.mark.skipif(sys.platform != "linux", reason="packaging targets Linux")
def test_both_launchers_keep_the_interpreter_search(tmp_path):
    packaged, archive = _generated_wrappers(tmp_path)
    for text in (packaged, archive):
        assert "python3.11" in text
        assert "3, 11" in text, "the python3 fallback must still check the version"
        assert "sudo dnf install python3.11" in text, "the failure message must help"


@pytest.mark.skipif(sys.platform != "linux", reason="packaging targets Linux")
def test_the_two_launchers_differ_only_in_where_they_point(tmp_path):
    """If they ever diverge beyond the substitution, the template has stopped being the
    single source and one of them is about to rot."""
    packaged, archive = _generated_wrappers(tmp_path)
    strip = lambda t: [ln for ln in t.splitlines()                       # noqa: E731
                       if "PYTHONPATH" not in ln and "fettle.pyz" not in ln
                       and "-m fettle" not in ln and "dirname" not in ln]
    assert strip(packaged) == strip(archive)


def test_the_archive_name_cannot_collide_with_github_source_archives():
    """GitHub attaches its own `fettle-<version>.zip` and `.tar.gz` to every tag. The
    zipapp archives carry a `-zipapp` suffix so both can exist on one release page."""
    build = (ROOT / "packaging/zipapp/build.sh").read_text()
    assert "-zipapp.tar.gz" in build
    assert "-zipapp.zip" in build
