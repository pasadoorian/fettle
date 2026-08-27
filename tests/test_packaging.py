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

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ("install.sh", "version.sh", "check-tag.sh",
           "deb/build.sh", "rpm/build.sh", "arch/build.sh", "zipapp/build.sh",
           "release-notes.sh", "publish.sh")


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
    # Non-zero, not specifically 1: `${1:?…}` exits 1 under bash and 2 under dash, and
    # /bin/sh is dash on Debian and Ubuntu — including the CI runner. Pinning the exact
    # code made this a test of which shell happened to be /bin/sh.
    assert out.returncode != 0


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


# -- release-notes.sh --------------------------------------------------------
#
# The changelog entry is written by hand for every release, with the reasoning in it.
# Generating the release page from it means one account of each change rather than two,
# and no chance of the two disagreeing.

def test_notes_are_the_changelog_section_for_that_version():
    import fettle

    out = _run("release-notes.sh", fettle.__version__)
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith(f"## [{fettle.__version__}]")


def test_notes_stop_at_the_next_release():
    """An off-by-one in the range would attach every previous release's notes to this
    one, which reads as a plausible changelog and is wrong from the second line on."""
    versions = re.findall(r"^## \[([0-9][^\]]*)\]", (ROOT / "CHANGELOG.md").read_text(),
                          re.M)
    assert len(versions) > 2, "need at least three entries to test a boundary"
    newest, following = versions[0], versions[1]

    body = _run("release-notes.sh", newest).stdout
    assert f"## [{following}]" not in body


def test_the_oldest_entry_works_even_with_no_following_heading():
    """The last section has no `## [` after it, so the range has to end at EOF."""
    versions = re.findall(r"^## \[([0-9][^\]]*)\]", (ROOT / "CHANGELOG.md").read_text(),
                          re.M)
    out = _run("release-notes.sh", versions[-1])
    assert out.returncode == 0, out.stderr
    assert out.stdout.startswith(f"## [{versions[-1]}]")


def test_a_version_with_no_changelog_section_fails_loudly():
    """The important one. The fallback would be GitHub's auto-generated commit list —
    for a release like 1.0.0 that is a wall of "packaging P4: …" lines saying nothing a
    user wants, and it would ship without anyone noticing."""
    out = _run("release-notes.sh", "9.9.9")
    assert out.returncode == 1
    assert "9.9.9" in out.stderr
    assert "CHANGELOG.md" in out.stderr


def test_notes_explain_what_each_artifact_is():
    """Six files on a release page with no explanation is unhelpful, and this part is
    identical every time, so it is generated rather than retyped."""
    import fettle

    body = _run("release-notes.sh", fettle.__version__).stdout
    for fragment in (".deb", ".rpm", ".pkg.tar.zst", "zipapp", "fettle.pyz",
                     "python 3.11", "SHA256SUMS"):
        assert fragment in body, f"the notes never mention {fragment}"


def test_release_notes_needs_an_argument():
    assert _run("release-notes.sh").returncode != 0


# -- the compiled binary's build ---------------------------------------------

def test_the_axis_list_is_derived_not_hardcoded():
    """A literal list in the build script is a second copy of AXIS_NAMES, and the day a
    seventh axis is added the build would drop it silently — the binary would compile,
    run, and report that axis as blind forever."""
    build = (ROOT / "packaging/binary/build.sh").read_text()
    assert "AXIS_NAMES" in build, "the axis list must come from fettle, not a literal"

    from fettle.hardening.axes import AXIS_NAMES
    for axis in AXIS_NAMES:
        assert f'"{axis}"' not in build and f"'{axis}'" not in build, \
            f"{axis} appears as a literal — the list has been hardcoded again"


def test_the_build_smoke_tests_its_own_output():
    """A binary that fails the smoke test must never become an artifact, so the call has
    to be in the build rather than something a person remembers to run."""
    build = (ROOT / "packaging/binary/build.sh").read_text()
    assert "smoke.sh" in build


def test_the_smoke_test_checks_for_positive_results():
    """The failures here are silent — a binary missing its axes exits 0 and audits
    nothing — so "it ran" is not evidence. These are the assertions that make it a
    test rather than a launch."""
    smoke = (ROOT / "packaging/binary/smoke.sh").read_text()
    assert "did not complete" in smoke, "must detect axes reported as blind"
    assert "(binary)" in smoke, "must check the build reports its own kind"
    assert "FileNotFoundError" in smoke, "must detect a missing embedded zipapp"
    assert "checked" in smoke, "must check something was actually examined"


# -- publish.sh --------------------------------------------------------------
# Written after the v1.16.0 release, where `gh release create … staged/*` hit HTTP 400
# on one asset: it aborted with 2 of 9 attached, could not be re-run (`create` refuses
# when the release exists), and had nothing checking the result. The third is the one
# that matters — had the 400 hit the last file, `gh` would have exited 0 with a package
# missing from the release.
def _gh_stub(tmp_path: Path, script: str) -> dict:
    """Put a fake `gh` on PATH and return an env that finds it first."""
    import os

    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    gh = bindir / "gh"
    gh.write_text("#!/bin/sh\n" + script)
    gh.chmod(0o755)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
               GH_LOG=str(tmp_path / "gh.log"))
    return env


def _publish(tmp_path: Path, env: dict, files=("a.deb", "b.rpm")):
    staged = tmp_path / "staged"
    staged.mkdir(exist_ok=True)
    for f in files:
        (staged / f).write_text("x")
    notes = tmp_path / "NOTES.md"
    notes.write_text("# notes\n")
    return subprocess.run(
        [str(ROOT / "packaging" / "publish.sh"), "v9.9.9", "fettle 9.9.9",
         str(notes), str(staged)],
        capture_output=True, text=True, env=env)


_LOG_AND_LIST = '''
echo "$@" >> "$GH_LOG"
case "$1 $2" in
  "release view") [ "$3" = "v9.9.9" ] && [ "$4" = "--json" ] && { %s; exit 0; }
                  exit 1 ;;
esac
exit 0
'''


def test_publish_attaches_each_asset_separately_not_as_one_glob():
    """One `gh release upload` per file, so a failure is isolated to that file instead
    of aborting every asset after it."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = _gh_stub(tmp, _LOG_AND_LIST % 'printf "a.deb\\nb.rpm\\n"')
        out = _publish(tmp, env)
        log = (tmp / "gh.log").read_text()
    assert out.returncode == 0, out.stderr
    uploads = [ln for ln in log.splitlines() if ln.startswith("release upload")]
    assert len(uploads) == 2, log
    assert all("--clobber" in ln for ln in uploads)


def test_publish_adopts_an_existing_release_instead_of_failing():
    """`gh release create` refuses when the release exists, so the obvious recovery —
    re-run the failed job — could only ever print "already exists"."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # `release view <tag>` succeeds => the release already exists
        env = _gh_stub(tmp, '''
echo "$@" >> "$GH_LOG"
[ "$1 $2" = "release view" ] && { printf "a.deb\\nb.rpm\\n"; exit 0; }
exit 0
''')
        out = _publish(tmp, env)
        log = (tmp / "gh.log").read_text()
    assert out.returncode == 0, out.stderr
    assert "release create" not in log, "tried to create a release that already exists"
    assert "repair run" in out.stdout


def test_publish_fails_when_an_asset_is_missing_from_the_release():
    """The check that makes a silent partial release impossible: asked of the release
    itself, not inferred from the upload loop, because an upload can report success and
    still leave nothing attached."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # every upload "succeeds", but the release only ever lists one asset
        env = _gh_stub(tmp, _LOG_AND_LIST % 'printf "a.deb\\n"')
        out = _publish(tmp, env)
    assert out.returncode == 1
    assert "INCOMPLETE" in out.stderr
    assert "b.rpm" in out.stderr
    assert "still a draft" in out.stderr


def test_publish_retries_a_failed_upload_before_giving_up():
    """The failure that prompted this was transient — the same file uploaded fine on a
    later attempt."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = _gh_stub(tmp, '''
echo "$@" >> "$GH_LOG"
case "$1 $2" in
  "release view") printf "a.deb\\nb.rpm\\n"; exit 0 ;;
  "release upload")
      n=$(grep -c "release upload .*a.deb" "$GH_LOG" 2>/dev/null || echo 0)
      case "$4" in *a.deb) [ "$n" -lt 2 ] && exit 1 ;; esac
      exit 0 ;;
esac
exit 0
''')
        out = _publish(tmp, env)
        log = (tmp / "gh.log").read_text()
    assert out.returncode == 0, out.stderr
    assert log.count("a.deb") >= 2, "did not retry"
    assert "retrying" in out.stderr


def test_publish_refuses_an_empty_staged_directory():
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        env = _gh_stub(tmp, "exit 0")
        out = _publish(tmp, env, files=())
    assert out.returncode == 1 and "empty" in out.stderr


def test_publish_keeps_a_multiword_title_as_one_argument():
    """Caught in production on v1.19.0. The title is built from `fettle $VERSION`, so it
    contains a space; expanded from an unquoted string it split into `--title fettle`
    plus a stray `1.19.0`, which gh read as an asset pattern and rejected with
    "no matches found for 1.19.0". The earlier test only checked that `release create`
    was called, not that its arguments survived."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # one argument per line, so a split title is visible
        env = _gh_stub(tmp, '''
printf '%s\\n' "$@" >> "$GH_LOG"
echo "--" >> "$GH_LOG"
[ "$1 $2" = "release view" ] && { printf "a.deb\\nb.rpm\\n"; exit 1; }
exit 0
''')
        # `release view` exits 1 so the create branch runs
        env2 = _gh_stub(tmp, '''
printf '%s\\n' "$@" >> "$GH_LOG"
case "$1 $2" in
  "release view") [ "$4" = "--json" ] && { printf "a.deb\\nb.rpm\\n"; exit 0; }; exit 1 ;;
esac
exit 0
''')
        out = _publish(tmp, env2)
        log = (tmp / "gh.log").read_text().splitlines()
    assert out.returncode == 0, out.stderr
    assert "fettle 9.9.9" in log, \
        f"the title was split into separate arguments: {log}"
    assert "9.9.9" not in log, "a bare version leaked in as a positional argument"
    assert env  # the first stub is unused; kept to document the shape
