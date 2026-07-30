"""Distro-neutral backend behaviour that every backend inherits.

Snap pruning is here rather than in `test_debian.py` because the point of the code is
that it is *not* Debian's: snapd installs and refreshes identically on every
distribution, so an Arch or RHEL box with snapd accumulates the same superseded
revisions. All three backends are driven against the one `SNAP_LIST_ALL` fixture.
"""

from pathlib import Path
from unittest.mock import patch

from conftest import SNAP_LIST_ALL

from fettle import command
from fettle.backends.arch import ArchBackend
from fettle.backends.base import Context
from fettle.backends.debian import DebianBackend
from fettle.backends.rhel import RhelBackend
from fettle.config import Config
from fettle.output import Output

_BACKENDS = [ArchBackend, DebianBackend, RhelBackend]


def _ctx(cfg=None, **kw):
    return Context(output=Output(color=False), config=cfg or Config(),
                   sudo_user="paul", user_home=Path("/home/paul"), **kw)


def _clean(backend, *, snaps=SNAP_LIST_ALL, present=True, ctx=None, **kw):
    """Run `backend().clean_caches`, answering `snap list --all` with `snaps`."""
    calls: list[list[str]] = []

    def fake_run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        calls.append(cmd)
        if cmd[:3] == ["snap", "list", "--all"]:
            return command.Proc(0, snaps, "")
        return command.Proc(0, "", "")

    def fake_which(name):
        return present if name == "snap" else True

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=fake_which):
        backend().clean_caches(ctx or _ctx(**kw))
    return calls


def test_every_backend_prunes_disabled_snaps():
    """The parity that was missing: an Arch or RHEL box with snapd installed was never
    offered its superseded revisions, only a Debian one was."""
    for backend in _BACKENDS:
        argvs = _clean(backend, assume_yes=True)  # --yes accepts all prompts
        assert ["snap", "list", "--all"] in argvs, backend.name
        assert ["snap", "remove", "core20", "--revision=2015"] in argvs, backend.name
        assert ["snap", "remove", "firefox", "--revision=3026"] in argvs, backend.name
        # the active revision of core20 is not disabled and must survive
        assert not any(a[:3] == ["snap", "remove", "core20"] and "--revision=1974" in a
                       for a in argvs), backend.name


def test_no_backend_removes_a_snap_without_confirmation():
    """No --yes and no TTY -> every per-revision prompt is declined. Removing an
    installed snap revision must never happen unasked."""
    for backend in _BACKENDS:
        with patch("builtins.input", side_effect=EOFError):  # no TTY -> declined
            argvs = _clean(backend)
        assert ["snap", "list", "--all"] in argvs, backend.name
        assert not any(a[:2] == ["snap", "remove"] for a in argvs), backend.name


def test_snapless_box_is_not_even_queried():
    """Self-gated on `which snap`, so a machine without snapd pays one which call."""
    for backend in _BACKENDS:
        argvs = _clean(backend, present=False, assume_yes=True)
        assert not any(a[0] == "snap" for a in argvs), backend.name


def test_nothing_disabled_removes_nothing():
    header = "Name Version Rev Tracking Publisher Notes\n"
    for backend in _BACKENDS:
        argvs = _clean(backend, snaps=header + "core20 20230801 2015 x canonical base\n",
                       assume_yes=True)
        assert not any(a[:2] == ["snap", "remove"] for a in argvs), backend.name


def test_snap_updater_none_opts_out_where_configured():
    """Debian and RHEL expose `snap_updater`; setting it to none skips snap entirely."""
    for backend, section in [(DebianBackend, "debian"), (RhelBackend, "rhel")]:
        cfg = Config(updaters={section: {"snap_updater": "none"}})
        argvs = _clean(backend, ctx=_ctx(cfg, assume_yes=True))
        assert not any(a[0] == "snap" for a in argvs), backend.name


def test_dry_run_previews_the_revisions_it_would_offer(capsys):
    """A dry run names the revisions a real run would ask about, and removes none.

    The read-only listing deliberately DOES run under --dry-run, matching every other
    `_query` path in this codebase. Skipping it would be cheaper by one subprocess and
    strictly worse: for an action that confirms per item, "which ones would you ask me
    about?" is the question --dry-run exists to answer, and a generic "would look for
    superseded revisions" cannot answer it.
    """
    for backend in _BACKENDS:
        argvs = _clean(backend, dry_run=True)
        out = capsys.readouterr().out
        assert ["snap", "list", "--all"] in argvs, backend.name
        assert "core20 (rev 2015)" in out and "firefox (rev 3026)" in out, backend.name
        assert "core20 (rev 1974)" not in out, backend.name   # active, not superseded
        assert not any(a[:2] == ["snap", "remove"] for a in argvs), backend.name
