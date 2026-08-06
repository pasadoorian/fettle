"""`--yes` semantics: it answers questions, it does not override safety judgements.

That distinction is already fettle's design language — a CRITICAL AUR pre-check finding
needs `--force-aur` *on top of* `--yes`, and container images awaiting confirmation are
skipped under `--yes` rather than auto-approved. This row checks the rest agrees.
"""

from unittest.mock import patch

from fettle.backends.base import Context
from fettle.backends.debian import DebianBackend
from fettle.config import Config
from fettle.output import Output


def _ctx(**kw):
    return Context(output=Output(color=False), config=Config(), **kw)


def _orphans(ctx, source, names):
    """Run the orphan half of check_foreign_orphans with a controlled candidate list."""
    ran = []
    with patch.object(DebianBackend, "_orphan_candidates",
                      return_value=(source, names)), \
         patch.object(DebianBackend, "_obsolete_packages", return_value=[]), \
         patch.object(DebianBackend, "_autoremove_preview", return_value=[]), \
         patch.object(DebianBackend, "installed_packages", return_value=set()), \
         patch.object(Context, "execute", side_effect=lambda c, **k: ran.append(list(c))):
        DebianBackend().check_foreign_orphans(ctx)
    return ran


def test_yes_does_not_auto_purge_a_list_fettle_inferred(capsys):
    """`deborphan` is gone from Debian 13, so the fallback is fettle's OWN reverse-
    dependency scan. Under `--yes` that meant purging every package a heuristic guessed
    at, with apt's confirmation suppressed too — no human anywhere in the loop."""
    ctx = _ctx(assume_yes=True)
    ran = _orphans(ctx, "dpkg reverse-deps", ["libfoo1", "libbar2"])
    assert not [c for c in ran if "purge" in c], ran
    text = "".join(capsys.readouterr())
    assert "NOT removed" in text


def test_yes_still_purges_what_a_dedicated_tool_reported():
    """deborphan's verdict is a tool's, not ours — existing behaviour is unchanged where
    it is available."""
    ctx = _ctx(assume_yes=True)
    ran = _orphans(ctx, "deborphan", ["libfoo1"])
    assert [c for c in ran if "purge" in c], ran


def test_interactive_runs_are_unaffected_by_the_guard():
    """The guard is about unattended runs. With a human present, the inferred list is
    still offered — per package, as before."""
    ctx = _ctx(assume_yes=False)
    with patch.object(Context, "select", return_value=["libfoo1"]):
        ran = _orphans(ctx, "dpkg reverse-deps", ["libfoo1"])
    assert [c for c in ran if "purge" in c], ran


def test_the_skipped_orphans_are_reported_not_silently_dropped():
    """A guard that quietly does nothing is its own bug."""
    ctx = _ctx(assume_yes=True)
    _orphans(ctx, "dpkg reverse-deps", ["libfoo1"])
    assert any("not removed" in w for w in ctx.output._warnings), ctx.output._warnings
