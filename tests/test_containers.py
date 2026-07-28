"""`fettle container-update` (-C) — per-image decisions and the confirmation gates."""

import json
from unittest.mock import patch

from fettle import command, containers
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


def _ctx(*, dry_run=False, assume_yes=False, **cfg):
    c = Config()
    c.containers = cfg
    return Context(output=Output(color=False), config=c,
                   dry_run=dry_run, assume_yes=assume_yes)


def _images(*refs):
    out = []
    for r in refs:
        repo, _, tag = r.partition(":")
        out.append({"Repository": repo, "Tag": tag or "latest",
                    "CreatedAt": "2026-06-15 10:30:30 -0400 EDT", "ID": "i", "Size": "1MB"})
    return "\n".join(json.dumps(i) for i in out)


def _run(refs, ctx, *, answers=None, list_rc=0, pull_rc=0):
    """Drive containers.run; returns the commands actually executed."""
    calls = []
    replies = list(answers or [])

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        calls.append(c)
        if c[1:2] == ["images"]:
            return command.Proc(list_rc, _images(*refs), "denied" if list_rc else "")
        return command.Proc(pull_rc, "", "")

    def fake_input(_prompt=""):
        return replies.pop(0) if replies else "n"

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n == "docker"), \
         patch("builtins.input", side_effect=fake_input):
        containers.run(ctx)
    return [c for c in calls if c[1:2] == ["pull"]]


# -- the decision table ------------------------------------------------------
def test_decide_order_override_beats_lists():
    cfg = {"auto_update": "never", "always_update": ["*"]}
    assert containers.decide("x:latest", "x", cfg)[0] == containers.SKIP
    cfg = {"auto_update": "always", "never_update": ["*"]}
    assert containers.decide("x:latest", "x", cfg)[0] == containers.PULL


def test_decide_never_beats_always():
    cfg = {"never_update": ["x*"], "always_update": ["x:latest"]}
    assert containers.decide("x:latest", "x", cfg)[0] == containers.SKIP


def test_decide_unlisted_asks():
    assert containers.decide("x:latest", "x", {})[0] == containers.ASK


def test_lists_match_bare_repo_as_well_as_repo_tag():
    """`never_update = ["cvetool"]` should work without writing `cvetool:*`."""
    cfg = {"never_update": ["cvetool"]}
    assert containers.decide("cvetool:latest", "cvetool", cfg)[0] == containers.SKIP


# -- interactive -------------------------------------------------------------
def test_prompt_yes_pulls_and_no_skips():
    pulls = _run(["a:latest", "b:latest"], _ctx(), answers=["y", "n"])
    assert [p[2] for p in pulls] == ["a:latest"]


def test_always_list_pulls_without_asking():
    # No answers queued: any prompt would fall through to "n" and pull nothing.
    pulls = _run(["keep:latest"], _ctx(always_update=["keep"]))
    assert [p[2] for p in pulls] == ["keep:latest"]


def test_never_list_is_not_pulled_even_when_confirmed():
    pulls = _run(["skipme:latest"], _ctx(never_update=["skipme"]), answers=["y"])
    assert pulls == []


# -- unattended: honour config only -----------------------------------------
def test_yes_pulls_only_always_update_and_skips_the_rest():
    """--yes must NOT auto-approve unlisted images. ctx.confirm() returns True under
    assume_yes, so the ask-branch has to short-circuit before reaching it."""
    pulls = _run(["listed:latest", "unlisted:latest"],
                 _ctx(assume_yes=True, always_update=["listed"]))
    assert [p[2] for p in pulls] == ["listed:latest"]


def test_yes_with_no_config_pulls_nothing(capsys):
    pulls = _run(["a:latest", "b:latest"], _ctx(assume_yes=True))
    assert pulls == []
    out = capsys.readouterr().out
    assert "unattended" in out and "always_update" in out


def test_auto_update_always_pulls_everything_unattended():
    pulls = _run(["a:latest", "b:latest"], _ctx(assume_yes=True, auto_update="always"))
    assert sorted(p[2] for p in pulls) == ["a:latest", "b:latest"]


# -- dry-run -----------------------------------------------------------------
def test_dry_run_pulls_nothing_and_shows_each_decision(capsys):
    pulls = _run(["ask-me:latest", "keep:latest", "no:latest"],
                 _ctx(dry_run=True, always_update=["keep"], never_update=["no"]))
    assert pulls == []                       # ctx.execute is a no-op under dry-run
    out = capsys.readouterr().out
    assert "would ask before pulling ask-me:latest" in out
    assert "would run" in out and "keep:latest" in out     # the always_update one
    assert "no:latest: skipped (never_update)" in out
    assert "nothing pulled" in out


# -- failure paths -----------------------------------------------------------
def test_listing_failure_updates_nothing_and_says_so(capsys):
    pulls = _run(["a:latest"], _ctx(assume_yes=True, auto_update="always"), list_rc=1)
    assert pulls == []
    assert "no images were updated" in capsys.readouterr().err


def test_failed_pull_is_reported(capsys):
    _run(["a:latest"], _ctx(auto_update="always"), pull_rc=1)
    assert "pull failed" in capsys.readouterr().err


def test_no_runtime_does_nothing(capsys):
    with patch("fettle.command.which", side_effect=lambda n: False):
        containers.run(_ctx())
    assert "no container runtime" in capsys.readouterr().out


def test_dangling_images_are_not_pull_targets():
    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[1:2] == ["images"]:
            return command.Proc(0, json.dumps(
                {"Repository": "<none>", "Tag": "<none>", "ID": "i", "Size": "1MB",
                 "CreatedAt": "2026-06-15 10:30:30 -0400 EDT"}), "")
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n == "docker"):
        containers.run(_ctx(auto_update="always"))   # would pull everything if listed
