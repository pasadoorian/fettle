from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.arch import ArchBackend
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output


def _ctx(cfg=None, **kw):
    return Context(output=Output(color=False), config=cfg or Config(),
                   sudo_user="paul", user_home=Path("/home/paul"), **kw)


def _recorder():
    calls: list[tuple[list[str], str | None]] = []

    def fake_run(cmd, *, as_user=None, capture=False):
        calls.append((list(cmd), as_user))
        return command.Proc(0, "", "")

    return calls, fake_run


def test_clean_clears_pacman_cache_and_removes_dirs():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().clean_caches(_ctx())
    argvs = [c for c, _ in calls]
    assert ["pacman", "-Scc", "--noconfirm"] in argvs
    assert any(c[:2] == ["rm", "-rf"] and c[2].endswith(".cache/yay") for c in argvs)
    # pamac clean runs as the invoking user, not root
    assert any(c[:2] == ["pamac", "clean"] and u == "paul" for c, u in calls)


def test_update_default_pacman_then_yay():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        b, ctx = ArchBackend(), _ctx()
        b.update_system(ctx)
        b.update_extras(ctx)
    argvs = [c for c, _ in calls]
    assert ["pacman", "-Syuu", "--noconfirm"] in argvs
    assert any(c[0] == "yay" and u == "paul" for c, u in calls)


def test_update_aur_none_skips_yay():
    calls, fake = _recorder()
    cfg = Config(updaters={"arch": {"aur_updater": "none"}})
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        b, ctx = ArchBackend(), _ctx(cfg)
        b.update_system(ctx)
        b.update_extras(ctx)
    assert not any(c[0] == "yay" for c, _ in calls)


def test_update_pamac_all_in_one_skips_pacman():
    calls, fake = _recorder()
    cfg = Config(updaters={"arch": {"aur_updater": "pamac"}})
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        b, ctx = ArchBackend(), _ctx(cfg)
        b.update_system(ctx)
        b.update_extras(ctx)
    argvs = [c for c, _ in calls]
    assert any(c[0] == "pamac" and "update" in c for c in argvs)
    assert not any("-Syuu" in c for c in argvs)


def test_invalid_updater_falls_back_with_warning(capsys):
    cfg = Config(updaters={"arch": {"system_updater": "bogus", "aur_updater": "nope"}})
    b, ctx = ArchBackend(), _ctx(cfg)
    system, aur = b._updaters(ctx)
    assert (system, aur) == ("pacman", "yay")
    assert "invalid" in capsys.readouterr().err


def test_dry_run_executes_no_commands():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake):
        ArchBackend().clean_caches(_ctx(dry_run=True))
    assert calls == []  # dry-run never touches command.run
