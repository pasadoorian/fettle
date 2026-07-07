"""M3 maintenance checks for the Arch backend — all via the single run() mock."""

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


def _fake(responses, calls):
    """responses: {(cmd prefix tuple): stdout}. Records every call into `calls`."""
    def run(cmd, *, as_user=None, capture=False):
        calls.append((list(cmd), as_user))
        for key, val in responses.items():
            if list(cmd)[: len(key)] == list(key):
                return command.Proc(0, val, "")
        return command.Proc(0, "", "")
    return run


# -- orphans -----------------------------------------------------------------
def test_orphans_writes_alien_file_and_removes(tmp_path):
    calls = []
    responses = {
        ("pacman", "-Qm"): "brave-bin 1.0-1\nmy-aur-pkg 2.3-4\n",
        ("pacman", "-Qtdq"): "orphan-a\norphan-b\n",
    }
    cfg = Config(exclude_foreign=["brave-bin"])
    ctx = Context(output=Output(color=False), config=cfg, sudo_user="paul",
                  user_home=tmp_path, assume_yes=True)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)):
        ArchBackend().check_foreign_orphans(ctx)
    alien = (tmp_path / "alien-pkgs.txt").read_text()
    assert "my-aur-pkg 2.3-4" in alien  # name AND version preserved (parity with -Qm)
    assert "brave-bin" not in alien     # excluded by name
    # assume_yes -> both orphans removed in one pacman -Rsn
    assert any(c[:3] == ["pacman", "-Rsn", "--noconfirm"] and "orphan-a" in c
               for c, _ in calls)


def test_orphans_keep_list_protects(tmp_path):
    calls = []
    responses = {("pacman", "-Qm"): "", ("pacman", "-Qtdq"): "downgrade\n"}
    cfg = Config(keep_orphans=["downgrade"])
    ctx = Context(output=Output(color=False), config=cfg, sudo_user="paul",
                  user_home=tmp_path, assume_yes=True)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)):
        ArchBackend().check_foreign_orphans(ctx)
    assert not any(c[:2] == ["pacman", "-Rsn"] for c, _ in calls)  # protected


# -- rebuilds ----------------------------------------------------------------
def test_rebuilds_lists_when_not_auto(capsys):
    calls = []
    responses = {("checkrebuild",): "123 foo\n456 bar\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_rebuilds(_ctx())
    out = capsys.readouterr().out
    assert "foo" in out and "bar" in out
    assert not any(c[0] == "yay" for c, _ in calls)  # no rebuild without -R


def test_rebuilds_auto_rebuild_invokes_yay():
    calls = []
    responses = {("checkrebuild",): "123 foo\n456 bar\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_rebuilds(_ctx(auto_rebuild=True, assume_yes=True))
    yay = [c for c, _ in calls if c[0] == "yay"]
    assert yay and "foo" in yay[0] and "bar" in yay[0]


# -- python rebuild ----------------------------------------------------------
def test_python_rebuild_finds_old_dir(tmp_path, capsys):
    (tmp_path / "usr/lib/python3.11").mkdir(parents=True)
    (tmp_path / "usr/lib/python3.13").mkdir(parents=True)
    calls = []
    responses = {
        ("python3",): "3.13",
        ("pacman", "-Qoq"): "stale-pkg\n",
    }
    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)):
        ArchBackend().check_python_rebuilds(ctx)
    out = capsys.readouterr().out
    assert "python3.11" in out and "stale-pkg" in out
    assert "python3.13" not in out  # current version excluded


# -- config drift ------------------------------------------------------------
def test_config_drift_lists_pacnew(capsys):
    responses = {("pacdiff", "-o"): "/etc/pacman.conf.pacnew\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_config_drift(_ctx())
    assert "/etc/pacman.conf.pacnew" in capsys.readouterr().out


# -- firmware (base-class impl, distro-neutral) ------------------------------
def test_firmware_reports_up_to_date(capsys):
    responses = {("fwupdmgr", "get-updates"): "No updates available"}
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().firmware_updates(_ctx())
    assert "no firmware updates" in capsys.readouterr().out.lower()


def test_firmware_reports_available(capsys):
    responses = {("fwupdmgr", "get-updates"): "Dell TB16\n  1.2 -> 1.3"}
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().firmware_updates(_ctx())
    assert "firmware updates available" in capsys.readouterr().out


def test_firmware_absent_tool_skips(capsys):
    with patch("fettle.command.which", return_value=False):
        ArchBackend().firmware_updates(_ctx())
    assert "not installed" in capsys.readouterr().out


# -- kernels -----------------------------------------------------------------
def test_kernels_dry_run_lists_only(capsys):
    responses = {
        ("mhwd-kernel", "-li"): "Currently running: linux66\n",
        ("mhwd-kernel", "-l"): "linux612\nlinux61\n",
    }
    calls = []
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().manage_kernels(_ctx(dry_run=True))
    out = capsys.readouterr().out
    assert "linux66" in out
    assert "linux612" in out  # available-kernel listing restored (parity with -l)
    assert not any(c[:2] == ["mhwd-kernel", "-i"] for c, _ in calls)


def test_running_kernel_digits_exact_match():
    """The running-kernel guard reduces uname -r to major.minor digits, not a substring."""
    responses = {("uname", "-r"): "6.12.1-2-MANJARO\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, [])):
        assert ArchBackend()._running_kernel_digits() == "612"
