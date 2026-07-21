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
    d = tmp_path / ".fettle/reports/local"
    alien = list(d.glob("alien-pkgs-*.txt"))[0].read_text()
    assert "my-aur-pkg 2.3-4" in alien  # name AND version preserved (parity with -Qm)
    assert "brave-bin" not in alien     # excluded by name
    import json
    pkgs = json.loads(list(d.glob("alien-pkgs-*.json"))[0].read_text())["data"]["packages"]
    byname = {p["name"]: p["version"] for p in pkgs}
    assert byname.get("my-aur-pkg") == "2.3-4"   # split into name/version in JSON
    assert "brave-bin" not in byname
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
def _pyfake(current, dir_owners, os_py_owners):
    """python-rebuild mock: dir_owners[ver] = recursive `-Qoq <dir>` output;
    os_py_owners[ver] = owner of the stdlib sentinel <dir>/os.py (the interpreter)."""
    def run(cmd, *, as_user=None, capture=False):
        if cmd[:2] == ["python3", "-c"]:
            return command.Proc(0, current, "")
        if cmd[:2] == ["pacman", "-Qoq"]:
            path = cmd[2]
            if path.endswith("/os.py"):
                for ver, owner in os_py_owners.items():
                    if f"python{ver}/os.py" in path:
                        return command.Proc(0, owner, "")
                return command.Proc(0, "", "")
            for ver, owners in dir_owners.items():
                if path.endswith(f"python{ver}"):
                    return command.Proc(0, owners, "")
        return command.Proc(0, "", "")
    return run


def _rebuild_section(out: str) -> str:
    """The text after the 'need rebuilding' header (the actual candidate list)."""
    marker = "need rebuilding"
    return out[out.index(marker):] if marker in out else ""


def test_python_rebuild_finds_old_dir(tmp_path, capsys):
    (tmp_path / "usr/lib/python3.11").mkdir(parents=True)
    (tmp_path / "usr/lib/python3.13").mkdir(parents=True)
    fake = _pyfake("3.13",
                   {"3.11": "python311\nstale-pkg\n"},   # interpreter + a real module
                   {"3.11": "python311\n"})               # os.py owner = the interpreter
    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", side_effect=fake):
        ArchBackend().check_python_rebuilds(ctx)
    out = capsys.readouterr().out
    assert "stale-pkg" in _rebuild_section(out)            # the module needs rebuilding
    assert "python311" not in _rebuild_section(out)        # interpreter not a candidate
    assert "skipped 1 installed Python interpreter" in out  # ...but noted as skipped


def test_python_rebuild_excludes_interpreter_package(tmp_path, capsys):
    # The wopr case: an old dir owned ONLY by its interpreter package (python312)
    # -> nothing to rebuild; python312 is noted as skipped, not flagged.
    (tmp_path / "usr/lib/python3.12").mkdir(parents=True)
    fake = _pyfake("3.14", {"3.12": "python312\n"}, {"3.12": "python312\n"})
    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", side_effect=fake):
        ArchBackend().check_python_rebuilds(ctx)
    out = capsys.readouterr().out
    assert "no packages need rebuilding" in out
    assert "python312" in out and "python312" not in _rebuild_section(out)


def test_python_rebuild_name_fallback_excludes_interpreter(tmp_path, capsys):
    # Even if the os.py sentinel query returns nothing, the name pattern drops it.
    (tmp_path / "usr/lib/python3.12").mkdir(parents=True)
    fake = _pyfake("3.14", {"3.12": "python312\nreal-mod\n"}, {"3.12": ""})
    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", side_effect=fake):
        ArchBackend().check_python_rebuilds(ctx)
    out = capsys.readouterr().out
    assert "real-mod" in _rebuild_section(out)
    assert "python312" not in _rebuild_section(out)


def test_python_rebuild_notes_orphaned_dir_as_cruft(tmp_path, capsys):
    # A dir with no owning package (e.g. /usr/lib/python3.10 left over) -> cruft,
    # not a rebuild target.
    (tmp_path / "usr/lib/python3.10").mkdir(parents=True)
    (tmp_path / "usr/lib/python3.12").mkdir(parents=True)
    fake = _pyfake("3.14",
                   {"3.10": "", "3.12": "python312\n"},   # 3.10 owned by nothing
                   {"3.12": "python312\n"})
    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", side_effect=fake):
        ArchBackend().check_python_rebuilds(ctx)
    out = capsys.readouterr().out
    assert "orphaned old-Python directories" in out and "python3.10" in out
    assert "no packages need rebuilding" in out


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


def test_kernels_refuses_to_remove_the_running_series(capsys):
    # Phase 7 audit: Arch removal is user-driven, but the running series is
    # refused outright (reboot into another first) — no auto-rollback possible.
    responses = {
        ("mhwd-kernel", "-li"): "Currently running: linux612\n",
        ("mhwd-kernel", "-l"): "linux612\n",
        ("uname", "-r"): "6.12.1-2-MANJARO\n",
    }
    calls = []
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch("builtins.input", side_effect=["n", "y", "612"]):  # remove the running one
        ArchBackend().manage_kernels(_ctx())
    assert not any(c[:2] == ["mhwd-kernel", "-r"] for c, _ in calls)  # never removed
    assert "refusing to remove the running kernel" in capsys.readouterr().err
