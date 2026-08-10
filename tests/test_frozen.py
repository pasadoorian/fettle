"""Compiled-build behaviour: the two places fettle re-executes itself.

fettle restarts itself twice — to elevate via sudo, and to record a session under a pty
— and both used to build ``[sys.executable, "-m", "fettle", …]``. In a Nuitka binary
there is no interpreter to point at and no ``fettle`` package on disk, so that becomes
two arguments fettle would try to parse as options: `sudo fettle -u`, the single most
important thing the tool does, would fail.

These tests cover the argv *construction*, which is what a regression would break. They
are not a substitute for running a real binary — an exec path is gone the moment it
succeeds, so the milestone that added this also built one and watched it work. What they
buy is that a future change fails here, in a second, rather than in a 60-second compile
nobody runs.

The measured facts they encode, from a real Nuitka 4.1.3 onefile build:

* ``sys.executable`` is **not** the binary — it is ``/tmp/onefile_…/python``, a scratch
  directory Nuitka unpacks into and removes on exit. Re-exec'ing it would work while the
  parent lived and fail afterwards, which is about the worst failure shape available.
* ``sys.argv[0]`` **is** the binary, absolute, even when invoked by bare name from PATH.
* Nuitka does not set ``sys.frozen``; it adds ``__compiled__`` to every compiled module.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fettle import cli, util


@pytest.fixture
def frozen(monkeypatch):
    """Pretend to be a compiled build at /opt/fettle/fettle."""
    monkeypatch.setattr(util, "frozen_binary", lambda: "/opt/fettle/fettle")
    return "/opt/fettle/fettle"


# -- detection ---------------------------------------------------------------

def test_a_normal_install_is_not_frozen():
    """The path every package and checkout takes. If this ever returned a path, the
    sudo re-exec would try to run the *test runner* as root."""
    assert util.frozen_binary() == ""


def test_pyinstaller_style_frozen_is_also_recognised(monkeypatch):
    """Nuitka is what fettle ships, but sys.frozen costs one `or` and means a
    PyInstaller build would work without anyone revisiting this."""
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "argv", ["/usr/local/bin/fettle", "-u"])
    assert util.frozen_binary().endswith("fettle")


# -- the sudo re-exec --------------------------------------------------------

def _argv(args=None):
    return cli._reexec_argv(args, "/unused/pythonpath")


def test_a_frozen_build_re_execs_itself(frozen, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/opt/fettle/fettle", "-u", "--yes"])
    argv = _argv()

    assert argv[0] == "sudo"
    assert argv[1] == frozen, "the binary must be what sudo runs"
    assert argv[2:] == ["-u", "--yes"], "the original arguments, unchanged"


def test_a_frozen_build_carries_no_interpreter_or_module(frozen, monkeypatch):
    """The whole bug. `-m fettle` in a compiled build is two arguments fettle would try
    to parse as options, and `python3` is not there to run them."""
    monkeypatch.setattr(sys, "argv", ["/opt/fettle/fettle", "-u"])
    argv = _argv()

    assert "-m" not in argv
    assert "fettle" not in argv[2:], "the literal module name must not be an argument"
    assert not any(a.startswith("PYTHONPATH=") for a in argv)
    assert sys.executable not in argv, "sys.executable is Nuitka's scratch python"


def test_a_normal_install_is_completely_unchanged(monkeypatch):
    """The 99% path. Everything above is additive, and this is what proves it."""
    monkeypatch.setattr(sys, "argv", ["/usr/lib/fettle/fettle/__main__.py", "-u"])
    argv = cli._reexec_argv(None, "/usr/lib/fettle")

    assert argv[:3] == ["sudo", "env", "PYTHONPATH=/usr/lib/fettle"]
    assert argv[3:] == [sys.executable, "-m", "fettle", "-u"]


def test_the_config_pin_survives_in_a_frozen_build(frozen, monkeypatch):
    """sudo's env_reset sets HOME=/root, so without pinning the elevated process
    re-resolves the config to root's (usually absent) and silently falls back to
    built-in defaults — dropping keep_orphans, exclude_foreign and [updaters]. That was
    this project's highest-impact bug once; it must not come back through the binary."""
    monkeypatch.setattr(sys, "argv", ["/opt/fettle/fettle", "-u"])
    args = SimpleNamespace(no_config=False, config="/home/paul/.config/fettle/config.toml")

    argv = _argv(args)
    assert argv[-2:] == ["--config", "/home/paul/.config/fettle/config.toml"]


def test_no_config_is_honoured_in_a_frozen_build(frozen, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/opt/fettle/fettle", "-u", "--no-config"])
    args = SimpleNamespace(no_config=True, config="/ignored")

    assert "--config" not in _argv(args)


def test_the_runlog_guard_is_forwarded_when_frozen(frozen, monkeypatch):
    """Without it the elevated child opens a SECOND pty and records a run inside a run."""
    monkeypatch.setattr(sys, "argv", ["/opt/fettle/fettle", "-u"])
    monkeypatch.setenv("FETTLE_RUNLOG", "1")

    argv = _argv()
    assert argv[1:3] == ["env", "FETTLE_RUNLOG=1"]
    assert argv[3] == "/opt/fettle/fettle"


def test_no_pointless_env_wrapper_when_there_is_nothing_to_set(frozen, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/opt/fettle/fettle", "-u"])
    monkeypatch.delenv("FETTLE_RUNLOG", raising=False)
    assert _argv()[1] != "env"


# -- the pty re-exec ---------------------------------------------------------

def _pty_child(monkeypatch, tmp_path, binary):
    """The argv `_run_pty` hands to pty.spawn, without forking anything."""
    from fettle import runlog

    # frozen_binary is imported inside the function, so the patch has to land on the
    # module it comes FROM rather than on runlog's namespace.
    monkeypatch.setattr(util, "frozen_binary", lambda: binary)
    captured = {}

    def fake_spawn(child, _reader):
        captured["child"] = child
        return 0

    with patch("pty.spawn", side_effect=fake_spawn), \
         patch.object(runlog, "_write_log_json"):
        ctxlike = SimpleNamespace(sudo_user=None, user_home=tmp_path,
                                 config=SimpleNamespace(reports={}))
        runlog._run_pty(["-H"], tmp_path / "run.txt", tmp_path, ctxlike)
    return captured["child"]


def test_the_runlog_child_is_the_binary_when_frozen(monkeypatch, tmp_path):
    """The second exec path, and the one that produces every run-log on the dashboard."""
    assert _pty_child(monkeypatch, tmp_path, "/opt/fettle/fettle") == \
        ["/opt/fettle/fettle", "-H"]


def test_the_runlog_child_is_unchanged_for_a_normal_install(monkeypatch, tmp_path):
    assert _pty_child(monkeypatch, tmp_path, "") == [sys.executable, "-m", "fettle", "-H"]


# -- provenance --------------------------------------------------------------

def test_version_says_which_artifact_it_is(frozen, capsys):
    """A bug report then carries whether it came from the binary, a package or the
    zipapp — the first thing worth knowing while the compiled paths are new."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--version"])
    assert "(binary)" in capsys.readouterr().out


def test_version_is_plain_for_a_normal_install(capsys):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--version"])
    out = capsys.readouterr().out
    assert "(binary)" not in out
    assert out.startswith("fettle ")


# -- `fettle remote` from a compiled build ------------------------------------
#
# build_zipapp stages a .pyz by copying fettle's own .py files off disk. A compiled
# build has none — Nuitka turns them into the binary — so it failed with a bare
# FileNotFoundError traceback pointing at Nuitka's scratch directory, which says nothing
# about the cause. Measured before fixing:
#
#   File ".../fettle/remote.py", line 120, in build_zipapp
#   File ".../shutil.py", line 652, in copytree
#   FileNotFoundError: [Errno 2] No such file or directory: '/tmp/onefile_…/fettle'
#
# The build now embeds a prebuilt zipapp and this copies it out instead.

def test_a_compiled_build_ships_its_embedded_zipapp(monkeypatch, tmp_path):
    from fettle import remote

    embedded = tmp_path / "fettle.pyz"
    embedded.write_bytes(b"PK\x03\x04 pretend zipapp")
    monkeypatch.setattr(util, "frozen_binary", lambda: "/opt/fettle/fettle")
    monkeypatch.setattr(remote, "bundled_zipapp", lambda: embedded)

    dest = tmp_path / "shipped.pyz"
    remote.build_zipapp(dest)
    assert dest.read_bytes() == embedded.read_bytes()


def test_a_compiled_build_without_one_says_so_in_those_words(monkeypatch, tmp_path):
    """It must NOT fall through to the staging path. That raises FileNotFoundError from
    inside shutil.copytree, which names a temp directory and not the actual mistake —
    a binary compiled without the data file has a broken `fettle remote`."""
    from fettle import remote

    monkeypatch.setattr(util, "frozen_binary", lambda: "/opt/fettle/fettle")
    monkeypatch.setattr(remote, "bundled_zipapp", lambda: None)

    with pytest.raises(RuntimeError) as excinfo:
        remote.build_zipapp(tmp_path / "shipped.pyz")

    message = str(excinfo.value)
    assert "fettle remote" in message
    assert "include-data-files" in message, "name the build flag that was missing"
    assert "packaging/binary/build.sh" in message, "and where to fix it"


def test_a_normal_install_still_stages_from_source(tmp_path):
    """The 99% path, unchanged: a real zipapp built from the checkout on disk."""
    import zipfile

    from fettle import remote

    dest = tmp_path / "fettle.pyz"
    remote.build_zipapp(dest)

    assert dest.is_file()
    names = zipfile.ZipFile(dest).namelist()
    assert "__main__.py" in names
    assert any(n.startswith("fettle/hardening/axes/") for n in names), \
        "the axes travel to remote hosts too"


def test_bundled_zipapp_is_none_for_a_normal_install():
    from fettle import remote

    assert remote.bundled_zipapp() is None
