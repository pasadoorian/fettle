import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from fettle import cli
from fettle.cli import main


def test_reexec_carries_pythonpath_across_sudo():
    """The sudo re-exec must pass PYTHONPATH via `env` so root finds the package
    when running from a checkout (regression: 'fettle is a package and cannot be
    directly executed' when sudo stripped PYTHONPATH)."""
    captured = {}
    with patch("os.execvp", side_effect=lambda f, a: captured.update(file=f, argv=a)):
        with patch.object(sys, "argv", ["fettle", "-c"]):
            cli._reexec_with_sudo()
    argv = captured["argv"]
    assert argv[:3] == ["sudo", "env", argv[2]]
    assert argv[2].startswith("PYTHONPATH=")
    # the package's parent dir (repo root) must be on the carried PYTHONPATH
    repo_root = str(Path(cli.__file__).resolve().parent.parent)
    assert repo_root in argv[2]
    assert argv[3:] == [sys.executable, "-m", "fettle", "-c"]


def test_print_config_exits_zero(capsys):
    rc = main(["--print-config", "--no-config"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Effective configuration" in out


def test_dry_run_lists_actions_without_elevating(capsys):
    rc = main(["--distro", "arch", "--dry-run", "-u", "-c"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Cleaning caches" in out
    assert "Updating packages" in out
    assert "would run:" in out  # dry-run shows commands, executes nothing


def test_unsupported_action_is_skipped(capsys):
    # python_rebuild is Arch-only; the Debian backend should skip it (a note on stdout).
    main(["--distro", "debian", "--dry-run", "-y"])
    cap = capsys.readouterr()
    assert "not supported by the debian backend" in cap.out


def test_bare_action_words_work(capsys):
    rc = main(["--distro", "arch", "--dry-run", "clean", "update"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Cleaning caches" in out and "Updating packages" in out


def test_unknown_action_word_errors():
    with pytest.raises(SystemExit):
        main(["--distro", "arch", "--dry-run", "frobnicate"])


def test_skip_removes_action(capsys):
    main(["--distro", "arch", "--dry-run", "-c", "-u", "--skip", "update"])
    out = capsys.readouterr().out
    assert "Cleaning caches" in out
    assert "Updating packages" not in out  # skipped


def test_unknown_distro_returns_one(capsys):
    rc = main(["--distro", "temple-os", "--dry-run", "-c"])
    assert rc == 1
    assert "not a known backend" in capsys.readouterr().err
