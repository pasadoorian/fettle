import pytest

from fettle.cli import main


def test_print_config_exits_zero(capsys):
    rc = main(["--print-config", "--no-config"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Effective configuration" in out


def test_dry_run_lists_actions_without_elevating(capsys):
    rc = main(["--distro", "arch", "--dry-run", "-u", "-c"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "update" in out
    assert "clean" in out


def test_unsupported_action_is_skipped(capsys):
    # python_rebuild is Arch-only; the Debian backend should skip it (a note on stdout).
    main(["--distro", "debian", "--dry-run", "-y"])
    cap = capsys.readouterr()
    assert "not supported by the debian backend" in cap.out


def test_bare_action_words_work(capsys):
    rc = main(["--distro", "arch", "--dry-run", "clean", "update"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "clean" in out and "update" in out


def test_unknown_action_word_errors():
    with pytest.raises(SystemExit):
        main(["--distro", "arch", "--dry-run", "frobnicate"])


def test_skip_removes_action(capsys):
    main(["--distro", "arch", "--dry-run", "-c", "-u", "--skip", "update"])
    out = capsys.readouterr().out
    assert "clean" in out
    # 'update' should not appear as a section header line
    assert "▸" in out and "update" not in out


def test_unknown_distro_returns_one(capsys):
    rc = main(["--distro", "temple-os", "--dry-run", "-c"])
    assert rc == 1
    assert "not a known backend" in capsys.readouterr().err
