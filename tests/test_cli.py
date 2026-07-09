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


def _actions_for(argv):
    from fettle.cli import _requested_actions, build_parser
    from fettle.config import Config
    return _requested_actions(build_parser().parse_args(argv), Config())


def test_new_short_flags_route_to_renamed_actions():
    assert _actions_for(["-I"]) == ["aur_ioc_scan"]   # was -S
    assert _actions_for(["-d"]) == ["config_drift"]   # was -p/--pacnew
    assert _actions_for(["-P"]) == ["pkg_audit"]      # new flag
    assert _actions_for(["-r"]) == ["rebuild_check"]
    assert _actions_for(["-y"]) == ["python_rebuild_check"]


def test_update_upgrade_aliases_and_long_options():
    assert _actions_for(["--update"]) == ["update"]
    assert _actions_for(["--upgrade"]) == ["update"]
    assert _actions_for(["--config-drift"]) == ["config_drift"]
    assert _actions_for(["--aur-ioc-scan"]) == ["aur_ioc_scan"]
    assert _actions_for(["--pkg-audit"]) == ["pkg_audit"]


def test_retired_long_flags_are_unrecognized():
    # Old long forms are gone from the pipeline parser.
    for dead in (["--pacnew"], ["--rebuilds"]):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(dead)


def test_dispatch_shortcuts_route_to_runners():
    with patch("fettle.secure.audit.main", return_value=0) as sa:
        main(["-S"])
    sa.assert_called_once_with(["--all"])  # bare -S == sys-audit --all

    with patch("fettle.secure.audit.main", return_value=0) as sa:
        main(["-S", "--list"])
    sa.assert_called_once_with(["--all", "--list"])  # sub-args forwarded

    with patch("fettle.cli._run_upgrade_check", return_value=0) as uc:
        main(["-U", "--effort", "high"])
    uc.assert_called_once_with(["--effort", "high"])

    with patch("fettle.aur.precheck.main", return_value=0) as pc:
        main(["-p", "somepkg"])
    pc.assert_called_once_with(["somepkg"])


def test_two_dispatch_shortcuts_error():
    with pytest.raises(SystemExit):
        main(["-S", "-U"])


def test_help_tags_distro_specific_actions(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out
    # Arch-only actions carry the [arch] tag; cross-distro ones don't.
    assert "--aur-audit" in help_text and "[arch]" in help_text
    assert "--python-rebuild" in help_text
    assert "clean package-manager caches" in help_text  # descriptive per-action help
    assert "[arch]/[debian] are specific to that distro" in help_text


def test_help_documents_subcommands(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out
    assert "--pkg-audit" in help_text          # pkg-audit is now the -P action
    assert "fettle sys-audit" in help_text      # sys-audit still a subcommand (via -S)
    assert "fettle aur-precheck" in help_text   # aur-precheck subcommand (via -p)
    assert "fettle remote" in help_text


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


def test_dry_run_update_lists_pending_packages(capsys):
    from unittest.mock import patch

    from fettle.backends.base import Transaction, TxItem
    tx = Transaction(items=[
        TxItem(name="linux", new="6.18-1", old="6.12-1", kind="upgrade"),
        TxItem(name="libfoo", new="1.0-1", old=None, kind="new-dep"),
    ])
    with patch("fettle.backends.arch.ArchBackend.pending_transaction", return_value=tx), \
         patch("fettle.command.which", return_value=True):
        main(["--distro", "arch", "--dry-run", "-u"])
    out = capsys.readouterr().out
    assert "2 package(s) would be installed/changed" in out
    assert "official repos (2)" in out
    assert "linux  6.12-1 -> 6.18-1" in out
    assert "+ libfoo  1.0-1  (new dependency)" in out  # new deps marked


def test_dry_run_update_reports_nothing_to_install(capsys):
    from unittest.mock import patch

    from fettle.backends.base import Transaction
    with patch("fettle.backends.arch.ArchBackend.pending_transaction",
               return_value=Transaction(items=[])), \
         patch("fettle.command.which", return_value=True):
        main(["--distro", "arch", "--dry-run", "-u"])
    assert "nothing to install" in capsys.readouterr().out


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
