# stale-flag-ok: these tests describe renames, so they name the old spellings.
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
    args = cli.build_parser().parse_args(["-c"])
    with patch("os.execvp", side_effect=lambda f, a: captured.update(file=f, argv=a)):
        with patch.object(sys, "argv", ["fettle", "-c"]):
            cli._reexec_with_sudo(args)
    argv = captured["argv"]
    assert argv[:3] == ["sudo", "env", argv[2]]
    assert argv[2].startswith("PYTHONPATH=")
    # the package's parent dir (repo root) must be on the carried PYTHONPATH
    repo_root = str(Path(cli.__file__).resolve().parent.parent)
    assert repo_root in argv[2]
    assert argv[3:6] == [sys.executable, "-m", "fettle"]


def test_reexec_pins_config_across_home_reset():
    # B1: sudo sets HOME=/root, so the config path must be carried explicitly or
    # the elevated run silently uses /root's config (defaults).
    args = cli.build_parser().parse_args(["-o"])  # no --config given
    argv = cli._reexec_argv(args, "PP")
    assert "--config" in argv
    assert argv[argv.index("--config") + 1] == str(cli.DEFAULT_CONFIG)


def test_reexec_respects_no_config():
    args = cli.build_parser().parse_args(["-o", "--no-config"])
    assert "--config" not in cli._reexec_argv(args, "PP")


def test_reexec_without_args_omits_config():
    # sys-audit's self-elevation path passes no namespace.
    assert "--config" not in cli._reexec_argv(None, "PP")


def _actions_for(argv):
    from fettle.cli import _requested_actions, build_parser
    from fettle.config import Config
    return _requested_actions(build_parser().parse_args(argv), Config())


def test_new_short_flags_route_to_renamed_actions():
    assert _actions_for(["-d"]) == ["config_drift"]   # was -p/--pacnew
    assert _actions_for(["-P"]) == ["pkg_audit"]      # new flag
    assert _actions_for(["-r"]) == ["rebuild_check"]
    assert _actions_for(["-y"]) == ["python_rebuild_check"]


def test_update_upgrade_aliases_and_long_options():
    assert _actions_for(["--update"]) == ["update"]
    assert _actions_for(["--upgrade"]) == ["update"]
    assert _actions_for(["upgrade"]) == ["update"]   # bare word alias
    assert _actions_for(["update"]) == ["update"]
    assert _actions_for(["--config-drift"]) == ["config_drift"]
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


def test_shortcut_combined_with_action_flag_errors_clearly(capsys):
    # `fettle -A -S` used to forward -A to sys-audit -> cryptic subparser error.
    rc = main(["-A", "-S"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "-S (sys-audit) can't be combined" in err and "-A" in err


def test_shortcut_suboptions_still_pass_through():
    # --list / --effort / categories are NOT action flags — must still forward.
    with patch("fettle.secure.audit.main", return_value=0) as sa:
        main(["-S", "secureboot"])
    sa.assert_called_once_with(["--all", "secureboot"])
    with patch("fettle.cli._run_upgrade_check", return_value=0) as uc:
        main(["-U", "--effort", "high"])
    uc.assert_called_once_with(["--effort", "high"])


def test_help_tags_distro_specific_actions(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    help_text = capsys.readouterr().out
    # Arch-only actions carry the [arch] tag; cross-distro ones don't.
    assert "--aur-audit" in help_text and "[arch]" in help_text
    assert "--python-rebuild" in help_text
    assert "reclaim disk from downloaded package files" in help_text  # per-action help
    # All three invocation forms are named up front, not just implied by the flags.
    assert "`fettle -c` == `fettle --clean` == `fettle clean`" in help_text
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


def _elevation(argv):
    """Whether `main(argv)` would re-exec under sudo."""
    from unittest.mock import patch
    with patch("fettle.cli._is_root", return_value=False), \
         patch("fettle.cli._in_test", return_value=False), \
         patch("fettle.cli._reexec_with_sudo") as reexec, \
         patch("fettle.actions.run"):
        main(argv)
    return reexec.called


def test_dry_run_stays_passwordless():
    assert _elevation(["--distro", "rhel", "--dry-run", "-O"]) is False


def test_full_preview_elevates_a_dry_run():
    """The only way to resolve a full dnf transaction is `dnf upgrade --assumeno` as
    root, so the complete preview has to be an explicit opt-in rather than something
    --dry-run does behind a sudo prompt."""
    assert _elevation(["--distro", "rhel", "--dry-run", "-O",
                       "--full-preview"]) is True


def test_full_preview_does_not_elevate_a_read_only_action():
    """--full-preview grants permission to elevate, it does not demand it: pkg-audit
    needs no root, so nothing should ask for a password."""
    assert _elevation(["--distro", "rhel", "--dry-run", "-P", "--full-preview"]) is False


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
    # python_rebuild is Arch-only; NAMED explicitly on Debian -> a skip note.
    main(["--distro", "debian", "--dry-run", "-y"])
    cap = capsys.readouterr()
    assert "not supported by the debian backend" in cap.out


def test_default_set_includes_the_supply_chain_audit():
    """`pkg_audit` covers every ecosystem, including all three AUR IoC checks.

    `aur_ioc_scan` is gone entirely (v0.73.0): it was a strict subset of pkg-audit's AUR
    provider, so having both meant every routine run fetched the AUR RPC and the IOC
    feeds twice and reported each finding twice. It stays available on its own.
    """
    from fettle.config import DEFAULT_ACTIONS
    assert "pkg_audit" in DEFAULT_ACTIONS
    assert "aur_ioc_scan" not in DEFAULT_ACTIONS


def test_hardening_audit_flag_word_and_opt_in():
    from fettle.config import DEFAULT_ACTIONS
    assert _actions_for(["-H"]) == ["hardening_audit"]
    assert _actions_for(["--hardening-audit"]) == ["hardening_audit"]
    assert _actions_for(["hardening-audit"]) == ["hardening_audit"]  # bare word
    assert "hardening_audit" not in DEFAULT_ACTIONS  # opt-in, not in -a


def test_hardening_audit_is_read_only():
    from fettle.cli import READ_ONLY_ACTIONS
    assert "hardening_audit" in READ_ONLY_ACTIONS  # no sudo for a standalone -H


def test_hardening_audit_dispatches_to_runner():
    with patch("fettle.hardening.audit.run", return_value=None) as run:
        main(["--distro", "arch", "-H"])
    assert run.called
    backend, ctx = run.call_args[0]
    assert backend.name == "arch"


def test_aur_gate_flags_wire_into_context():
    captured = {}
    with patch("fettle.actions.run", side_effect=lambda a, b, ctx: captured.update(ctx=ctx)):
        main(["--distro", "arch", "--dry-run", "-c", "--force-aur", "--no-aur-precheck"])
    ctx = captured["ctx"]
    assert ctx.force_aur is True                          # --force-aur -> Context
    assert ctx.config.aur_precheck_on_update is False     # --no-aur-precheck -> config off


def test_default_set_silently_skips_unsupported(capsys):
    # bare run on Debian: python-rebuild-check is Arch-only and in the default set,
    # but it must NOT print a skip note (that would be default-set noise).
    main(["--distro", "debian", "--dry-run"])
    assert "skipping 'python_rebuild_check'" not in capsys.readouterr().out


def test_explicitly_named_unsupported_still_warns(capsys):
    main(["--distro", "debian", "--dry-run", "aur-audit"])
    assert "skipping 'aur_audit'" in capsys.readouterr().out


def test_retired_action_explains_where_it_went(capsys):
    """argparse would say "unrecognized arguments: -I", which tells you nothing about
    where the capability went — and it did not go away, it moved into -P."""
    for token in ("-I", "--aur-ioc-scan", "aur-ioc-scan"):
        assert main([token]) == 2
        err = capsys.readouterr().err
        assert "retired in v0.73.0" in err and "pkg-audit" in err


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


def test_report_subcommand_dispatches():
    from unittest.mock import patch
    with patch("fettle.htmlreport.build", return_value="/tmp/x/report.html") as b:
        rc = main(["report", "--no-config"])
    assert rc == 0 and b.called


def test_report_backfill_flag_calls_backfill():
    from unittest.mock import patch
    with patch("fettle.htmlreport.backfill", return_value=3) as bf, \
         patch("fettle.htmlreport.build", return_value="/tmp/x/report.html"):
        main(["report", "--backfill-json", "--no-config"])
    assert bf.called


def test_help_documents_report_subcommand(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert "fettle report" in capsys.readouterr().out


def test_read_only_and_no_root_come_apart_in_both_directions():
    """They are different questions, and each direction has been got wrong once.

    container-update MUTATES but needs no root (docker socket, as the invoking user).
    pkg-integrity is READ-ONLY but needs root: it hashes every installed file, and
    unprivileged it silently verifies ~65 fewer of them. The old invariant here was
    "read-only implies no-root", which put pkg-integrity in the no-root set and left
    `fettle -V` permanently unable to read a large share of what it checks.
    """
    from fettle.cli import (NO_ROOT_ACTIONS, READ_ONLY_ACTIONS,
                            _MUTATES_BUT_NO_ROOT, _READ_ONLY_BUT_NEEDS_ROOT)
    assert "container_update" in NO_ROOT_ACTIONS
    assert "container_update" not in READ_ONLY_ACTIONS      # it is not read-only
    assert "pkg_integrity" in READ_ONLY_ACTIONS             # it changes nothing
    assert "pkg_integrity" not in NO_ROOT_ACTIONS           # ...but it must elevate
    # Every difference between the two sets is one of the listed exceptions.
    assert READ_ONLY_ACTIONS - NO_ROOT_ACTIONS == _READ_ONLY_BUT_NEEDS_ROOT
    assert NO_ROOT_ACTIONS - READ_ONLY_ACTIONS == _MUTATES_BUT_NO_ROOT


def test_default_run_says_which_actions_the_backend_cannot_do(capsys):
    """`-a` silently dropped unsupported actions. That was tolerable when a backend
    lacked one or two, but the RHEL backend implements a small subset: `-a` ran 1 of
    10 actions and reported nothing, so a nearly-empty run looked like a full one."""
    from unittest.mock import patch
    from fettle.backends.rhel import RhelBackend
    from fettle.cli import main as cli_main
    with patch("fettle.cli.detect", return_value=RhelBackend()), \
         patch("fettle.actions.run"):
        cli_main(["-a", "--dry-run"])
    out = capsys.readouterr().out
    assert "not implemented by the rhel backend" in out
    assert out.count("not implemented by the rhel backend") == 1   # ONE line, not nine
    # Assert the *property* rather than specific action names: the line names the
    # skipped actions, and never names one the backend actually supports. Pinning
    # literal names meant this test claimed `update` and `clean` were unsupported on
    # RHEL, which went stale the moment those landed.
    named = {n.strip() for n in
             next(ln for ln in out.splitlines() if "not implemented" in ln)
             .split(":", 1)[1].split(",")}
    assert named
    assert not (named & RhelBackend.supported)


def test_backend_supporting_everything_says_nothing(capsys):
    """Arch supports the whole default set — no notice should appear."""
    from unittest.mock import patch
    from fettle.backends.arch import ArchBackend
    from fettle.cli import main as cli_main
    with patch("fettle.cli.detect", return_value=ArchBackend()), \
         patch("fettle.actions.run"):
        cli_main(["-a", "--dry-run"])
    assert "not implemented by" not in capsys.readouterr().out


# -- help layout -------------------------------------------------------------
def _help_text():
    return cli.build_parser().format_help()


def test_sys_audit_is_findable_in_the_help():
    """QA: -S appeared only under "shortcut flags", so the deepest security scan in
    the tool read as a footnote. It belongs with the other audits."""
    text = _help_text()
    audit = text[text.index("audit & security actions"):]
    assert "-S, --sys-audit" in audit.split("positional arguments")[0]


def test_every_flag_action_is_in_exactly_one_purpose_group():
    """A new action must land in maintenance or audit — not silently in neither."""
    assert set(cli.MAINTENANCE_ACTIONS) | set(cli.AUDIT_ACTIONS) == set(cli.FLAG_ACTIONS)
    assert not set(cli.MAINTENANCE_ACTIONS) & set(cli.AUDIT_ACTIONS)


def test_default_set_membership_is_visible():
    """"What does -a run?" must be answerable from the help itself."""
    text = _help_text()
    assert "· = runs under -a" in text
    # Only the option rows, not the prose (the group description names --clean too).
    rows = [ln for ln in text.splitlines() if ln.startswith("  -")]
    assert any(ln.startswith("  -c, --clean") and "·" in ln for ln in rows)
    assert any(ln.startswith("  -O, --only-update") and "·" not in ln for ln in rows)


def test_actions_are_shown_before_global_options():
    text = _help_text()
    assert text.index("maintenance actions") < text.index("options (apply to any action)")


def test_dispatch_shortcuts_are_documented_but_not_parsed():
    """They are declared for the help only; main() routes them first. If argparse
    ever started owning them, `fettle -S --list` would break."""
    text = _help_text()
    for opts, _, _ in cli.SHORTCUT_HELP:
        assert opts[0] in text
    assert set(cli.DISPATCH_SHORTCUTS) >= {"-S", "-U", "-p"}


def test_default_config_follows_the_invoking_user_not_root(monkeypatch, tmp_path):
    """Under sudo, HOME is /root, so `Path.home()` sends every consumer of
    DEFAULT_CONFIG to a config that does not exist -- where they silently fall back to
    built-in defaults.

    Phase 9 fixed this once, by teaching the sudo re-exec to carry `--config`. It came
    back in v0.84.0 the moment `sys-audit` learned to read config, because that command
    elevates by a different route: `fettle -S firmware` reported chipsec as
    unconfigured on a machine where it was configured. Fixing the constant fixes all
    eight routes to it.
    """
    import importlib
    import pwd

    real = pwd.getpwnam
    monkeypatch.setattr(pwd, "getpwnam",
                        lambda n: real(n) if n != "someone" else
                        type("P", (), {"pw_dir": str(tmp_path / "home/someone")})())
    monkeypatch.setenv("HOME", "/root")
    monkeypatch.setenv("SUDO_USER", "someone")
    import fettle.cli as c
    importlib.reload(c)
    try:
        assert str(c.DEFAULT_CONFIG).startswith(str(tmp_path / "home/someone"))
        assert "/root" not in str(c.DEFAULT_CONFIG)
    finally:
        monkeypatch.undo()
        importlib.reload(c)


def test_default_config_is_the_real_home_without_sudo(monkeypatch):
    from fettle.util import invoking_user_home
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("HOME", "/home/nobody")
    assert str(invoking_user_home()) == "/home/nobody"
