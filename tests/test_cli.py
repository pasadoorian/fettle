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
    """What this is about is dispatch and the dry-run gate, not the exit status.

    It used to assert `rc == 0`, which quietly made it a test of the HOST: with
    `--distro arch` forced on a machine with no pacman, `update` correctly reports
    "could not determine what is pending" and the run exits 1 — fettle being truthful,
    not fettle being broken. It passed on the Arch development box and failed on every
    CI runner, which is how it went unnoticed for days.
    """
    main(["--distro", "arch", "--dry-run", "-u", "-c"])
    out = capsys.readouterr().out
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
    """`fettle clean update` == `fettle -c -u`. The evidence is that both actions ran
    and in that order — the exit status depends on whether the host has pacman, which
    is not what this test is about. See the note above."""
    main(["--distro", "arch", "--dry-run", "clean", "update"])
    out = capsys.readouterr().out
    assert "Cleaning caches" in out and "Updating packages" in out
    assert out.index("Cleaning caches") < out.index("Updating packages")


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


# -- --everything --------------------------------------------------------------
#
# "Everything that is safe to run start-to-finish without supervision", which is a
# narrower claim than "every action fettle has" and is documented as such.

def test_everything_adds_the_audits_the_default_set_leaves_out():
    from fettle.config import DEFAULT_ACTIONS
    got = _actions_for(["--everything"])
    for extra in ("pkg_integrity", "hardening_audit", "sys_audit", "advisory_check",
                  "aur_audit"):
        assert extra in got, extra
        assert extra not in DEFAULT_ACTIONS, f"{extra} is already in the default set"


def test_everything_excludes_the_two_dangerous_actions():
    """`kernel` can remove the ability to boot — it is kept out of the default set for
    that reason and stays out here. `container_update` pulls images over the network.
    Both are one flag away; neither belongs in something you leave running."""
    got = _actions_for(["--everything"])
    assert "kernel" not in got
    assert "container_update" not in got


def test_everything_excludes_only_update_as_redundant():
    got = _actions_for(["--everything"])
    assert "update" in got and "only_update" not in got


def test_everything_orders_update_before_what_describes_its_result():
    """Each of these exists to describe the system the update left behind, so running
    them first would describe the machine you booted rather than the one you now have.
    The rebuild checks catch what the update made stale; orphans and config-drift are
    both things an upgrade CREATES; pkg-integrity would otherwise verify packages about
    to be replaced; advisory-check reports what is STILL unfixed."""
    got = _actions_for(["--everything"])
    for later in ("rebuild_check", "python_rebuild_check", "orphans", "config_drift",
                  "pkg_integrity", "advisory_check"):
        assert got.index("update") < got.index(later), later


def test_everything_cleans_before_updating():
    """clean frees space BEFORE the upgrade needs it, which is the point on a box with a
    small /var. It costs nothing to do first: clean removes cached packages that are no
    longer installed and trims the rest to keep_versions, while the upgrade downloads
    NEW versions that were never in the cache. An earlier revision put clean last on the
    stated grounds that going first 'forces a re-download' — which was simply wrong."""
    got = _actions_for(["--everything"])
    assert got.index("clean") < got.index("update")


def test_everything_keeps_the_two_aur_queries_adjacent():
    """Both hit the AUR RPC; the second benefits from the first's TTL-cached fetch.
    Not correctness — they keep separate maintainer snapshots deliberately — but a
    gratuitous second round trip is worth avoiding."""
    got = _actions_for(["--everything"])
    assert abs(got.index("pkg_audit") - got.index("aur_audit")) == 1


def test_everything_composes_with_skip():
    got = _actions_for(["--everything", "--skip", "hardening-audit"])
    assert "hardening_audit" not in got and "sys_audit" in got


def test_everything_composes_with_only():
    got = _actions_for(["--everything", "--only", "sys-audit"])
    assert got == ["sys_audit"]


def test_everything_has_no_duplicates():
    got = _actions_for(["--everything"])
    assert len(got) == len(set(got))


def test_everything_is_not_the_default_set():
    """`-a` stays the conservative set; --everything is opt-in and larger."""
    assert set(_actions_for(["-a"])) < set(_actions_for(["--everything"]))


def test_everything_actions_all_have_handlers():
    """A name in the list that nothing can run would be a silent no-op mid-sweep."""
    from fettle.actions import HANDLERS
    from fettle.cli import EVERYTHING_ACTIONS
    assert set(EVERYTHING_ACTIONS) <= set(HANDLERS)


def test_remote_recognises_everything_as_an_action_choice():
    """Without this, `fettle remote host --everything` would ALSO have the remote
    default set prepended — the caller has plainly stated an intent."""
    from fettle.cli import _remote_has_action
    assert _remote_has_action(["--everything"])
    assert _remote_has_action(["--everything", "--yes"])
    assert not _remote_has_action(["--yes"])          # a modifier is not an intent


def test_everything_exit_code_answers_did_it_complete_not_is_it_clean():
    """Fourteen checks on a real host essentially always find something, and a status
    that is red every time is one nobody reads. So `--everything` fails only when an
    action could not do its job.

    Blindness deliberately does not fail it either: on the QA workstation chipsec cannot
    run at all, so two checks report "could not run" on EVERY run, and failing on that
    would put the sweep permanently red for a condition nobody can fix. The invariant is
    served by listing it under "Not checked" instead.
    """
    from unittest.mock import patch

    from fettle import cli
    from fettle.output import BLIND, FAILED, FOUND

    def run_with(kind):
        def fake(actions, backend, ctx):
            ctx.output.summary_fail("x", kind=kind)
        with patch("fettle.actions.run", side_effect=fake):
            return cli.main(["--everything", "--only", "config-drift", "--dry-run"])

    assert run_with(FOUND) == 0, "a finding must not fail a sweep"
    assert run_with(BLIND) == 0, "blindness is reported, not failed on"
    assert run_with(FAILED) == 1, "an action that could not do its job must fail"


def test_single_action_stays_strict_on_all_three():
    """A single check is the tripwire you gate automation on: `fettle -V` must go red
    when a packaged file's contents changed, and `fettle -S` when a check could not
    run."""
    from unittest.mock import patch

    from fettle import cli
    from fettle.output import BLIND, FAILED, FOUND

    for kind in (FOUND, BLIND, FAILED):
        def fake(actions, backend, ctx, _k=kind):
            ctx.output.summary_fail("x", kind=_k)
        with patch("fettle.actions.run", side_effect=fake):
            assert cli.main(["-d", "--dry-run"]) == 1, kind


def test_remote_reports_a_config_it_could_not_read(capsys, tmp_path, monkeypatch):
    """A config that could not be READ must not look like a config with no groups.

    Measured: a stray unquoted line in config.toml made the whole file invalid, so
    `fettle remote fleet` treated the group name as a hostname and reported "could not
    resolve hostname fleet" — a true statement about the wrong thing, while the real
    cause was known and thrown away. The local path always printed these.
    """
    from unittest.mock import patch

    from fettle import cli

    bad = tmp_path / "config.toml"
    bad.write_text('[remote.groups.fleet]\nhosts = ["a"]\nthis is not toml\n')
    monkeypatch.setattr(cli, "DEFAULT_CONFIG", bad)
    with patch.object(cli, "_in_test", return_value=False), \
         patch.object(cli, "_remote_one", return_value=0) as one:
        cli._run_remote_maintenance(["fleet"])
    err = capsys.readouterr().err
    assert "invalid TOML" in err or "could not be read" in err, err
    # and it still falls through to treating the name as a host, as before
    assert one.called


# -- host labels in a group run -------------------------------------------------
def test_section_and_summary_carry_the_host_label():
    """Six hosts' output runs together in one terminal and the per-host banner scrolls
    off long before the actions do, so by the third host you are reading a summary with
    no idea whose it is."""
    import io
    from contextlib import redirect_stdout

    from fettle.output import Output

    out = Output(color=False, host_label="bifrost")
    out.step_total = 2
    buf = io.StringIO()
    with redirect_stdout(buf):
        out.section("Cleaning caches")
        out.print_summary()
    text = buf.getvalue()
    assert "[1/2] Cleaning caches (bifrost)" in text
    assert "Summary (bifrost)" in text


def test_no_label_means_no_parentheses():
    """A single host does not need it — its banner is right there."""
    import io
    from contextlib import redirect_stdout

    from fettle.output import Output

    buf = io.StringIO()
    with redirect_stdout(buf):
        Output(color=False).section("Cleaning caches")
    assert "Cleaning caches\n" in buf.getvalue().replace("\x1b", "")
    assert "(" not in buf.getvalue()


def test_group_run_labels_each_host():
    from unittest.mock import patch

    from fettle import cli
    from fettle.remote import RemoteGroup

    seen = []

    def fake_one(host, ssh_args, forwarded, label=""):
        seen.append((host, label))
        return 0

    g = RemoteGroup(name="fleet", hosts=["bifrost", "wopr"], ssh_args=(),
                    actions=("--everything",), yes=True)
    with patch.object(cli, "_remote_one", side_effect=fake_one):
        cli._run_group(g, [], [])
    assert seen == [("bifrost", "bifrost"), ("wopr", "wopr")]


def test_host_label_is_appended_after_the_action_check():
    """`--host-label bifrost` puts a BARE WORD in the argument list, and
    `_remote_has_action` treats any bare word as "the user named an action" — so adding
    it before the check would silently suppress the default action set."""
    from unittest.mock import patch

    from fettle import cli

    sent = {}

    def fake_run(host, fwd, **kw):
        sent["fwd"] = list(fwd)
        return 0

    with patch("fettle.remote.run", side_effect=fake_run), \
         patch.object(cli, "_fetch_remote_reports"):
        cli._remote_one("h", [], [], label="bifrost")
    fwd = sent["fwd"]
    assert fwd[-2:] == ["--host-label", "bifrost"], fwd
    # the default set still got prepended despite the bare word
    assert any(a.replace("_", "-") in fwd for a in cli.REMOTE_DEFAULT_ACTIONS), fwd


# -- hardening-audit needs root now ------------------------------------------
# Measured on three hosts: the useful AppArmor state is root-only. `aa-status`
# unprivileged prints "You do not have enough privilege to read the profile set" and
# exits 0, and /sys/kernel/security/apparmor/profiles is mode 0444 yet still returns
# EACCES. Without root the axis can report that the module is loaded and nothing about
# whether anything is confined, which is the reassuring half of the answer.
def test_hardening_audit_elevates():
    assert _elevation(["--distro", "arch", "-H"]) is True


def test_hardening_audit_stays_unprivileged_with_user():
    """The opt-out. An action that starts demanding root with no way to decline is a
    worse change than the one it fixes."""
    assert _elevation(["--distro", "arch", "-H", "--user"]) is False


def test_user_does_not_disarm_elevation_for_a_mutating_action():
    """--user says 'audit me unprivileged', not 'skip the sudo you actually need'.
    Silently running `-u` without root would fail deep inside the package manager."""
    from unittest.mock import patch
    with patch("fettle.cli._is_root", return_value=False), \
         patch("fettle.cli._in_test", return_value=False), \
         patch("fettle.cli._reexec_with_sudo") as reexec, \
         patch("fettle.actions.run"):
        rc = main(["--distro", "arch", "-u", "--user"])
    assert reexec.called is False, "elevated anyway"
    assert rc == 1, "should refuse rather than run a mutating action unprivileged"


def test_user_is_accepted_for_the_other_root_audits():
    """sys-audit already has its own --user; pkg-integrity and compromise-check have
    the same shape, so the flag means the same thing everywhere."""
    assert _elevation(["--distro", "arch", "-V", "--user"]) is False


def test_the_other_read_only_actions_still_do_not_elevate():
    """Guard: -H moving does not drag the rest of the read-only set with it."""
    assert _elevation(["--distro", "arch", "-P"]) is False
