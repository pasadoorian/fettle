# stale-flag-ok: these tests describe renames, so they name the old spellings.
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
    assert any(c[:2] == ["rm", "-rf"] and c[2].endswith(".cache/yay") for c in argvs)
    # pamac clean runs as the invoking user, not root
    assert any(c[:2] == ["pamac", "clean"] and u == "paul" for c, u in calls)


def test_clean_never_uses_scc_noconfirm():
    """`pacman -Scc --noconfirm` removes NOTHING.

    --noconfirm takes pacman's own default answer, and -Scc defaults to No because it
    is destructive. Measured on a lab guest: 194 cached packages before, 194 after,
    exit 0 — so the caller cannot tell. This guards the regression, not the fix.
    """
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().clean_caches(_ctx())
    assert ["pacman", "-Scc", "--noconfirm"] not in [c for c, _ in calls]


def test_clean_drops_uninstalled_then_keeps_two_versions():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().clean_caches(_ctx())
    argvs = [c for c, _ in calls]
    # cached packages no longer installed have no rollback value -> all of them go
    assert ["paccache", "-r", "-u", "-k0"] in argvs
    # installed packages keep their last two versions, so a rollback stays possible
    assert ["paccache", "-r", "-k2"] in argvs


def test_clean_keep_versions_is_configurable():
    calls, fake = _recorder()
    ctx = _ctx()
    ctx.config.clean = {"keep_versions": 5}
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().clean_caches(ctx)
    assert ["paccache", "-r", "-k5"] in [c for c, _ in calls]


def test_clean_bad_keep_versions_falls_back_to_default():
    calls, fake = _recorder()
    ctx = _ctx()
    ctx.config.clean = {"keep_versions": "lots"}
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().clean_caches(ctx)
    assert ["paccache", "-r", "-k2"] in [c for c, _ in calls]


def test_clean_falls_back_to_sc_without_paccache():
    """No pacman-contrib -> `pacman -Sc`, whose prompt defaults to YES and which
    keeps installed versions. Less thorough than paccache, but it actually works."""
    calls, fake = _recorder()

    def which(name):
        return None if name == "paccache" else f"/usr/bin/{name}"

    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", side_effect=which):
        ArchBackend().clean_caches(_ctx())
    argvs = [c for c, _ in calls]
    assert ["pacman", "-Sc", "--noconfirm"] in argvs
    assert not any(c and c[0] == "paccache" for c in argvs)


def test_update_default_pacman_then_yay():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        b, ctx = ArchBackend(), _ctx()
        b.update_system(ctx)
        b.update_extras(ctx)
    argvs = [c for c, _ in calls]
    assert ["pacman", "-Syuu"] in argvs          # interactive: pacman prompts (no --noconfirm)
    assert any(c[0] == "yay" and u == "paul" for c, u in calls)


def test_update_skips_pacman_mirrors_when_absent():
    # vanilla Arch / EndeavourOS lack pacman-mirrors (Manjaro-only) -> guarded,
    # the pacman upgrade still runs.
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", side_effect=lambda n: n != "pacman-mirrors"):
        ArchBackend().update_system(_ctx())
    argvs = [c for c, _ in calls]
    assert ["pacman-mirrors", "-f"] not in argvs   # not attempted
    assert ["pacman", "-Syuu"] in argvs            # upgrade still runs


def test_update_extras_hint_uses_current_aur_flags():
    """The post-update hint must name flags that still exist.

    It has been wrong twice. v0.4.0 renamed the IoC scan to `-I` and the hint still
    said `-A -S`; v0.73.0 retired `-I` into `-P` and the hint still said `-A -I` --
    and THIS TEST asserted the stale spelling, so correcting the message would have
    failed a test and the obvious move is to put the message back. A guard that pins
    a bug is worse than no guard.
    """
    _, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ctx = _ctx()
        ArchBackend().update_extras(ctx)
    steps = ctx.output._next_steps
    assert any("fettle -A -P" in s for s in steps)
    assert not any("-A -S" in s for s in steps)     # v0.4.0 spelling
    assert not any("-A -I" in s for s in steps)     # v0.73.0 spelling


def test_pending_upgrades_via_checkupdates():
    calls, _ = _recorder()
    resp = "linux 6.12.1-1 -> 6.18.2-1\nnvidia 550.1-1 -> 560.3-1 [ignored]\n"

    def fake(cmd, *, as_user=None, capture=False):
        return command.Proc(0, resp if cmd[0] == "checkupdates" else "", "")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        pending = ArchBackend().pending_upgrades(_ctx())
    assert ("linux", "6.12.1-1", "6.18.2-1") in pending
    assert ("nvidia", "550.1-1", "560.3-1") in pending  # trailing [ignored] tolerated


def test_pending_upgrades_falls_back_to_pacman_qu():
    calls = []

    def fake(cmd, *, as_user=None, capture=False):
        calls.append(list(cmd))
        return command.Proc(0, "bash 5.2-1 -> 5.3-1\n" if cmd[:2] == ["pacman", "-Qu"] else "", "")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", side_effect=lambda n: n == "pacman"):  # no checkupdates
        pending = ArchBackend().pending_upgrades(_ctx())
    assert pending == [("bash", "5.2-1", "5.3-1")]
    assert ["pacman", "-Qu"] in calls


def test_parse_sup_lines():
    from fettle.backends.arch import _parse_sup_lines
    out = _parse_sup_lines("core/linux 6.2-1\nextra/libfoo 1.0-2\n\nbadline\n")
    assert out == [("linux", "6.2-1"), ("libfoo", "1.0-2")]


def _tx_fake(qu="", sup="", aur=""):
    """command.run stub keyed on the pacman/yay subcommand."""
    calls = []

    def fake(cmd, *, as_user=None, capture=False):
        calls.append((list(cmd), as_user))
        if cmd[0] == "pacman" and cmd[1] == "-Qu":
            return command.Proc(0, qu, "")
        if cmd[0] == "pacman" and cmd[1] == "-Sup":
            return command.Proc(0, sup, "")
        if cmd[0] == "yay" and cmd[1] == "-Qua":
            return command.Proc(0, aur, "")
        return command.Proc(0, "", "")

    return calls, fake


def test_pending_transaction_classifies_upgrades_and_new_deps():
    calls, fake = _tx_fake(qu="linux 6.1-1 -> 6.2-1\n",
                           sup="core/linux 6.2-1\nextra/newdep 1.0-1\n")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True), \
         patch.object(ArchBackend, "_temp_synced_db", return_value=(Path("/tmp/db"), "")):
        tx = ArchBackend().pending_transaction(_ctx())
    kinds = {i.name: (i.kind, i.old, i.new, i.source) for i in tx.items}
    assert kinds["linux"] == ("upgrade", "6.1-1", "6.2-1", "repo")
    assert kinds["newdep"] == ("new-dep", None, "1.0-1", "repo")  # in -Sup, not -Qu
    assert tx.ok and not any("stale" in n for n in tx.notes)
    # queried the fresh temp DB
    assert ["pacman", "-Sup", "--print-format", "%r/%n %v", "--dbpath", "/tmp/db"] \
        in [c for c, _ in calls]


def test_pending_transaction_merges_aur():
    _, fake = _tx_fake(sup="", aur="claude-desktop-bin 1-1 -> 1-2\n")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True), \
         patch.object(ArchBackend, "_temp_synced_db", return_value=(Path("/tmp/db"), "")):
        tx = ArchBackend().pending_transaction(_ctx())
    aur = [i for i in tx.items if i.source == "aur"]
    assert aur and aur[0].name == "claude-desktop-bin" and aur[0].new == "1-2"
    assert any("devel" in n for n in tx.notes)


def test_pending_transaction_stale_note_when_sync_fails():
    calls, fake = _tx_fake(qu="bash 5.2-1 -> 5.3-1\n", sup="core/bash 5.3-1\n")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True), \
         patch.object(ArchBackend, "_temp_synced_db",
                      return_value=(None, "repo sync failed: could not resolve host")):
        tx = ArchBackend().pending_transaction(_ctx())
    assert [i.name for i in tx.items if i.source == "repo"] == ["bash"]
    assert any("STALE" in n for n in tx.notes)
    # The note must carry the REAL reason. It used to say "needs fakeroot +
    # pacman-contrib" whatever had happened — measured telling a user to install two
    # packages that were already there, when the mirror was simply unreachable.
    assert any("could not resolve host" in n for n in tx.notes)
    assert not any("pacman-contrib" in n for n in tx.notes)
    # fell back to the system DB — no --dbpath on the query
    assert ["pacman", "-Sup", "--print-format", "%r/%n %v"] in [c for c, _ in calls]


def test_pending_transaction_no_sync_skips_refresh():
    with patch("fettle.command.run", side_effect=_tx_fake()[1]), \
         patch("fettle.command.which", return_value=True), \
         patch.object(ArchBackend, "_temp_synced_db") as temp:
        ArchBackend().pending_transaction(_ctx(), sync=False)
    temp.assert_not_called()  # sync=False never attempts a refresh


def test_pending_transaction_no_pacman_is_not_ok():
    with patch("fettle.command.which", side_effect=lambda n: n != "pacman"):
        tx = ArchBackend().pending_transaction(_ctx())
    assert tx.ok is False and tx.items == []


def test_base_pending_transaction_derives_from_pending_upgrades():
    from fettle.backends.base import PackageBackend

    class _Stub(PackageBackend):
        def pending_upgrades(self, ctx):
            return [("bash", "5.2-1", "5.3-1")]

    tx = _Stub().pending_transaction(_ctx())
    assert [(i.name, i.old, i.new, i.kind) for i in tx.items] == \
        [("bash", "5.2-1", "5.3-1", "upgrade")]


def test_aur_upgrade_names_from_yay_qua():
    # AP1: the pre-upgrade gate's input — names yay -Sua would upgrade.
    def fake(cmd, *, as_user=None, capture=False):
        if cmd[:2] == ["yay", "-Qua"]:
            return command.Proc(0, "foo 1-1 -> 1-2\nbar-git 2 -> 3\n", "")
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        names = ArchBackend()._aur_upgrade_names(_ctx())
    assert names == ["foo", "bar-git"]


# -- AUR pre-upgrade IoC gate (AP2) ------------------------------------------
def test_aur_gate_proceeds_silently_when_clean(capsys):
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["foo"]), \
         patch("fettle.aur.precheck.scan", return_value=([], [])):
        assert b._aur_precheck_gate(_ctx()) is True
    assert "no indicators" in capsys.readouterr().out


def test_aur_gate_aborts_on_findings_when_declined(capsys):
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["evil"]), \
         patch("fettle.aur.precheck.scan", return_value=(["evil is compromised"], [])), \
         patch("builtins.input", return_value="n"):
        assert b._aur_precheck_gate(_ctx()) is False
    assert "evil is compromised" in capsys.readouterr().err   # CRIT shown (stderr)


def test_aur_gate_proceeds_when_confirmed():
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["evil"]), \
         patch("fettle.aur.precheck.scan", return_value=(["bad"], [])), \
         patch("builtins.input", return_value="y"):
        assert b._aur_precheck_gate(_ctx()) is True


def test_aur_gate_crit_aborts_under_yes_without_force(capsys):
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["evil"]), \
         patch("fettle.aur.precheck.scan", return_value=(["evil bad"], [])):
        assert b._aur_precheck_gate(_ctx(assume_yes=True)) is False
    assert "refusing to install unattended" in capsys.readouterr().err


def test_aur_gate_warn_only_proceeds_under_yes():
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["stale"]), \
         patch("fettle.aur.precheck.scan", return_value=([], ["stale is old"])):
        assert b._aur_precheck_gate(_ctx(assume_yes=True)) is True


def test_aur_gate_dry_run_is_preview_only(capsys):
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["evil"]), \
         patch("fettle.aur.precheck.scan", return_value=(["bad"], [])):
        assert b._aur_precheck_gate(_ctx(dry_run=True)) is True  # no gate in dry-run
    assert "dry-run" in capsys.readouterr().out


def test_aur_gate_disabled_by_config():
    b = ArchBackend()
    cfg = Config()
    cfg.aur_precheck_on_update = False
    with patch.object(b, "_aur_upgrade_names") as names:
        assert b._aur_precheck_gate(_ctx(cfg=cfg)) is True
    names.assert_not_called()  # disabled -> doesn't even enumerate


def test_aur_gate_force_aur_overrides_crit_under_yes():
    # --yes + CRIT normally aborts; force_aur=True lets it proceed unattended.
    b = ArchBackend()
    with patch.object(b, "_aur_upgrade_names", return_value=["evil"]), \
         patch("fettle.aur.precheck.scan", return_value=(["evil bad"], [])):
        assert b._aur_precheck_gate(_ctx(assume_yes=True, force_aur=True)) is True


def test_update_extras_skips_yay_when_gate_aborts():
    b = ArchBackend()
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True), \
         patch.object(b, "_aur_precheck_gate", return_value=False):
        b.update_extras(_ctx())
    assert not any(c[:2] == ["yay", "-Sua"] for c, _ in calls)  # AUR update skipped


def test_refresh_metadata_never_syncs_system_db(capsys):
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().refresh_metadata(_ctx())
    # Safety: -O must never run `pacman -Sy` (partial-upgrade footgun); it only
    # notes that the report comes from a private cache.
    assert all(c[:2] != ["pacman", "-Sy"] for c, _ in calls)
    assert "untouched" in capsys.readouterr().out


def test_update_yes_makes_pacman_noninteractive():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().update_system(_ctx(assume_yes=True))
    assert ["pacman", "-Syuu", "--noconfirm"] in [c for c, _ in calls]


def test_update_yes_makes_yay_noninteractive():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        b, ctx = ArchBackend(), _ctx(assume_yes=True)
        b.update_extras(ctx)
    yay = next(c for c, _ in calls if c[:2] == ["yay", "-Sua"])  # the upgrade, not the gate's -Qua
    assert "--noconfirm" in yay and "--diffmenu=false" in yay  # review skipped, no menus
    assert "--diffmenu=true" not in yay


def test_update_interactive_keeps_yay_review():
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().update_extras(_ctx())  # no assume_yes
    yay = next(c for c, _ in calls if c[:2] == ["yay", "-Sua"])  # the upgrade, not the gate's -Qua
    assert "--diffmenu=true" in yay and "--noconfirm" not in yay


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
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().clean_caches(_ctx(dry_run=True))
    # Only the read-only snap listing, which previews the disabled revisions a real run
    # would offer (dry-run declines every prompt). Nothing that changes the system.
    assert [c for c, _ in calls] == [["snap", "list", "--all"]]


# -- automatic updates -------------------------------------------------------
def _timer_fake(enabled_units):
    """systemctl is-enabled <unit> -> 'enabled' for units in enabled_units,
    'disabled' otherwise. Everything else returns empty stdout."""
    enabled = set(enabled_units)

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            state = "enabled" if cmd[2] in enabled else "disabled"
            return command.Proc(0, state + "\n", "")
        return command.Proc(0, "", "")
    return run


def test_auto_updates_reports_enabled_timer(capsys):
    with patch("fettle.command.run", side_effect=_timer_fake({"pacman-auto-update.timer"})), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_auto_updates(_ctx())
    out = capsys.readouterr().out
    assert "enabled" in out and "pacman-auto-update.timer" in out


def test_auto_updates_none_enabled_is_manual(capsys):
    with patch("fettle.command.run", side_effect=_timer_fake(set())), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_auto_updates(_ctx())
    out = capsys.readouterr().out
    assert "none detected" in out and "Arch default" in out


def test_auto_updates_no_systemctl(capsys):
    calls, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=False):
        ArchBackend().check_auto_updates(_ctx())
    assert "cannot determine auto-update state" in capsys.readouterr().out
    assert calls == []  # short-circuits before any query


# -- [updaters.arch] refresh_mirrors ------------------------------------------
def _mirror_argvs(cfg=None):
    calls, fake = _recorder()
    ctx = _ctx()
    if cfg is not None:
        ctx.config.updaters = {"arch": {"refresh_mirrors": cfg}}
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().update_system(ctx)
    return [c for c, _ in calls], ctx


def test_mirrors_refresh_on_by_default():
    """Default ON: a mirrorlist that has fallen behind serves an old database and
    the upgrade then resolves against packages the mirror no longer has."""
    argvs, _ = _mirror_argvs()
    assert ["pacman-mirrors", "-f"] in argvs


def test_mirrors_refresh_can_be_turned_off():
    argvs, ctx = _mirror_argvs(False)
    assert not any(c and c[0] == "pacman-mirrors" for c in argvs)
    assert ["pacman", "-Syuu"] in argvs          # the upgrade still runs


def test_mirrors_refresh_accepts_a_count():
    """Bare -f tests the ENTIRE mirror pool (nargs='?', const=-1); a count bounds it."""
    argvs, _ = _mirror_argvs(5)
    assert ["pacman-mirrors", "-f", "5"] in argvs


def test_mirrors_refresh_zero_means_no_limit():
    argvs, _ = _mirror_argvs(0)
    assert ["pacman-mirrors", "-f"] in argvs


def test_mirrors_refresh_junk_value_warns_and_refreshes():
    argvs, _ = _mirror_argvs("sometimes")
    assert ["pacman-mirrors", "-f"] in argvs


def test_mirrors_requested_but_tool_absent_says_so(capsys):
    """Vanilla Arch has no pacman-mirrors. The setting is on and the user expects an
    effect, so skipping in silence would leave them believing it happened."""
    _, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", side_effect=lambda n: n != "pacman-mirrors"):
        ArchBackend().update_system(_ctx())
    out = capsys.readouterr().out
    assert "pacman-mirrors" in out and "reflector" in out


# -- orphan removal: consent and an honest count -------------------------------
def _orphan_run(assume_yes=False, installed=("nmap", "lua54", "bash")):
    """Run the orphan path with `nmap` chosen; pacman also takes `lua54` with it."""
    calls = []
    state = {"pkgs": list(installed)}

    def fake(cmd, *, as_user=None, capture=False):
        calls.append(list(cmd))
        if cmd[:2] == ["pacman", "-Qq"]:
            return command.Proc(0, "\n".join(state["pkgs"]) + "\n", "")
        if cmd[:2] == ["pacman", "-Qtdq"]:
            return command.Proc(0, "nmap\n", "")
        if cmd[:2] == ["pacman", "-Qm"]:
            return command.Proc(0, "", "")
        if cmd[0] == "pacman" and cmd[1].startswith("-Rs"):
            state["pkgs"] = [p for p in state["pkgs"] if p not in ("nmap", "lua54")]
            return command.Proc(0, "", "")
        return command.Proc(0, "", "")

    ctx = _ctx(assume_yes=assume_yes)
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True), \
         patch("fettle.backends.base.Context.select", lambda self, items, *, prompt: ["nmap"]):
        ArchBackend().check_foreign_orphans(ctx)
    return [c for c in calls], ctx


def test_orphan_removal_keeps_pacmans_confirmation():
    """`-Rs` removes dependencies the chosen package was the last thing needing, so the
    real transaction is bigger than the consent. pacman prints that set — and
    `--noconfirm` answered its own question, so the user saw the extra package go by
    with no way to refuse. Measured: choosing `nmap` also removed `lua54`."""
    calls, _ = _orphan_run()
    rm = [c for c in calls if c[0] == "pacman" and c[1].startswith("-Rs")][0]
    assert "--noconfirm" not in rm


def test_orphan_removal_still_unattended_under_yes():
    calls, _ = _orphan_run(assume_yes=True)
    rm = [c for c in calls if c[0] == "pacman" and c[1].startswith("-Rs")][0]
    assert "--noconfirm" in rm


def test_orphan_summary_counts_what_was_actually_removed(capsys):
    """One package was chosen; two went. The summary said "1 orphan(s) removed"."""
    _, ctx = _orphan_run()
    ctx.output.print_summary()
    out = capsys.readouterr().out
    assert "2 package(s) removed" in out
    assert "lua54" in out            # and names the one nobody asked about


# -- rebuild-check: the running kernel being replaced underneath you -----------
def _mods(tmp_path, dirs):
    base = tmp_path / "usr/lib/modules"
    base.mkdir(parents=True)
    for d in dirs:
        (base / d).mkdir()
    return tmp_path


def test_rebuild_check_reports_a_replaced_running_kernel(tmp_path, capsys):
    """Measured on a guest running 7.1.3-arch1-3 with 7.1.5-arch1-2 installed: the
    running kernel's module tree was gone — so it could no longer load any module —
    and fettle said only "no packages need rebuilding"."""
    import os as _os
    root = _mods(tmp_path, [f"not-{_os.uname().release}"])
    ctx = _ctx(root=root)
    with patch("fettle.command.run", return_value=command.Proc(0, "", "")), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_rebuilds(ctx)
    ctx.output.print_summary()
    out = capsys.readouterr().out + capsys.readouterr().err
    assert "reboot required" in out.lower()


def test_rebuild_check_quiet_when_running_kernel_is_installed(tmp_path, capsys):
    import os as _os
    ctx = _ctx(root=_mods(tmp_path, [_os.uname().release]))
    with patch("fettle.command.run", return_value=command.Proc(0, "", "")), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_rebuilds(ctx)
    ctx.output.print_summary()
    assert "reboot" not in capsys.readouterr().out.lower()


def test_rebuild_check_silent_without_a_module_tree(tmp_path, capsys):
    """A container has no /usr/lib/modules — that is not a stale kernel."""
    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", return_value=command.Proc(0, "", "")), \
         patch("fettle.command.which", return_value=True):
        ArchBackend().check_rebuilds(ctx)
    ctx.output.print_summary()
    assert "reboot" not in capsys.readouterr().out.lower()


# -- config-drift: the /etc walk, and the two kinds --------------------------
def _seed_etc(tmp_path, names):
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    for n in names:
        (etc / n).write_text("x")
    return tmp_path


def _drift(tmp_path, names, has_pacdiff=True):
    ctx = _ctx(root=_seed_etc(tmp_path, names))
    with patch("fettle.command.run", return_value=command.Proc(0, "", "")), \
         patch("fettle.command.which",
               side_effect=lambda n: has_pacdiff or n != "pacdiff"):
        ArchBackend().check_config_drift(ctx)
    return ctx


def test_config_drift_warns_about_displaced_configs(tmp_path, capsys):
    """`.pacorig` means the package's version is in effect and yours was moved aside.
    All of pacman's leftovers used to be reported as "pacnew files", so a config that
    had been *replaced* read like a new default sitting harmlessly beside yours."""
    ctx = _drift(tmp_path, ["sshd_config.pacorig", "fstab.pacnew"])
    said = capsys.readouterr()
    assert "NOT active" in said.err               # .pacorig warned
    assert "still in effect" in said.out          # .pacnew merely noted
    ctx.output.print_summary()
    assert "no longer in effect" in capsys.readouterr().out


def test_config_drift_finds_pacsave_which_pacdiff_skips(tmp_path, capsys):
    """`pacdiff -o` lists only leftovers whose base file still exists — it is a merge
    tool. A `.pacsave` is created when a package is REMOVED, so its base is gone by
    definition and pacdiff never reported it. Measured: three seeded files, `pacdiff -o`
    returned none of them."""
    _drift(tmp_path, ["oldpkg.conf.pacsave"])
    assert "oldpkg.conf.pacsave" in capsys.readouterr().out


def test_config_drift_works_without_pacdiff(tmp_path, capsys):
    """Detection no longer depends on pacman-contrib at all; only the advice does."""
    ctx = _drift(tmp_path, ["fstab.pacnew"], has_pacdiff=False)
    ctx.output.print_summary()                    # next_step prints with the summary
    out = capsys.readouterr().out
    assert "fstab.pacnew" in out
    assert "install pacman-contrib" in out        # still tells you how to merge


def test_config_drift_quiet_when_clean(tmp_path, capsys):
    _drift(tmp_path, [])
    assert "no pending config-file merges" in capsys.readouterr().out


# -- python-rebuild-check ------------------------------------------------------
def _pyreb(tmp_path, dirs, owners=None, current="3.14", rebuild_rc=0, **kw):
    """Stub /usr/lib/python3.* and pacman -Qoq. `owners` maps a path fragment -> pkgs."""
    lib = tmp_path / "usr/lib"
    lib.mkdir(parents=True)
    for d in dirs:
        (lib / d).mkdir()
    owners = owners or {}

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        if cmd[:2] == ["python3", "-c"]:
            return command.Proc(0, current + "\n", "")
        if cmd[:2] == ["pacman", "-Qoq"]:
            return command.Proc(0, "\n".join(owners.get(cmd[2], [])) + "\n", "")
        if cmd[0] in ("yay", "pamac"):
            return command.Proc(rebuild_rc, "", "build failed")
        return command.Proc(0, "", "")

    ctx = _ctx(root=tmp_path, **kw)
    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=True):
        res = ArchBackend().check_python_rebuilds(ctx)
    return res, ctx


def test_python_rebuild_reports_stranded_packages_in_the_summary(tmp_path, capsys):
    """The digest said nothing at all, so a `fettle -a` run with stranded packages
    looked identical to one with none — in the action whose whole purpose is to
    surface them."""
    _, ctx = _pyreb(tmp_path, ["python3.10", "python3.14"],
                    owners={str(tmp_path / "usr/lib/python3.10"): ["some-module"]})
    ctx.output.print_summary()
    assert "stranded on an old Python" in capsys.readouterr().out


def test_python_rebuild_refuses_to_guess_without_a_version(tmp_path, capsys):
    """Without the current version every python3.* dir looks old, and every package
    owning one would be reported as stranded."""
    res, _ = _pyreb(tmp_path, ["python3.10", "python3.14"], current="")
    assert res.ok is False
    assert "NOT checked" in capsys.readouterr().err


def test_python_rebuild_failure_is_not_reported_as_success(tmp_path, capsys):
    """The guard added to check_rebuilds in v0.57.0 was never applied to its sibling
    in the same file — the second consecutive instance of a fix not reaching the
    pattern."""
    _, ctx = _pyreb(tmp_path, ["python3.10", "python3.14"],
                    owners={str(tmp_path / "usr/lib/python3.10"): ["some-module"]},
                    auto_rebuild=True, assume_yes=True, rebuild_rc=1)
    ctx.output.print_summary()
    out = capsys.readouterr().out
    assert "did NOT complete" in out
    assert "✓" not in out.split("Summary")[1].split("did NOT")[0]


def test_arch_read_only_actions_need_no_root():
    """Measured: checkrebuild and pacman -Qoq exit 0 as an unprivileged user, and
    refresh_metadata on Arch runs no command at all. fettle asked for a password anyway."""
    from fettle.cli import NO_ROOT_ACTIONS
    no_root = NO_ROOT_ACTIONS | ArchBackend.extra_no_root
    for action in ("only_update", "rebuild_check", "python_rebuild_check"):
        assert action in no_root


def test_other_backends_still_elevate_for_those():
    """apt and dnf genuinely write under /var for the same actions."""
    from fettle.backends.debian import DebianBackend
    from fettle.backends.rhel import RhelBackend
    for cls in (DebianBackend, RhelBackend):
        assert "only_update" not in cls.extra_no_root


# -- kernels on plain Arch (no mhwd-kernel) ------------------------------------
#
# `mhwd-kernel` is Manjaro-only, so this action used to print "skipping" and do nothing
# on Arch — an action that appears to exist and then declines at runtime. Arch reports
# rather than removes, the same choice the RHEL backend makes: kernel removal is the most
# consequential thing this tool can do, and an inventory is useful where an auto-selected
# removal is a liability.

def _kernel_ctx(tmp_path, releases):
    for rel in releases:
        d = tmp_path / "usr/lib/modules" / rel
        d.mkdir(parents=True)
        (d / "vmlinuz").write_bytes(b"\x7fELF")
    return _ctx(root=tmp_path)


def _run_kernels(tmp_path, releases, running, owners):
    """owners: {release: package-name}; a missing entry means no package owns it."""
    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:2] == ["pacman", "-Qoq"]:
            for rel, pkg in owners.items():
                if rel in c[-1]:
                    return command.Proc(0, pkg + "\n", "")
            return command.Proc(1, "", "No package owns that file")
        return command.Proc(0, "", "")

    ctx = _kernel_ctx(tmp_path, releases)
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n != "mhwd-kernel"), \
         patch("os.uname", return_value=type("U", (), {"release": running})()):
        ArchBackend().manage_kernels(ctx)
    ctx.output.print_summary()


def test_arch_kernels_are_reported_not_skipped(tmp_path, capsys):
    _run_kernels(tmp_path, ["6.15.4-arch2-1"], "6.15.4-arch2-1",
                 {"6.15.4-arch2-1": "linux"})
    out = capsys.readouterr()
    text = out.out + out.err
    assert "skipping kernel management" not in text
    assert "linux" in text and "<- running" in text
    assert "1 installed, running 6.15.4-arch2-1" in text


def test_arch_running_kernel_is_identified_by_pacman_not_by_name(tmp_path):
    """Building the package name from `uname -r` is the Debian bug this project already
    recorded: a kernel named anything unexpected stops matching, and the RUNNING kernel
    then looks like just another removable entry."""
    seen = []

    def fake_run(cmd, *, as_user=None, capture=False):
        seen.append(list(cmd))
        return command.Proc(0, "linux-custom\n", "")

    ctx = _kernel_ctx(tmp_path, ["9.9.9-weird"])
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n != "mhwd-kernel"), \
         patch("os.uname", return_value=type("U", (), {"release": "9.9.9-weird"})()):
        ArchBackend().manage_kernels(ctx)
    assert any(c[:2] == ["pacman", "-Qoq"] for c in seen), seen


def test_arch_never_removes_a_kernel(tmp_path):
    """Removal on Arch is a deliberate `pacman -R` the user runs; fettle must not."""
    seen = []

    def fake_run(cmd, *, as_user=None, capture=False):
        seen.append(list(cmd))
        return command.Proc(0, "linux\n", "")

    ctx = _kernel_ctx(tmp_path, ["6.15.4-arch2-1", "6.12.0-lts"])
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n != "mhwd-kernel"), \
         patch("os.uname", return_value=type("U", (), {"release": "6.15.4-arch2-1"})()):
        ArchBackend().manage_kernels(ctx)
    assert not [c for c in seen if "-R" in c or "-Rns" in c], seen


def test_arch_unowned_module_tree_is_flagged(tmp_path, capsys):
    """A tree no package owns is an upgrade leftover — worth naming, not silently kept."""
    _run_kernels(tmp_path, ["6.15.4-arch2-1", "6.9.0-orphan"], "6.15.4-arch2-1",
                 {"6.15.4-arch2-1": "linux"})
    text = "".join(capsys.readouterr())
    assert "owned by no package" in text and "6.9.0-orphan" in text


def test_arch_missing_running_module_tree_is_warned(tmp_path, capsys):
    """The state where module loading is already broken: the running kernel's tree was
    deleted by an upgrade."""
    _run_kernels(tmp_path, ["6.16.0-arch1-1"], "6.15.4-arch2-1",
                 {"6.16.0-arch1-1": "linux"})
    text = "".join(capsys.readouterr())
    assert "has no module tree on disk" in text
