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
    # v0.4.0: AUR IoC scan is -I (-S is now sys-audit). The post-update hint must
    # point at `-A -I`, not the old `-A -S`.
    _, fake = _recorder()
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True):
        ctx = _ctx()
        ArchBackend().update_extras(ctx)
    steps = ctx.output._next_steps
    assert any("fettle -A -I" in s for s in steps)
    assert not any("-A -S" in s for s in steps)


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
         patch.object(ArchBackend, "_temp_synced_db", return_value=Path("/tmp/db")):
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
         patch.object(ArchBackend, "_temp_synced_db", return_value=Path("/tmp/db")):
        tx = ArchBackend().pending_transaction(_ctx())
    aur = [i for i in tx.items if i.source == "aur"]
    assert aur and aur[0].name == "claude-desktop-bin" and aur[0].new == "1-2"
    assert any("devel" in n for n in tx.notes)


def test_pending_transaction_stale_note_when_sync_fails():
    calls, fake = _tx_fake(qu="bash 5.2-1 -> 5.3-1\n", sup="core/bash 5.3-1\n")
    with patch("fettle.command.run", side_effect=fake), \
         patch("fettle.command.which", return_value=True), \
         patch.object(ArchBackend, "_temp_synced_db", return_value=None):  # refresh failed
        tx = ArchBackend().pending_transaction(_ctx())
    assert [i.name for i in tx.items if i.source == "repo"] == ["bash"]
    assert any("stale" in n for n in tx.notes)
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
    with patch("fettle.command.run", side_effect=fake):
        ArchBackend().clean_caches(_ctx(dry_run=True))
    assert calls == []  # dry-run never touches command.run


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
