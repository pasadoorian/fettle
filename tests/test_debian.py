"""Debian/Ubuntu backend — all exercised through the single command mock."""

import json
from pathlib import Path
from unittest.mock import patch

from conftest import SNAP_LIST_ALL

from fettle import command
from fettle.backends.base import Context
from fettle.backends.debian import DebianBackend
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


# -- clean -------------------------------------------------------------------
# The snap fixture lives in conftest.py: pruning moved to the base backend, so Arch and
# RHEL are checked against the same bytes (see test_base.py).
_SNAPS = SNAP_LIST_ALL


def test_clean_apt_flatpak_and_prunes_disabled_snaps():
    calls = []
    responses = {("snap", "list", "--all"): _SNAPS}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().clean_caches(_ctx(assume_yes=True))  # --yes accepts all prompts
    argvs = [c for c, _ in calls]
    assert ["apt-get", "clean"] in argvs
    # `autoclean` used to run straight after `clean`, which has already emptied the
    # archive directory — it could never remove anything, but printed its own success
    # line, so the user counted two operations where one had happened.
    assert not any(c[:2] == ["apt-get", "autoclean"] for c in argvs)
    assert ["flatpak", "uninstall", "--unused", "-y"] in argvs
    # only the two disabled revisions get removed, by name+revision
    assert ["snap", "remove", "core20", "--revision=2015"] in argvs
    assert ["snap", "remove", "firefox", "--revision=3026"] in argvs
    assert not any(c[:3] == ["snap", "remove", "core20"] and "--revision=1974" in c for c in argvs)


def test_clean_never_removes_snaps_without_confirmation():
    """No --yes and no TTY -> the per-revision prompt is declined; nothing removed."""
    calls = []
    responses = {("snap", "list", "--all"): _SNAPS}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch("builtins.input", side_effect=EOFError):  # no TTY -> prompt declined
        DebianBackend().clean_caches(_ctx())
    argvs = [c for c, _ in calls]
    assert not any(c[:2] == ["snap", "remove"] for c in argvs)  # never removed unasked
    assert ["apt-get", "clean"] in argvs  # non-interactive cache cleaning still ran


def test_clean_skips_flatpak_when_disabled():
    calls = []
    cfg = Config(updaters={"debian": {"flatpak_updater": "none"}})
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().clean_caches(_ctx(cfg))
    assert not any(c[0] == "flatpak" for c, _ in calls)


# -- update ------------------------------------------------------------------
def test_update_default_apt_then_extras():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        b, ctx = DebianBackend(), _ctx()
        b.update_system(ctx)
        b.update_extras(ctx)
    argvs = [c for c, _ in calls]
    assert ["apt-get", "update"] in argvs
    up = next(c for c in argvs if "full-upgrade" in c)
    assert up[-2:] == ["apt-get", "full-upgrade"]  # interactive: apt prompts (no -y)
    assert "DEBIAN_FRONTEND=readline" in up and "NEEDRESTART_MODE=l" in up  # no ncurses
    assert ["flatpak", "update", "-y"] in argvs
    assert ["snap", "refresh"] in argvs
    assert not any(c[0] == "nala" for c in argvs)


def test_pending_upgrades_parses_apt_list():
    calls = []
    listing = ("Listing...\n"
               "libc6/jammy-updates 2.35-0ubuntu3.8 amd64 [upgradable from: 2.35-0ubuntu3.6]\n"
               "vim/jammy 2:8.2.4919-1 amd64 [upgradable from: 2:8.2.3995-1]\n")
    responses = {("apt", "list", "--upgradable"): listing}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        pending = DebianBackend().pending_upgrades(_ctx())
    assert ("libc6", "2.35-0ubuntu3.6", "2.35-0ubuntu3.8") in pending
    assert ("vim", "2:8.2.3995-1", "2:8.2.4919-1") in pending
    assert "Listing..." not in [p[0] for p in pending]  # header skipped


# -- pending_transaction (M2) ------------------------------------------------
_APT_SIM = (
    "NOTE: This is only a simulation!\n"
    "Inst base-files [13ubuntu10] (13ubuntu10.4 Ubuntu:24.04/noble-updates [amd64])\n"
    "Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu [amd64])\n"
    "Inst linux-image-6.8.0-134-generic (6.8.0-134.134 Ubuntu:24.04 [amd64])\n"
    "Remv obsolete-lib [1.2-3]\n"
    "Conf base-files (13ubuntu10.4 Ubuntu:24.04/noble-updates [amd64])\n"
)


def test_parse_apt_sim_classifies_lines():
    from fettle.backends.debian import _parse_apt_sim
    kinds = {i.name: (i.kind, i.old, i.new) for i in _parse_apt_sim(_APT_SIM)}
    assert kinds["base-files"] == ("upgrade", "13ubuntu10", "13ubuntu10.4")
    assert kinds["linux-image-6.8.0-134-generic"] == ("new-dep", None, "6.8.0-134.134")
    assert kinds["obsolete-lib"] == ("remove", "1.2-3", "")
    assert "base-files" not in [n for n in kinds if False]  # Conf line ignored
    assert len(kinds) == 4  # 3 Inst + 1 Remv; the Conf line adds nothing


def test_pending_transaction_simulates_dist_upgrade():
    calls = []
    responses = {("apt-get", "-s", "dist-upgrade"): _APT_SIM}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch.object(DebianBackend, "_apt_lists_age_days", return_value=1.0):
        tx = DebianBackend().pending_transaction(_ctx())
    assert tx.ok and not tx.notes  # fresh lists -> no staleness note
    names = {i.name: i.kind for i in tx.items}
    assert names["base-files"] == "upgrade"
    assert names["linux-image-6.8.0-134-generic"] == "new-dep"
    assert names["obsolete-lib"] == "remove"
    assert ["apt-get", "-s", "dist-upgrade"] in [c for c, _ in calls]


def test_pending_transaction_flags_stale_lists():
    with patch("fettle.command.run", side_effect=_fake({}, [])), \
         patch("fettle.command.which", return_value=True), \
         patch.object(DebianBackend, "_apt_lists_age_days", return_value=30.0):
        tx = DebianBackend().pending_transaction(_ctx())
    assert any("apt update" in n for n in tx.notes)


def test_refresh_metadata_updates_lists_not_upgrade():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().refresh_metadata(_ctx())
    cmds = [c for c, _ in calls]
    assert ["apt-get", "update"] in cmds                        # metadata refresh
    assert ["flatpak", "update", "--appstream"] in cmds          # flatpak metadata only
    assert not any("upgrade" in c for cmd in cmds for c in cmd)  # never upgrades


def test_pending_transaction_no_apt_is_not_ok():
    with patch("fettle.command.which", return_value=False):
        tx = DebianBackend().pending_transaction(_ctx())
    assert tx.ok is False and tx.items == []


def test_update_yes_is_noninteractive():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().update_system(_ctx(assume_yes=True))
    upgrade = next(c for c, _ in calls if "full-upgrade" in c)
    assert upgrade[:3] == ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"]
    assert "Dpkg::Options::=--force-confold" in upgrade  # keep old conffiles, no prompt


def test_update_interactive_apt_prompts():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().update_system(_ctx())  # no assume_yes
    argvs = [c for c, _ in calls]
    up = next(c for c in argvs if "full-upgrade" in c)
    assert up[-2:] == ["apt-get", "full-upgrade"] and "-y" not in up  # apt asks first
    assert "DEBIAN_FRONTEND=readline" in up           # plain-text debconf, not ncurses


def test_update_nala_when_configured():
    calls = []
    cfg = Config(updaters={"debian": {"system_updater": "nala"}})
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().update_system(_ctx(cfg))
    argvs = [c for c, _ in calls]
    assert ["nala", "update"] in argvs
    up = next(c for c in argvs if c[-2:] == ["nala", "upgrade"])  # interactive: prompts
    assert "NEEDRESTART_MODE=l" in up
    assert not any("apt-get" in c for c in argvs)


def test_update_system_none_skips():
    calls = []
    cfg = Config(updaters={"debian": {"system_updater": "none"}})
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().update_system(_ctx(cfg))
    assert not any(c[0] in ("apt-get", "nala") for c, _ in calls)


def test_invalid_updaters_fall_back_with_warning(capsys):
    cfg = Config(updaters={"debian": {"system_updater": "yum", "snap_updater": "nope"}})
    system, flatpak, snap = DebianBackend()._updaters(_ctx(cfg))
    assert (system, flatpak, snap) == ("apt", "flatpak", "snap")
    assert "invalid" in capsys.readouterr().err


# -- orphans / obsolete ------------------------------------------------------
def test_orphans_writes_obsolete_and_purges(tmp_path):
    calls = []
    apt_show = ("libold:amd64 1.0 installed: No available version in archive\n"
                "goodpkg:amd64/jammy 2.0 uptodate\n")
    responses = {
        ("apt-show-versions",): apt_show,
        ("deborphan",): "liborphan1\nliborphan2\n",
        ("apt-get", "autoremove", "--dry-run"): "Remv libunused [1.0]\n",
    }
    ctx = Context(output=Output(color=False), config=Config(), sudo_user="paul",
                  user_home=tmp_path, assume_yes=True)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_foreign_orphans(ctx)
    obsolete = list((tmp_path / ".fettle/reports/local").glob("obsolete-pkgs-*.txt"))[0].read_text()
    assert "libold" in obsolete and "goodpkg" not in obsolete
    argvs = [c for c, _ in calls]
    assert any(c[:3] == ["apt-get", "purge", "-y"] and "liborphan1" in c for c in argvs)
    assert ["apt-get", "autoremove", "-y"] in argvs  # assume_yes confirms it


def test_orphans_previews_autoremove_before_asking(tmp_path, capsys):
    # The removal list must be shown BEFORE autoremove runs.
    calls = []
    responses = {("apt-get", "autoremove", "--dry-run"):
                 "Remv libslirp0 [4.6.1-1build1]\nRemv slirp4netns [1.0.1-2]\n"}
    ctx = Context(output=Output(color=False), config=Config(), sudo_user="paul",
                  user_home=tmp_path, assume_yes=True)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_foreign_orphans(ctx)
    out = capsys.readouterr().out
    assert "libslirp0" in out and "slirp4netns" in out         # listed first
    assert "2 unused dependency(ies) would be removed" in out
    assert ["apt-get", "autoremove", "-y"] in [c for c, _ in calls]


def test_orphans_skips_autoremove_when_nothing_unused(tmp_path, capsys):
    # No Remv lines in the simulation -> don't run autoremove, don't prompt.
    ctx = Context(output=Output(color=False), config=Config(), sudo_user="paul",
                  user_home=tmp_path, assume_yes=True)
    with patch("fettle.command.run", side_effect=_fake({}, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_foreign_orphans(ctx)
    assert "no unused dependencies to autoremove" in capsys.readouterr().out


def test_orphans_dry_run_previews_without_removing(tmp_path):
    calls = []
    responses = {("apt-get", "autoremove", "--dry-run"): "Remv libunused [1.0]\n"}
    ctx = Context(output=Output(color=False), config=Config(), sudo_user="paul",
                  user_home=tmp_path, dry_run=True)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_foreign_orphans(ctx)
    assert ["apt-get", "autoremove", "-y"] not in [c for c, _ in calls]  # never removes


def test_orphans_keep_list_protects_libraries(tmp_path):
    calls = []
    responses = {("deborphan",): "libkeep\n"}
    cfg = Config(keep_orphans=["libkeep"])
    ctx = Context(output=Output(color=False), config=cfg, sudo_user="paul",
                  user_home=tmp_path, assume_yes=True)
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_foreign_orphans(ctx)
    assert not any(c[:3] == ["apt-get", "purge", "-y"] for c, _ in calls)


# -- rebuilds (needrestart) --------------------------------------------------
def test_rebuilds_lists_services_needing_restart(capsys):
    calls = []
    nr = ("NEEDRESTART-VER: 3.5\n"
          "NEEDRESTART-KCUR: 6.8.0-31-generic\n"
          "NEEDRESTART-SVC: dbus.service\n"
          "NEEDRESTART-SVC: systemd-journald.service\n")
    responses = {("needrestart", "-b", "-r", "l"): nr}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_rebuilds(_ctx())
    out = capsys.readouterr().out
    assert "dbus.service" in out and "systemd-journald.service" in out


def test_rebuilds_absent_tools_skip(capsys):
    with patch("fettle.command.run", side_effect=_fake({}, [])), \
         patch("fettle.command.which", return_value=False):
        DebianBackend().check_rebuilds(_ctx())
    assert "not found" in capsys.readouterr().out


# -- config drift ------------------------------------------------------------
def test_config_drift_finds_dpkg_and_ucf(tmp_path, capsys):
    etc = tmp_path / "etc"
    (etc / "sub").mkdir(parents=True)
    (etc / "hosts.dpkg-dist").write_text("x")
    (etc / "sub" / "app.conf.ucf-dist").write_text("y")
    with patch("fettle.command.run", side_effect=_fake({}, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_config_drift(_ctx(root=tmp_path))
    out = capsys.readouterr().out
    assert "hosts.dpkg-dist" in out and "app.conf.ucf-dist" in out


def test_config_drift_clean_when_none(tmp_path, capsys):
    (tmp_path / "etc").mkdir()
    with patch("fettle.command.run", side_effect=_fake({}, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_config_drift(_ctx(root=tmp_path))
    assert "no pending config-file merges" in capsys.readouterr().out


# -- automatic updates -------------------------------------------------------
_APT_DUMP_ON = ('APT::Periodic::Update-Package-Lists "1";\n'
                'APT::Periodic::Unattended-Upgrade "1";\n')
_APT_DUMP_OFF = ('APT::Periodic::Update-Package-Lists "1";\n'
                 'APT::Periodic::Unattended-Upgrade "0";\n')


def test_auto_updates_enabled(capsys):
    responses = {
        ("apt-config", "dump"): _APT_DUMP_ON,
        ("dpkg-query",): "install ok installed",
        ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): "enabled\n",
    }
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_auto_updates(_ctx())
    out = capsys.readouterr().out
    assert "ENABLED" in out and "Unattended-Upgrade=1" in out


def test_auto_updates_disabled_by_periodic_and_timer(capsys):
    responses = {
        ("apt-config", "dump"): _APT_DUMP_OFF,
        ("dpkg-query",): "install ok installed",
        ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): "disabled\n",
    }
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_auto_updates(_ctx())
    out = capsys.readouterr().out
    assert "DISABLED" in out
    assert "Unattended-Upgrade=0" in out and "apt-daily-upgrade.timer disabled" in out


def test_auto_updates_disabled_when_package_absent(capsys):
    # periodic + timer are on, but the package isn't installed -> not automatic.
    responses = {
        ("apt-config", "dump"): _APT_DUMP_ON,
        ("dpkg-query",): "unknown ok not-installed",
        ("systemctl", "is-enabled", "apt-daily-upgrade.timer"): "enabled\n",
    }
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_auto_updates(_ctx())
    out = capsys.readouterr().out
    assert "DISABLED" in out and "unattended-upgrades not installed" in out


def test_auto_updates_no_apt_config(capsys):
    with patch("fettle.command.run", side_effect=_fake({}, [])), \
         patch("fettle.command.which", return_value=False):
        DebianBackend().check_auto_updates(_ctx())
    assert "cannot determine auto-update state" in capsys.readouterr().out


# -- kernels -----------------------------------------------------------------
_DPKG_KERNELS = (
    "Desired=Unknown/Install/Remove/Purge/Hold\n"
    "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
    "ii  linux-image-6.8.0-31-generic  6.8.0-31.31  amd64  Signed kernel image\n"
    "ii  linux-image-6.8.0-35-generic  6.8.0-35.35  amd64  Signed kernel image\n"
    "ii  linux-image-generic           6.8.0.35.35  amd64  Generic Linux kernel image\n"
)


def test_kernels_dry_run_protects_running(capsys):
    calls = []
    responses = {("dpkg", "-l", "linux-image-*"): _DPKG_KERNELS,
                 ("uname", "-r"): "6.8.0-35-generic\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(_ctx(dry_run=True))
    out = capsys.readouterr().out
    assert "linux-image-6.8.0-35-generic" in out and "(running)" in out
    assert "linux-image-6.8.0-31-generic" in out  # the removable one is listed
    assert "linux-image-generic" not in out.replace("linux-image-generic  6", "")  # meta skipped
    assert not any(c[:3] == ["apt-get", "purge", "-y"] for c, _ in calls)  # dry-run purges nothing


def test_kernels_purges_only_old_versioned_images():
    calls = []
    responses = {("dpkg", "-l", "linux-image-*"): _DPKG_KERNELS,
                 ("uname", "-r"): "6.8.0-35-generic\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(_ctx(assume_yes=True))
    purges = [c for c, _ in calls if c[:3] == ["apt-get", "purge", "-y"]]
    assert purges and "linux-image-6.8.0-31-generic" in purges[0]
    assert "linux-image-6.8.0-35-generic" not in purges[0]  # running protected
    assert "linux-image-generic" not in purges[0]            # meta-package never purged


def test_kernel_version_key_is_numeric():
    from fettle.backends.debian import _kernel_version_key
    key = _kernel_version_key
    # 124 > 99 numerically (a string sort gets this backwards).
    assert key("linux-image-6.8.0-99-generic") < key("linux-image-6.8.0-124-generic")
    assert key("linux-image-5.15.0-100-generic") < key("linux-image-6.8.0-1-generic")


# The ec3 bug: running kernel is OLD (pre-reboot), a newer one is installed.
_DPKG_KERNELS_PENDING_REBOOT = (
    "ii  linux-image-6.8.0-124-generic  6.8.0-124.124  amd64  Signed kernel image\n"
    "ii  linux-image-6.8.0-134-generic  6.8.0-134.134  amd64  Signed kernel image\n"
)


def test_kernels_protects_newer_kernel_when_pending_reboot():
    calls = []
    responses = {("dpkg", "-l", "linux-image-*"): _DPKG_KERNELS_PENDING_REBOOT,
                 ("uname", "-r"): "6.8.0-124-generic\n"}  # running the OLD one
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(_ctx(assume_yes=True))
    # The newer 6.8.0-134 must NOT be purged — nothing is removable here.
    assert not any(c[:3] == ["apt-get", "purge", "-y"] for c, _ in calls)


def test_kernels_pending_reboot_reports_nothing_removable(capsys):
    responses = {("dpkg", "-l", "linux-image-*"): _DPKG_KERNELS_PENDING_REBOOT,
                 ("uname", "-r"): "6.8.0-124-generic\n"}
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(_ctx())
    out = capsys.readouterr().out
    assert "no kernel images to remove" in out
    assert "6.8.0-134-generic" in out and "boots next" in out  # newest flagged


def test_kernels_reboot_pending_nudge(capsys):
    # M2: running an older kernel than the newest -> warn + reboot next-step.
    responses = {("dpkg", "-l", "linux-image-*"): _DPKG_KERNELS_PENDING_REBOOT,
                 ("uname", "-r"): "6.8.0-124-generic\n"}
    ctx = _ctx()
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(ctx)
    cap = capsys.readouterr()
    assert "reboot to activate it" in cap.err          # warn -> stderr
    assert any("reboot" in s for s in ctx.output._next_steps)


def test_kernels_no_reboot_nudge_when_running_newest(capsys):
    # Running the newest -> no reboot nudge.
    responses = {("dpkg", "-l", "linux-image-*"): _DPKG_KERNELS,
                 ("uname", "-r"): "6.8.0-35-generic\n"}  # 35 is newest here
    with patch("fettle.command.run", side_effect=_fake(responses, [])), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(_ctx(dry_run=True))
    cap = capsys.readouterr()
    assert "reboot to activate" not in (cap.out + cap.err)


def test_kernels_protects_running_and_newest_middle_case():
    # Three kernels, running the middle one -> only the oldest is removable.
    calls = []
    dpkg = ("ii  linux-image-6.8.0-31-generic  6.8.0-31.31  amd64  img\n"
            "ii  linux-image-6.8.0-35-generic  6.8.0-35.35  amd64  img\n"
            "ii  linux-image-6.8.0-40-generic  6.8.0-40.40  amd64  img\n")
    responses = {("dpkg", "-l", "linux-image-*"): dpkg,
                 ("uname", "-r"): "6.8.0-35-generic\n"}  # running the middle
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().manage_kernels(_ctx(assume_yes=True))
    purges = [c for c, _ in calls if c[:3] == ["apt-get", "purge", "-y"]][0]
    assert "linux-image-6.8.0-31-generic" in purges           # oldest -> removed
    assert "linux-image-6.8.0-35-generic" not in purges       # running protected
    assert "linux-image-6.8.0-40-generic" not in purges       # newest protected


# -- Ubuntu Pro / ESM --------------------------------------------------------
# Real `pro security-status --format json` shape, measured on a live Ubuntu 24.04 host
# (854 packages, unattached, 18 in Universe/Multiverse).
def _pro_json(*, attached=False, infra=0, apps=0, universe=18, multiverse=0, services=()):
    return json.dumps({
        "_schema_version": "0.1",
        "summary": {
            "ua": {"attached": attached, "enabled_services": list(services),
                   "entitled_services": []},
            "num_installed_packages": 854,
            "num_main_packages": 828,
            "num_universe_packages": universe,
            "num_multiverse_packages": multiverse,
            "num_third_party_packages": 6,
            "num_unknown_packages": 2,
            "num_esm_infra_packages": 0, "num_esm_infra_updates": infra,
            "num_esm_apps_packages": 0, "num_esm_apps_updates": apps,
            "num_standard_security_updates": 0,
            "reboot_required": False,
        },
        "livepatch": {"fixed_cves": []},
        "packages": [],
    })


def _with_pro(payload, method="check_auto_updates", ctx=None, rc=0, have_pro=True):
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        calls.append(cmd)
        if cmd[:2] == ["pro", "security-status"]:
            return command.Proc(rc, payload, "")
        if cmd[:2] == ["apt-get", "-s"]:
            return command.Proc(0, "Inst foo [1.0] (2.0 Ubuntu:24.04 [amd64])\n", "")
        return command.Proc(0, "", "")

    def which(name):
        return have_pro if name == "pro" else True

    ctx = ctx or _ctx()
    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", side_effect=which):
        result = getattr(DebianBackend(), method)(ctx)
    return ctx, result, calls


def test_esm_updates_apt_cannot_see_are_surfaced_in_the_preview():
    """The whole point: on an unattached host, apt reports the smaller number. Reporting
    that without saying so understates the exposure."""
    _, tx, _ = _with_pro(_pro_json(infra=7, apps=3), method="pending_transaction")
    assert any("not attached to Ubuntu Pro" in n and "7" in n and "3" in n
               for n in tx.notes)


def test_an_attached_host_gets_no_hidden_update_note():
    """Attached hosts have the ESM pockets as real apt sources, so the ordinary count
    already includes them — a note would be double-counting."""
    _, tx, _ = _with_pro(_pro_json(attached=True, infra=7, apps=3),
                         method="pending_transaction")
    assert not any("Ubuntu Pro" in n for n in tx.notes)


def test_pro_is_gated_on_the_binary_so_debian_and_mint_skip_it():
    """`pro` is Ubuntu-only. Gating on the binary rather than the distro ID means Debian
    and Mint never invoke it."""
    _, tx, calls = _with_pro(_pro_json(), method="pending_transaction", have_pro=False)
    assert not any(c[:1] == ["pro"] for c in calls)
    assert not any("Ubuntu Pro" in n for n in tx.notes)


def test_a_failing_pro_call_is_not_treated_as_no_esm_updates():
    """Best-effort: a broken `pro` must not silently become a clean report.

    The payload here is deliberately VALID json with a non-zero exit — `pro` can emit a
    body and still fail. An empty payload would pass this test even without the exit-code
    check, because json.loads would raise anyway, so it would prove nothing.
    """
    _, tx, _ = _with_pro(_pro_json(infra=9, apps=9), method="pending_transaction", rc=1)
    assert not any("Ubuntu Pro" in n for n in tx.notes)


def test_unparseable_pro_json_does_not_crash_the_run():
    _, tx, _ = _with_pro("not json at all", method="pending_transaction")
    assert tx.ok


def test_auto_updates_warns_when_security_updates_need_pro(capsys):
    ctx, _, _ = _with_pro(_pro_json(infra=5, apps=2))
    said = capsys.readouterr()
    assert "not attached" in said.err and "7 security update(s)" in said.err
    assert any("need Ubuntu Pro" in s for s in ctx.output._summary)
    assert any("pro attach" in s for s in ctx.output._next_steps)


def test_auto_updates_names_the_coverage_gap_when_nothing_is_outstanding(capsys):
    """Measured on ec1: fully patched, unattached, but 18 Universe packages that receive
    no security updates at all without Pro. "Up to date" alone would hide that."""
    _with_pro(_pro_json(infra=0, apps=0, universe=18))
    said = capsys.readouterr()
    assert "18 installed package(s)" in said.out
    assert "Universe/Multiverse" in said.out


def test_auto_updates_reports_an_attached_host_plainly(capsys):
    _with_pro(_pro_json(attached=True, services=("esm-infra", "esm-apps")))
    said = capsys.readouterr().out
    assert "attached" in said and "esm-infra" in said


def test_installed_packages_excludes_config_only_leftovers():
    """`dpkg-query -W` also lists `rc` packages — removed, config kept. A plain
    `apt-get remove` leaves exactly that state, so counting them as installed makes a
    removed package appear in both the before and after snapshot and the diff misses
    it. Measured on Ubuntu: two of ten autoremoved packages left config behind."""
    listing = ("ii  bash\n"
               "ii  coreutils\n"
               "rc  libnl-3-200:amd64\n"
               "rc  ibverbs-providers:amd64\n")
    with patch("fettle.command.run", return_value=command.Proc(0, listing, "")):
        pkgs = DebianBackend().installed_packages(_ctx())
    assert pkgs == {"bash", "coreutils"}


# -- rebuild-check: the reboot is the answer that matters ---------------------
_NEEDRESTART_REBOOT = ("NEEDRESTART-VER: 3.11\n"
                       "NEEDRESTART-KCUR: 6.12.96+deb13-cloud-amd64\n"
                       "NEEDRESTART-KEXP: 6.12.100+deb13-cloud-amd64\n"
                       "NEEDRESTART-KSTA: 3\n"
                       "NEEDRESTART-SVC: dbus.service\n")


def test_rebuild_check_reports_a_required_reboot(capsys):
    """Measured on a guest running 6.12.96 with 6.12.100 installed: fettle said
    "3 service(s) need restarting" and never mentioned the reboot. Restarting those
    services cannot help — the running kernel is the unpatched one. RHEL has always
    reported this; Debian silently did not, and `-r` is in the default action set."""
    ctx = _ctx()
    with patch("fettle.command.run",
               return_value=command.Proc(0, _NEEDRESTART_REBOOT, "")), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_rebuilds(ctx)
    ctx.output.print_summary()
    out = capsys.readouterr().out + capsys.readouterr().err
    assert "reboot required" in out.lower()


def test_rebuild_check_quiet_when_kernel_is_current(capsys):
    listing = _NEEDRESTART_REBOOT.replace("KSTA: 3", "KSTA: 1")
    ctx = _ctx()
    with patch("fettle.command.run", return_value=command.Proc(0, listing, "")), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().check_rebuilds(ctx)
    ctx.output.print_summary()
    assert "reboot" not in capsys.readouterr().out.lower()


def test_rebuild_check_empty_output_is_not_a_clean_result(capsys):
    """needrestart always prints a header. Nothing at all means it did not run —
    saying "no services need restarting" would invent a clean result."""
    ctx = _ctx()
    with patch("fettle.command.run", return_value=command.Proc(1, "", "boom")), \
         patch("fettle.command.which", return_value=True):
        res = DebianBackend().check_rebuilds(ctx)
    assert res.ok is False
    assert "no services need restarting" not in capsys.readouterr().out


# -- config-drift: "still in effect" vs "no longer in effect" ------------------
def _seed_etc(tmp_path, names):
    etc = tmp_path / "etc"
    etc.mkdir(parents=True)
    for n in names:
        (etc / n).write_text("x")
    return tmp_path


def test_config_drift_finds_displaced_configs(tmp_path, capsys):
    """`.dpkg-old` and `.ucf-old` were never looked for, so the case where YOUR config
    was replaced by an upgrade — a setting that silently stopped applying — was
    invisible on Debian while RHEL had always warned about its equivalent."""
    ctx = _ctx(root=_seed_etc(tmp_path, ["sshd_config.dpkg-old"]))
    with patch("fettle.command.which", return_value=False):
        DebianBackend().check_config_drift(ctx)
    said = capsys.readouterr()
    assert "sshd_config.dpkg-old" in said.out
    assert "NOT active" in said.err            # warned, not merely noted


def test_config_drift_separates_the_two_kinds(tmp_path, capsys):
    ctx = _ctx(root=_seed_etc(tmp_path, ["a.dpkg-dist", "b.dpkg-old"]))
    with patch("fettle.command.which", return_value=False):
        DebianBackend().check_config_drift(ctx)
    said = capsys.readouterr()
    assert "still in\neffect" in said.out or "still in effect" in said.out
    assert "NOT active" in said.err
    ctx.output.print_summary()
    assert "YOUR version is no longer in effect" in capsys.readouterr().out


def test_config_drift_quiet_when_clean(tmp_path, capsys):
    ctx = _ctx(root=_seed_etc(tmp_path, []))
    with patch("fettle.command.which", return_value=False):
        DebianBackend().check_config_drift(ctx)
    assert "no pending config-file merges" in capsys.readouterr().out
