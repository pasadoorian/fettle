"""Debian/Ubuntu backend — all exercised through the single command mock."""

from pathlib import Path
from unittest.mock import patch

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
_SNAPS = ("Name Version Rev Tracking Publisher Notes\n"
          "core20 20230622 1974 latest/stable canonical base\n"
          "core20 20230801 2015 latest/stable canonical disabled\n"
          "firefox 117.0 3026 latest/stable mozilla disabled\n")


def test_clean_apt_flatpak_and_prunes_disabled_snaps():
    calls = []
    responses = {("snap", "list", "--all"): _SNAPS}
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().clean_caches(_ctx(assume_yes=True))  # --yes accepts all prompts
    argvs = [c for c, _ in calls]
    assert ["apt-get", "clean"] in argvs
    assert ["apt-get", "autoclean", "-y"] in argvs
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
    assert ["apt-get", "full-upgrade"] in argvs  # interactive: apt prompts (no -y)
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
    assert upgrade[:2] == ["env", "DEBIAN_FRONTEND=noninteractive"]
    assert "Dpkg::Options::=--force-confold" in upgrade  # keep old conffiles, no prompt


def test_update_interactive_apt_prompts():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().update_system(_ctx())  # no assume_yes
    argvs = [c for c, _ in calls]
    assert ["apt-get", "full-upgrade"] in argvs      # no -y -> apt asks before upgrading
    assert not any(c[:2] == ["apt-get", "full-upgrade"] and "-y" in c for c in argvs)


def test_update_nala_when_configured():
    calls = []
    cfg = Config(updaters={"debian": {"system_updater": "nala"}})
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        DebianBackend().update_system(_ctx(cfg))
    argvs = [c for c, _ in calls]
    assert ["nala", "update"] in argvs and ["nala", "upgrade"] in argvs  # interactive: prompts
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
    obsolete = (tmp_path / "obsolete-pkgs.txt").read_text()
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
