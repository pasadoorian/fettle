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
