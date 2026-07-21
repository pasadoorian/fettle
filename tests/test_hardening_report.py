"""HA2: attribution, exclude lists, per-package rollup, report rendering."""

from unittest.mock import patch

from fettle import command
from fettle.backends.arch import ArchBackend
from fettle.backends.debian import DebianBackend
from fettle.config import Config
from fettle.hardening import baseline as bl
from fettle.hardening import report
from fettle.hardening.engine import Deviation


def _dev(path, check, got="x"):
    return Deviation(path=path, check=check, got=got, want=("good",))


DEVS = [
    _dev("/usr/lib/Xorg.wrap", "relro", "Partial RELRO"),
    _dev("/usr/lib/Xorg.wrap", "canary", "No Canary Found"),
    _dev("/usr/bin/sudo", "runpath", "RUNPATH [/usr/lib/sudo]"),
    _dev("/usr/bin/cdrecord", "fortify_source", "No"),
    _dev("/usr/bin/x86_64-w64-mingw32-gcc", "pie", "PIE Disabled"),
]
PKGMAP = {
    "/usr/lib/Xorg.wrap": "xorg-server",
    "/usr/bin/sudo": "sudo",
    "/usr/bin/cdrecord": "cdrtools",
    "/usr/bin/x86_64-w64-mingw32-gcc": "mingw-w64-gcc",
}


# -- attribution + rollup ----------------------------------------------------
def test_rollup_groups_by_package_and_counts_binaries():
    reports, stats = report.apply(DEVS, PKGMAP, report.Exclusions())
    assert stats["kept"] == 5
    xorg = next(r for r in reports if r.package == "xorg-server")
    assert xorg.total == 2 and xorg.binaries == 1
    assert xorg.checks == {"relro": 1, "canary": 1}


def test_rollup_sorted_by_deviation_count_desc():
    reports, _ = report.apply(DEVS, PKGMAP, report.Exclusions())
    assert reports[0].package == "xorg-server"  # 2 deviations, ranks first


def test_unowned_file_becomes_unowned_bucket():
    reports, _ = report.apply([_dev("/opt/vendor/blob", "pie")], {}, report.Exclusions())
    assert reports[0].package == "(unowned)"


# -- exclude lists -----------------------------------------------------------
def test_exclude_check_drops_that_criterion_everywhere():
    excl = report.Exclusions(checks=["runpath"])
    reports, stats = report.apply(DEVS, PKGMAP, excl)
    assert stats["excluded_check"] == 1
    assert not any("runpath" in r.checks for r in reports)


def test_exclude_package_glob():
    excl = report.Exclusions(packages=["mingw-w64-*"])
    reports, stats = report.apply(DEVS, PKGMAP, excl)
    assert stats["excluded_package"] == 1
    assert not any(r.package == "mingw-w64-gcc" for r in reports)


def test_exclude_path_glob():
    excl = report.Exclusions(paths=["/usr/lib/*"])
    reports, stats = report.apply(DEVS, PKGMAP, excl)
    assert stats["excluded_path"] == 2  # both Xorg.wrap deviations
    assert not any(r.package == "xorg-server" for r in reports)


def test_exclusions_default_empty_keeps_everything():
    reports, stats = report.apply(DEVS, PKGMAP, report.Exclusions())
    assert stats["kept"] == 5 and report.Exclusions().is_empty()


# -- config parsing ----------------------------------------------------------
def test_exclusions_read_from_config():
    cfg = Config()
    cfg.hardening = {"exclude_checks": ["stack_clash"],
                     "exclude_packages": ["mingw-w64-*"],
                     "exclude_paths": ["/opt/*"]}
    ex = report.exclusions(cfg)
    assert ex.checks == ["stack_clash"]
    assert ex.packages == ["mingw-w64-*"] and ex.paths == ["/opt/*"]


def test_exclusions_tolerate_missing_or_malformed_config():
    assert report.exclusions(Config()).is_empty()          # no [hardening] table
    cfg = Config()
    cfg.hardening = {"exclude_checks": "notalist"}          # wrong type
    assert report.exclusions(cfg).checks == []
    cfg.hardening = "garbage"                               # not even a dict
    assert report.exclusions(cfg).is_empty()


# -- rendering ---------------------------------------------------------------
_BASE = bl.Baseline(name="arch (test)",
                    criteria={"relro": ("Full RELRO",), "canary": ("Canary Found",),
                              "runpath": ("No RUNPATH",), "pie": ("PIE Enabled",),
                              "fortify_source": ("Yes",)},
                    notes=["GCC supplies PIE and stack canary by default"])
_SCAN = {"analyzed": 8728, "static": 98, "unreadable": 0}


def test_render_includes_baseline_notes_and_counts():
    reports, stats = report.apply(DEVS, PKGMAP, report.Exclusions())
    text = "\n".join(report.render(reports, stats, _BASE, _SCAN))
    assert "GCC supplies PIE" in text          # note surfaced
    assert "8728 ELF" in text                    # scan stats
    assert "xorg-server" in text and "sudo" in text
    assert "legend:" in text                     # criterion glosses present


def test_render_reports_config_hidden_count():
    excl = report.Exclusions(checks=["runpath"])
    reports, stats = report.apply(DEVS, PKGMAP, excl)
    text = "\n".join(report.render(reports, stats, _BASE, _SCAN))
    assert "excluded by your [hardening] config: 1" in text


def test_render_clean_when_no_deviations():
    reports, stats = report.apply([], {}, report.Exclusions())
    text = "\n".join(report.render(reports, stats, _BASE, _SCAN))
    assert "No deviations" in text
    assert report.summary_line(reports, stats).startswith("no hardening")


# -- backend attribution -----------------------------------------------------
def test_arch_map_files_to_packages_parses_pacman_qo():
    qo = ("/usr/bin/sudo is owned by sudo 1.9.17.p2-6\n"
          "/usr/lib/Xorg.wrap is owned by xorg-server 21.1.24-1\n")
    with patch("fettle.command.run", return_value=command.Proc(0, qo, "")), \
         patch("fettle.command.which", return_value=True):
        m = ArchBackend().map_files_to_packages(["/usr/bin/sudo", "/usr/lib/Xorg.wrap"])
    assert m == {"/usr/bin/sudo": "sudo", "/usr/lib/Xorg.wrap": "xorg-server"}


def test_arch_map_empty_without_pacman_or_paths():
    with patch("fettle.command.which", return_value=False):
        assert ArchBackend().map_files_to_packages(["/usr/bin/ls"]) == {}
    with patch("fettle.command.which", return_value=True):
        assert ArchBackend().map_files_to_packages([]) == {}


def test_debian_map_files_to_packages_parses_dpkg_query():
    ds = ("sudo: /usr/bin/sudo\n"
          "libc6:amd64, libc6-dev: /usr/bin/shared\n")
    with patch("fettle.command.run", return_value=command.Proc(0, ds, "")), \
         patch("fettle.command.which", return_value=True):
        m = DebianBackend().map_files_to_packages(["/usr/bin/sudo", "/usr/bin/shared"])
    assert m["/usr/bin/sudo"] == "sudo"
    assert m["/usr/bin/shared"] == "libc6"  # first owner, arch-qualifier stripped
