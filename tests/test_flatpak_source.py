"""Flatpak source provider — remote origin + sandbox permissions."""

from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import (
    INSECURE_TRANSPORT,
    OVER_PRIVILEGED,
    STALE_OR_ABANDONED,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
)
from fettle.supplychain.flatpak_source import FlatpakSource


def _ctx():
    return Context(output=Output(color=False), config=Config())


def _run(*, apps, remotes="", perms=None):
    """apps/remotes: tab-separated column text. perms: {appid: permissions-dump}."""
    perms = perms or {}

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:2] == ["flatpak", "list"]:
            return command.Proc(0, apps, "")
        if c[:2] == ["flatpak", "remotes"]:
            return command.Proc(0, remotes, "")
        if c[:3] == ["flatpak", "info", "--show-permissions"]:
            return command.Proc(0, perms.get(c[-1], ""), "")   # app id is last, after `--`
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake_run):
        return FlatpakSource().findings(_ctx())


def test_non_flathub_origin_flagged():
    findings = _run(apps="org.x.App\tsketchy-remote\n")
    assert any(f.question == UNOFFICIAL_SOURCE and f.package == "org.x.App" for f in findings)


def test_flathub_origin_clean():
    findings = _run(apps="org.good.App\tflathub\n")
    assert not any(f.question == UNOFFICIAL_SOURCE for f in findings)


def test_broad_filesystem_is_over_privileged():
    perms = {"org.x.App": "[Context]\nfilesystems=host;xdg-download\n"}
    findings = _run(apps="org.x.App\tflathub\n", perms=perms)
    op = [f for f in findings if f.question == OVER_PRIVILEGED]
    assert op and "host" in op[0].detail


def test_device_all_is_over_privileged():
    perms = {"org.x.App": "[Context]\ndevices=all\n"}
    findings = _run(apps="org.x.App\tflathub\n", perms=perms)
    assert any(f.question == OVER_PRIVILEGED and "device" in f.detail for f in findings)


def test_narrow_permissions_clean():
    perms = {"org.x.App": "[Context]\nfilesystems=xdg-download\ndevices=dri\n"}
    findings = _run(apps="org.x.App\tflathub\n", perms=perms)
    assert not any(f.question == OVER_PRIVILEGED for f in findings)


def test_http_remote_flagged():
    findings = _run(apps="", remotes="myremote\thttp://repo.example/flat\n")
    assert any(f.question == INSECURE_TRANSPORT and f.package == "myremote" for f in findings)


def test_app_id_passed_after_end_of_options_guard():
    """`--` so an app id can never be parsed as a flatpak option."""
    seen = []

    def fake_run(cmd, **k):
        c = list(cmd)
        seen.append(c)
        if c[:2] == ["flatpak", "list"]:
            return command.Proc(0, "org.x.App\tflathub\n", "")
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run):
        FlatpakSource().findings(_ctx())
    info = next(c for c in seen if c[:3] == ["flatpak", "info", "--show-permissions"])
    assert info[-2:] == ["--", "org.x.App"]


# -- is it still offered? ------------------------------------------------------
def _run_remote(apps, *, info_rc=0, info_err=""):
    calls = []

    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        calls.append(c)
        if c[:2] == ["flatpak", "list"]:
            return command.Proc(0, apps, "")
        if c[:2] == ["flatpak", "remote-info"]:
            return command.Proc(info_rc, "", info_err)
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake_run):
        return FlatpakSource().findings(_ctx()), calls


def test_withdrawn_app_is_reported():
    findings, _ = _run_remote(
        "org.gone.App\tflathub\n", info_rc=1,
        info_err="error: Error searching remote flathub: Can't find ref org.gone.App")
    f = next(f for f in findings if f.question == STALE_OR_ABANDONED)
    assert f.package == "org.gone.App"
    assert "no longer offered by remote 'flathub'" in f.detail


def test_unreachable_remote_is_not_a_withdrawal():
    """An unreachable remote must never read as "every app you have was pulled"."""
    findings, _ = _run_remote("org.mozilla.firefox\tflathub\n", info_rc=1,
                              info_err="error: Unable to connect to flathub")
    assert not [f for f in findings if f.question == STALE_OR_ABANDONED]
    gap = next(f for f in findings if f.question == UNVERIFIABLE)
    assert "could not reach" in gap.detail


def test_app_is_checked_against_its_own_remote_not_flathub():
    """A third-party app is checked where it came from. Asking flathub about it would
    report every non-flathub app as withdrawn, which is a different bug wearing the
    same clothes."""
    _, calls = _run_remote("com.vendor.Tool\tvendor-remote\n")
    info = next(c for c in calls if c[:2] == ["flatpak", "remote-info"])
    assert info[2] == "vendor-remote", info
