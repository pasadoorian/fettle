"""Flatpak source provider — remote origin + sandbox permissions."""

from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import INSECURE_TRANSPORT, OVER_PRIVILEGED, UNOFFICIAL_SOURCE
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
            return command.Proc(0, perms.get(c[3], ""), "")
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
