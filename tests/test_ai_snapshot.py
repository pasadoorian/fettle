"""Upgrade Checker system snapshot + redaction (UC2)."""

from unittest.mock import patch

from fettle import command
from fettle.ai import snapshot


def test_redact_strips_serial_mac_uuid():
    raw = ("Machine: serial: ABC123XYZ\n"
           "Network: mac: de:ad:be:ef:00:11\n"
           "Drive: uuid: 12345678-90ab-cdef-1234-567890abcdef\n")
    out = snapshot.redact(raw)
    assert "ABC123XYZ" not in out and "serial: <redacted>" in out
    assert "de:ad:be:ef:00:11" not in out and "<mac>" in out
    assert "567890abcdef" not in out and "<uuid>" in out


class _Backend:
    def pending_upgrades(self, ctx):
        return [("linux", "6.12-1", "6.18-1"), ("nvidia", "550-1", "560-1")]


def test_gather_builds_snapshot(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('PRETTY_NAME="Manjaro Linux"\nID=manjaro\n')

    def fake_run(cmd, *, as_user=None, capture=False):
        if cmd[0] == "uname":
            return command.Proc(0, "6.12.1-2-MANJARO\n", "")
        if cmd[0] == "inxi":
            return command.Proc(0, "System: Host: wopr serial: SECRET1\n", "")
        return command.Proc(0, "", "")
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", return_value=True):
        snap = snapshot.gather(ctx=None, backend=_Backend(), root=tmp_path)
    assert snap.distro == "Manjaro Linux"
    assert snap.kernel == "6.12.1-2-MANJARO"
    assert "SECRET1" not in snap.inxi and "serial: <redacted>" in snap.inxi  # redacted at gather
    prompt = snap.as_prompt()
    assert "Pending package upgrades (2)" in prompt
    assert "linux  6.12-1 -> 6.18-1" in prompt


def test_gather_without_inxi(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=ubuntu\n")
    with patch("fettle.command.run", return_value=command.Proc(0, "6.8.0\n", "")), \
         patch("fettle.command.which", return_value=False):  # no inxi
        snap = snapshot.gather(ctx=None, backend=_Backend(), root=tmp_path)
    assert snap.inxi == ""
    assert "(inxi not installed)" in snap.as_prompt()
