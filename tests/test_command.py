from unittest.mock import MagicMock, patch

from fettle import command


def test_run_passes_argv_and_returns_proc():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=0, stdout="hi", stderr="")
        proc = command.run(["echo", "hi"], capture=True)
    assert proc.ok and proc.stdout == "hi"
    assert m.call_args[0][0] == ["echo", "hi"]


def test_run_as_user_prefixes_sudo():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["yay", "-Sua"], as_user="paul")
    assert m.call_args[0][0] == ["sudo", "-u", "paul", "yay", "-Sua"]


def test_run_nonzero_is_not_raised():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        proc = command.run(["false"], capture=True)
    assert not proc.ok and proc.returncode == 1


def test_which():
    assert command.which("sh") is True
    assert command.which("definitely-not-a-real-binary-xyz") is False
