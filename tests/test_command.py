from unittest.mock import MagicMock, patch

from fettle import command


def test_run_passes_argv_and_returns_proc():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=0, stdout="hi", stderr="")
        proc = command.run(["echo", "hi"], capture=True)
    assert proc.ok and proc.stdout == "hi"
    assert m.call_args[0][0] == ["echo", "hi"]


def test_run_as_user_prefixes_sudo_only_when_root():
    # As root, drop to the user via `sudo -u`.
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=0):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["yay", "-Sua"], as_user="paul")
    assert m.call_args[0][0] == ["sudo", "-u", "paul", "yay", "-Sua"]


def test_run_as_user_no_sudo_when_unprivileged():
    # euid != 0 -> we can't drop privileges we don't hold; run direct (no sudo
    # prompt during an unprivileged/dry-run query).
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=1000):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["yay", "-Qua"], as_user="paul")
    assert m.call_args[0][0] == ["yay", "-Qua"]


def test_run_nonzero_is_not_raised():
    with patch("subprocess.run") as m:
        m.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        proc = command.run(["false"], capture=True)
    assert not proc.ok and proc.returncode == 1


def test_run_missing_binary_returns_127_not_raise():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        proc = command.run(["definitely-not-a-real-binary-xyz"], capture=True)
    assert proc.returncode == 127 and "command not found" in proc.stderr


def test_which():
    assert command.which("sh") is True
    assert command.which("definitely-not-a-real-binary-xyz") is False
