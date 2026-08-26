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


# -- restoring the user's session for `sudo -u` -------------------------------
# `sudo -u` resets the environment, so dropping privileges is not on its own enough to
# reach the user's session bus. Measured on wopr (24 GNOME extensions):
#
#   gnome-extensions list                                       -> exit 0
#   env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR ... list  -> exit 2
#   env -u DBUS_SESSION_BUS_ADDRESS ... list                     -> exit 0
#   env -u XDG_RUNTIME_DIR ... list                              -> exit 0
#
# Either variable is enough (libdbus derives `unix:path=$XDG_RUNTIME_DIR/bus` when the
# address is unset), and XDG_RUNTIME_DIR is the one reconstructable from the uid alone.
def _pw(uid):
    return MagicMock(pw_uid=uid)


def test_session_restores_the_runtime_dir_when_dropping_to_the_user():
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=0), \
         patch("pwd.getpwnam", return_value=_pw(1000)), \
         patch("os.path.isdir", return_value=True):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["gnome-extensions", "list"], as_user="paul", session=True)
    assert m.call_args[0][0] == ["sudo", "-u", "paul", "env",
                                 "XDG_RUNTIME_DIR=/run/user/1000",
                                 "gnome-extensions", "list"]


def test_no_session_env_without_the_session_flag():
    """The prefix is opt-in: every other `as_user` caller (yay, pamac) must be
    untouched, because they want the user's *identity*, not a session bus."""
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=0), \
         patch("pwd.getpwnam", return_value=_pw(1000)), \
         patch("os.path.isdir", return_value=True):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["yay", "-Sua"], as_user="paul")
    assert m.call_args[0][0] == ["sudo", "-u", "paul", "yay", "-Sua"]


def test_a_user_with_no_live_session_gets_no_invented_runtime_dir():
    """`/run/user/<uid>` is absent for a service account, a headless box, or a user who
    is not logged in. Pointing at it anyway would not conjure a session — the tool still
    fails, and the caller must be free to report that honestly."""
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=0), \
         patch("pwd.getpwnam", return_value=_pw(1000)), \
         patch("os.path.isdir", return_value=False):
        m.return_value = MagicMock(returncode=2, stdout="", stderr="")
        command.run(["gnome-extensions", "list"], as_user="paul", session=True)
    assert m.call_args[0][0] == ["sudo", "-u", "paul", "gnome-extensions", "list"]


def test_an_unknown_user_does_not_crash_the_run():
    import pwd as _pwd
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=0), \
         patch("pwd.getpwnam", side_effect=KeyError("nope")):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["gnome-extensions", "list"], as_user="ghost", session=True)
    assert m.call_args[0][0] == ["sudo", "-u", "ghost", "gnome-extensions", "list"]
    assert _pwd  # imported for the patch target to exist


def test_session_is_a_no_op_when_already_unprivileged():
    """Running as the user already: the ambient environment *is* the session."""
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=1000):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["gnome-extensions", "list"], as_user="paul", session=True)
    assert m.call_args[0][0] == ["gnome-extensions", "list"]


def test_an_unprivileged_run_with_no_session_of_its_own_derives_one():
    """Measured: `fettle -P` from a plain crontab entry has no XDG_RUNTIME_DIR, so the
    extension audit went dark there too — for a different reason than the root case,
    with the identical symptom."""
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=1000), \
         patch("os.getuid", return_value=1000), patch("os.path.isdir", return_value=True), \
         patch.dict("os.environ", {}, clear=True):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["gnome-extensions", "list"], as_user="paul", session=True)
    assert m.call_args[0][0] == ["env", "XDG_RUNTIME_DIR=/run/user/1000",
                                 "gnome-extensions", "list"]


def test_an_existing_session_in_the_environment_is_left_alone():
    with patch("subprocess.run") as m, patch("os.geteuid", return_value=1000), \
         patch.dict("os.environ", {"XDG_RUNTIME_DIR": "/run/user/1000"}, clear=True):
        m.return_value = MagicMock(returncode=0, stdout="", stderr="")
        command.run(["gnome-extensions", "list"], as_user="paul", session=True)
    assert m.call_args[0][0] == ["gnome-extensions", "list"]
