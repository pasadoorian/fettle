"""The single subprocess entry point — every external command goes through here.

One wrapper means tests mock exactly one function, and the sudo-drop-to-user logic
(AUR builds and pamac's per-user DB must NOT run as root) lives in one place.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class Proc:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def which(name: str) -> bool:
    """True if ``name`` is on PATH."""
    return shutil.which(name) is not None


def _session_env(user: str) -> list[str]:
    """An ``env NAME=VALUE`` prefix restoring ``user``'s session bus, or ``[]``.

    **Dropping privileges is not enough to reach a desktop session.** fettle re-execs
    itself under plain ``sudo``, whose ``env_reset`` discards
    ``DBUS_SESSION_BUS_ADDRESS`` and ``XDG_RUNTIME_DIR`` for the whole run — and
    ``sudo -u`` on the way back down resets the environment a second time. So a tool
    that talks to the user's session bus finds no bus at either end.

    Measured on a GNOME workstation with 24 extensions installed::

        gnome-extensions list                                          exit 0
        env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR ... list    exit 2
        env -u DBUS_SESSION_BUS_ADDRESS ... list                       exit 0
        env -u XDG_RUNTIME_DIR ... list                                exit 0

    **Either** variable is sufficient — libdbus derives ``unix:path=$XDG_RUNTIME_DIR/bus``
    when the address is unset — and ``XDG_RUNTIME_DIR`` is the one that can be rebuilt
    from the uid alone, without having captured anything before the re-exec.

    Returns ``[]`` when there is no live runtime directory: a service account, a
    headless host, a user who is not logged in. Naming a directory that does not exist
    would not conjure a session, and the caller must stay free to report "could not
    look" rather than have a fabricated path make it look like something else.
    """
    import pwd

    try:
        uid = pwd.getpwnam(user).pw_uid
    except (KeyError, TypeError):
        return []
    return _runtime_env(uid)


def _runtime_env(uid: int) -> list[str]:
    runtime = f"/run/user/{uid}"
    return ["env", f"XDG_RUNTIME_DIR={runtime}"] if os.path.isdir(runtime) else []


def session_available(user: str) -> bool:
    """Whether ``user`` has a live session bus to talk to. See :func:`_session_env`."""
    return bool(_session_env(user))


def run(cmd: Sequence[str], *, as_user: str | None = None, capture: bool = False,
        session: bool = False) -> Proc:
    """Run ``cmd``. With ``as_user`` set, drop privileges via ``sudo -u`` first.

    ``session=True`` additionally restores that user's session bus (see
    :func:`_session_env`) — needed only by tools that speak D-Bus to the running
    desktop. It is opt-in because the usual reason to pass ``as_user`` is the user's
    *identity* (an AUR build, pamac's per-user database), not their session, and those
    callers must keep the clean environment they have always had.

    Never raises — a missing binary returns ``Proc(127)`` (not a traceback), and a
    non-zero exit is returned as-is. Callers decide what a failure means (this is
    an advisory maintenance tool, not a fail-fast pipeline).
    """
    argv = list(cmd)
    # Only drop privileges when we actually hold them: `sudo -u` from a non-root
    # user re-prompts for a password, which would stall an unprivileged/dry-run
    # query (e.g. `yay -Qua`). If euid != 0 we're already unprivileged — run direct,
    # and the ambient environment already *is* the user's session.
    if as_user and os.geteuid() == 0:
        argv = ["sudo", "-u", as_user,
                *(_session_env(as_user) if session else []), *argv]
    elif session and not os.environ.get("XDG_RUNTIME_DIR"):
        # Already the right user, but with no session in our own environment either.
        # Measured: `fettle -P` from a plain crontab entry, which sets no
        # XDG_RUNTIME_DIR — the runtime dir is still there and still ours, so deriving
        # it is the difference between auditing the extensions and reporting that we
        # could not look at them.
        argv = [*_runtime_env(os.getuid()), *argv]
    try:
        completed = subprocess.run(argv, capture_output=capture, text=True)  # noqa: S603
    except FileNotFoundError:
        prog = argv[0] if argv else "(empty command)"
        return Proc(returncode=127, stderr=f"command not found: {prog}")
    except OSError as exc:
        return Proc(returncode=126, stderr=f"could not run {argv[0]}: {exc}")
    return Proc(
        returncode=completed.returncode,
        stdout=(completed.stdout or "") if capture else "",
        stderr=(completed.stderr or "") if capture else "",
    )
