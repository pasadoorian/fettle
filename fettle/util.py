"""Small shared helpers (no fettle imports — safe to use anywhere)."""

from __future__ import annotations

import fnmatch
import shutil
from pathlib import Path


def invoking_user_home() -> Path:
    """The home of the user who *invoked* fettle, not of whoever it is running as.

    Under sudo, ``HOME`` is ``/root`` and ``Path.home()`` follows it — so anything
    resolved from it reads a path that does not exist and silently falls back to
    built-in defaults. That was already this project's highest-impact bug once (the
    sudo re-exec had to be taught to carry ``--config``), and it came back the moment
    a *second* elevating entry point learned to read config: ``fettle -S`` elevates
    itself, so it looked for ``/root/.config/fettle/config.toml`` and reported chipsec
    as unconfigured on a machine where it was configured.

    Four places did this lookup by hand. This is the one that gets fixed.
    """
    import os
    import pwd

    name = os.environ.get("SUDO_USER")
    if name:
        try:
            return Path(pwd.getpwnam(name).pw_dir)
        except KeyError:                       # the user went away mid-session
            pass
    return Path.home()


def frozen_binary() -> str:
    """Absolute path of the compiled binary we are running as, or ``""`` if we are not.

    fettle re-executes itself twice — to elevate via sudo, and to record a session under
    a pty — and both build ``[sys.executable, "-m", "fettle", …]``. That is meaningless
    in a compiled build: there is no interpreter to point at and no ``fettle`` package on
    disk. Both call sites ask here instead, and re-exec this path with the original
    arguments when it is non-empty.

    **``sys.executable`` is the wrong answer and would fail in a way nobody could
    diagnose.** Measured against a real Nuitka onefile build: it is
    ``/tmp/onefile_1411836_.../python`` — a scratch directory Nuitka unpacks itself into,
    which is removed when the process exits. Re-exec'ing it would work while the parent
    lived and fail afterwards. ``sys.argv[0]`` is the binary, and Nuitka resolves it to an
    absolute path even when invoked by bare name from PATH (also measured).

    Nuitka does not set ``sys.frozen`` either — it adds ``__compiled__`` to *every*
    compiled module, so testing this module's own globals is enough. ``sys.frozen`` is
    checked as well, so a PyInstaller build would work without revisiting this.
    """
    import os
    import sys

    if "__compiled__" in globals() or getattr(sys, "frozen", False):
        return os.path.realpath(sys.argv[0])
    return ""


def invoking_user() -> str | None:
    """The name of the user who invoked fettle, or None if not running under sudo.

    The companion to :func:`invoking_user_home`, for the cases that need to hand
    privileges *back* — running a helper tool unprivileged, or chowning a file we
    created as root.
    """
    import os

    return os.environ.get("SUDO_USER") or None


#: Cached per process — the probe costs a real timeout on a wedged host, and three
#: call sites (clean, pkg-audit, update-extras) would otherwise each pay it.
_SNAP_READY: bool | None = None

#: Long enough for `snap version` on a healthy daemon, short enough not to feel like a
#: hang. **The healthy-path latency is unmeasured** — the host this was found on has
#: snapd deliberately disabled and no working snapd was available to time against — so
#: this is chosen conservatively rather than fitted. The failure mode of it being too
#: short is "could not look", which is honest; the failure mode of having no timeout at
#: all was fettle never returning.
SNAP_PROBE_TIMEOUT = 5.0

#: The inventory queries themselves, once the probe has passed. More generous than the
#: probe because a host with many snaps has more to enumerate; still bounded, because a
#: daemon can wedge between the probe and the query.
SNAP_QUERY_TIMEOUT = 30.0


def snap_ready(*, timeout: float | None = None) -> bool:
    """Whether ``snap`` will actually answer, rather than block forever.

    **A stale socket is not a running daemon.** Measured on Manjaro with `snapd`
    disabled — which is its default state on Arch, `preset: disabled` — the `snap`
    binary is still installed *and* `/run/snapd.socket` is still on disk, left behind
    from the last time the service ran. `snap` connects to it, nobody is accepting, and
    it waits forever. `snap list`, `snap list --all` and `snap version` all hang.

    So the obvious probe — does the socket exist? — answers *yes* on exactly the host
    where snap does not work. The only reliable question is whether snap replies, which
    means asking it something cheap under a clock.

    Cached: on a wedged host the answer costs a real wait, and three call sites would
    each pay it otherwise.
    """
    global _SNAP_READY
    if _SNAP_READY is None:
        from . import command

        _SNAP_READY = bool(command.which("snap")) and command.run(
            ["snap", "version"], capture=True,
            timeout=timeout or SNAP_PROBE_TIMEOUT).returncode != command.TIMED_OUT
    return _SNAP_READY


def _reset_snap_probe() -> None:
    """Tests only — the cache is per-process and per-host, never per-run."""
    global _SNAP_READY
    _SNAP_READY = None


SNAPD_DOWN = ("snapd is installed but not responding (the service is stopped or "
              "wedged) — snaps were NOT audited; `systemctl start snapd.socket` if "
              "you use snaps, or remove the snapd package if you do not")


def invoking_user_for(ctx) -> str | None:
    """Who a **per-user** store must be queried as, or ``None`` to stay as we are.

    Some things belong to the machine and some belong to a person, and the second kind
    lives in that person's home directory where only they (or a query made *as* them)
    can see it. fettle usually runs as root — most of a maintenance run needs it — and
    at that moment the personal half of the host goes invisible. It does not error; it
    returns an empty list, which is indistinguishable from having nothing installed.

    Known per-user stores, all found the hard way:

    ``gnome-extensions``
        Answers from the *session* bus, so as root it fails outright (fixed v1.13.0).
    ``podman``
        Rootless images live under ``~/.local/share/containers/storage``. Root reads
        ``/var/lib/containers/storage`` instead and finds nothing — **silently**.
    ``flatpak``
        ``--user`` installs live under ``~/.local/share/flatpak``. Root sees the system
        ones plus *root's own*, never yours.

    Machine-wide by contrast, and deliberately NOT routed through here: ``docker`` (one
    system daemon behind a group-owned socket — root can always reach it and an ordinary
    user often cannot, so dropping privileges would break it), ``snap``, and every
    distro package manager.

    Returns ``None`` when we are not root, or when there is no invoking user to drop
    back to — in both cases the current identity is already the right one to ask as.
    """
    import os

    if os.geteuid() != 0:
        return None
    return getattr(ctx, "sudo_user", None) or invoking_user()


# How to install a package, per package manager. Detected from what is on PATH rather
# than from the backend, so any code path can produce a working instruction without
# having to be handed a distro.
_INSTALLERS = (
    ("pacman", "sudo pacman -S {pkg}"),
    ("apt-get", "sudo apt install {pkg}"),
    ("dnf", "sudo dnf install {pkg}"),
    ("zypper", "sudo zypper install {pkg}"),
    ("apk", "sudo apk add {pkg}"),
)


def install_hint(package: str) -> str:
    """``sudo pacman -S smartmontools`` — the command that would install *package* here.

    Empty when no known package manager is on PATH, because a confidently wrong install
    command is worse than none: it sends someone to a shell prompt to be told the tool
    does not exist, and they conclude fettle is broken rather than that the hint was.
    """
    from . import command

    if not package:
        return ""
    for tool, template in _INSTALLERS:
        if command.which(tool):
            return template.format(pkg=package)
    return ""


def matches_any(name: str, patterns) -> bool:
    """True if ``name`` equals or glob-matches any pattern (case-sensitive)."""
    return any(fnmatch.fnmatchcase(name, p) for p in patterns if p)


def chown_to_user(path: Path, user: str | None) -> None:
    """Best-effort chown a file back to the invoking user; ignore failure."""
    if not user:
        return
    try:
        shutil.chown(path, user=user, group=user)
    except (LookupError, PermissionError, OSError):
        pass
