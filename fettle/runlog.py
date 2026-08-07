"""script(1)-style run-logger: record a full transcript of every run.

WHY THIS RE-EXECS ITSELF  (read this before touching the file)
--------------------------------------------------------------
To capture the COMPLETE transcript of a run — fettle's own output AND every
interactive subprocess it spawns (yay / pacman / apt) — the recorder has to sit
*above* fettle on a real terminal. A Python-level tee of ``sys.stdout`` can't:
a subprocess writes to file descriptor 1 directly, bypassing Python entirely.

So on an interactive terminal the very first thing ``main()`` does is re-exec
fettle under a pseudo-terminal (PTY), exactly like the ``script`` command::

    your terminal  <->  PTY master (parent = recorder)  <->  PTY slave (child = fettle)

The child — the real fettle run — gets the PTY **slave** as its controlling
terminal, so ``isatty()`` is true and every tool behaves EXACTLY as if it were
unrecorded: colours, progress bars, and ``sudo`` / PKGBUILD prompts all work.
The parent just shuttles bytes both ways and tees a copy (ANSI-stripped) to the
log. There is **no interference by construction** — the child is on a genuine tty.

RISKS this design creates, and how each is handled (this is the bug surface):
  * infinite re-exec loop  -> env guard ``FETTLE_RUNLOG=1`` is set for the child;
                              a guarded process never wraps again.
  * sudo strips the env    -> ``cli._reexec_argv`` FORWARDS the guard through
                              ``sudo env`` so the elevated child does NOT open a
                              second PTY; it inherits the same PTY slave as its tty.
  * non-tty (pipe/cron/CI) -> no PTY (there's nothing to preserve); a lightweight
                              Python tee logs fettle's own output instead.
  * any PTY/termios error  -> run normally, no log, one stderr note; NEVER block.
  * exit status / signals  -> the child's exit code is propagated; Ctrl-C reaches
                              the child through the PTY.
  * passwords              -> we log DISPLAYED master output, not keystrokes, and
                              sudo disables echo, so a password never reaches the log.

The ANSI-stripped ``.txt`` is best-effort clean text (progress-bar redraws are
collapsed). A future phase can store structured/raw logs instead.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

from . import reports as _reports

GUARD = "FETTLE_RUNLOG"

# CSI / OSC / Fe escape sequences — stripped so the log is readable in an editor.
_ANSI = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]"        # CSI  (colour, cursor moves)
    rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC  (title sets)
    rb"|\x1b[@-Z\\-_]",                # other Fe escapes
    re.DOTALL,
)


def is_active() -> bool:
    """True inside an already-recorded process (the guard is set)."""
    return os.environ.get(GUARD) == "1"


# Subcommands that must NOT be run-logged: long-running servers whose output never
# ends (a transcript would grow unbounded and never finalize).
# `--complete` is here for a data-loss reason, the same one `--dry-run` is in `_skip`:
# writing a run-log rotates the directory to `keep` entries, and shell completion shells
# out to fettle on every tab press. Without this, tab-completing would quietly evict real
# run history a few keystrokes at a time. Guarded by a test, not by this comment.
_NO_RECORD = frozenset({"web", "--complete"})


def _skip(argv=()) -> bool:
    """Whether this invocation should NOT be recorded.

    ``--dry-run`` is in here for two reasons, and the first is a data-loss bug measured
    on a real tree: writing a run-log rotates the directory to ``keep`` entries, so a
    dry run **deletes older real run-logs**. Eleven real logs went to nine after a single
    `fettle -d --dry-run`. The one command whose entire promise is "change nothing"
    was destroying history.

    The second is that a dry run appearing in `fettle report` as a run is misleading in
    its own right: the dashboard would show maintenance happening on a host where
    nothing was touched. Its output is on your terminal, which is where a preview
    belongs.
    """
    return (is_active() or os.environ.get("FETTLE_TEST") == "1"
            or "--dry-run" in tuple(argv)
            or bool(argv) and argv[0] in _NO_RECORD)


def clean(data: bytes) -> bytes:
    """Strip ANSI and collapse carriage-return progress redraws to plain text."""
    data = _ANSI.sub(b"", data)
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"")


def _enabled(config) -> bool:
    r = getattr(config, "reports", None)
    r = r if isinstance(r, dict) else {}
    val = r.get("log", True)
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() not in ("false", "0", "no", "off")


def _invoker() -> tuple[Path, str | None]:
    import pwd
    sudo_user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    home = Path.home()
    if sudo_user:
        try:
            home = Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return home, sudo_user


def _early_config(argv):
    """Best-effort config load before the real parser runs (honors --config /
    --no-config); returns built-in defaults on any problem."""
    from .cli import DEFAULT_CONFIG
    from .config import Config, load
    if "--no-config" in argv:
        return Config()
    path = DEFAULT_CONFIG
    if "--config" in argv:
        i = argv.index("--config")
        if i + 1 < len(argv):
            path = Path(argv[i + 1])
    try:
        cfg, _ = load(path)
        return cfg
    except Exception:
        return Config()


def log_host(argv) -> str:
    """Always ``local`` — this log is the record of a **local invocation**.

    It used to dig the target out of ``fettle remote <host> …`` and file the log under
    that name, which was wrong twice over. The remote machine writes and ships back
    its *own* transcript (see ``_fetch_remote_reports``), so this one duplicated it
    under a second name; and the name came from argv **before the host was validated**,
    so a rejected command minted a directory from whatever the arguments happened to
    contain. A real one, found on disk during QA:

        fettle remote -- -oProxyCommand=touch /tmp/pwned-by-fettle clean

    fettle refused it — the guard worked — and still left a permanent host called
    `clean` on the dashboard. Deriving nothing from argv cannot go wrong.
    """
    return "local"


def _ctxlike(user_home, sudo_user, config):
    return SimpleNamespace(user_home=user_home, sudo_user=sudo_user, config=config)


def _open_private(path, mode="wb"):
    """Create *path* owner-only from the start, never 0644-then-chmod.

    A run-log is the whole terminal session — package names, hostnames, paths, whatever
    a tool printed. It was created with the default 0644 and only chmod'd to 0600 when
    the run FINISHED, so on a shared machine it was readable by everyone for the entire
    duration of the run — and permanently if the run was killed, which leaves a
    world-readable transcript behind. Found in the author's own tree: a 0-byte 0644 log
    from an interrupted run.

    O_CREAT with the mode passed to open(2) closes the window rather than narrowing it.
    """
    import os as _os

    fd = _os.open(path, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
    return _os.fdopen(fd, mode)


def _new_log(ctxlike, host: str, now=None):
    import datetime as _dt
    directory = _reports.logs_dir(ctxlike, host)
    ts = (now or _dt.datetime.now()).strftime("%Y%m%d-%H%M%S")
    path = directory / f"run-{ts}.txt"
    i = 1
    while path.exists():
        path = directory / f"run-{ts}-{i}.txt"
        i += 1
    return path, directory


LOG_SCHEMA = "fettle.log/1"


def _write_log_json(txt_path: Path, ctxlike, *, host: str, argv, exit_code) -> None:
    """Write a ``run-<ts>.json`` sibling: metadata + the cleaned transcript. A log
    has no per-line structure, so this is a wrapper. Best-effort (never raises)."""
    import json

    from . import __version__
    try:
        transcript = txt_path.read_text(errors="replace")
    except OSError:
        transcript = ""
    ts = txt_path.stem[len("run-"):] if txt_path.stem.startswith("run-") else ""
    env = {
        "schema": LOG_SCHEMA, "tool": "run", "host": host, "timestamp": ts,
        "fettle_version": __version__, "argv": list(argv),
        "exit_code": exit_code, "transcript": transcript,
    }
    js = txt_path.with_suffix(".json")
    try:
        with _open_private(js, "w") as fh:      # owner-only from creation, as above
            fh.write(json.dumps(env, indent=2) + "\n")
    except OSError:
        return
    from .util import chown_to_user
    chown_to_user(js, getattr(ctxlike, "sudo_user", None))


def _finalize(path: Path, directory: Path, ctxlike):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    from .util import chown_to_user
    chown_to_user(path, ctxlike.sudo_user)
    _, keep = _reports._settings(ctxlike)
    _reports.prune(directory, "run", keep)


def maybe_record(argv) -> int | None:
    """If we should PTY-record and aren't already, re-exec fettle under a pty and
    return the child's exit code (the caller must ``return`` it). Otherwise return
    ``None`` — this process is the real run and should continue normally.

    Never raises: any failure falls through to a normal, unlogged run.
    """
    if _skip(argv) or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    try:
        config = _early_config(argv)
        if not _enabled(config):
            return None
        user_home, sudo_user = _invoker()
        ctxlike = _ctxlike(user_home, sudo_user, config)
        path, directory = _new_log(ctxlike, log_host(argv))
        return _run_pty(argv, path, directory, ctxlike)
    except Exception as exc:  # pragma: no cover - defensive; never block a run
        sys.stderr.write(f"fettle: run-logging unavailable ({exc}); continuing\n")
        return None


def _run_pty(argv, path, directory, ctxlike) -> int:  # pragma: no cover - forks a real pty
    import pty

    logf = _open_private(path)

    def master_read(fd):
        data = os.read(fd, 65536)
        try:
            logf.write(clean(data))
            logf.flush()
        except OSError:
            pass
        return data

    # the child re-runs `python -m fettle <argv>`; carry PYTHONPATH like the sudo
    # re-exec so a checkout resolves, and set the guard so the child won't re-wrap.
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    existing = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = pkg_parent + (os.pathsep + existing if existing else "")
    os.environ[GUARD] = "1"
    child = [sys.executable, "-m", "fettle", *argv]
    status = None
    try:
        status = pty.spawn(child, master_read)
    finally:
        logf.close()
        code = os.waitstatus_to_exitcode(status) if status is not None else None
        _write_log_json(path, ctxlike, host=log_host(argv), argv=argv, exit_code=code)
        _finalize(path, directory, ctxlike)
    return os.waitstatus_to_exitcode(status)


class _Tee:
    """Wrap a text stream so writes also land (ANSI-stripped) in a log file."""

    def __init__(self, stream, logf):
        self._stream = stream
        self._logf = logf

    def write(self, s):
        n = self._stream.write(s)
        try:
            self._logf.write(clean(s.encode("utf-8", "replace")))
        except (OSError, ValueError):
            pass
        return n

    def flush(self):
        self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _NonTtyLog:
    """Best-effort log for a non-interactive run: tees fettle's own stdout/stderr
    (subprocess output isn't captured — there's no tty to record)."""

    def __init__(self, path, directory, ctxlike, argv=()):
        self._path, self._dir, self._ctx = path, directory, ctxlike
        self._argv = list(argv)
        self._logf = _open_private(path)
        self._saved = (sys.stdout, sys.stderr)
        sys.stdout = _Tee(sys.stdout, self._logf)
        sys.stderr = _Tee(sys.stderr, self._logf)

    def close(self):
        sys.stdout, sys.stderr = self._saved
        try:
            self._logf.close()
        except OSError:
            pass
        _write_log_json(self._path, self._ctx, host=log_host(self._argv),
                        argv=self._argv, exit_code=None)
        _finalize(self._path, self._dir, self._ctx)


def start_nontty_log(argv):
    """Install a Python-level tee for a non-tty run; returns a closer or None."""
    if _skip(argv) or sys.stdout.isatty():
        return None
    try:
        config = _early_config(argv)
        if not _enabled(config):
            return None
        user_home, sudo_user = _invoker()
        ctxlike = _ctxlike(user_home, sudo_user, config)
        path, directory = _new_log(ctxlike, log_host(argv))
        return _NonTtyLog(path, directory, ctxlike, argv)
    except Exception:  # pragma: no cover - never block a run
        return None
