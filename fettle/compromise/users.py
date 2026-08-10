"""Which accounts are worth looking at, and which are noise.

The user-scope half of the persistence checks has to walk every real user's
``~/.config/systemd/user/``, because the non-root branch of the June 2026 AUR wave
persisted there rather than in ``/etc/systemd/system``. "Every user" is the trap:
**wopr has 32 `nixbld*` accounts pointing at `/var/empty`**, plus service accounts, so
a naive sweep of every UID >= 1000 walks 34 directories to examine one, and then
reports "34 users checked" — a count that is true and useless.

So this module answers a narrower question: whose home could plausibly hold a user
service? A real, existing directory, and a shell that is not a refusal. Everything
skipped is *counted and explained*, never silently dropped — a coverage number nobody
can audit is the same failure as a clean result nobody can audit.
"""

from __future__ import annotations

import pwd
from dataclasses import dataclass
from pathlib import Path

# Shells that mean "this account does not log in". Matched on the basename so
# /usr/sbin/nologin, /sbin/nologin and /usr/bin/nologin are one rule rather than three.
_NO_LOGIN_SHELLS = frozenset({"nologin", "false", "sync", "shutdown", "halt", "true"})

# Below this, accounts are system accounts on every distro fettle supports. Debian and
# Arch both start ordinary users at 1000; RHEL has since RHEL 7. `nobody` (65534) and
# the systemd/dbus range sit outside it at the top, which is what the upper bound is for.
_UID_MIN, _UID_MAX = 1000, 60000


@dataclass(frozen=True)
class RealUser:
    name: str
    uid: int
    home: Path


@dataclass
class UserScan:
    """Who was examined, and — the half that matters — who was not, and why."""

    users: list[RealUser]
    # reason -> how many accounts it excluded. Rendered as a note, so a run says
    # "32 accounts skipped: no home directory" rather than quietly checking one user.
    skipped: dict[str, int]

    @property
    def skipped_total(self) -> int:
        return sum(self.skipped.values())

    def note(self) -> str:
        """One sentence naming the coverage, or empty when nothing was skipped."""
        if not self.skipped:
            return ""
        parts = ", ".join(f"{n} {why}" for why, n in sorted(self.skipped.items()))
        return (f"{len(self.users)} user account(s) examined; "
                f"{self.skipped_total} skipped ({parts})")


def real_users(root: Path = Path("/"), *, readable_only: bool = False) -> UserScan:
    """Accounts whose home directory could hold a user service.

    ``readable_only`` drops homes this process cannot actually read, which is what an
    unprivileged run needs: without it the caller reports N users examined when it
    could only open its own. The distinction is the caller's to make visible — this
    just refuses to guess on its behalf.

    ``root`` is honoured for the home-directory existence test so the check is
    testable against a scratch tree, but the account list always comes from the real
    ``pwd`` database: there is no portable way to parse an arbitrary ``/etc/passwd``
    that also picks up LDAP/SSSD accounts, and silently seeing fewer users than the
    system has is precisely the failure this module is about.
    """
    users: list[RealUser] = []
    skipped: dict[str, int] = {}

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    for entry in pwd.getpwall():
        if entry.pw_uid == 0:
            # root is examined by the system-scope checks, which read /root directly
            # rather than going through this list.
            continue
        if not (_UID_MIN <= entry.pw_uid <= _UID_MAX):
            continue                       # system account — not skipped, not a user
        shell = (entry.pw_shell or "").rsplit("/", 1)[-1]
        if shell in _NO_LOGIN_SHELLS:
            skip("cannot log in")
            continue
        if not entry.pw_dir:
            skip("no home directory")
            continue
        home = root / entry.pw_dir.lstrip("/")
        if not home.is_dir():
            skip("no home directory")
            continue
        if readable_only:
            try:
                next(home.iterdir(), None)
            except OSError:
                skip("home not readable without root")
                continue
        users.append(RealUser(name=entry.pw_name, uid=entry.pw_uid, home=home))

    users.sort(key=lambda u: u.uid)
    return UserScan(users=users, skipped=skipped)
