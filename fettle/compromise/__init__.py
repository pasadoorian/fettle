"""Compromise indicators — *has this machine already been compromised?*

A different question from `hardening-audit`, and deliberately a different action.
Hardening asks whether the system is **configured** safely; this asks whether
something is **already here**. The two have different answers, different audiences and
— the reason they must not be merged — different responses. A hardening finding is
fixed by running a command. A finding here is investigated *before* running anything,
because the evidence is destroyed by the cleanup.

Three rules this module exists to enforce, none of which is optional:

* **Nothing here emits a fix.** :class:`Finding` carries ``fix``, and every check in
  this package puts an *investigation step* in it — what to look at, in what order, to
  decide whether the finding is real. Rebooting, deleting the artifact or reinstalling
  the package destroys timestamps, open descriptors and unlinked inodes, which on a
  compromised host is the evidence. :func:`fettle.compromise.render.screen` labels the
  column ``INVESTIGATE`` for exactly this reason.
* **Nothing here is proof.** Every finding names the boring explanation alongside the
  alarming one. wopr's two unowned `rumble-agent-*.service` units are the working
  example: they are exactly the shape the AUR-wave implant used, and they are the
  runZero agent, installed on purpose.
* **"Could not look" is never "found nothing".** Inherited from the hardening axes and
  restated here because it matters more in this action: most checks need root, and an
  unprivileged run that printed a clean result would be the worst output this project
  could produce.

The check *groups* reuse :class:`fettle.hardening.axes.AxisResult` rather than
defining a parallel type. That import direction is deliberate and one-way — the shape
(findings / blind / na / checked) is the contract the QA pass produced, the renderer
and the JSON serialiser already speak it, and a second near-identical dataclass is how
two of them drift into disagreeing. If a third consumer ever appears, extract it then.
"""

from __future__ import annotations

from ..hardening.axes import (  # noqa: F401 — re-exported: this is the local vocabulary
    CRITICAL,
    HIGH,
    LOW,
    MEDIUM,
    SEVERITY_ORDER,
    AxisResult as CheckResult,
    Finding,
)

# The groups that EXIST, in print order. Grows one entry per milestone.
#
# Empty is a legitimate state and is handled explicitly by `audit.run`: listing an
# unbuilt group here would report it as blind on every host, which is a louder lie
# than not mentioning it — the same call the hardening axes made for the same reason.
GROUP_NAMES: tuple[str, ...] = ("persistence",)


def is_directory(path) -> bool:
    """``Path.is_dir()`` that cannot raise — and it has to be written out.

    **`Path.is_dir()` behaves differently on a permission error depending on the Python
    version, and this action walks exactly the directories where that happens.** On
    3.11-3.13 it calls ``self.stat()`` and re-raises anything ``_ignore_error`` does not
    cover — which is ENOENT, ENOTDIR, EBADF and ELOOP, but **not EACCES**. On 3.14 it is
    ``os.path.isdir()``, which swallows everything and returns False.

    That difference shipped a real bug: probing `/var/spool/cron/crontabs` under a
    `/var/spool/cron` this process cannot search raised on CI's interpreters and returned
    False on the developer's. Debian ships that directory `0730 root:crontab`, so on a
    Debian host running python 3.11 an unprivileged `compromise-check` would have thrown
    out of the persistence group entirely — `run_all` would have caught it and reported
    the whole group blind, so a user would have got **no** persistence findings rather
    than the ones this check can see without root.

    Every filesystem predicate in this package goes through here or its sibling for that
    reason. "Cannot tell" is answered by the caller asking, explicitly, rather than by
    whichever interpreter happens to be installed.
    """
    import os

    try:
        return os.path.isdir(path)
    except OSError:                      # pragma: no cover — os.path already swallows
        return False


def is_regular_file(path) -> bool:
    """``Path.is_file()`` that cannot raise. See :func:`is_directory`."""
    import os

    try:
        return os.path.isfile(path) and not os.path.islink(path)
    except OSError:                      # pragma: no cover
        return False


def disabled(cfg) -> set[str]:
    """Group names switched off via ``[compromise] disable_checks``.

    Everything is on by default, matching `[hardening] disable_axes`. A separate key
    rather than a shared one because the two actions are separately opt-in-able, and a
    user silencing a noisy hardening axis must not silence a rootkit check as a side
    effect.
    """
    section = getattr(cfg, "compromise", None) or {}
    if not isinstance(section, dict):
        return set()
    raw = section.get("disable_checks") or []
    if not isinstance(raw, (list, tuple)):
        return set()
    return {str(x).strip().lower().replace("_", "-") for x in raw if str(x).strip()}


def unknown_disabled(cfg) -> list[str]:
    """Names in ``disable_checks`` that are not groups — a typo disables nothing."""
    return sorted(disabled(cfg) - set(GROUP_NAMES))


def _module(name: str):
    from importlib import import_module

    return import_module(f".{name.replace('-', '_')}", __package__)


def run_all(backend, ctx) -> list[CheckResult]:
    """Run every enabled group, in :data:`GROUP_NAMES` order.

    A group that raises is reported as **blind**, never as clean, and never takes the
    others with it. Same contract as the hardening axes, and the stakes are higher: a
    crashed rootkit check that rendered as "nothing found" is the failure mode this
    whole action exists to avoid.
    """
    off = disabled(ctx.config)
    results: list[CheckResult] = []
    for name in GROUP_NAMES:
        if name in off:
            continue
        try:
            results.append(_module(name).run(backend, ctx))
        except Exception as exc:                       # noqa: BLE001 — see docstring
            results.append(CheckResult(
                name=name, title=name.replace("-", " ").capitalize(),
                blind=[(f"the {name} checks did not complete",
                        f"{type(exc).__name__}: {exc}", "")],
            ))
    return results
