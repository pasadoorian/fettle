"""Cross-checks the action registry so a rename can't silently drop an action.

Every maintenance action must line up across five structures: the CLI name set,
the action handlers, the section titles, the config default set, and at least one
backend's `supported` set. This is the guard for the Phase 6 key rename.
"""

from fettle.actions import HANDLERS, TITLES
from fettle.backends.base import ALL_ACTIONS, PackageBackend
from fettle.cli import ACTION_NAMES, PIPELINE_ONLY_ACTIONS, REMOTE_DEFAULT_ACTIONS
from fettle.config import DEFAULT_ACTIONS
from fettle.distro import _REGISTRY

# Derived from the registry, not a hardcoded list of backend classes: a hardcoded
# pair silently stopped covering the RHEL backend the moment it was added, so a typo
# in its `supported` set would not have been caught. Every registered backend is
# checked, and a fourth is covered automatically.
_BACKENDS = sorted(set(_REGISTRY.values()), key=lambda c: c.name)
_BACKEND_SUPPORT = set().union(*(b.supported for b in _BACKENDS))
# Names retired in the Phase 6 rework — must not linger anywhere.
_RETIRED = {"rebuilds", "python_rebuild", "firmware", "kernels",
            "integrity", "source_audit"}


def test_every_action_has_a_handler():
    # 1:1 with the flags, PLUS the pipeline-only actions that are reached by their own
    # subcommand instead. Still exact, so a handler nothing can invoke is still caught.
    assert set(HANDLERS) == ACTION_NAMES | PIPELINE_ONLY_ACTIONS


def test_every_action_has_a_title():
    missing = ACTION_NAMES - set(TITLES)
    assert not missing, f"actions with no TITLES entry: {missing}"


def test_every_action_is_supported_by_some_backend():
    orphans = ACTION_NAMES - _BACKEND_SUPPORT
    assert not orphans, f"actions no backend supports: {orphans}"


def test_backend_support_sets_only_name_real_actions():
    for backend in _BACKENDS:
        stray = backend.supported - ACTION_NAMES
        assert not stray, f"{backend.name} lists unknown actions: {stray}"


# Actions whose implementation is a backend method (so "claimed" is checkable).
# Provider-driven actions — pkg_audit, hardening_audit, container_update, the aur_*
# trio — are deliberately absent: they run off supply-chain providers and shared
# modules, not a per-backend method.
_ACTION_METHODS = {
    "clean": ("clean_caches",),
    "orphans": ("check_foreign_orphans",),
    "update": ("update_system", "update_extras"),
    "only_update": ("refresh_metadata", "pending_transaction"),
    "rebuild_check": ("check_rebuilds",),
    "python_rebuild_check": ("check_python_rebuilds",),
    "config_drift": ("check_config_drift",),
    "auto_updates": ("check_auto_updates",),
    "kernel": ("manage_kernels",),
    # firmware_check is concrete on the base class (fwupd is distro-neutral), so a
    # backend legitimately claims it without overriding anything.
}


def test_claimed_actions_are_actually_implemented():
    """A backend must not advertise an action it inherited as a stub.

    `supported` is how the CLI decides what to offer, and the base methods raise
    NotImplementedError — so claiming one without writing it turns a clean "not
    supported on this distro" note into an error surfaced at the user. This is the
    direction the old hardcoded RHEL set was really guarding, expressed so it holds for
    every backend and needs no edit as each wave lands.
    """
    for backend in _BACKENDS:
        for action in sorted(backend.supported & set(_ACTION_METHODS)):
            for meth in _ACTION_METHODS[action]:
                own = getattr(backend, meth, None)
                assert own is not getattr(PackageBackend, meth), (
                    f"{backend.name} claims '{action}' but inherits {meth}() "
                    f"from the base class")


def test_default_and_remote_sets_are_valid_actions():
    assert set(DEFAULT_ACTIONS) <= ACTION_NAMES
    assert set(REMOTE_DEFAULT_ACTIONS) <= ACTION_NAMES
    assert set(ALL_ACTIONS) <= ACTION_NAMES


def test_retired_names_are_gone_everywhere():
    surfaces = ACTION_NAMES | set(HANDLERS) | set(TITLES) | _BACKEND_SUPPORT \
        | set(DEFAULT_ACTIONS) | set(ALL_ACTIONS) | set(REMOTE_DEFAULT_ACTIONS)
    lingering = _RETIRED & surfaces
    assert not lingering, f"retired action names still present: {lingering}"


# -- sys-audit and advisory-check as pipeline actions ---------------------------
#
# Both have their own subcommands and used to be reachable ONLY that way. Folding them
# into the pipeline is what lets --everything produce one summary and one exit code.
# Two integration defects showed up on the first live run and are pinned here.

def _pipeline_out():
    from fettle.output import Output
    return Output(color=False)


def test_sys_audit_does_not_print_its_own_summary_in_a_pipeline(capsys):
    """It called print_summary() itself, so a pipeline run ended with two digests in a
    row — exactly the noise folding it in was meant to remove."""
    from unittest.mock import patch

    from fettle.actions import _sys_audit
    from fettle.backends.base import Context
    from fettle.config import Config

    ctx = Context(output=_pipeline_out(), config=Config())
    with patch("fettle.secure.audit.run") as run, \
         patch("fettle.secure.audit._write_report"):
        _sys_audit(ctx)
    assert run.call_args.kwargs.get("summarize") is False, run.call_args


def test_sys_audit_restores_the_pipeline_step_counter():
    """It sets step_total to its own category count and numbers each one, so nesting it
    produced `[3/9] … [10/9]` — a running number against someone else's total, ending
    past it. Both halves must be restored."""
    from unittest.mock import patch

    from fettle.actions import _sys_audit
    from fettle.backends.base import Context
    from fettle.config import Config

    out = _pipeline_out()
    out.step_total = 14
    out._step_cur = 3
    ctx = Context(output=out, config=Config())

    def clobber(categories, scan, **kw):
        scan.output.step_total = 9
        scan.output._step_cur = 9        # as if it had run all its categories

    with patch("fettle.secure.audit.run", side_effect=clobber), \
         patch("fettle.secure.audit._write_report"):
        _sys_audit(ctx)
    assert (out.step_total, out._step_cur) == (14, 3)


def test_both_are_runnable_on_every_backend():
    """They do not go through a package manager at all, so a backend that forgot to add
    them to `supported` would silently drop the action from --everything."""
    for backend_cls in _REGISTRY.values():
        b = backend_cls()
        assert b.supports("sys_audit"), b.name
        assert b.supports("advisory_check"), b.name
