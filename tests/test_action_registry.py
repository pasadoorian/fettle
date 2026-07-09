"""Cross-checks the action registry so a rename can't silently drop an action.

Every maintenance action must line up across five structures: the CLI name set,
the action handlers, the section titles, the config default set, and at least one
backend's `supported` set. This is the guard for the Phase 6 key rename.
"""

from fettle.actions import HANDLERS, TITLES
from fettle.backends.arch import ArchBackend
from fettle.backends.base import ALL_ACTIONS
from fettle.backends.debian import DebianBackend
from fettle.cli import ACTION_NAMES, REMOTE_DEFAULT_ACTIONS
from fettle.config import DEFAULT_ACTIONS

_BACKEND_SUPPORT = ArchBackend.supported | DebianBackend.supported
# Names retired in the Phase 6 rework — must not linger anywhere.
_RETIRED = {"rebuilds", "python_rebuild", "firmware", "kernels",
            "integrity", "source_audit"}


def test_every_action_has_a_handler():
    assert set(HANDLERS) == ACTION_NAMES  # exact 1:1 — no orphan handlers or actions


def test_every_action_has_a_title():
    missing = ACTION_NAMES - set(TITLES)
    assert not missing, f"actions with no TITLES entry: {missing}"


def test_every_action_is_supported_by_some_backend():
    orphans = ACTION_NAMES - _BACKEND_SUPPORT
    assert not orphans, f"actions no backend supports: {orphans}"


def test_backend_support_sets_only_name_real_actions():
    for backend in (ArchBackend, DebianBackend):
        stray = backend.supported - ACTION_NAMES
        assert not stray, f"{backend.name} lists unknown actions: {stray}"


def test_default_and_remote_sets_are_valid_actions():
    assert set(DEFAULT_ACTIONS) <= ACTION_NAMES
    assert set(REMOTE_DEFAULT_ACTIONS) <= ACTION_NAMES
    assert set(ALL_ACTIONS) <= ACTION_NAMES


def test_retired_names_are_gone_everywhere():
    surfaces = ACTION_NAMES | set(HANDLERS) | set(TITLES) | _BACKEND_SUPPORT \
        | set(DEFAULT_ACTIONS) | set(ALL_ACTIONS) | set(REMOTE_DEFAULT_ACTIONS)
    lingering = _RETIRED & surfaces
    assert not lingering, f"retired action names still present: {lingering}"
