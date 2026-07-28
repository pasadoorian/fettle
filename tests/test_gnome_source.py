"""GNOME Shell extension provider — attribution of extension code."""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import UNOFFICIAL_SOURCE, UNVERIFIABLE, Severity
from fettle.supplychain.gnome_source import GnomeSource, parse_details

_HOME = "/home/tester"

# Real `gnome-extensions list --details` shape. Note the Description of the second
# extension WRAPS onto a line with NO leading whitespace — parsing must not treat
# that as the start of a new extension.
_DETAILS = """\
appindicatorsupport@rgcjonas.gmail.com
  Name: AppIndicator Support
  Description: Adds AppIndicator support
  Path: /usr/share/gnome-shell/extensions/appindicatorsupport@rgcjonas.gmail.com
  Enabled: Yes
  State: ACTIVE

apps-menu@gnome-shell-extensions.gcampax.github.com
  Name: Apps Menu
  Description: Add a category-based menu for apps.
This extension is part of Classic Mode: do not report bugs here, use GitLab instead.
  Path: /usr/share/gnome-shell/extensions/apps-menu@gnome-shell-extensions.gcampax.github.com
  Enabled: No
  State: INACTIVE

sketchy@example.com
  Name: Sketchy
  Description: hand installed
  Path: /home/tester/.local/share/gnome-shell/extensions/sketchy@example.com
  Enabled: Yes
  State: ACTIVE
"""

_UUIDS = ("appindicatorsupport@rgcjonas.gmail.com\n"
          "apps-menu@gnome-shell-extensions.gcampax.github.com\n"
          "sketchy@example.com\n")


def _ctx():
    return Context(output=Output(color=False), config=Config(),
                   user_home=Path(_HOME))


def _run(*, uuids=_UUIDS, details=_DETAILS, list_rc=0, owned=True, pm="pacman"):
    def fake_run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:2] == ["gnome-extensions", "list"]:
            if "--details" in c:
                return command.Proc(0, details, "")
            return command.Proc(list_rc, uuids, "no shell" if list_rc else "")
        if c[0] in ("pacman", "dpkg"):
            return command.Proc(0 if owned else 1, "", "")
        return command.Proc(0, "", "")

    tools = {"gnome-extensions"} | ({pm} if pm else set())
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n in tools):
        return GnomeSource().findings(_ctx())


# -- parsing -----------------------------------------------------------------
def test_wrapped_description_does_not_swallow_the_next_extension():
    """The continuation line has no leading whitespace; keying block starts off
    indentation would merge apps-menu's neighbour into its description."""
    d = parse_details(_DETAILS, _UUIDS.split())
    assert set(d) == set(_UUIDS.split())
    assert d["apps-menu@gnome-shell-extensions.gcampax.github.com"]["Enabled"] == "No"
    assert d["sketchy@example.com"]["Path"].startswith("/home/tester")


# -- attribution -------------------------------------------------------------
def test_hand_installed_enabled_extension_is_flagged():
    f = _run()
    hits = [x for x in f if x.package == "sketchy@example.com"]
    assert len(hits) == 1
    assert hits[0].question == UNOFFICIAL_SOURCE and hits[0].severity == Severity.WARN
    assert "ENABLED" in hits[0].detail and "gnome-shell process" in hits[0].detail


def test_packaged_extensions_are_not_flagged():
    assert {x.package for x in _run()} == {"sketchy@example.com"}


def test_disabled_unattributed_extension_is_lower_severity():
    details = _DETAILS.replace("""  Path: /home/tester/.local/share/gnome-shell/extensions/sketchy@example.com
  Enabled: Yes""",
                               """  Path: /home/tester/.local/share/gnome-shell/extensions/sketchy@example.com
  Enabled: No""")
    hits = [x for x in _run(details=details) if x.package == "sketchy@example.com"]
    assert hits[0].severity == Severity.LOW and "disabled" in hits[0].detail


def test_system_path_owned_by_no_package_is_flagged():
    """Placed under /usr/share by hand as root — stranger than a home install."""
    f = _run(owned=False)
    assert {x.package for x in f} == {
        "appindicatorsupport@rgcjonas.gmail.com",
        "apps-menu@gnome-shell-extensions.gcampax.github.com",
        "sketchy@example.com"}
    sys_hit = [x for x in f if x.package.startswith("appindicator")][0]
    assert "owned by no package" in sys_hit.detail


def test_no_package_manager_means_no_claim_about_system_paths():
    """"No package owns it" and "I could not ask" are different; only the home-dir
    extension can be judged without a package manager."""
    assert {x.package for x in _run(pm=None)} == {"sketchy@example.com"}


# -- failure path ------------------------------------------------------------
def test_listing_failure_reports_instead_of_returning_clean():
    f = _run(list_rc=1)
    assert len(f) == 1 and f[0].question == UNVERIFIABLE
    assert "NOT audited" in f[0].detail


def test_no_extensions_yields_nothing():
    assert _run(uuids="", details="") == []


def test_absent_tool_is_not_present():
    with patch("fettle.command.which", side_effect=lambda n: False):
        assert GnomeSource().is_present(_ctx()) is False
