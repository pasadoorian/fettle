"""GNOME Shell extension provider — attribution of extension code."""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import (
    STALE_OR_ABANDONED,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
    Severity,
)
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
    # `sudo_user` is what the extension listing drops back to: the audits self-elevate,
    # and the extension list lives in that user's session, not root's.
    return Context(output=Output(color=False), config=Config(),
                   sudo_user="paul", user_home=Path(_HOME))


def _scan(tools, responses):
    """(unused scan, run-patch, which-patch) — the `_run` plumbing, without the call,
    so a test can inspect the provider instance afterwards."""
    def fake_run(cmd, *, as_user=None, capture=False, session=False):
        val = responses.get(tuple(cmd), "")
        text, rc = val if isinstance(val, tuple) else (val, 0)
        return command.Proc(rc, text, "")
    return None, patch("fettle.command.run", side_effect=fake_run), \
        patch("fettle.command.which", side_effect=lambda n: n in tools)


def _run(*, uuids=_UUIDS, details=_DETAILS, list_rc=0, owned=True, pm="pacman",
         upstream=True, calls=None):
    def fake_run(cmd, *, as_user=None, capture=False, session=False):
        c = list(cmd)
        if calls is not None:
            calls.append({"argv": c, "as_user": as_user, "session": session})
        if c[:2] == ["gnome-extensions", "list"]:
            if "--details" in c:
                return command.Proc(0, details, "")
            return command.Proc(list_rc, uuids, "no shell" if list_rc else "")
        if c[0] in ("pacman", "dpkg"):
            return command.Proc(0 if owned else 1, "", "")
        return command.Proc(0, "", "")

    tools = {"gnome-extensions"} | ({pm} if pm else set())
    # Patched by default so the suite never touches the network — without this every
    # test uuid 404s on e.g.o for real and reads as de-listed.
    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.supplychain.gnome_source.still_upstream_url",
               return_value=upstream), \
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
    assert hits[0].question == UNOFFICIAL_SOURCE and hits[0].severity == Severity.MEDIUM
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


# -- the extension list belongs to a session, not to the machine --------------
def test_the_listing_drops_back_to_the_user_and_restores_their_session():
    """The bug this guards, live for a week across four runs: `-P` self-elevates, so
    `gnome-extensions` ran as root against no session bus and exited 2 — every run
    reporting `extensions were NOT audited` on a desktop with 24 of them working.

    Both halves are required. `as_user` alone is not enough: `sudo -u` resets the
    environment too, so the child still has no bus address."""
    calls = []
    _run(calls=calls)
    listings = [c for c in calls if c["argv"][:2] == ["gnome-extensions", "list"]]
    assert listings, "the extension list was never requested"
    for c in listings:
        assert c["as_user"] == "paul", f"ran as root: {c['argv']}"
        assert c["session"] is True, f"no session bus restored: {c['argv']}"


def test_the_package_manager_query_stays_as_root():
    """`pacman -Qo` reads a root-owned database and wants no session — dropping
    privileges for it would be pointless work, and the guard against a fix applied
    with too broad a brush."""
    calls = []
    _run(calls=calls)
    for c in [c for c in calls if c["argv"][0] in ("pacman", "dpkg")]:
        assert c["as_user"] is None and c["session"] is False


def test_a_failed_listing_says_when_the_reason_is_a_missing_session():
    import fettle.supplychain.gnome_source as gs
    with patch("os.geteuid", return_value=0), \
         patch("fettle.command.session_available", return_value=False):
        f = _run(list_rc=2)
    assert "no active login session" in f[0].detail
    assert gs  # module referenced so the patch target is unambiguous


def test_a_failed_listing_with_a_live_session_does_not_blame_the_session():
    """It would be worse to explain a real failure with a wrong cause."""
    with patch("os.geteuid", return_value=0), \
         patch("fettle.command.session_available", return_value=True):
        f = _run(list_rc=2)
    assert "no active login session" not in f[0].detail
    assert "NOT audited" in f[0].detail


def test_no_extensions_yields_nothing():
    assert _run(uuids="", details="") == []


def test_absent_tool_is_not_present():
    with patch("fettle.command.which", side_effect=lambda n: False):
        assert GnomeSource().is_present(_ctx()) is False


# -- is it still listed on e.g.o? ---------------------------------------------
def test_delisted_extension_is_reported():
    """e.g.o de-lists for malware as well as for policy, and an enabled extension runs
    inside gnome-shell with the whole session's privileges."""
    f = _run(owned=False, upstream=False)
    w = [x for x in f if x.question == STALE_OR_ABANDONED]
    assert w and "no longer listed on extensions.gnome.org" in w[0].detail


def test_unreachable_ego_is_not_a_delisting():
    f = _run(owned=False, upstream=None)
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]
    assert [x for x in f if x.question == UNVERIFIABLE]


def test_packaged_extension_is_never_asked_about():
    """Plenty of extensions that ship in a distro package were never on e.g.o at all,
    so asking would report them de-listed on every run."""
    seen = []
    with patch("fettle.supplychain.gnome_source.still_upstream_url",
               side_effect=lambda u, **k: seen.append(u) or True):
        _run(owned=True)
    assert seen == []


# -- M1/M2: what was examined, and what is enabled ---------------------------
def test_the_provider_records_what_it_examined():
    """A provider that examined 24 extensions and cleared every one used to render
    identically to one that never ran: its coverage sentence, and nothing else."""
    src = GnomeSource()
    scan, p_run, p_which = _scan({"gnome-extensions", "pacman"},
                                 {("gnome-extensions", "list"): _UUIDS,
                                  ("gnome-extensions", "list", "--details"): _DETAILS})
    with p_run, p_which, patch(
            "fettle.supplychain.gnome_source.still_upstream_url", return_value=True):
        src.findings(_ctx())
    assert src.examined is not None
    assert src.examined.count == len(_UUIDS.split())
    assert src.examined.unit == "extensions"
    assert "enabled" in src.examined.detail


def test_nothing_installed_is_recorded_as_examined_zero():
    """`Examined(0)` is not `Examined(24, all clean)` and must not read like it."""
    src = GnomeSource()
    scan, p_run, p_which = _scan({"gnome-extensions", "pacman"},
                                 {("gnome-extensions", "list"): ""})
    with p_run, p_which:
        src.findings(_ctx())
    assert src.examined is not None and src.examined.count == 0


def test_a_failed_listing_records_no_examination_at_all():
    """Could-not-look must not be recorded as examined-zero — that would turn the
    blind case into the empty case, which is the whole bug this project is about."""
    src = GnomeSource()
    scan, p_run, p_which = _scan({"gnome-extensions", "pacman"},
                                 {("gnome-extensions", "list"): ("", 2)})
    with p_run, p_which:
        f = src.findings(_ctx())
    assert src.examined is None
    assert f and f[0].question == UNVERIFIABLE


def test_enabled_extensions_are_listed_even_when_all_are_packaged():
    """The provider's own trust model is that extension code runs inside gnome-shell
    with full session privileges. On a machine where everything is distro-packaged it
    had that list in hand and said nothing."""
    src = GnomeSource()
    scan, p_run, p_which = _scan({"gnome-extensions", "pacman"},
                                 {("gnome-extensions", "list"): _UUIDS,
                                  ("gnome-extensions", "list", "--details"): _DETAILS})
    with p_run, p_which, patch(
            "fettle.supplychain.gnome_source.still_upstream_url", return_value=True):
        src.findings(_ctx())
    rows = getattr(src, "detail_rows", [])
    assert rows and "enabled and running inside gnome-shell" in rows[0]


def test_the_enabled_list_is_not_a_finding():
    """Findings drive the count and the summary mark, so an informational one would
    turn every GNOME desktop into `N supply-chain finding(s)` with a warn beside it."""
    src = GnomeSource()
    scan, p_run, p_which = _scan({"gnome-extensions", "pacman"},
                                 {("gnome-extensions", "list"): _UUIDS,
                                  ("gnome-extensions", "list", "--details"): _DETAILS})
    with p_run, p_which, patch(
            "fettle.supplychain.gnome_source.still_upstream_url", return_value=True):
        f = src.findings(_ctx())
    assert not any("enabled and running" in x.detail for x in f)
