"""Every `✗` line must say WHICH kind of bad news it is.

One channel on screen, three different situations behind it:

    failed   the action could not do its job       -> something is broken, go look
    blind    the check could not look              -> you have a blind spot, and the
                                                      all-clear you just got is not one
    found    the check looked and found something  -> the tool worked; go fix the thing

They call for opposite responses from the reader, and until they were labelled the exit
status could not tell them apart — which is why a fourteen-action sweep had to choose
between being red on every real machine and treating "could not look" as success.
"""

import ast
import pathlib

from fettle.output import BLIND, FAILED, FOUND, Output

SRC = pathlib.Path(__file__).resolve().parent.parent / "fettle"


def _call_sites():
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "summary_fail"):
                yield path.relative_to(SRC.parent), node


def test_every_failure_declares_its_kind():
    """The guard. A new `✗` that does not say which kind it is defaults to `failed`,
    which is the safe direction but makes the exit code wrong for a finding — so it has
    to be a deliberate choice at every call site, not an omission."""
    missing = [f"{p}:{n.lineno}" for p, n in _call_sites()
               if not any(k.arg == "kind" for k in n.keywords)]
    assert not missing, "summary_fail() without kind=: " + ", ".join(missing)


def test_every_kind_used_is_a_real_one():
    named = {k.value.id for _, n in _call_sites() for k in n.keywords
             if k.arg == "kind" and isinstance(k.value, ast.Name)}
    assert named <= {"FAILED", "BLIND", "FOUND"}, named


def test_all_three_kinds_are_actually_in_use():
    """If a kind has no call sites the classification is not describing reality."""
    named = {k.value.id for _, n in _call_sites() for k in n.keywords
             if k.arg == "kind" and isinstance(k.value, ast.Name)}
    assert named == {"FAILED", "BLIND", "FOUND"}, named


# -- the recording itself ------------------------------------------------------
def test_kind_is_recorded_and_queryable():
    out = Output(color=False)
    out.summary_fail("update did not complete", kind=FAILED)
    out.summary_fail("could not reach the advisory feed", kind=BLIND)
    out.summary_fail("3 packages have known CVEs", kind=FOUND)
    assert out.failures_of(FAILED) == ["update did not complete"]
    assert out.failures_of(BLIND) == ["could not reach the advisory feed"]
    assert out.failures_of(FAILED, BLIND) == ["update did not complete",
                                              "could not reach the advisory feed"]


def test_default_kind_is_the_strict_one():
    """An unlabelled failure must fail every rule, not slip through the loosest one."""
    out = Output(color=False)
    out.summary_fail("something")
    assert out.failures_of(FAILED) == ["something"]


def test_classification_changes_nothing_that_prints(capsys):
    """This milestone is deliberately inert: same three lines, same marks, same order."""
    out = Output(color=False)
    out.summary_fail("a", kind=FAILED)
    out.summary_fail("b", kind=BLIND)
    out.summary_fail("c", kind=FOUND)
    out.print_summary()
    printed = [ln.strip() for ln in capsys.readouterr().out.splitlines()
               if ln.strip().startswith("✗")]
    assert printed == ["✗ a", "✗ b", "✗ c"]


def test_exit_status_is_still_blind_to_kind():
    """X1 only labels. Every exit code stays exactly what it was, so the change is
    provably inert; X2 is where the status starts branching on this."""
    for kind in (FAILED, BLIND, FOUND):
        out = Output(color=False)
        out.summary_fail("x", kind=kind)
        assert out.had_failures is True


# -- X1a: the roll-ups that mixed "found" with "could not look" -----------------
#
# pkg-integrity and sys-audit each built ONE summary line from every record they marked
# as an error — and that bucket is not homogeneous. "The rpm database could not be
# queried" and "10 files have changed contents" are opposite news reported identically,
# and once the exit status reads these labels, calling the first one a finding would let
# a sweep pass on a host that was never actually audited.

def test_pkg_integrity_separates_could_not_look_from_found():
    from fettle import integrity
    from fettle.backends.base import Context
    from fettle.config import Config

    recs = [
        {"category": "c", "sub": "s", "label": "rpm", "value": "Not installed",
         "level": "error", "blind": True},
        {"category": "c", "sub": "s", "label": "Package Integrity",
         "value": "2 files changed", "level": "error", "blind": False},
    ]

    class FakeBackend:
        name = "fake"

        def verify_integrity(self, scan):
            scan.records.extend(recs)

    ctx = Context(output=Output(color=False), config=Config())
    integrity.run(FakeBackend(), ctx)
    out = ctx.output
    assert out.failures_of(BLIND) == ["pkg-integrity did NOT verify: rpm: Not installed"]
    assert out.failures_of(FOUND) == ["pkg-integrity: Package Integrity: 2 files changed"]


def test_sys_audit_separates_could_not_look_from_found():
    from fettle.output import Output as O
    from fettle.secure import audit
    from fettle.secure.base import Scan

    scan = Scan(output=O(color=False))
    scan.section("Secure Boot")
    scan.status("Secure Boot", "UNKNOWN — mokutil failed (exit 2)", "error", blind=True)
    scan.status("Setup Mode", "Enabled — anyone can enrol keys", "error")
    audit._summarize(scan)

    blind = scan.output.failures_of(BLIND)
    found = scan.output.failures_of(FOUND)
    assert blind and "could NOT run" in blind[0], blind
    assert found and "finding(s) needing attention" in found[0], found


def test_a_wholly_blind_scan_is_not_reported_as_nothing_flagged():
    """The failure this guards: every check unable to run, and the summary saying
    "nothing flagged" — a clean bill of health from an audit that never happened."""
    from fettle.output import Output as O
    from fettle.secure import audit
    from fettle.secure.base import Scan

    scan = Scan(output=O(color=False))
    scan.section("Firmware")
    scan.status("chipsec", "UNKNOWN — chipsec failed (exit 1)", "error", blind=True)
    audit._summarize(scan)
    assert not [ln for ln in scan.output._summary if "nothing flagged" in ln]
    assert scan.output.failures_of(BLIND)


# -- "Not checked": how much of the machine did you actually see? ---------------
#
# A summary of what WAS found cannot answer that. A short list of ticks reads identically
# whether nine checks passed or one passed and eight never ran. Paul's call on X2 was to
# leave the exit code alone and make the gap impossible to miss instead.

def test_not_checked_block_lists_what_was_skipped_and_how_to_fix_it(capsys):
    from unittest.mock import patch

    out = Output(color=False)
    out.summary_add("everything else was fine")
    out.not_checked("storage device firmware", "smartctl is not installed",
                    "smartmontools")
    with patch("fettle.command.which", side_effect=lambda n: n == "pacman"):
        out.print_summary()
    text = capsys.readouterr().out
    assert "Not checked" in text
    assert "storage device firmware — smartctl is not installed" in text
    assert "install: sudo pacman -S smartmontools" in text


def test_install_hint_matches_the_package_manager_present():
    from unittest.mock import patch

    from fettle.util import install_hint

    for tool, expected in (("pacman", "sudo pacman -S inxi"),
                           ("apt-get", "sudo apt install inxi"),
                           ("dnf", "sudo dnf install inxi")):
        with patch("fettle.command.which", side_effect=lambda n, t=tool: n == t):
            assert install_hint("inxi") == expected


def test_no_install_hint_when_no_known_package_manager():
    """A confidently wrong install command is worse than none: it sends someone to a
    shell to be told the tool does not exist, and they conclude fettle is broken."""
    from unittest.mock import patch

    from fettle.util import install_hint

    with patch("fettle.command.which", return_value=False):
        assert install_hint("inxi") == ""


def test_no_block_when_everything_was_checked(capsys):
    out = Output(color=False)
    out.summary_add("all good")
    out.print_summary()
    assert "Not checked" not in capsys.readouterr().out


def test_chipsec_unsupported_platform_says_why(capsys):
    """Paul asked specifically for this: not just that chipsec could not run, but that
    the reason is an unsupported CPU rather than something he can fix."""
    from fettle.output import Output as O
    from fettle.secure import checks
    from fettle.secure.base import Scan

    scan = Scan(output=O(color=False))
    scan.section("Firmware")
    with_unknown = "Unsupported Platform\nUnknown Platform: results may be incorrect"
    scan.run_text_rc = lambda cmd, **kw: (with_unknown, 32)
    checks._chipsec_cmd = lambda s: ["chipsec_main"]
    scan.is_root = lambda: True
    checks.firmware(scan)
    scan.output.print_summary()
    text = capsys.readouterr().out
    assert "not supported by chipsec" in text, text
