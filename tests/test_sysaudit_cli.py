"""sys-audit CLI — category selection, --list, --all, dispatch, error handling."""

from unittest.mock import patch

from fettle.cli import main as cli_main
from fettle.secure import audit


def test_list_categories(capsys):
    rc = audit.main(["--list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "secureboot" in out and "microcode" in out and "storage" in out


def test_unknown_category_errors(capsys):
    rc = audit.main(["bogus"])
    assert rc == 1
    assert "unknown check" in capsys.readouterr().err


def test_no_categories_is_a_noop(capsys):
    rc = audit.main([])
    assert rc == 0
    assert "nothing to check" in capsys.readouterr().err


def test_all_dispatches_every_category():
    seen = []
    fakes = {cat: (lambda scan, c=cat: seen.append(c)) for cat in audit.CATEGORIES}
    with patch("fettle.secure.audit._registry", return_value=fakes):
        audit.main(["--all"])
    assert seen == list(audit.CATEGORIES)  # all, in order


def test_intel_me_hyphen_category_dispatches():
    seen = []
    fakes = {cat: (lambda scan, c=cat: seen.append(c)) for cat in audit.CATEGORIES}
    with patch("fettle.secure.audit._registry", return_value=fakes):
        audit.main(["intel-me"])
    assert seen == ["intel-me"]


def test_cli_routes_sys_audit_subcommand(capsys):
    # `fettle sys-audit --list` is intercepted before the maintenance parser.
    rc = cli_main(["sys-audit", "--list"])
    assert rc == 0
    assert "Available check categories" in capsys.readouterr().out


# -- self-elevation (so `fettle sys-audit` works without typing `sudo fettle`) --
def test_sys_audit_self_elevates_when_not_root():
    with patch("fettle.cli._is_root", return_value=False), \
         patch("fettle.cli._in_test", return_value=False), \
         patch("fettle.cli._reexec_with_sudo") as reexec, \
         patch("fettle.secure.audit.run"):
        audit.main(["microcode"])
    reexec.assert_called_once()  # re-execs under sudo via the full module path


def test_sys_audit_user_flag_skips_elevation():
    with patch("fettle.cli._is_root", return_value=False), \
         patch("fettle.cli._in_test", return_value=False), \
         patch("fettle.cli._reexec_with_sudo") as reexec, \
         patch("fettle.secure.audit.run") as run:
        audit.main(["--user", "microcode"])
    reexec.assert_not_called()
    run.assert_called_once()


def test_sys_audit_no_elevation_when_already_root():
    with patch("fettle.cli._is_root", return_value=True), \
         patch("fettle.cli._in_test", return_value=False), \
         patch("fettle.cli._reexec_with_sudo") as reexec, \
         patch("fettle.secure.audit.run"):
        audit.main(["microcode"])
    reexec.assert_not_called()


def test_sys_audit_list_does_not_elevate(capsys):
    with patch("fettle.cli._is_root", return_value=False), \
         patch("fettle.cli._in_test", return_value=False), \
         patch("fettle.cli._reexec_with_sudo") as reexec:
        audit.main(["--list"])
    reexec.assert_not_called()  # --list is informational, never elevates
