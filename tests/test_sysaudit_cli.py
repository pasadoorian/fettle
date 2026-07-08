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
