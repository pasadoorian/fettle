"""The TLS certificate expiry axis.

The design question here is *which* certificates to look at, and the tests guard the
answer harder than they guard the arithmetic. `/etc/ssl/certs` on the reference machine
is 121 root CAs symlinked out of the ca-certificates bundle. Some of them expire; that
is normal, no local action fixes it, and an axis that reported them would produce dozens
of findings nobody can act on.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening.axes import HIGH, MEDIUM, certs
from fettle.output import Output

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)


def _ctx(root: Path, **cfg) -> Context:
    return Context(output=Output(color=False), config=Config(**cfg), root=root,
                   user_home=root)


def _openssl(expiries: dict[str, str]):
    """Stub openssl. ``expiries`` maps a file name to its raw `notAfter` value, or to
    the literal "ERROR:<text>" to simulate a failure."""
    def run(cmd, *, as_user=None, capture=False, timeout=None):
        argv = list(cmd)
        if argv[:2] != ["openssl", "x509"]:
            return command.Proc(0, "", "")
        path = Path(argv[argv.index("-in") + 1])
        value = expiries.get(path.name)
        if value is None:
            return command.Proc(1, "", "unable to load certificate")
        if value.startswith("ERROR:"):
            return command.Proc(1, "", value[len("ERROR:"):])
        return command.Proc(0, f"notAfter={value}\nsubject=CN=example.test\n", "")
    return run


def _findings(names_to_expiry, *, warn_days=30):
    paths = [Path("/etc/nginx") / n for n in names_to_expiry]
    with patch("fettle.command.run", side_effect=_openssl(names_to_expiry)):
        return certs.findings_for(paths, NOW, warn_days)


# -- what counts as a finding ----------------------------------------------

def test_an_expired_certificate_is_high():
    found, _ = _findings({"site.pem": "Aug  1 00:00:00 2026 GMT"})
    assert len(found) == 1
    assert found[0].check == "cert-expired"
    assert found[0].severity == HIGH
    assert "expired 5 day(s) ago" in found[0].detail
    assert "CN=example.test" in found[0].detail


def test_a_certificate_expiring_inside_the_window_is_medium():
    soon = (NOW + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    found, _ = _findings({"site.pem": soon})
    assert found[0].check == "cert-expiring"
    assert found[0].severity == MEDIUM
    assert "expires in 10 day(s)" in found[0].detail


def test_a_certificate_beyond_the_window_is_silent():
    far = (NOW + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    found, _ = _findings({"site.pem": far})
    assert found == []


def test_the_warning_window_is_configurable():
    at_60 = (NOW + timedelta(days=60)).strftime("%b %d %H:%M:%S %Y GMT")
    assert _findings({"site.pem": at_60})[0] == []
    assert _findings({"site.pem": at_60}, warn_days=90)[0] != []


def test_a_single_digit_day_parses():
    """openssl pads with two spaces: `notAfter=Aug  1 00:00:00 2047 GMT`."""
    when, _, err = None, "", ""
    with patch("fettle.command.run",
               side_effect=_openssl({"x.pem": "Aug  1 00:00:00 2047 GMT"})):
        when, _, err = certs.not_after(Path("/etc/nginx/x.pem"))
    assert err == ""
    assert when == datetime(2047, 8, 1, tzinfo=timezone.utc)


# -- what is silence, and what is blindness --------------------------------

def test_a_file_that_is_not_a_certificate_is_skipped_silently():
    """httpd.conf sitting beside a .pem is not a defect and not a blind spot."""
    found, unreadable = _findings({"notacert.pem": "ERROR:unable to load certificate"})
    assert found == [] and unreadable == []


def test_a_file_that_cannot_be_read_is_blindness():
    """Private-key directories need root. "Could not open" must never become "fine" —
    the same distinction as everywhere else in this audit."""
    found, unreadable = _findings(
        {"server.pem": "ERROR:Could not open file or uri for loading certificate"})
    assert found == []
    assert unreadable == ["/etc/nginx/server.pem"]


def test_no_openssl_is_blind_with_an_install_hint(tmp_path):
    with patch("fettle.command.which", return_value=False):
        res = certs.run(None, _ctx(tmp_path))
    assert res.findings == []
    assert res.blind[0][2] == "openssl"          # so the install command is generated
    assert "cannot be parsed with the standard library" in res.blind[0][1]


# -- which directories --------------------------------------------------------

def _tree(root: Path, files) -> Path:
    for rel in files:
        p = root / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("-----BEGIN CERTIFICATE-----\n")
    return root


def test_the_ca_trust_store_is_never_scanned(tmp_path):
    """121 root CAs on the reference machine, several legitimately expired. No local
    action fixes them and update-ca-certificates already handles it."""
    root = _tree(tmp_path, ["/etc/ssl/certs/GlobalSign_Root.pem",
                            "/etc/ca-certificates/extracted/bundle.pem"])
    found, _ = certs.find_certificates(root, list(certs.DEFAULT_PATHS)
                                       + ["/etc/ssl/certs", "/etc/ca-certificates"])
    assert found == []


def test_adding_a_trust_store_by_hand_is_refused_and_said_out_loud(tmp_path):
    """Refused rather than honoured — but never silently, or the user is left believing
    a directory is being watched when it is not."""
    root = _tree(tmp_path, ["/etc/ssl/certs/root.pem", "/etc/nginx/site.pem"])
    with patch("fettle.command.which", return_value=True), \
         patch("fettle.command.run",
               side_effect=_openssl({"site.pem": "Aug  1 00:00:00 2047 GMT"})):
        res = certs.run(None, _ctx(root, hardening={
            "certificate_paths": ["/etc/ssl/certs"]}))

    assert res.checked == 1                       # only the nginx one
    assert "not scanned: /etc/ssl/certs" in " ".join(res.notes)
    assert "packaging system's business" in " ".join(res.notes)


def test_service_certificates_are_found_a_few_levels_deep(tmp_path):
    """/etc/letsencrypt/live/<domain>/fullchain.pem is the shape that matters."""
    root = _tree(tmp_path, ["/etc/letsencrypt/live/example.test/fullchain.pem",
                            "/etc/nginx/tls/site.crt"])
    found, capped = certs.find_certificates(root, list(certs.DEFAULT_PATHS))
    assert {p.name for p in found} == {"fullchain.pem", "site.crt"}
    assert capped is False


def test_files_that_do_not_look_like_certificates_are_not_opened(tmp_path):
    """Saves running openssl on httpd.conf and mime.types, which are what actually sit
    in /etc/httpd on the reference machine."""
    root = _tree(tmp_path, ["/etc/httpd/httpd.conf", "/etc/httpd/mime.types"])
    found, _ = certs.find_certificates(root, list(certs.DEFAULT_PATHS))
    assert found == []


def test_no_certificates_anywhere_is_not_applicable(tmp_path):
    """The ordinary answer on a workstation — and a different statement from "they are
    all fine"."""
    with patch("fettle.command.which", return_value=True):
        res = certs.run(None, _ctx(tmp_path))
    assert res.na.startswith("no service certificates were found")
    assert res.findings == [] and res.blind == []
