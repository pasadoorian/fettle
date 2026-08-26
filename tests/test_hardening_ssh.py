"""The SSH effective-configuration axis.

This axis exists because of one specific failure mode, and the tests are built around
it. Lynis greps `sshd_config` and prints twenty-two "OpenSSH option: X [ NOT FOUND ]"
lines on the reference machine — where the file is three lines long and *everything* is
at an OpenSSH default that is already safe. Twenty-two finding-shaped lines conveying
nothing about exposure, because the question was asked of the file rather than of the
server.

So the load-bearing test is `test_a_stock_openssh_is_almost_entirely_silent`, built
from the real `sshd -T` output of an unmodified Debian 13.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.hardening.axes import HIGH, LOW, MEDIUM, ssh
from fettle.output import Output

# Verified verbatim against `sshd -T` in a stock debian:13 container. Everything here
# is an OpenSSH default that nobody touched.
STOCK = {
    "port": "22", "logingracetime": "120", "maxauthtries": "6",
    "permitrootlogin": "without-password", "ignorerhosts": "yes",
    "hostbasedauthentication": "no", "passwordauthentication": "yes",
    "x11forwarding": "yes", "permitemptypasswords": "no", "gatewayports": "no",
    "permittunnel": "no",
    "ciphers": "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,"
               "aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr",
    # hmac-sha1 IS a stock default — a "modern crypto" deny-list containing it would
    # fire on every unmodified host, which is the failure this axis exists to avoid.
    "macs": "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
            "hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha1",
    "kexalgorithms": "mlkem768x25519-sha256,curve25519-sha256,ecdh-sha2-nistp256",
}


def _ctx() -> Context:
    return Context(output=Output(color=False), config=Config(),
                   user_home=Path("/home/paul"))


def _checks(findings) -> set[str]:
    return {f.check for f in findings}


def _sev(findings, check) -> str:
    return next(f.severity for f in findings if f.check == check)


# -- judging an effective config -------------------------------------------

def test_a_stock_openssh_is_almost_entirely_silent():
    """Nothing an unmodified install does is a defect, beyond two low notes that are
    genuine exposure rather than misconfiguration."""
    found = ssh.findings_for(STOCK)

    assert _checks(found) == {"ssh-password-auth", "ssh-x11"}
    assert all(f.severity == LOW for f in found)


def test_stock_defaults_never_trip_the_weak_algorithm_lists():
    """Guards the deny-lists against drifting into a modern-crypto wishlist. hmac-sha1
    and aes*-ctr are shipped defaults; flagging them would fire everywhere."""
    found = ssh.findings_for(STOCK)
    assert not any(f.check.startswith("ssh-weak-") for f in found)


def test_root_password_login_is_the_worst_case_and_is_reported_once():
    """The combination is the finding. `PermitRootLogin yes` with keys only is a policy
    choice; with password auth the account that matters is reachable by guessing."""
    found = ssh.findings_for({**STOCK, "permitrootlogin": "yes",
                              "passwordauthentication": "yes"})

    assert "ssh-root-password-login" in _checks(found)
    assert _sev(found, "ssh-root-password-login") == HIGH
    # not also reported as the milder root finding, nor as bare password auth
    assert "ssh-root-login" not in _checks(found)
    assert "ssh-password-auth" not in _checks(found)


def test_root_login_with_keys_only_is_milder():
    found = ssh.findings_for({**STOCK, "permitrootlogin": "yes",
                              "passwordauthentication": "no"})
    assert _sev(found, "ssh-root-login") == MEDIUM
    assert "ssh-root-password-login" not in _checks(found)


def test_prohibit_password_is_not_a_finding():
    """The modern default. Lynis reports PermitRootLogin as "NOT FOUND" here and says
    nothing about what is actually in effect."""
    for safe in ("prohibit-password", "without-password", "no", "forced-commands-only"):
        found = ssh.findings_for({**STOCK, "permitrootlogin": safe,
                                  "passwordauthentication": "no"})
        assert not any(c.startswith("ssh-root") for c in _checks(found)), safe


def test_empty_passwords_are_high():
    found = ssh.findings_for({**STOCK, "permitemptypasswords": "yes"})
    assert _sev(found, "ssh-empty-passwords") == HIGH


def test_deliberately_weakened_ciphers_are_reported_without_the_strong_ones():
    """Verified live: appending `Ciphers 3des-cbc,aes256-ctr` produces one finding
    naming only 3des-cbc."""
    found = ssh.findings_for({**STOCK, "ciphers": "3des-cbc,aes256-ctr"})
    weak = [f for f in found if f.check == "ssh-weak-ciphers"]

    assert len(weak) == 1
    assert "3des-cbc" in weak[0].detail
    assert "aes256-ctr" not in weak[0].detail
    assert weak[0].severity == MEDIUM


def test_maxauthtries_only_fires_above_the_default():
    assert "ssh-maxauthtries" not in _checks(ssh.findings_for(STOCK))
    assert "ssh-maxauthtries" in _checks(
        ssh.findings_for({**STOCK, "maxauthtries": "20"}))
    # a non-numeric value must not crash the axis
    assert "ssh-maxauthtries" not in _checks(
        ssh.findings_for({**STOCK, "maxauthtries": "unset"}))


def test_hostbased_rhosts_and_gatewayports():
    found = ssh.findings_for({**STOCK, "hostbasedauthentication": "yes",
                              "ignorerhosts": "no", "gatewayports": "clientspecified"})
    assert {"ssh-hostbased-auth", "ssh-rhosts", "ssh-gatewayports"} <= _checks(found)


# -- reading the config ----------------------------------------------------

def _run(*, rc=0, stdout="", stderr="", have_sshd=True, active=True):
    def which(name):
        return name == "sshd" and have_sshd or name == "systemctl"

    def run(cmd, *, as_user=None, capture=False, timeout=None):
        argv = list(cmd)
        if argv[:2] == ["systemctl", "is-active"]:
            return command.Proc(0 if active else 3, "", "")
        if argv[0] == "sshd" and "-T" in argv:
            return command.Proc(rc, stdout, stderr)
        return command.Proc(0, "", "")

    with patch("fettle.command.which", side_effect=which), \
         patch("fettle.command.run", side_effect=run), \
         patch("pathlib.Path.exists", return_value=False):
        return ssh.run(None, _ctx())


def test_no_ssh_server_is_not_applicable_rather_than_blind():
    """No server, no exposure. Sending the reader off to install an SSH server so it
    can be audited would be an absurd remedy."""
    res = _run(have_sshd=False)
    assert res.na == "no SSH server is installed"
    assert res.blind == [] and res.findings == []


def test_unprivileged_is_blind_with_the_reason_not_a_guess():
    """Verified live: `sshd -T` as a non-root user exits with exactly this. fettle must
    NOT fall back to parsing sshd_config against a built-in table of defaults — that
    table drifts with every OpenSSH release, and being confidently wrong about
    PermitRootLogin is worse than saying nothing."""
    res = _run(rc=1, stderr="sshd: no hostkeys available -- exiting.")

    assert res.findings == []
    assert res.checked == 0
    what, why, _ = res.blind[0]
    assert "NOT checked" in what
    assert "needs root" in why and "sudo" in why


def test_a_real_config_error_is_reported_as_itself_not_as_needing_root():
    res = _run(rc=1, stderr="/etc/ssh/sshd_config: line 4: Bad configuration option")
    assert "Bad configuration option" in res.blind[0][1]
    assert "needs root" not in res.blind[0][1]


def test_an_installed_but_stopped_sshd_says_so():
    """Worth auditing — it is what would take effect if started — but it is not live
    exposure, and that difference is the difference between a finding and an emergency."""
    res = _run(stdout="permitrootlogin yes\npasswordauthentication yes\n", active=False)

    assert "ssh-root-password-login" in _checks(res.findings)
    assert "not currently running" in " ".join(res.notes)


def test_a_running_sshd_adds_no_such_note():
    res = _run(stdout="permitrootlogin no\npasswordauthentication no\n", active=True)
    assert res.notes == []


def test_repeated_options_are_kept_rather_than_overwritten():
    config, err = ("", "")
    with patch("fettle.command.run",
               return_value=command.Proc(0, "listenaddress 0.0.0.0:22\n"
                                            "listenaddress [::]:22\nport 22\n", "")):
        config, err = ssh.effective_config("sshd")

    assert err == ""
    assert config["listenaddress"] == "0.0.0.0:22,[::]:22"
