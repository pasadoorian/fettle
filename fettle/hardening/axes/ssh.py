"""SSH server configuration — what is actually in effect, not what is written down.

This axis exists because of one specific failure. The tool that prompted this work
greps ``sshd_config`` and prints a line per option it does not find there:

    - OpenSSH option: PermitRootLogin      [ NOT FOUND ]
    - OpenSSH option: MaxAuthTries         [ NOT FOUND ]
    ... twenty-two of them

On the reference machine ``sshd_config`` is three non-comment lines, so *everything*
is at an OpenSSH default — and modern OpenSSH defaults are fine
(``PermitRootLogin prohibit-password``, ``PermitEmptyPasswords no``,
``HostbasedAuthentication no``). Twenty-two finding-shaped lines that say nothing about
actual exposure, because the question was asked of the file rather than of the server.

``sshd -T`` answers the real question: the **effective** configuration, defaults filled
in. So this axis reports only what is genuinely weak and stays silent where the default
is fine — which on a stock host means saying nothing at all.

``sshd -T`` **needs root** (it loads host keys; unprivileged it exits with "no hostkeys
available"). When it cannot run, this reports blindness with the reason. It does *not*
fall back to parsing the file against a built-in table of defaults: that table drifts
with every OpenSSH release, and being confidently wrong about ``PermitRootLogin`` is
worse than saying nothing.
"""

from __future__ import annotations

from . import HIGH, LOW, MEDIUM, AxisResult, Finding
from ... import command

# sshd lives in sbin, which is often not on a non-root PATH.
_SSHD_PATHS = ("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd")

# Stderr that means "you are not root", as opposed to a broken configuration. The
# distinction decides whether this run reports blindness or a real problem.
_NEED_ROOT = ("no hostkeys available", "permission denied", "must be run as root",
              "could not open", "operation not permitted")

# Algorithms weak enough that their presence means somebody deliberately re-enabled
# them for a legacy peer. Deliberately NOT a "modern crypto" wishlist: `hmac-sha1` and
# `hmac-sha1-etm` are still OpenSSH *defaults* (verified against a stock Debian 13
# `sshd -T`), so listing them would fire on every unmodified host — the exact
# everything-is-a-finding failure this axis exists to avoid.
_WEAK_ALGORITHMS = {
    "kexalgorithms": ("diffie-hellman-group1-sha1", "gss-group1-sha1-"),
    "macs": ("hmac-md5", "hmac-md5-96", "hmac-md5-etm@openssh.com",
             "hmac-ripemd160", "hmac-ripemd160@openssh.com"),
    "ciphers": ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "arcfour",
                "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc"),
    "hostkeyalgorithms": ("ssh-dss", "ssh-dss-cert-v01@openssh.com"),
}


def _sshd_binary() -> str:
    """The sshd to interrogate, or "" if there is no SSH server here.

    ``command.which`` answers *whether* something is on PATH, not where — so the name
    is returned for the PATH case and the sbin paths are probed by hand, because sbin
    is routinely absent from a non-root PATH and that is exactly the case this axis
    runs in.
    """
    if command.which("sshd"):
        return "sshd"
    from pathlib import Path
    for path in _SSHD_PATHS:
        if Path(path).exists():
            return path
    return ""


def effective_config(binary: str) -> tuple[dict[str, str], str]:
    """``(config, error)`` from ``sshd -T``. A non-empty error means nothing was read.

    Keys are lowercased by sshd itself; values are kept verbatim. Options that may be
    repeated (``listenaddress``, ``hostkey``) are joined, since nothing here judges
    them and losing all but the last would be quietly wrong for anything that later
    does.
    """
    proc = command.run([binary, "-T"], capture=True)
    text, err = (proc.stdout or ""), (proc.stderr or "")
    if proc.returncode != 0 or not text.strip():
        return {}, (err.strip() or f"sshd -T exited {proc.returncode}")
    config: dict[str, str] = {}
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        if not key:
            continue
        value = value.strip()
        config[key] = f"{config[key]},{value}" if key in config else value
    return config, ""


def _weak_algorithms(config: dict[str, str]) -> list[Finding]:
    out = []
    for key, bad in _WEAK_ALGORITHMS.items():
        offered = {a.strip().lower() for a in config.get(key, "").split(",") if a.strip()}
        hits = sorted(offered & set(bad))
        if hits:
            out.append(Finding(
                check=f"ssh-weak-{key}", subject=key, severity=MEDIUM,
                detail=(f"offers {', '.join(hits)} — these are not OpenSSH defaults, "
                        f"so they were re-enabled deliberately for a legacy peer, and "
                        f"they weaken every session that negotiates them"),
                fix=f"remove them from {key.capitalize()} in sshd_config"))
    return out


def findings_for(config: dict[str, str]) -> list[Finding]:
    """Judge an effective config. Silent wherever the OpenSSH default is already fine."""
    out: list[Finding] = []
    root_login = config.get("permitrootlogin", "").lower()
    passwords = config.get("passwordauthentication", "").lower() == "yes"

    # The combination is the finding, not either half. `permitrootlogin yes` with keys
    # only is a policy choice; with password auth it means the one account that matters
    # is reachable by guessing, from anywhere that can open the port.
    if root_login == "yes" and passwords:
        out.append(Finding(
            check="ssh-root-password-login", subject="PermitRootLogin", severity=HIGH,
            detail="root can log in directly with a password, so the account that "
                   "matters most is reachable by guessing from anywhere that can "
                   "reach this port",
            fix="PermitRootLogin prohibit-password (or no)"))
    elif root_login == "yes":
        out.append(Finding(
            check="ssh-root-login", subject="PermitRootLogin", severity=MEDIUM,
            detail="root can log in directly — every administrative action arrives "
                   "unattributed, and there is no second step to compromise",
            fix="PermitRootLogin prohibit-password (or no)"))
    elif passwords:
        # Low, and phrased as exposure rather than defect: this is the stock Debian
        # default, and a host whose users have no keys yet legitimately needs it.
        out.append(Finding(
            check="ssh-password-auth", subject="PasswordAuthentication", severity=LOW,
            detail="password authentication is enabled, so every account is reachable "
                   "by guessing — the host's safety rests on password strength and on "
                   "rate limiting rather than on key possession",
            fix="PasswordAuthentication no, once every user has a key installed"))

    if config.get("permitemptypasswords", "").lower() == "yes":
        out.append(Finding(
            check="ssh-empty-passwords", subject="PermitEmptyPasswords", severity=HIGH,
            detail="accounts with an empty password can log in over the network",
            fix="PermitEmptyPasswords no"))
    if config.get("hostbasedauthentication", "").lower() == "yes":
        out.append(Finding(
            check="ssh-hostbased-auth", subject="HostbasedAuthentication",
            severity=MEDIUM,
            detail="trusts the client host's own claim about which user it is, so "
                   "compromising one trusted host reaches the accounts on this one",
            fix="HostbasedAuthentication no"))
    if config.get("ignorerhosts", "").lower() == "no":
        out.append(Finding(
            check="ssh-rhosts", subject="IgnoreRhosts", severity=MEDIUM,
            detail="honours per-user .rhosts files, so a user can grant host-based "
                   "access to their own account without administrator involvement",
            fix="IgnoreRhosts yes"))
    if config.get("gatewayports", "").lower() in ("yes", "clientspecified"):
        out.append(Finding(
            check="ssh-gatewayports", subject="GatewayPorts", severity=MEDIUM,
            detail="ports forwarded by a client are bound to every interface, so a "
                   "user's tunnel is reachable by the whole network rather than only "
                   "by this host",
            fix="GatewayPorts no"))
    if config.get("x11forwarding", "").lower() == "yes":
        out.append(Finding(
            check="ssh-x11", subject="X11Forwarding", severity=LOW,
            detail="X11 forwarding is offered; a compromised server can read the "
                   "connecting client's keystrokes and screen through it",
            fix="X11Forwarding no, unless remote GUI applications are needed"))
    if config.get("permittunnel", "").lower() not in ("", "no"):
        out.append(Finding(
            check="ssh-permittunnel", subject="PermitTunnel", severity=LOW,
            detail="clients may create layer-2/3 tunnel devices, which bridges "
                   "networks rather than forwarding a port",
            fix="PermitTunnel no"))
    try:
        tries = int(config.get("maxauthtries", "6"))
    except ValueError:
        tries = 6
    if tries > 6:
        out.append(Finding(
            check="ssh-maxauthtries", subject="MaxAuthTries", severity=LOW,
            detail=f"allows {tries} authentication attempts per connection, which "
                   f"multiplies how fast a guessing attack can work",
            fix="MaxAuthTries 6 or fewer"))

    out.extend(_weak_algorithms(config))
    return out


def run(backend, ctx) -> AxisResult:
    res = AxisResult(name="ssh", title="SSH server configuration")

    binary = _sshd_binary()
    if not binary:
        # No server, no exposure. Not blindness — sending the reader off to install an
        # SSH server so it can be audited would be an absurd remedy.
        res.na = "no SSH server is installed"
        return res

    config, err = effective_config(binary)
    if err:
        needs_root = any(m in err.lower() for m in _NEED_ROOT)
        res.blind.append((
            "the SSH server configuration was NOT checked",
            "reading the effective configuration needs root (`sshd -T` loads the host "
            "keys) — re-run with sudo" if needs_root else
            f"`sshd -T` could not be read: {err}", ""))
        return res

    res.checked = len(config)
    res.findings.extend(findings_for(config))

    # An installed-but-stopped sshd is worth auditing (it can be started, and the
    # config is what it will start with) but it is not current exposure, and saying so
    # is the difference between a finding and an emergency.
    if command.which("systemctl"):
        active = any(command.run(["systemctl", "is-active", name],
                                 capture=True).returncode == 0
                     for name in ("sshd", "ssh"))
        if not active:
            res.notes.append("sshd is installed but not currently running, so nothing "
                             "above is live exposure — it is what would take effect if "
                             "it were started")
    return res
