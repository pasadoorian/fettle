"""TLS certificates — is anything this host serves with expired, or about to be?

**The trust store is deliberately excluded, and that is the whole design.**
``/etc/ssl/certs`` on the reference machine is 121 root CAs, symlinked out of the
``ca-certificates`` bundle. Some of them expire; that is normal, it is the distro's
business, and ``update-ca-certificates`` handles it. An axis that walked that directory
would report dozens of "expired certificates" that no local action can or should fix —
noise of exactly the kind that teaches people to skip a section.

What matters is the certificates this host *presents*: the ones a web server, a mail
server or a VPN hands to whoever connects. Those live in service configuration
directories, and when one expires everything that connects starts failing.

Parsing is an ``openssl`` shell-out. Without it this axis reports blindness rather than
a clean bill of health — X.509 cannot be parsed with the standard library, and fettle
has no runtime dependencies to reach for.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import HIGH, MEDIUM, AxisResult, Finding
from ... import command

# Where a service keeps the certificate it serves with. NOT the trust store — see the
# module docstring.
DEFAULT_PATHS = (
    "/etc/letsencrypt/live", "/etc/nginx", "/etc/httpd", "/etc/apache2",
    "/etc/pki/tls/certs", "/etc/pki/tls/private", "/etc/ssl/private",
    "/etc/dovecot", "/etc/postfix", "/etc/openvpn",
)

# Refused outright, even if a user adds one via config. These hold trust anchors rather
# than certificates this host presents, and their expiry is the packaging system's job.
TRUST_STORES = ("/etc/ssl/certs", "/etc/ca-certificates", "/etc/pki/ca-trust",
                "/usr/share/ca-certificates", "/etc/pki/fwupd", "/etc/pki/fwupd-metadata")

_SUFFIXES = (".pem", ".crt", ".cer", ".cert")
_MAX_DEPTH = 3        # /etc/letsencrypt/live/<domain>/fullchain.pem is 3
_MAX_FILES = 200      # a bound, so a misconfigured path cannot turn this into a walk
DEFAULT_WARN_DAYS = 30


def _settings(cfg) -> tuple[list[str], int]:
    """``(extra paths, warn days)`` from ``[hardening]``."""
    h = getattr(cfg, "hardening", None) or {}
    if not isinstance(h, dict):
        return [], DEFAULT_WARN_DAYS
    raw = h.get("certificate_paths") or []
    extra = [str(p) for p in raw if str(p).strip()] \
        if isinstance(raw, (list, tuple)) else []
    try:
        days = int(h.get("certificate_warn_days", DEFAULT_WARN_DAYS))
    except (TypeError, ValueError):
        days = DEFAULT_WARN_DAYS
    return extra, max(1, days)


def _is_trust_store(path: str) -> bool:
    p = path.rstrip("/")
    return any(p == t or p.startswith(t + "/") for t in TRUST_STORES)


def find_certificates(root: Path, paths) -> tuple[list[Path], bool]:
    """``(certificate files, hit the cap)``, breadth-bounded and depth-bounded."""
    out: list[Path] = []
    for rel in paths:
        if _is_trust_store(rel):
            continue
        base = root / rel.lstrip("/") if root != Path("/") else Path(rel)
        if not base.is_dir():
            continue
        for depth in range(1, _MAX_DEPTH + 1):
            try:
                for f in sorted(base.glob("/".join(["*"] * depth))):
                    if f.is_file() and f.suffix.lower() in _SUFFIXES:
                        out.append(f)
                        if len(out) >= _MAX_FILES:
                            return out, True
            except OSError:
                continue
    return out, False


def not_after(path: Path) -> tuple[datetime | None, str, str]:
    """``(expiry, subject, error)`` via ``openssl x509``.

    A file that is not a certificate — ``httpd.conf`` sitting beside a ``.pem`` — comes
    back as an error and is skipped, not reported. A file that cannot be *read* is a
    different thing entirely and is reported as blindness by the caller: private-key
    directories need root, and "could not open" must never become "fine".
    """
    proc = command.run(["openssl", "x509", "-in", str(path), "-noout",
                        "-enddate", "-subject"], capture=True)
    if proc.returncode != 0:
        return None, "", (proc.stderr or "").strip() or "openssl could not read it"
    when, subject = None, ""
    for line in (proc.stdout or "").splitlines():
        if line.startswith("notAfter="):
            raw = " ".join(line[len("notAfter="):].split())
            # Drop the trailing zone name: %Z parsing of "GMT" is platform-dependent,
            # and these are always UTC.
            parts = raw.split()
            if parts and parts[-1].isalpha():
                parts = parts[:-1]
            try:
                when = datetime.strptime(" ".join(parts), "%b %d %H:%M:%S %Y").replace(
                    tzinfo=timezone.utc)
            except ValueError:
                return None, "", f"unparseable expiry date: {raw!r}"
        elif line.startswith("subject="):
            subject = line[len("subject="):].strip()
    if when is None:
        return None, subject, "openssl reported no notAfter date"
    return when, subject, ""


def findings_for(certs, now: datetime, warn_days: int) -> tuple[list[Finding], list[str]]:
    """``(findings, unreadable paths)``. Pure, so the clock can be injected."""
    findings: list[Finding] = []
    unreadable: list[str] = []
    horizon = now + timedelta(days=warn_days)
    for path in certs:
        when, subject, err = not_after(path)
        if when is None:
            # "not a certificate" is silence; "cannot open it" is blindness. Only the
            # second is worth the reader's attention.
            if "permission denied" in err.lower() or "could not open" in err.lower():
                unreadable.append(str(path))
            continue
        who = f" ({subject})" if subject else ""
        if when <= now:
            days = (now - when).days
            findings.append(Finding(
                check="cert-expired", subject=path.name, severity=HIGH,
                detail=(f"expired {days} day(s) ago, on {when:%Y-%m-%d}{who} — "
                        f"anything presenting this certificate is already failing "
                        f"verification for every client that checks"),
                fix=f"renew or replace {path}"))
        elif when <= horizon:
            days = (when - now).days
            findings.append(Finding(
                check="cert-expiring", subject=path.name, severity=MEDIUM,
                detail=(f"expires in {days} day(s), on {when:%Y-%m-%d}{who}"),
                fix=f"renew {path} before then"))
    return findings, unreadable


def run(backend, ctx) -> AxisResult:
    res = AxisResult(name="certs", title="TLS certificates")

    if not command.which("openssl"):
        res.blind.append(("TLS certificate expiry was NOT checked",
                          "openssl is not installed, and X.509 cannot be parsed with "
                          "the standard library", "openssl"))
        return res

    extra, warn_days = _settings(ctx.config)
    paths = list(DEFAULT_PATHS) + [p for p in extra if p not in DEFAULT_PATHS]
    refused = [p for p in extra if _is_trust_store(p)]
    certs, capped = find_certificates(ctx.root, paths)

    if not certs:
        # No exposure to have. This is the ordinary answer on a workstation, and it is
        # a different statement from "they are all fine".
        res.na = ("no service certificates were found in the usual locations "
                  "(the CA trust store is deliberately not scanned)")
        return res

    res.checked = len(certs)
    findings, unreadable = findings_for(certs, datetime.now(timezone.utc), warn_days)
    res.findings.extend(findings)

    if unreadable:
        res.blind.append((
            f"{len(unreadable)} certificate file(s) could not be read",
            "certificates kept beside private keys need root — re-run with sudo", ""))
    if refused:
        res.notes.append(
            f"not scanned: {', '.join(refused)} — that is the CA trust store, whose "
            f"expiring root certificates are the packaging system's business rather "
            f"than this host's")
    if capped:
        res.notes.append(f"stopped after {_MAX_FILES} certificate files; narrow "
                         f"[hardening] certificate_paths if that truncated something")
    return res
