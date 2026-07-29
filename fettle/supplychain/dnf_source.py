"""DNF / YUM repositories — the Package Supply Chain view for the RPM family.

Trust model: every package on the system arrives from a repository listed in
``/etc/yum.repos.d``. Three properties of that list decide whether "installed from
the distro" means anything — whether package signatures are actually checked, whether
the metadata arrives over TLS, and whose repository it is.

Answers: ``INSECURE_TRANSPORT`` (``gpgcheck=0``, i.e. signatures not verified, and
plain-http URLs), ``UNOFFICIAL_SOURCE`` (a repo outside the distro vendors),
``UNVERIFIABLE`` (a ``.repo`` file that could not be parsed — never silently skipped).

Read from the filesystem through ``ctx.root`` rather than by shelling out to
``dnf repolist``, matching ``apt_source``: it works under a test root, needs no dnf,
and reports what is *configured* rather than what dnf could reach today.

Two deliberate calls:

* **``gpgcheck`` is resolved, not read.** An absent ``gpgcheck`` in a repo section
  inherits ``[main]`` from ``/etc/dnf/dnf.conf``, which ships as ``gpgcheck=1``.
  Treating "absent" as "disabled" would flag essentially every repo on every box.
* **``repo_gpgcheck=0`` is NOT flagged.** Metadata signing is rarely deployed in the
  RPM world — EPEL itself ships ``repo_gpgcheck=0`` — so reporting it would produce a
  finding that is true, universal and therefore useless. ``coverage`` says that only
  package signing is assessed.
"""

from __future__ import annotations

import configparser
from pathlib import Path

from .base import (INSECURE_TRANSPORT, UNOFFICIAL_SOURCE, UNVERIFIABLE, Finding,
                   Severity, SourceProvider)

_REPO_DIR = "etc/yum.repos.d"
_DNF_CONF = "etc/dnf/dnf.conf"

# Hosts belonging to the distributions this backend claims. Kept small and stable,
# mirroring apt_source's `_OFFICIAL_SUFFIXES`. EPEL (fedoraproject.org) is
# deliberately absent: it is a third-party repository on a RHEL box, exactly as a
# Launchpad PPA is on Ubuntu, and apt flags those at LOW too.
_OFFICIAL_SUFFIXES = (".redhat.com", ".centos.org", ".rockylinux.org",
                      ".almalinux.org", ".oracle.com")


def _reader() -> configparser.ConfigParser:
    """A parser tolerant of what real ``.repo`` files contain.

    ``interpolation=None`` because values carry ``$releasever``/``$basearch`` and may
    contain ``%``, which the default interpolation would treat as a directive;
    ``strict=False`` so a duplicated key does not abort the whole file.
    """
    return configparser.ConfigParser(strict=False, interpolation=None)


def _host(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def _is_official(host: str) -> bool:
    return any(host == s.lstrip(".") or host.endswith(s) for s in _OFFICIAL_SUFFIXES)


def _global_gpgcheck(root: Path) -> bool:
    """The ``[main] gpgcheck`` default. dnf's own default is on, so an unreadable or
    absent dnf.conf means on — never assume a system is less safe than it is."""
    cfg = root / _DNF_CONF
    if not cfg.is_file():
        return True
    cp = _reader()
    try:
        cp.read_string(cfg.read_text(errors="replace"))
        return cp.getboolean("main", "gpgcheck", fallback=True)
    except (OSError, ValueError, configparser.Error):
        return True


def _url_of(section) -> tuple[str, str]:
    """``(url, kind)`` — a repo points at exactly one of these three."""
    for key in ("baseurl", "metalink", "mirrorlist"):
        val = (section.get(key) or "").strip()
        if val:
            return val.split()[0], key
    return "", ""


class DnfSource(SourceProvider):
    source = "dnf"
    coverage = ("dnf/yum repository configuration: whether package signature checking "
                "is switched off (gpgcheck=0), plain-http URLs, and repositories "
                "outside the distro vendors. Assesses PACKAGE signing only — metadata "
                "signing (repo_gpgcheck) is rarely deployed on RPM systems, EPEL "
                "included, so it is not reported. No malware feed exists for RPM "
                "repositories.")

    def _root(self, ctx) -> Path:
        return Path(getattr(ctx, "root", None) or "/")

    def is_present(self, ctx) -> bool:
        return (self._root(ctx) / _REPO_DIR).is_dir()

    def findings(self, ctx) -> list[Finding]:
        root = self._root(ctx)
        repo_dir = root / _REPO_DIR
        if not repo_dir.is_dir():
            return []
        default_gpg = _global_gpgcheck(root)

        out: list[Finding] = []
        for path in sorted(repo_dir.glob("*.repo")):
            cp = _reader()
            try:
                cp.read_string(path.read_text(errors="replace"))
            except (OSError, configparser.Error) as exc:
                out.append(Finding(
                    Severity.WARN, self.source, path.name, UNVERIFIABLE,
                    f"could not parse {path.name} ({exc}) — the repositories it "
                    "defines were NOT audited"))
                continue

            for repo_id in cp.sections():
                sec = cp[repo_id]
                enabled = sec.get("enabled", "1").strip() in ("1", "true", "True")
                # A disabled repo is inert today but is a landmine if switched on, so
                # it is reported at a lower severity rather than hidden.
                sev = Severity.WARN if enabled else Severity.LOW
                suffix = "" if enabled else " (repo is disabled)"
                url, _kind = _url_of(sec)

                try:
                    gpg = sec.getboolean("gpgcheck", fallback=default_gpg)
                except ValueError:
                    gpg = default_gpg
                if not gpg:
                    out.append(Finding(
                        sev, self.source, repo_id, INSECURE_TRANSPORT,
                        "gpgcheck=0 — packages from this repository are installed "
                        f"without verifying their signature{suffix}"))

                if url.startswith("http://"):
                    out.append(Finding(
                        Severity.LOW, self.source, repo_id, INSECURE_TRANSPORT,
                        f"served over plain http: {url}{suffix}"))

                host = _host(url)
                if enabled and host and not _is_official(host):
                    out.append(Finding(
                        Severity.LOW, self.source, repo_id, UNOFFICIAL_SOURCE,
                        f"third-party repository ({host}) — not one of the "
                        "distribution's own"))
        return out
