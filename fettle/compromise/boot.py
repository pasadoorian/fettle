"""Boot chain — has anything been injected into how this machine starts?

chkrootkit 0.59 added a Bootkitty check, which is the right threat and one line of
implementation: `egrep "LD_PRELOAD" /etc/grub.d/* /boot/grub/grub.cfg`. That is grub-only
— nothing for systemd-boot, rEFInd or a unified kernel image, all of which are ordinary
on Arch — and it says nothing about whether the boot chain is verified at all.

Two things are done differently here.

**The bootloader actually in use is detected, and only its configuration is read.**
Reporting "grub looks clean" on a systemd-boot machine is worse than saying nothing.

**Secure Boot state is reported alongside, always.** On the reference machine the grub
configuration is clean *and* Secure Boot is disabled with the platform in setup mode —
which means nothing verifies the bootloader, the kernel or the initramfs, so a clean
config proves very much less than it appears to. Printing the first without the second
is the kind of half-truth that makes a report feel reassuring and be worthless.

**Ownership is deliberately not the test here.** `/boot/grub/grub.cfg` is *generated* by
`grub-mkconfig` and no package owns it — measured on the reference machine — so the
asymmetry that governs user crontabs applies again: judge generated files on content,
and only the hand-edited sources on provenance.
"""

from __future__ import annotations

import re

from . import HIGH, MEDIUM, CheckResult, Finding, is_directory, is_regular_file

# (label, detection file, generated paths, package-owned sources).
#
# The split is the whole subtlety, and getting it wrong fires on every healthy machine
# of that flavour. **Generated** paths are judged on *content only* — nothing owns a
# generated file, so an ownership test there reports every host. `/boot/grub/grub.cfg`
# is written by `grub-mkconfig` (measured unowned on the reference machine), and
# `/boot/loader/entries/*.conf` are written by `kernel-install`/`bootctl`, so both are
# generated even though one looks hand-edited. **Sources** are the files a package
# genuinely ships and an admin edits in place — `/etc/default/grub` and `/etc/grub.d/*`
# are owned by the `grub` package, verified — so a whole file nobody owns there is worth
# a line.
LOADERS = (
    ("grub", "boot/grub/grub.cfg",
     ("boot/grub/grub.cfg",), ("etc/default/grub", "etc/grub.d")),
    ("grub (EFI)", "boot/efi/EFI/grub/grub.cfg",
     ("boot/efi/EFI/grub/grub.cfg",), ()),
    ("systemd-boot", "boot/loader/loader.conf",
     ("boot/loader/loader.conf", "boot/loader/entries"), ()),
    ("rEFInd", "boot/EFI/refind/refind.conf",
     ("boot/EFI/refind/refind.conf",), ()),
)

# Directives that have no business appearing in a bootloader configuration. LD_PRELOAD
# is Bootkitty's; the initrd/init ones are how a boot chain is redirected at the point
# where nothing is watching yet.
INJECTED = (
    (re.compile(r"\bLD_PRELOAD\s*="), "an LD_PRELOAD assignment — the technique the "
                                      "Bootkitty UEFI bootkit uses"),
    (re.compile(r"\binit=/(?:tmp|dev/shm|var/tmp)/"), "an init= pointing into a "
                                                      "world-writable directory"),
    (re.compile(r"\bmodule_blacklist=.*\b(?:lockdown|ima|evm)\b"), "a module_blacklist "
                                                                  "disabling an "
                                                                  "integrity subsystem"),
)


def run(backend, ctx) -> CheckResult:
    res = CheckResult(name="boot", title="Boot chain")
    found_any = False

    for label, detect, generated, sources in LOADERS:
        if not is_regular_file(ctx.root / detect):
            continue
        found_any = True
        for rel in generated:
            _each(ctx.root / rel, label, res, generated=True)
        for rel in sources:
            _each(ctx.root / rel, label, res, generated=False, backend=backend)

    if not found_any:
        res.na = ("no bootloader configuration was found — this is normal in a "
                  "container, and on a host it means the boot chain lives somewhere "
                  "this check does not know about")
        return res

    _secure_boot(ctx, res)
    return res


def _each(target, label: str, res: CheckResult, *, generated: bool, backend=None) -> None:
    """Scan a file, or every file in a directory. Directories are one level deep:
    `/etc/grub.d` and `/boot/loader/entries` are both flat by design."""
    if is_directory(target):
        try:
            children = sorted(target.iterdir())
        except OSError as exc:
            res.blind.append((str(target), f"could not be listed ({exc.strerror})", ""))
            return
        for child in children:
            if is_regular_file(child):
                res.checked += 1
                _scan(child, label, res, generated=generated, backend=backend)
    elif is_regular_file(target):
        res.checked += 1
        _scan(target, label, res, generated=generated, backend=backend)


def _scan(path, label: str, res: CheckResult, *, generated: bool, backend=None) -> None:
    try:
        body = path.read_text(errors="replace")
    except OSError as exc:
        res.blind.append((str(path), f"could not be read ({exc.strerror})", ""))
        return

    for pattern, why in INJECTED:
        match = pattern.search(body)
        if not match:
            continue
        line = next((ln.strip() for ln in body.splitlines() if pattern.search(ln)), "")
        res.findings.append(Finding(
            check="boot-config-injection", subject=str(path), severity=HIGH,
            detail=(f"the {label} configuration contains {why}. Anything set here runs "
                    f"before the system this report describes exists, so nothing later "
                    f"in this report speaks for it. Line: {line[:120]}"),
            summary=f"injected directive in the {label} config",
            fix=f"read it in full: cat {path} — and compare against a known-good copy"))

    # A hand-edited source that no package owns is worth a line; the generated config
    # never is, because nothing owns a generated file by construction.
    if generated or backend is None:
        return
    if not backend.map_files_to_packages([str(path)]):
        res.findings.append(Finding(
            check="unowned-boot-config", subject=str(path), severity=MEDIUM,
            detail=(f"a {label} configuration source that no package owns. These are "
                    f"normally shipped by the bootloader's package and edited in place; "
                    f"a whole file nobody owns is either yours or something else's"),
            summary="no package owns this boot config file",
            fix=f"confirm you added it: cat {path}"))


def _secure_boot(ctx, res: CheckResult) -> None:
    """Whether anything verifies the boot chain at all.

    Read from the EFI variable directly rather than through `sys-audit`: this check has
    to work when only `compromise-check` was asked for, and the variable is two files
    and no parsing. `sys-audit` remains the place that *judges* Secure Boot posture —
    this only states it, as the context every finding above needs.
    """
    efivars = ctx.root / "sys/firmware/efi/efivars"
    if not is_directory(efivars):
        res.notes.append(
            "this machine booted without UEFI, so Secure Boot does not apply and "
            "nothing cryptographically verifies the bootloader or kernel. Findings "
            "above are the only evidence about the boot chain there is.")
        return

    state = "unknown"
    try:
        for entry in efivars.iterdir():
            if entry.name.startswith("SecureBoot-"):
                data = entry.read_bytes()
                # 4 bytes of EFI attributes, then a single boolean.
                state = "enabled" if len(data) > 4 and data[4] else "disabled"
                break
    except OSError:
        state = "unknown (needs root to read the EFI variables)"

    if state == "enabled":
        res.notes.append("Secure Boot is enabled, so the bootloader and kernel are "
                         "signature-checked at boot.")
    else:
        res.notes.append(
            f"Secure Boot is {state}. Nothing cryptographically verifies the "
            f"bootloader, kernel or initramfs on this machine, so a clean boot "
            f"configuration above proves less than it looks like it does — `sys-audit` "
            f"(-S) is where that posture is judged.")
