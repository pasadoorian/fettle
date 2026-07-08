"""Secure Boot check — state, boot control, and the 2026 Microsoft cert-expiry
matrix (ported verbatim from supply_chain_check.sh, the real domain logic).

Microsoft's 2011 Secure Boot CAs expire in 2026; systems must migrate to the 2023
replacements. For each 2011 cert, *presence* is the risk (it will expire — warn,
or error once past); for each 2023 cert, *absence* is the risk (not yet migrated).
"""

from __future__ import annotations

from datetime import datetime

# Hardcoded Microsoft cert-expiry dates (the "2026" cliff).
_KEK_EXPIRY = "2026-06-27"   # KEK CA 2011 and UEFI CA 2011
_PCA_EXPIRY = "2026-10-01"   # Windows Production PCA 2011
_REF = "Ref: https://eclypsium.com/blog/microsoft-secure-boot-certificates-expire-2026/"


def _days_until(target: str, now: datetime) -> int | None:
    try:
        y, m, d = (int(x) for x in target.split("-"))
        target_ts = datetime(y, m, d).timestamp()
    except (ValueError, TypeError):
        return None
    # int(x/86400) truncates toward zero, matching bash `(( diff / 86400 ))`.
    return int((target_ts - now.timestamp()) / 86400)


def _efi_reader(scan):
    """Memoized UEFI store reader: efi-readvar preferred, mokutil fallback.

    Caches per store (including empty results) — matches the bash `_EFI_VAR_CACHE`.
    """
    cache: dict[str, str] = {}
    flags = {"KEK": "--kek", "db": "--db", "dbx": "--dbx"}

    def get(store: str) -> str:
        if store in cache:
            return cache[store]
        out = ""
        if scan.which("efi-readvar"):
            out = scan.run_text(["efi-readvar", "-v", store])
        elif scan.which("mokutil"):
            out = scan.run_text(["mokutil", flags[store]])
        cache[store] = out
        return out

    return get


def _report_cert_row(scan, label: str, present: bool, days: int | None) -> None:
    """days is None for a 2023 cert (absence is bad), an int for a 2011 cert."""
    if present:
        if days is not None:
            if days > 0:
                scan.status(label, f"Present (expires in {days} days)", "warn")
            else:
                scan.status(label, f"Present (EXPIRED {-days} days ago)", "error")
        else:
            scan.status(label, "Present", "ok")
    else:
        scan.status(label, "Not present", "ok" if days is not None else "warn")


def check(scan, *, now: datetime | None = None) -> None:
    now = now or datetime.now()

    scan.sub("Secure Boot State (mokutil)")
    if scan.which("mokutil"):
        state = scan.run_text(["mokutil", "--sb-state"])
        low = state.lower()
        if "enabled" in low:
            scan.status("Secure Boot", "Enabled", "ok")
        elif "disabled" in low:
            scan.status("Secure Boot", "Disabled", "warn")
        else:
            scan.status("Secure Boot", state, "info")
        if scan.verbose:
            scan.result(state)
    else:
        scan.status("mokutil", "Not installed", "warn")

    scan.sub("Boot Control Status (bootctl)")
    if scan.which("bootctl"):
        out = scan.run_text(["bootctl", "status"])
        if scan.verbose:
            scan.result(out)
        else:
            wanted = ("Secure Boot", "Setup Mode", "Boot Loader", "Product")
            for ln in out.splitlines():
                if any(w in ln for w in wanted):
                    print(f"    {ln}")
    else:
        scan.status("bootctl", "Not installed (systemd-boot)", "info")

    _cert_expiry(scan, now)


def _cert_expiry(scan, now: datetime) -> None:
    scan.sub("Certificate Expiration (2026)")
    if not scan.which("efi-readvar") and not scan.which("mokutil"):
        scan.status("Skipped",
                    "Install 'efitools' (efi-readvar) or 'mokutil' to enable", "warn")
        return
    get = _efi_reader(scan)
    kek_data, db_data = get("KEK"), get("db")
    if not kek_data and not db_data:
        scan.status("Skipped", "Could not read UEFI variables (try as root)", "warn")
        return

    kek_days = _days_until(_KEK_EXPIRY, now)
    pca_days = _days_until(_PCA_EXPIRY, now)

    kek11 = "Microsoft Corporation KEK CA 2011" in kek_data
    kek23 = "Microsoft Corporation KEK CA 2023" in kek_data
    uefi11 = "Microsoft Corporation UEFI CA 2011" in db_data
    uefi23 = "Microsoft UEFI CA 2023" in db_data
    oprom23 = "Microsoft Option ROM UEFI CA 2023" in db_data
    win11 = "Microsoft Windows Production PCA 2011" in db_data
    win23 = "Windows UEFI CA 2023" in db_data

    _report_cert_row(scan, "KEK CA 2011 (KEK)", kek11, kek_days)
    _report_cert_row(scan, "KEK CA 2023 (KEK)", kek23, None)
    _report_cert_row(scan, "UEFI CA 2011 (db)", uefi11, kek_days)
    _report_cert_row(scan, "UEFI CA 2023 (db)", uefi23, None)
    _report_cert_row(scan, "Option ROM UEFI CA 2023 (db)", oprom23, None)
    _report_cert_row(scan, "Windows PCA 2011 (db)", win11, pca_days)
    _report_cert_row(scan, "Windows UEFI CA 2023 (db)", win23, None)
    print()

    migrated_uefi = uefi23 or oprom23
    if kek23 and migrated_uefi and win23:
        scan.status("Migration Status", "Migrated to 2023 certificates", "ok")
    elif kek23 or migrated_uefi or win23:
        scan.status("Migration Status", "Partial migration (see details above)", "warn")
        scan.dim(_REF)
    elif kek11 or uefi11 or win11:
        scan.status("Migration Status", "NOT MIGRATED (still on 2011 certificates)", "error")
        scan.dim(_REF)
    else:
        scan.status("Migration Status",
                    "No Microsoft Secure Boot certificates detected", "info")

    if scan.verbose:
        if kek_data:
            scan.sub("Full KEK contents")
            scan.result(kek_data)
        if db_data:
            scan.sub("Full db contents")
            scan.result(db_data)
