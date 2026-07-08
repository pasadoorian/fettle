"""The distro-neutral sys-audit checks (ported from supply_chain_check.sh).

Each takes a :class:`~fettle.secure.base.Scan` and emits via it. Unlike the bash
original, external tools are not individually `sudo`-prefixed — run the whole
`fettle sys-audit` under sudo for root-only data (the checks note when that's
needed). Filesystem reads go through the injected `root` so they're testable.
"""

from __future__ import annotations

import re
from pathlib import Path

# External helper tools (chipsec etc.) are looked for under these roots.
_TOOL_DIRS = ("/opt", "/usr/share")


def _find_tool(scan, subdir: str, marker: str):
    """Return the path to ``<dir>/<subdir>/<marker>`` for the first dir that has it."""
    candidates = [scan.path(f"{d}/{subdir}") for d in _TOOL_DIRS]
    candidates.append(Path.home() / subdir)
    for base in candidates:
        tool = base / marker
        if tool.is_file():
            return tool
    return None


# ---------------------------------------------------------------------------
def bios(scan) -> None:
    if not scan.is_root():
        scan.status("Warning", "run as root for complete BIOS information", "warn")
    scan.sub("BIOS Version and Date")
    if scan.which("dmidecode"):
        for label, key in (("Vendor", "bios-vendor"), ("Version", "bios-version"),
                           ("Release Date", "bios-release-date")):
            p = scan.run(["dmidecode", "-s", key])
            scan.status(label, p.stdout.strip() if p.ok else "Unknown", "info")
        if scan.verbose:
            scan.sub("Full BIOS Details (dmidecode -t 0)")
            scan.result(scan.run_text(["dmidecode", "-t", "0"]))
    else:
        scan.status("dmidecode", "Not installed", "error")

    scan.sub("Machine/Motherboard Info")
    if scan.which("inxi"):
        scan.result(scan.run_text(["inxi", "-M"]))
    else:
        scan.status("inxi", "Not installed", "warn")

    if scan.verbose and scan.which("lshw"):
        scan.sub("Firmware Details (lshw)")
        scan.result(scan.run_text(["lshw"]))


# ---------------------------------------------------------------------------
def firmware(scan) -> None:
    """Chipsec-based firmware checks (ME manufacturing mode, BIOS write protect)."""
    chipsec = _find_tool(scan, "chipsec", "chipsec_main.py")
    if chipsec is None:
        scan.status("Chipsec", "Not found - install from https://github.com/chipsec/chipsec",
                    "warn")
        for line in ("Chipsec checks would include:",
                     "- Intel ME manufacturing mode verification",
                     "- SPI flash write protection status",
                     "- Comprehensive firmware security audit"):
            scan.dim(line)
        return
    scan.status("Chipsec Path", str(chipsec), "ok")
    if not scan.is_root():
        scan.status("Warning", "chipsec requires root privileges", "error")
        return

    scan.sub("Intel ME Manufacturing Mode")
    me = scan.run_text(["python3", str(chipsec), "-m", "common.me_mfg_mode"]).lower()
    if "passed" in me:
        scan.status("ME Manufacturing Mode", "Disabled (PASSED)", "ok")
    elif "failed" in me:
        scan.status("ME Manufacturing Mode", "Enabled (FAILED)", "error")

    scan.sub("BIOS Write Protection")
    wp = scan.run_text(["python3", str(chipsec), "-m", "common.bios_wp"]).lower()
    if "passed" in wp:
        scan.status("BIOS Write Protection", "Enabled (PASSED)", "ok")
    elif "failed" in wp:
        scan.status("BIOS Write Protection", "Disabled (FAILED)", "error")


# ---------------------------------------------------------------------------
def fwupd(scan) -> None:
    if not scan.which("fwupdmgr"):
        scan.status("fwupd", "Not installed", "error")
        return
    scan.sub("Devices with Firmware")
    devices = scan.run_text(["fwupdmgr", "get-devices", "--no-unreported-check"])
    if scan.verbose:
        scan.result(devices)
    else:
        wanted = ("Device ID", "Current version", "Vendor")
        for ln in devices.splitlines():
            if (ln[:1].isalpha() and not ln.startswith(" ")) or any(w in ln for w in wanted):
                print(f"    {ln}")

    scan.sub("Available Updates")
    updates = scan.run_text(["fwupdmgr", "get-updates", "--no-unreported-check"])
    if "no updates" in updates.lower():
        scan.status("Firmware Updates", "System is up to date", "ok")
    else:
        scan.status("Firmware Updates", "Updates available", "warn")
        scan.result(updates)

    scan.sub("Security Attributes")
    security = scan.run_text(["fwupdmgr", "security", "--force"])
    if scan.verbose:
        scan.result(security)
    else:
        for ln in security.splitlines():
            if any(w in ln for w in ("HSI:", "✔", "✘", "Host Security ID")):
                print(f"    {ln}")


# ---------------------------------------------------------------------------
def intel_me(scan) -> None:
    scan.sub("ME Version via MEI")
    if scan.exists("/dev/mei0") or scan.exists("/dev/mei"):
        scan.status("MEI Device", "Present", "ok")
        fw = scan.read("/sys/class/mei/mei0/fw_ver")
        if fw:
            scan.status("ME Firmware Version", fw.strip(), "info")
    else:
        scan.status("MEI Device", "Not accessible (may need mei_me module)", "warn")

    tool = _find_tool(scan, "intel_csme", "intel_csme_version_detection_tool")
    if tool is not None:
        scan.sub("Intel CSME Version Detection Tool")
        scan.result(scan.run_text(["python3", str(tool)]))
    else:
        scan.dim("Intel CSME version detection tool not found.")
        scan.dim("Download from Intel for detailed ME analysis.")

    scan.sub("ME Controller (lspci)")
    if scan.which("lspci"):
        out = scan.run_text(["lspci"])
        hits = [ln for ln in out.splitlines()
                if re.search(r"management engine|MEI|HECI", ln, re.I)]
        if hits:
            scan.result("\n".join(hits))
        else:
            scan.dim("No ME controller found in lspci")


# ---------------------------------------------------------------------------
def microcode(scan) -> None:
    scan.sub("CPU Information")
    cpuinfo = scan.read("/proc/cpuinfo")
    if cpuinfo:
        scan.result("\n".join(cpuinfo.splitlines()[:7]))
        ucode = _cpuinfo_microcode(cpuinfo)
        if ucode:
            scan.status("Microcode Version", ucode, "ok")

    scan.sub("CPU Vulnerabilities")
    for v in scan.glob("/sys/devices/system/cpu/vulnerabilities/*"):
        try:
            status = v.read_text(errors="replace").strip()
        except OSError:
            continue
        level = "ok" if re.search(r"not affected|mitigat", status, re.I) else "warn"
        scan.status(v.name, status, level)

    if scan.verbose and scan.which("inxi"):
        scan.sub("Detailed CPU Info (inxi)")
        scan.result(scan.run_text(["inxi", "-C", "-a"]))


def _cpuinfo_microcode(cpuinfo: str) -> str:
    for line in cpuinfo.splitlines():
        if "microcode" in line:
            parts = line.split()
            return parts[2] if len(parts) >= 3 else ""
    return ""


# ---------------------------------------------------------------------------
def tpm(scan) -> None:
    scan.sub("TPM Device")
    if scan.exists("/dev/tpm0") or scan.exists("/dev/tpmrm0"):
        scan.status("TPM Device", "Present (/dev/tpm0)", "ok")
    else:
        scan.status("TPM Device", "Not found", "warn")
    if scan.exists("/sys/class/tpm/tpm0"):
        ver = scan.read("/sys/class/tpm/tpm0/tpm_version_major")
        if ver:
            scan.status("TPM Version", f"{ver.strip()}.x", "info")

    scan.sub("TPM DMI Information")
    if scan.which("dmidecode") and scan.is_root():
        dmi = scan.run_text(["dmidecode", "-t", "43"])
        if dmi and "not present" not in dmi.lower():
            scan.result(dmi)
        else:
            scan.dim("No TPM information in DMI tables")

    tool = _find_tool(scan, "tpm-vuln-checker", "tpm-vuln-checker")
    if tool is not None:
        scan.sub("TPM Vulnerability Check")
        scan.result(scan.run_text([str(tool), "check"]))
    else:
        scan.dim("tpm-vuln-checker not found.")
        scan.dim("Install from https://github.com/google/tpm-vuln-checker")

    if scan.which("tpm2_getcap"):
        scan.sub("TPM2 Capabilities")
        caps = scan.run_text(["tpm2_getcap", "properties-fixed"])
        if caps:
            scan.result("\n".join(caps.splitlines()[:20]))


# ---------------------------------------------------------------------------
def hardware(scan) -> None:
    if scan.which("inxi"):
        scan.sub("System Summary")
        scan.result(scan.run_text(["inxi", "-b"]))
        scan.sub("Memory Modules")
        scan.result(scan.run_text(["inxi", "-m", "-a"]))
        if scan.verbose:
            scan.sub("PCI Slots")
            scan.result(scan.run_text(["inxi", "--slots", "-a"]))

    scan.sub("PCI Devices")
    if scan.which("lspci"):
        cmd = ["lspci", "-nnmmvkD"] if scan.verbose else ["lspci"]
        scan.result(scan.run_text(cmd))

    if scan.verbose and scan.which("lshw"):
        scan.sub("Memory Details (lshw)")
        scan.result(scan.run_text(["lshw", "-class", "memory"]))


# ---------------------------------------------------------------------------
def storage(scan) -> None:
    if not scan.which("smartctl"):
        scan.status("smartctl", "Not installed (smartmontools package)", "error")
        return
    scan.sub("Storage Devices")
    for dev in _storage_devices(scan):
        print()
        print(f"  {scan.output.B}{dev}{scan.output.NC}")
        info = scan.run_text(["smartctl", "-i", str(dev)])
        if not info:
            scan.dim("Could not query device")
            continue
        model = _smart_field(info, ("Model", "Device Model"), ci=False)
        fw = _smart_field(info, ("firmware",), ci=True)
        serial = _smart_field(info, ("serial",), ci=True)
        if model:
            scan.status("Model", model, "info")
        if fw:
            scan.status("Firmware", fw, "info")
        if serial:
            scan.status("Serial", serial, "info")
        if scan.verbose:
            for ln in scan.run_text(["smartctl", "-H", str(dev)]).splitlines():
                if re.search(r"health|result", ln, re.I):
                    print(f"    {ln}")
                    break


def _storage_devices(scan) -> list[Path]:
    devs = scan.glob("/dev/nvme[0-9]*") + scan.glob("/dev/sd[a-z]")
    out = []
    for dev in devs:
        name = dev.name
        if name[-1:].isdigit() and name.startswith("sd"):
            continue                       # sd partition
        if re.search(r"p[0-9]+$", name):
            continue                       # nvme partition
        out.append(dev)
    return sorted(out)


def _smart_field(text: str, keys, *, ci: bool) -> str:
    for line in text.splitlines():
        hay = line.lower() if ci else line
        if any((k.lower() if ci else k) in hay for k in keys):
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[1].strip()
    return ""
