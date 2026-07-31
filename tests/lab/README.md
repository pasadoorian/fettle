# fettle test lab

Small, disposable distro VMs on a KVM/libvirt host, for the things containers cannot test:
systemd timers actually firing, snapd, fwupd, real reboots, the privilege model — and
`fettle remote` over ssh, which is how fettle is normally used and which nothing else
exercises.

Containers still carry most of the load (see `fettle-fleet.sh` in the scratchpad); this is
for the remainder.

## Setup

```bash
cp tests/lab/lab.conf.example tests/lab/lab.conf   # then edit it
./tests/lab/lab.py targets
./tests/lab/lab.py build debian
```

`lab.conf` is gitignored — it names a real host, network and key.

## Why it is built this way

**Cloud images, not installers.** Debian's genericcloud qcow2 is 328 MiB and boots in
seconds; its netinst ISO is 755 MiB and wants an interactive install. Every family
publishes one, including Arch.

**Snapshot-pinned.** A cloud image is dated the day it was built, so a VM reverted to its
`pristine` snapshot always presents the *same* set of pending updates — and that set grows
as the archive moves on. That is what keeps the lab reliably out-of-date without running
any repo infrastructure. cloud-init is told **not** to update on first boot for the same
reason: it would consume the very updates the tests need.

**Bridged, not NAT.** Guests get ordinary LAN addresses, so `fettle remote <ip>` needs no
jump host. Addresses come from `qemu-guest-agent`, because libvirt only knows DHCP leases
for networks it manages.

## Commands

| | |
|---|---|
| `lab.py targets` | distro targets, with disk sizes and caveats |
| `lab.py build <t>` | download → seed → install → snapshot `pristine` |
| `lab.py list` | VM state, snapshot presence, addresses |
| `lab.py reset <t>` | revert to `pristine` — do this before every test run |
| `lab.py ip <t>` / `ssh <t>` | address / shell |
| `lab.py destroy <t>` | remove VM and disks (base image kept) |

## Target status

| Target | Firmware | Seed | State |
|---|---|---|---|
| `arch` | BIOS | cdrom | **working** |
| `ubuntu` | BIOS | **virtio disk** | **working** |
| `debian` | **UEFI** | cdrom | **working** |
| `rocky9` | **UEFI** | cdrom | **working** |
| `alma9` | **UEFI** | cdrom | **working** |
| `fedora` | **UEFI** | cdrom | **working** — the only dnf5 target, and the only dnf host where `checksec` is packaged |

Six distros, and **four of them will not boot under BIOS at all**. That is not incidental complexity — each was forced by a failure that
produced no error message. All four images are BIOS+UEFI hybrids by partition layout, so
the layout does not predict which will work.

### What each one needed, and why

**Ubuntu — the seed must be a virtio disk, not a cdrom.** cloud-init's early `ds-identify`
pass did not recognise an emulated SCSI cdrom on 26.04, and when it finds no datasource it
disables cloud-init for the entire boot *silently*: no console output, no
`/var/log/cloud-init.log`, a guest that reaches a login prompt with none of the requested
config applied.

**Debian and Rocky 9 — UEFI.** Rocky under BIOS was worse than Debian: it produced an
**entirely empty** serial log, never reaching a bootloader at all.

**Debian — UEFI.** Under BIOS the genericcloud image printed ``Booting `Debian GNU/Linux'``
and reset, ~1400 times, with no kernel output whatsoever. Ruled out first: the seed as cdrom
*and* as virtio disk, explicit `boot.order`, and the `osinfo` id. (The same symptom shape —
bootloader message looping ~1/s with no kernel output — is documented in the bifrost lab for
a different guest, where the cause was machine type.)

**Debian's UEFI needs two more things than `--boot uefi`:**
1. libvirt refuses an internal snapshot of a pflash VM unless the NVRAM is qcow2, and
   virt-install 5.1 has no `nvram.format`. It does have `nvram.templateFormat`, so the
   firmware VARS template is converted to qcow2 once and libvirt inherits the format.
2. Handing a qcow2 template to `--boot uefi` then breaks libvirt's firmware
   auto-selection ("Unable to find 'efi' firmware compatible with the current
   configuration"), so the loader is named explicitly instead.

## Known limits

Even with VMs, some things stay out of reach, and the runner should report them as
SKIP-with-a-reason rather than silently passing:

- **Firmware updates** — no updatable firmware in a VM; only the no-updatable-devices path runs.
- **Secure Boot / TPM** — needs OVMF + swtpm; worth trying, not assumed.
- **`hardening-audit` on EL** — `checksec` is not packaged for el10 at all, EPEL included.
  Fedora is the only dnf target that can run it.
