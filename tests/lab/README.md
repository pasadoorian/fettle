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

| Target | State |
|---|---|
| `arch` | **working** — built, snapshotted, `fettle remote` verified |
| `ubuntu` | **working** — needs the seed as a virtio disk (see below) |
| `debian` | **blocked**: boots to GRUB, prints ``Booting `Debian GNU/Linux'`` and resets, forever, with no kernel output at all. Ruled out: seed as cdrom *and* as virtio disk, explicit `boot.order`, and the `osinfo` id (it is `debian13`, not `debian12`). The disk chain is intact — a `qemu-img info` failure while investigating was only the running-VM lock. Untried: UEFI firmware, a different machine type, the `generic` image instead of `genericcloud` |
| `rocky9`, `alma9`, `fedora` | not yet attempted |

## Known limits

Even with VMs, some things stay out of reach, and the runner should report them as
SKIP-with-a-reason rather than silently passing:

- **Firmware updates** — no updatable firmware in a VM; only the no-updatable-devices path runs.
- **Secure Boot / TPM** — needs OVMF + swtpm; worth trying, not assumed.
- **`hardening-audit` on EL** — `checksec` is not packaged for el10 at all, EPEL included.
  Fedora is the only dnf target that can run it.
