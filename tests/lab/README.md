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
| `lab.py matrix [--only <t>]` | every action × every target → PASS/FAIL/SKIP |

## The matrix sweep

`lab.py matrix` runs each action against each built target through **`fettle remote`** —
the path fettle is actually used by — and prints a grid.

**Every cell is PASS, FAIL, or SKIP-with-a-reason.** There is no fourth, quieter state: an
action that could not run must never look like one that ran and found nothing. That failure
mode is why this lab exists, so the runner refuses to reproduce it, and every non-PASS cell
prints why.

Two things the isolation depends on:

- **Read-only actions share one revert** (they cannot perturb each other); **every mutating
  action gets its own**. `-u` consumes the pending upgrades `-O` exists to report, so
  without that the sweep would measure whatever the previous action left behind.
- **`--yes` on mutating actions.** Without a tty `ctx.confirm` returns its safe default, so
  the action would decline and "pass" having done nothing — green and meaningless.

`✗` in fettle's output is *not* treated as failure. It marks "this part could not run" as
often as anything fatal: a real `-u` on Arch upgraded all 17 pending packages and then
printed `✗ yay not found` for the AUR half. That is a SKIP — scoring it FAIL condemns a
working action, scoring it PASS hides that half of it never happened.

Per-cell output lands in `tests/lab/matrix-logs/`.

## Target status

| Target | Firmware | Seed | Extras | State |
|---|---|---|---|---|
| `arch` | BIOS | cdrom | `checksec` **3.x** | **working** |
| `ubuntu` | BIOS | **virtio disk** | `checksec` 2.x | **working** |
| `debian` | **UEFI** | cdrom | `checksec` 2.x | **working** |
| `rocky9` | **UEFI** | cdrom | — | **working** |
| `alma9` | **UEFI** | cdrom | — | **working** |
| `fedora` | **UEFI** | cdrom | `checksec` 2.x | **working** — only dnf5 target |

Prerequisites in the `Extras` column are installed by cloud-init **at build time**, so they
are baked into the `pristine` snapshot and survive `reset`. Installing one by hand after
snapshotting means the next revert silently loses it.

**Both checksec generations are deliberately represented** — 3.x on Arch, 2.x on the other
three — because they share no command line, and running the wrong one made `hardening-audit`
report a clean system after analysing nothing (fettle 0.48.0/0.48.1). Neither path can now
rot unnoticed.

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

## Logging in

Each cloud image has its own default user (`arch`, `debian`, `ubuntu`, `rocky`,
`almalinux`, `fedora`). Setting **`ADMIN_USER`** in `lab.conf` adds one extra login with
the same key and passwordless sudo on every guest, so one name works everywhere.

Guests register their hostname with the LAN's DNS, so `ssh <user>@fettle-<target>` works
without hardcoding DHCP addresses — which change whenever a VM is rebuilt.

**One quirk:** a NetworkManager-based guest (Fedora) takes its DHCP lease *before*
cloud-init sets the hostname, so it registers under the wrong name on first boot.
`systemctl restart NetworkManager` once fixes it permanently — until then it needs an
explicit `HostName` below.

### `~/.ssh/config`

```sshconfig
Host fettle-fedora
    HostName 192.168.1.252      # only while its DNS registration is missing

Host fettle-*
    User paulda                 # whatever you set as ADMIN_USER
    IdentityFile ~/.ssh/paulda-ecdsa
    IdentitiesOnly yes
    UserKnownHostsFile ~/.ssh/known_hosts.fettle-lab
    StrictHostKeyChecking accept-new
```

**Lab host keys live in their own file** (`~/.ssh/known_hosts.fettle-lab`), and `lab.py`
writes there rather than to your real `known_hosts`. These VMs are rebuilt and
snapshot-reverted constantly and their keys change every time; mixed in with real hosts
that produces a steady stream of REMOTE HOST IDENTIFICATION HAS CHANGED warnings, and
the habit of clicking past those costs more than the convenience is worth. `rm` the file
to reset the lab's trust wholesale, losing nothing else.

`lab.py` records each guest under **both** spellings — `fettle-<target>,<address>` on one
line — because ssh keys `known_hosts` by whatever it actually connects to: the name you
typed, or `HostName` when the config overrides it. `lab.py` connects by address while you
type a name, so both have to be there or one of them prompts.

## Reverted guests wake up in the past

`snapshot-revert --running` restores the saved **memory** state, so a guest's clock resumes
at the moment the snapshot was taken and stays there — NTP is running, but it will not step
a jump that large by itself. Five days after the snapshots were made, the guests were five
days behind.

That breaks real things, not just cosmetics:

* **apt refuses the archive.** Ubuntu publishes Release files with a validity window, and a
  guest in the past gets `Release file ... is not valid yet (invalid for another 5d 4h)`.
  Both `only-update` and `update` failed on that guest for this reason alone.
* **Reports are filed on the wrong day.** A guest reporting from July 31 makes the dashboard
  read every lab host as stale and computes its "what changed since last run" delta against
  the wrong day.

`wait_ready()` now steps the clock from the controller and **verifies it took** before
returning, so every revert, reset and build is covered from one place. It sets the date
outright rather than nudging NTP: one command that behaves the same on chrony, timesyncd,
and a guest running neither. The check is not optional — an unverified sync would only move
the lie somewhere harder to see — and a guest still more than two minutes out is a hard
failure rather than a warning, because package metadata validity and report timestamps both
silently depend on it.

## Known limits

Even with VMs, some things stay out of reach, and the runner should report them as
SKIP-with-a-reason rather than silently passing:

- **Firmware updates** — no updatable firmware in a VM; only the no-updatable-devices path runs.
- **Secure Boot / TPM** — needs OVMF + swtpm; worth trying, not assumed.
- ~~**`hardening-audit` on EL**~~ — **this was wrong for EL9; corrected 2026-08-04.** The
  original measurement was on **EL10**, where `checksec` genuinely is absent from every
  repository, and it was generalised to "EL" without retesting on EL9 — which is 53% of the
  EL fleet. Measured during the `hardening-audit` sweep:
  `dnf install epel-release && dnf install checksec` gives checksec 2.5.0 on Rocky 9, and
  `fettle -H` then reports 147 real deviations across 35 packages including a Critical on
  `grub2-tools-minimal`. The rocky9/alma9 targets now install it, so this is real coverage
  rather than a permanent SKIP. The EL10 statement stands on its own.
