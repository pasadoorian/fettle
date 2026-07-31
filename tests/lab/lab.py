#!/usr/bin/env python3
"""fettle test lab — build and drive disposable distro VMs on a KVM/libvirt host.

The container fleet covers a lot, but not everything: no systemd as PID 1, no snapd, no
fwupd, no real reboots, and no privilege model worth the name. This builds small real VMs
for the rest, and is the only way `fettle remote` — the way fettle is actually used — gets
tested at all.

**Stdlib only, on purpose.** fettle ships `dependencies = []` so the remote zipapp runs
under any bare python3; nothing in this repo may quietly add a dependency. Everything here
shells out to ssh/virsh/qemu-img on the lab host.

Design notes worth knowing before changing anything:

* **Cloud images, not installers.** A Debian genericcloud qcow2 is 328 MiB and boots in
  seconds; the netinst ISO is 755 MiB and needs an interactive install. Sizes measured
  2026-07-30 — see TARGETS.
* **Snapshot-pinned, not re-pulled.** A cloud image is dated the day it was built, so a VM
  restored to its `pristine` snapshot always has the *same* set of pending updates, and
  that set grows over time as the archive moves on. That is what keeps the lab reliably
  "vulnerable" without maintaining any repo infrastructure. Never re-pull a base image
  without deliberately re-baselining.
* **Bridged, not NAT.** A libvirt NAT network is private to its host, so the same subnet
  is easily in use on a second hypervisor — and then an address alone no longer identifies
  a machine. Bridged guests take ordinary LAN addresses instead: unambiguous, directly
  reachable, and what makes `fettle remote <ip>` a realistic test rather than a
  jump-host exercise.
* **IP discovery via the guest agent.** libvirt knows DHCP leases only for networks it
  manages, so a bridged VM's address has to come from `qemu-guest-agent`, which cloud-init
  installs on first boot.

Usage:
    ./lab.py targets                    # what can be built
    ./lab.py build arch                 # download -> seed -> install -> snapshot
    ./lab.py list                       # VM state + addresses
    ./lab.py reset arch                 # revert to the pristine snapshot
    ./lab.py ssh arch [command...]      # shell into it
    ./lab.py ip arch                    # print its address
    ./lab.py destroy arch               # remove VM and disks

Host/network specifics live in `lab.conf` (gitignored) — see `lab.conf.example`.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONF = HERE / "lab.conf"

# Distro targets. Not sensitive, so this table is committed; only host/network/key are not.
#
# `disk` is chosen from measured free space in the stock image, not guessed:
#   * Arch ships a 2 GiB image with only ~504 MiB free — a `pacman -Syu` against a stale
#     snapshot will not fit, so it must be grown.
#   * The RHEL-family images ship at 10 GiB with ~8 GiB free; leave them alone.
#   * Debian is fine as-is at 3 GiB (577 MiB used) and grows its own root via
#     `x-systemd.growfs`, with no cloud-init involvement.
TARGETS = {
    "arch": {
        "url": "https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2",
        "user": "arch", "disk": "8G", "osinfo": "archlinux",
        "note": "530 MiB download; MUST be grown — stock image has ~504 MiB free",
    },
    "ubuntu": {
        "url": "https://cloud-images.ubuntu.com/minimal/releases/resolute/release/"
               "ubuntu-26.04-minimal-cloudimg-amd64.img",
        "user": "ubuntu", "disk": "6G", "osinfo": "ubuntu24.04", "seed": "disk",
        "packages": ["checksec"],
        "note": "407 MiB; 'minimal' strips man pages/editors/Recommends — tools may be absent",
    },
    "debian": {
        "url": "https://cloud.debian.org/images/cloud/trixie/latest/"
               "debian-13-genericcloud-amd64.qcow2",
        "user": "debian", "disk": "5G", "osinfo": "debian13", "firmware": "uefi",
        "packages": ["checksec"],
        "note": "328 MiB, smallest of the lot; genericcloud has a reduced driver set (virtio only)",
    },
    "rocky9": {
        "url": "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/"
               "Rocky-9-GenericCloud-Base.latest.x86_64.qcow2",
        "user": "rocky", "disk": "10G", "osinfo": "rocky9", "firmware": "uefi",
        "note": "EL9 is 53% of the enterprise fleet; Rocky publishes ~3x Alma's advisory rows",
    },
    "alma9": {
        "url": "https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/"
               "AlmaLinux-9-GenericCloud-latest.x86_64.qcow2",
        "user": "almalinux", "disk": "10G", "osinfo": "almalinux9", "firmware": "uefi",
        "note": "security-only errata feed — the contrast against Rocky's fuller one",
    },
    "fedora": {
        "url": "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/"
               "images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2",
        "user": "fedora", "disk": "6G", "osinfo": "fedora41", "firmware": "uefi",
        "packages": ["checksec"],
        "note": "the ONLY dnf5 target, and the only dnf host where checksec is packaged",
    },
}

# `packages` per target installs prerequisites the action under test needs — `checksec`
# for hardening-audit, which is packaged as **2.x** on Fedora/Debian/Ubuntu and 3.x on
# Arch. Those two generations share no command line, and running the 3.x form against a
# 2.x binary made the audit report a clean system after analysing nothing (fixed in
# fettle 0.48.0). Both generations therefore need to be represented in the lab.
#
# cloud-init user-data. Two things here are load-bearing:
#   * `#cloud-config` on line 1 is mandatory — it is a header, not a comment.
#   * ssh_pwauth must be set explicitly: Fedora/Alma/Rocky images ship it false, so without
#     this a password would get console-only access.
USER_DATA = """\
#cloud-config
hostname: {host}
fqdn: {host}
users:
  - name: {user}
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    ssh_authorized_keys:
      - {pubkey}
ssh_pwauth: true
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - python3
{extra_packages}runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
final_message: "fettle-lab ready after $UPTIME seconds"
"""

# `package_update: true` + `package_upgrade: false` is the exact pair that matters, and the
# distinction is easy to get backwards. `package_update` only refreshes package LISTS — no
# package changes version, so the host stays exactly as far behind as its base image. It has
# to be on, because on a minimal image the lists are empty and installing the guest agent
# below would simply fail (measured: the first Ubuntu build hung forever with no agent, for
# precisely this reason). `package_upgrade` is what would actually consume the pending
# updates the tests need, and stays off.


def die(msg: str) -> None:
    print(f"lab: {msg}", file=sys.stderr)
    raise SystemExit(1)


def load_conf() -> dict:
    """Read lab.conf (KEY=value). Kept out of git — it names real hosts and keys."""
    if not CONF.is_file():
        die(f"no {CONF.name}; copy {CONF.name}.example and edit it")
    conf = {}
    for raw in CONF.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        conf[key.strip()] = val.strip().strip('"').strip("'")
    for required in ("LAB_HOST", "NETWORK", "IMAGE_DIR", "SSH_PUBKEY"):
        if not conf.get(required):
            die(f"{CONF.name} is missing {required}")
    conf.setdefault("VM_PREFIX", "fettle-")
    conf.setdefault("LIBVIRT_URI", "qemu:///system")
    conf.setdefault("RAM_MB", "2048")
    conf.setdefault("VCPUS", "2")
    # Only consulted for targets that ask for UEFI.
    conf.setdefault("OVMF_VARS", "/usr/share/edk2/x64/OVMF_VARS.4m.fd")
    conf.setdefault("OVMF_CODE", "/usr/share/edk2/x64/OVMF_CODE.4m.fd")
    return conf


def host_run(conf: dict, script: str, *, check: bool = True, quiet: bool = False):
    """Run a shell snippet on the lab host over ssh."""
    cmd = ["ssh", "-o", "BatchMode=yes", conf["LAB_HOST"], script]
    if not quiet:
        print(f"  [{conf['LAB_HOST']}] {script.splitlines()[0][:100]}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        die(f"remote command failed ({proc.returncode}):\n{proc.stderr.strip()}")
    return proc


def virsh(conf: dict, args: str, *, check: bool = True, quiet: bool = True):
    return host_run(conf, f"virsh -c {conf['LIBVIRT_URI']} {args}",
                    check=check, quiet=quiet)


def vm_name(conf: dict, target: str) -> str:
    return f"{conf['VM_PREFIX']}{target}"


def vm_exists(conf: dict, target: str) -> bool:
    return virsh(conf, f"dominfo {vm_name(conf, target)}", check=False).returncode == 0


def vm_ip(conf: dict, target: str) -> str | None:
    """Address via the guest agent.

    Not via DHCP leases: libvirt only knows those for networks it manages, and these VMs
    are bridged onto the real LAN. The agent is installed by cloud-init on first boot, so
    this returns None until that has finished.
    """
    name = vm_name(conf, target)
    proc = virsh(conf, f"domifaddr {name} --source agent 2>/dev/null", check=False)
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        # Rows look like:  enp1s0  52:54:00:..  ipv4  <addr>/<prefix>
        if len(parts) >= 4 and parts[2] == "ipv4" and not parts[3].startswith("127."):
            return parts[3].split("/")[0]
    return None




def forget_host_key(addr: str) -> None:
    """Drop any known_hosts entry for `addr` on the controlling machine.

    Lab VMs take DHCP addresses off the real LAN, so an address is very likely to have
    belonged to something else before. A stale entry makes ssh refuse the new host, and
    `scp` reports it only as "Connection closed" — which reads like a broken guest rather
    than a local trust problem. Measured: this is exactly what happened on the first VM.
    """
    subprocess.run(["ssh-keygen", "-R", addr], capture_output=True, text=True)


def trust_host_key(addr: str) -> None:
    """Record the guest's current host key on the controlling machine.

    Removing the stale entry is only half the job: an *unknown* host is just as fatal to
    anything non-interactive, because it cannot answer the first-contact prompt. `fettle
    remote` runs `scp -q`, which reports that only as "Connection closed" — measured, and
    indistinguishable from a broken guest until you run scp by hand.
    """
    known = Path("~/.ssh/known_hosts").expanduser()
    scan = subprocess.run(["ssh-keyscan", "-H", addr], capture_output=True, text=True)
    if scan.returncode == 0 and scan.stdout.strip():
        known.parent.mkdir(mode=0o700, exist_ok=True)
        with known.open("a") as fh:
            fh.write(scan.stdout)


def agent_exec(conf: dict, target: str, shell_cmd: str) -> None:
    """Run a shell command inside the guest through the qemu guest agent.

    Used to make the guest originate traffic before we try to reach it — see
    `wait_ready`. Best-effort: the agent may refuse `guest-exec`, and nothing here depends
    on the output.
    """
    payload = json.dumps({"execute": "guest-exec", "arguments": {
        "path": "/bin/sh", "arg": ["-c", shell_cmd], "capture-output": False}})
    virsh(conf, f"qemu-agent-command {vm_name(conf, target)} {shlex.quote(payload)}",
          check=False)


def wait_ready(conf: dict, target: str, *, tries: int = 60) -> str:
    """Block until the guest is actually usable, and return its address.

    **An address is not readiness.** Some cloud images (Arch's, measured) ship
    `qemu-guest-agent` preinstalled, so the agent answers within seconds — long before
    cloud-init has injected the ssh key or finished configuring the box. Waiting on the
    address alone snapshots a half-built machine.

    There is also a networking trap: a freshly booted bridged guest is unreachable from
    outside until it has originated traffic, because nothing upstream has learned its MAC
    yet. Pinging the gateway from inside primes that; without it, ssh times out forever on
    a guest that is perfectly healthy.

    So: get an address, prime the path from inside, then poll ssh — which is the only
    signal that actually means "usable".
    """
    spec = TARGETS[target]
    addr = None
    for _ in range(tries):
        if not addr:
            addr = vm_ip(conf, target)
            if addr:
                forget_host_key(addr)
        if addr:
            # Prime the bridge/switch MAC learning from the guest side.
            agent_exec(conf, target, "ping -c2 -W2 $(ip route | "
                                     "awk '/^default/{print $3}') >/dev/null 2>&1")
            probe = subprocess.run(
                ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
                 f"{spec['user']}@{addr}", "cloud-init status --wait >/dev/null 2>&1; true"],
                capture_output=True, text=True)
            if probe.returncode == 0:
                trust_host_key(addr)
                return addr
        time.sleep(10)
        print("    ...")
    die(f"{vm_name(conf, target)} never became reachable"
        + (f" (agent reports {addr})" if addr else " (no address from the guest agent)")
        + f"\n     console log: {conf['LAB_HOST']}:{conf['IMAGE_DIR']}/"
          f"{vm_name(conf, target)}-console.log")
    return ""


def cmd_targets(conf, args) -> int:
    print(f"{'target':10} {'user':10} {'disk':6} note")
    for name, spec in sorted(TARGETS.items()):
        print(f"{name:10} {spec['user']:10} {spec['disk']:6} {spec['note']}")
    return 0


def cmd_list(conf, args) -> int:
    print(f"{'target':10} {'state':10} {'snapshot':10} address")
    for name in sorted(TARGETS):
        if not vm_exists(conf, name):
            print(f"{name:10} {'-':10} {'-':10} -")
            continue
        state = (virsh(conf, f"domstate {vm_name(conf, name)}").stdout or "").strip()
        snaps = virsh(conf, f"snapshot-list {vm_name(conf, name)} --name",
                      check=False).stdout or ""
        pristine = "pristine" if "pristine" in snaps else "-"
        addr = vm_ip(conf, name) if state == "running" else None
        print(f"{name:10} {state:10} {pristine:10} {addr or '-'}")
    return 0


def cmd_build(conf, args) -> int:
    target = args.target
    spec = TARGETS.get(target) or die(f"unknown target {target!r}")
    name = vm_name(conf, target)
    if vm_exists(conf, target):
        die(f"{name} already exists — `lab.py destroy {target}` first")

    pubkey = Path(conf["SSH_PUBKEY"]).expanduser().read_text().strip()
    imgdir, base = conf["IMAGE_DIR"], f"{conf['IMAGE_DIR']}/base"
    url = spec["url"]
    image = url.rsplit("/", 1)[-1]

    print(f"==> {name}: preparing on {conf['LAB_HOST']}")
    host_run(conf, f"mkdir -p {shlex.quote(base)} {shlex.quote(imgdir)}")

    # Download once and keep it. The base image is the lab's time anchor — see the module
    # docstring on snapshot pinning.
    print(f"==> downloading {image} (skipped if already present)")
    host_run(conf, f"cd {shlex.quote(base)} && "
                   f"[ -f {shlex.quote(image)} ] || curl -fL --retry 3 -O {shlex.quote(url)}")
    stamp = (host_run(conf, f"date -u -r {shlex.quote(base + '/' + image)} "
                            "+%Y-%m-%dT%H:%M:%SZ", quiet=True).stdout or "").strip()
    print(f"    base image fetched {stamp} — this is the lab's baseline date")

    # Overlay so the pristine download is never written to.
    disk = f"{imgdir}/{name}.qcow2"
    seed = f"{imgdir}/{name}-seed.iso"
    print(f"==> creating {spec['disk']} overlay")
    host_run(conf, f"rm -f {shlex.quote(disk)} {shlex.quote(seed)}", quiet=True)
    host_run(conf, f"qemu-img create -f qcow2 -F qcow2 -b {shlex.quote(base + '/' + image)} "
                   f"{shlex.quote(disk)} {spec['disk']}")

    # Seed ISO. cloud-localds if present, else genisoimage — both produce a `cidata`
    # volume with user-data and meta-data at the root, which is all NoCloud requires.
    # Extra packages are baked in at build time so they survive `reset` — installing a
    # prerequisite by hand after the snapshot means the next revert silently loses it.
    extra = "".join(f"  - {pkg}\n" for pkg in spec.get("packages", ()))
    user_data = USER_DATA.format(host=name, user=spec["user"], pubkey=pubkey,
                                 extra_packages=extra)
    meta_data = f"instance-id: {name}-01\nlocal-hostname: {name}\n"
    print("==> building cloud-init seed")
    host_run(conf, "set -e; d=$(mktemp -d); "
                   f"cat > $d/user-data <<'EOF'\n{user_data}EOF\n"
                   f"cat > $d/meta-data <<'EOF'\n{meta_data}EOF\n"
                   f"if command -v cloud-localds >/dev/null; then "
                   f"  cloud-localds {shlex.quote(seed)} $d/user-data $d/meta-data; "
                   f"else "
                   f"  genisoimage -quiet -output {shlex.quote(seed)} -volid cidata "
                   f"    -joliet -rock $d/user-data $d/meta-data; fi; rm -rf $d")

    # `boot.order` is explicit, and is not optional once the seed is a second virtio
    # disk: without it the firmware tried to boot the seed on Debian and looped forever
    # printing "Booting `Debian GNU/Linux'". Ubuntu happened to survive the same layout,
    # which is exactly why this needs pinning rather than leaving to chance.
    #
    # The seed is attached as a read-only virtio DISK, not a cdrom. NoCloud finds it
    # either way in principle — it probes for a filesystem labelled `cidata` — but
    # cloud-init's early `ds-identify` pass did not see it as an emulated SCSI cdrom on
    # Ubuntu 26.04, and when ds-identify finds no datasource it disables cloud-init for
    # that boot **silently**: no console output, no /var/log/cloud-init.log, a guest that
    # boots perfectly to a login prompt with none of your config applied.
    #
    # The serial console is logged to a file: without it, a guest that never brings up
    # networking or the agent is undiagnosable — there is nothing to look at, and `virsh
    # console` needs an interactive tty. Measured the hard way on the first Ubuntu build.
    #
    # `name=` is required: --osinfo takes EITHER a bare short-id OR key=value pairs, so a
    # bare id with a comma after it parses as an unknown KEY ("Unknown --osinfo options").
    # `require=off` because brand-new releases are often missing from the local osinfo-db
    # and virt-install errors out rather than guessing — Ubuntu 26.04 has no entry yet.
    #
    # Default (BIOS/SeaBIOS) boot: every cloud image here carries a BIOS boot partition,
    # and firmware selection is one more thing to go wrong for no benefit in a test lab.
    # How the seed is attached is per-target, because the distros genuinely differ:
    #
    #   * cdrom  — works everywhere it works, and is the conventional NoCloud form.
    #   * disk   — needed on Ubuntu 26.04, whose early `ds-identify` pass did not see an
    #     emulated SCSI cdrom and therefore disabled cloud-init for the whole boot,
    #     SILENTLY: no console output, no /var/log/cloud-init.log, a guest that reaches a
    #     login prompt with none of the requested config applied.
    #
    # Forcing `disk` on everything is not the answer: Debian's genericcloud image then
    # loops at GRUB forever printing "Booting `Debian GNU/Linux\'", with or without an
    # explicit boot order. So each target says what it needs.
    seed_attach = ("device=disk,bus=virtio,readonly=on" if spec.get("seed") == "disk"
                   else "device=cdrom")
    # Firmware, per target. `--boot uefi` is the modern flag; BIOS must emit **nothing**,
    # because current virt-install rejects `--boot bios` as an unknown option. (Both
    # conventions taken from the labctl lab manager in ~/src/bifrost, which drives this
    # same hypervisor.)
    firmware_arg = ""
    if spec.get("firmware") == "uefi":
        # UEFI needs one more thing than just `--boot uefi`: libvirt refuses an internal
        # snapshot of a pflash VM unless the NVRAM is qcow2 ("internal snapshots of a VM
        # with pflash based firmware require QCOW2 nvram format"), and virt-install 5.1
        # has no `nvram.format`. It does have `nvram.templateFormat` — so convert the
        # firmware's VARS template to qcow2 once and let libvirt inherit the format.
        nvram_tpl = f"{base}/OVMF_VARS.qcow2"
        host_run(conf, f"[ -f {shlex.quote(nvram_tpl)} ] || qemu-img convert -f raw "
                       f"-O qcow2 {shlex.quote(conf['OVMF_VARS'])} "
                       f"{shlex.quote(nvram_tpl)}", quiet=True)
        # The loader is named explicitly rather than using `--boot uefi`: libvirt's
        # firmware auto-selection matches against its shipped descriptors, and handing it
        # a qcow2 VARS template makes that match fail outright ("Unable to find 'efi'
        # firmware that is compatible with the current configuration").
        firmware_arg = (f"--boot loader={shlex.quote(conf['OVMF_CODE'])},"
                        f"loader.readonly=yes,loader.type=pflash,"
                        f"nvram.template={shlex.quote(nvram_tpl)},"
                        f"nvram.templateFormat=qcow2 ")
    print(f"==> virt-install {name}")
    host_run(conf,
             f"virt-install --connect {conf['LIBVIRT_URI']} --name {name} "
             f"--memory {conf['RAM_MB']} --vcpus {conf['VCPUS']} --import "
             f"--disk path={shlex.quote(disk)},format=qcow2,bus=virtio,boot.order=1 "
             f"--disk path={shlex.quote(seed)},{seed_attach},boot.order=2 "
             f"--network network={conf['NETWORK']},model=virtio "
             f"--channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 "
             f"--osinfo name={spec['osinfo']},require=off --virt-type kvm "
             f"{firmware_arg}"
             f"--serial file,path={shlex.quote(imgdir + '/' + name + '-console.log')} "
             f"--graphics none --noautoconsole")

    print("==> waiting for the guest to become usable (address, then ssh)")
    addr = wait_ready(conf, target)
    print(f"==> {name} is up and reachable at {addr}")

    # Snapshot LAST, so the baseline includes cloud-init's work but none of the tests'.
    print("==> snapshotting 'pristine'")
    virsh(conf, f"snapshot-create-as {name} pristine "
                f"'fettle lab baseline; base image {stamp}' --atomic", quiet=False)
    print(f"\n{name} ready. Baseline snapshot taken; `lab.py reset {target}` returns here.")
    print(f"Try: fettle remote {addr} -O --dry-run")
    return 0


def cmd_reset(conf, args) -> int:
    name = vm_name(conf, args.target)
    if not vm_exists(conf, args.target):
        die(f"{name} does not exist")
    print(f"==> reverting {name} to pristine")
    virsh(conf, f"snapshot-revert {name} pristine --running", quiet=False)
    addr = wait_ready(conf, args.target, tries=30)
    print(f"==> {name} back at {addr}")
    return 0


def cmd_ip(conf, args) -> int:
    addr = vm_ip(conf, args.target)
    if not addr:
        die(f"{vm_name(conf, args.target)} has no address (not running, or agent absent)")
    print(addr)
    return 0


def cmd_ssh(conf, args) -> int:
    spec = TARGETS.get(args.target) or die(f"unknown target {args.target!r}")
    addr = vm_ip(conf, args.target) or die("no address; is it running?")
    cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           f"{spec['user']}@{addr}", *args.rest]
    return subprocess.run(cmd).returncode


def cmd_destroy(conf, args) -> int:
    name = vm_name(conf, args.target)
    if not vm_exists(conf, args.target):
        print(f"{name} does not exist")
        return 0
    addr = vm_ip(conf, args.target)
    if addr:
        forget_host_key(addr)
    print(f"==> destroying {name} (base image is kept)")
    virsh(conf, f"destroy {name}", check=False)
    virsh(conf, f"snapshot-delete {name} pristine --metadata", check=False)
    virsh(conf, f"undefine {name} --nvram --remove-all-storage", check=False, quiet=False)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("targets", help="list buildable distro targets")
    sub.add_parser("list", help="show VM state and addresses")
    for name, help_text in [("build", "build a VM and snapshot it"),
                            ("reset", "revert to the pristine snapshot"),
                            ("ip", "print the VM's address"),
                            ("destroy", "remove the VM and its disks")]:
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("target")
    sp = sub.add_parser("ssh", help="ssh into the VM")
    sp.add_argument("target")
    sp.add_argument("rest", nargs=argparse.REMAINDER)

    args = p.parse_args(argv)
    conf = load_conf()
    return {
        "targets": cmd_targets, "list": cmd_list, "build": cmd_build,
        "reset": cmd_reset, "ip": cmd_ip, "ssh": cmd_ssh, "destroy": cmd_destroy,
    }[args.cmd](conf, args)


if __name__ == "__main__":
    raise SystemExit(main())
