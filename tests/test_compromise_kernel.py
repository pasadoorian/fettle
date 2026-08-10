"""Kernel, loader and boot-chain integrity — Phase 2.

Every check here is measured against the reference desktop before it is trusted, and
two of them exist in their current form only because the obvious implementation was
wrong on that machine by a wide margin. Those two are called out in their own tests.

A detection that has never detected anything is not a detection, so each check gets a
planted positive control alongside the clean-machine negative.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fettle.backends.base import Context
from fettle.compromise import CRITICAL, HIGH, LOW, MEDIUM, boot, kernel
from fettle.config import Config
from fettle.output import Output


class _Backend:
    name = "arch"

    def __init__(self, owned=()):
        self._owned = {str(p): "somepkg" for p in owned}

    def map_files_to_packages(self, paths):
        return {p: self._owned[p] for p in map(str, paths) if p in self._owned}


def _ctx(root: Path) -> Context:
    return Context(output=Output(color=False), config=Config(), root=root,
                   user_home=root, dry_run=True)


def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _sysroot(root: Path, *, modules="wireguard 122880 0 - Live 0x0\n",
             taint="0", sig_enforce="N") -> None:
    """The minimum /proc and /sys a kernel-group run needs to not be blind."""
    _write(root, "proc/modules", modules)
    _write(root, "proc/sys/kernel/tainted", taint + "\n")
    _write(root, "sys/module/module/parameters/sig_enforce", sig_enforce + "\n")


# ------------------------------------------------------------------- ld.so.preload


def test_ld_so_preload_absent_is_the_normal_case(tmp_path):
    _sysroot(tmp_path)
    res = kernel.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "ld-preload"] == []


def test_ld_so_preload_existing_is_the_finding(tmp_path):
    """A stock Arch, Debian or RHEL system does not have this file at all."""
    _sysroot(tmp_path)
    _write(tmp_path, "etc/ld.so.preload", "/usr/lib/libhide.so\n")
    res = kernel.run(_Backend(), _ctx(tmp_path))
    found = [f for f in res.findings if f.check == "ld-preload"]
    assert len(found) == 1
    assert found[0].severity == HIGH
    assert "/usr/lib/libhide.so" in found[0].detail
    assert "no package owns it" in found[0].detail


def test_a_packaged_preload_says_who_owns_it(tmp_path):
    """`libeatmydata` is a real, legitimate user of this file."""
    _sysroot(tmp_path)
    _write(tmp_path, "etc/ld.so.preload", "/usr/lib/libeatmydata.so\n")
    res = kernel.run(_Backend(owned=["/usr/lib/libeatmydata.so"]), _ctx(tmp_path))
    found = [f for f in res.findings if f.check == "ld-preload"][0]
    assert "somepkg" in found.detail, "the owning package is named, not just the path"


def test_comments_and_blank_lines_are_not_preloads(tmp_path):
    _sysroot(tmp_path)
    _write(tmp_path, "etc/ld.so.preload", "# nothing here\n\n")
    found = [f for f in kernel.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "ld-preload"][0]
    assert "the file is empty" in found.detail


# --------------------------------------------------------------- modules and taint


def test_a_clean_kernel_reports_no_module_findings(tmp_path):
    _sysroot(tmp_path, taint="0")
    res = kernel.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if "module" in f.check or "taint" in f.check] == []
    assert res.checked >= 1


def test_taint_with_no_loaded_module_to_explain_it(tmp_path):
    """The reference machine's actual state: 12288, and 155 clean modules.

    Bits 12 and 13 — out-of-tree and unsigned — set, while nothing currently loaded
    admits to either. Taint is sticky and never names its cause, so this says a module
    was loaded and unloaded, which is a DKMS rebuild almost every time and a
    self-removing LKM rootkit occasionally. Low, with the boring explanation first.
    """
    _sysroot(tmp_path, taint="12288")
    found = [f for f in kernel.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unexplained-taint"]
    assert len(found) == 1
    assert found[0].severity == LOW
    assert "DKMS" in found[0].detail, "the ordinary explanation is named first"
    assert "rootkit" in found[0].detail, "and the other one is not hidden"
    assert "journalctl" in found[0].fix


def test_taint_explained_by_a_loaded_module_is_not_a_finding(tmp_path):
    """A vendor driver that is still loaded explains its own taint. Nothing to say."""
    _sysroot(tmp_path, modules="nvidia 1 0 - Live 0x0\n", taint="12288")
    _write(tmp_path, "sys/module/nvidia/taint", "OE\n")
    res = kernel.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unexplained-taint"] == []
    assert any("accounted for" in n for n in res.notes)


def test_an_unsigned_module_is_reported_with_the_enforcement_state(tmp_path):
    """"No unsigned modules" means nothing if nothing would refuse one."""
    _sysroot(tmp_path, modules="evil 1 0 - Live 0x0\n", taint="8192", sig_enforce="N")
    _write(tmp_path, "sys/module/evil/taint", "E\n")
    found = [f for f in kernel.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unsigned-module"][0]
    assert found.severity == MEDIUM, "enforcement off: it got in because nothing stopped it"
    assert "enforcement is off" in found.detail


def test_an_unsigned_module_with_enforcement_on_is_worse(tmp_path):
    _sysroot(tmp_path, modules="evil 1 0 - Live 0x0\n", taint="8192", sig_enforce="Y")
    _write(tmp_path, "sys/module/evil/taint", "E\n")
    found = [f for f in kernel.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unsigned-module"][0]
    assert found.severity == HIGH, "enforcement on: it should not have been possible"


def test_unreadable_proc_modules_is_blind_not_clean(tmp_path):
    _write(tmp_path, "proc/sys/kernel/tainted", "0\n")
    res = kernel.run(_Backend(), _ctx(tmp_path))
    assert any("kernel modules" in what for what, _, _ in res.blind)


# ---------------------------------------------------------------- hidden processes


def _fake_procfs(root: Path, listed, cgrouped) -> None:
    for pid in listed:
        (root / f"proc/{pid}").mkdir(parents=True, exist_ok=True)
    cg = root / "sys/fs/cgroup/system.slice"
    cg.mkdir(parents=True, exist_ok=True)
    (cg / "cgroup.procs").write_text("".join(f"{p}\n" for p in cgrouped))


def test_agreement_between_proc_and_cgroups_is_silence(tmp_path):
    _sysroot(tmp_path)
    _fake_procfs(tmp_path, listed=[1, 2, 3], cgrouped=[1, 2, 3])
    res = kernel.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "hidden-process"] == []


def test_a_pid_in_cgroups_but_not_in_proc_is_critical(tmp_path):
    """The positive control for a getdents64 hook.

    ps, top and pgrep all read /proc, so none of them would show this either — which is
    the whole reason a second interface is consulted.
    """
    _sysroot(tmp_path)
    _fake_procfs(tmp_path, listed=[1, 2], cgrouped=[1, 2, 31337])
    found = [f for f in kernel.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "hidden-process"]
    assert len(found) == 1
    assert found[0].severity == CRITICAL
    assert "31337" in found[0].detail
    assert "getdents64" in found[0].detail


def test_no_cgroups_is_blind_and_does_not_blank_the_group(tmp_path):
    """The `res.na` trap, caught during Phase 2 and worth a permanent guard.

    `na` is a property of the whole group. Setting it from this sub-check would have
    rendered the entire kernel group as "not applicable" on any host without cgroups —
    hiding the ld.so.preload finding sitting right next to it.
    """
    _sysroot(tmp_path)
    _write(tmp_path, "etc/ld.so.preload", "/tmp/evil.so\n")
    res = kernel.run(_Backend(), _ctx(tmp_path))

    assert not res.na, "a sub-check must never mark the whole group not-applicable"
    assert any("hidden processes" in what for what, _, _ in res.blind)
    assert [f.check for f in res.findings] == ["ld-preload"], "the sibling still reports"


def test_the_thread_trap_is_documented_where_it_will_be_read():
    """6,272 false positives on the reference machine, from the obvious implementation.

    Every non-leader thread answers a direct `/proc/<tid>` stat while `readdir` lists
    only thread-group leaders. This asserts the number stays in the docstring, because
    the next person to reach for the classic chkproc approach needs to meet it.
    """
    assert "6,272" in kernel._hidden_processes.__doc__
    assert "7.8" in kernel._hidden_processes.__doc__      # the cost of the fixed version


# --------------------------------------------------------------------- eBPF surface


def test_the_aur_wave_pin_names_are_critical(tmp_path):
    """A name match against a known campaign, not an inference."""
    _sysroot(tmp_path)
    bpf = tmp_path / "sys/fs/bpf"
    bpf.mkdir(parents=True)
    for name in ("hidden_pids", "hidden_names", "cilium_ct4_global"):
        (bpf / name).write_text("")
    found = [f for f in kernel.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "bpf-ioc-pin"]
    assert len(found) == 1
    assert found[0].severity == CRITICAL
    assert "hidden_pids" in found[0].subject and "hidden_names" in found[0].subject
    assert "cilium" not in found[0].subject, "only the campaign names are the finding"


def test_ordinary_pins_are_listed_not_judged(tmp_path):
    """systemd, docker and Cilium all pin legitimately."""
    _sysroot(tmp_path)
    bpf = tmp_path / "sys/fs/bpf"
    bpf.mkdir(parents=True)
    (bpf / "cilium_ct4_global").write_text("")
    res = kernel.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "bpf-ioc-pin"] == []
    assert any("cilium_ct4_global" in n for n in res.notes)


@pytest.mark.skipif(os.geteuid() == 0, reason="chmod 000 does not apply to root")
def test_an_unreadable_bpf_directory_is_blind(tmp_path):
    """`/sys/fs/bpf` is drwx-----T root:root — this is the normal unprivileged case."""
    _sysroot(tmp_path)
    bpf = tmp_path / "sys/fs/bpf"
    bpf.mkdir(parents=True)
    bpf.chmod(0o000)
    try:
        res = kernel.run(_Backend(), _ctx(tmp_path))
        assert any("pinned eBPF" in what for what, _, _ in res.blind)
    finally:
        bpf.chmod(0o755)


def test_the_ebpf_blind_spot_is_stated_not_implied(tmp_path):
    """A clean eBPF result is weaker than a clean result elsewhere, and must say so."""
    assert "hooks" in kernel._ebpf.__doc__ and "bpftool" in kernel._ebpf.__doc__


# ----------------------------------------------------------------------- boot chain


GRUB_CFG = "menuentry 'Linux' {\n  linux /vmlinuz root=/dev/sda1 rw\n}\n"


def test_a_clean_grub_config_reports_nothing(tmp_path):
    _write(tmp_path, "boot/grub/grub.cfg", GRUB_CFG)
    res = boot.run(_Backend(), _ctx(tmp_path))
    assert res.findings == []
    assert res.checked >= 1


def test_bootkitty_style_ld_preload_in_the_boot_config(tmp_path):
    """chkrootkit 0.59's Bootkitty check, which is the right threat to look for."""
    _write(tmp_path, "boot/grub/grub.cfg",
           GRUB_CFG + "export LD_PRELOAD=/boot/evil.so\n")
    found = boot.run(_Backend(), _ctx(tmp_path)).findings
    assert [f.severity for f in found] == [HIGH]
    assert "LD_PRELOAD" in found[0].detail


def test_an_init_pointing_into_a_world_writable_directory(tmp_path):
    _write(tmp_path, "boot/grub/grub.cfg",
           "menuentry 'x' {\n  linux /vmlinuz init=/dev/shm/.x/init\n}\n")
    found = boot.run(_Backend(), _ctx(tmp_path)).findings
    assert [f.severity for f in found] == [HIGH]


def test_systemd_boot_is_read_when_that_is_the_bootloader(tmp_path):
    """Reporting "grub looks clean" on a systemd-boot machine is worse than silence."""
    _write(tmp_path, "boot/loader/loader.conf", "default arch\ntimeout 3\n")
    _write(tmp_path, "boot/loader/entries/arch.conf",
           "title Arch\nlinux /vmlinuz-linux\noptions init=/tmp/x root=/dev/sda2\n")
    found = boot.run(_Backend(), _ctx(tmp_path)).findings
    assert [f.severity for f in found] == [HIGH]
    assert "systemd-boot" in found[0].detail


def test_no_bootloader_config_is_not_applicable(tmp_path):
    """The container case — and here `na` on the whole group is correct."""
    res = boot.run(_Backend(), _ctx(tmp_path))
    assert res.na
    assert res.findings == []


def test_the_generated_config_is_never_judged_on_ownership(tmp_path):
    """`/boot/grub/grub.cfg` is generated by grub-mkconfig and no package owns it.

    Measured on the reference machine. The same asymmetry as user crontabs: judge
    generated files on content, and only hand-edited sources on provenance.
    """
    _write(tmp_path, "boot/grub/grub.cfg", GRUB_CFG)      # deliberately unowned
    res = boot.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-boot-config"] == []


def test_an_unowned_hand_edited_source_is_a_finding(tmp_path):
    _write(tmp_path, "boot/grub/grub.cfg", GRUB_CFG)
    _write(tmp_path, "etc/grub.d/99_backdoor", "#!/bin/sh\necho hi\n")
    found = [f for f in boot.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-boot-config"]
    assert len(found) == 1 and found[0].severity == MEDIUM


def test_secure_boot_state_accompanies_every_boot_result(tmp_path):
    """wopr's grub config is clean AND Secure Boot is off in setup mode.

    Printing the first without the second is the half-truth that makes a report feel
    reassuring and be worthless.
    """
    _write(tmp_path, "boot/grub/grub.cfg", GRUB_CFG)
    res = boot.run(_Backend(), _ctx(tmp_path))
    assert any("Secure Boot" in n or "UEFI" in n for n in res.notes)


def test_secure_boot_enabled_is_read_from_the_efi_variable(tmp_path):
    _write(tmp_path, "boot/grub/grub.cfg", GRUB_CFG)
    efivars = tmp_path / "sys/firmware/efi/efivars"
    efivars.mkdir(parents=True)
    # 4 attribute bytes, then the boolean.
    (efivars / "SecureBoot-8be4df61").write_bytes(b"\x06\x00\x00\x00\x01")
    res = boot.run(_Backend(), _ctx(tmp_path))
    assert any("Secure Boot is enabled" in n for n in res.notes)


def test_secure_boot_disabled_says_what_that_costs(tmp_path):
    _write(tmp_path, "boot/grub/grub.cfg", GRUB_CFG)
    efivars = tmp_path / "sys/firmware/efi/efivars"
    efivars.mkdir(parents=True)
    (efivars / "SecureBoot-8be4df61").write_bytes(b"\x06\x00\x00\x00\x00")
    res = boot.run(_Backend(), _ctx(tmp_path))
    assert any("Nothing cryptographically verifies" in n for n in res.notes)
