"""Running-process provenance — Phase 3.

The measured floor on the reference desktop: **0** memfd processes, **0** unowned
listener binaries, **0** regular files under `/dev`, and **0** promiscuous interfaces
once bridge ports are excluded. Two processes run deleted binaries and neither is High.

Two calibrations here came from the check being wrong on that machine first, and both
have a test that fails if the calibration is removed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fettle.backends.base import Context
from fettle.compromise import CRITICAL, HIGH, LOW, MEDIUM, processes
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


def _proc(root: Path, pid: int, exe: str, *, cmdline="thing --run") -> None:
    """A fake /proc/<pid> whose `exe` symlink points where we want.

    The symlink deliberately dangles: `os.readlink` reports the target regardless, and
    that is what the check reads. A resolvable target would need the whole tree.
    """
    d = root / f"proc/{pid}"
    d.mkdir(parents=True, exist_ok=True)
    os.symlink(exe, d / "exe")
    (d / "cmdline").write_bytes(cmdline.replace(" ", "\0").encode() + b"\0")


def _iface(root: Path, name: str, flags: int, *, bridge_port=False) -> None:
    d = root / f"sys/class/net/{name}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "flags").write_text(f"0x{flags:x}\n")
    if bridge_port:
        (d / "brport").mkdir()


# --------------------------------------------------------------- fileless execution


def test_a_process_running_from_memory_is_critical(tmp_path):
    """chkrootkit 0.59's best idea, implemented so that it can actually match.

    Its own version cannot: the pattern anchors `^` to a line beginning `lrwxrwxrwx`
    and uses a PCRE lazy quantifier that plain grep reads literally.
    """
    _proc(tmp_path, 31337, "/memfd:payload (deleted)", cmdline="[kworker/0:2]")
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "memfd-exec"]
    assert len(found) == 1
    assert found[0].severity == CRITICAL
    assert "never written to disk" in found[0].detail
    assert "[kworker/0:2]" in found[0].detail, "the command line is the identifying bit"
    assert "/proc/31337/exe" in found[0].fix, "capture it before it exits"


def test_an_ordinary_process_is_not_a_finding(tmp_path):
    _proc(tmp_path, 100, "/usr/bin/bash")
    assert processes.run(_Backend(), _ctx(tmp_path)).findings == []


# ------------------------------------------------------------- deleted but running


def test_a_deleted_binary_from_tmp_is_high(tmp_path):
    """Ran from /tmp and then deleted itself — how a dropper covers its tracks."""
    _proc(tmp_path, 200, "/tmp/.x/agent (deleted)")
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "deleted-exe"]
    assert [f.severity for f in found] == [HIGH]
    assert "/tmp" in found[0].detail


def test_a_deleted_appimage_in_a_normal_place_is_low(tmp_path):
    """The reference machine's real case: a self-updating AppImage in ~/.local/bin.

    True and worth knowing — the process is running code that is no longer on disk —
    but not an alarm, because that is what self-updating applications do.
    """
    _proc(tmp_path, 201, "/home/paulda/.local/bin/thing.AppImage (deleted)")
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "deleted-exe"]
    assert [f.severity for f in found] == [LOW]


def test_a_package_owned_deleted_binary_is_a_note_not_a_finding(tmp_path):
    """An upgrade replaced it while it was running. The useful advice is "restart"."""
    _proc(tmp_path, 202, "/usr/lib/signal-desktop/signal-desktop (deleted)")
    res = processes.run(_Backend(owned=["/usr/lib/signal-desktop/signal-desktop"]),
                        _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "deleted-exe"] == []
    assert any("restarting them" in n for n in res.notes)


# ----------------------------------------------------------------- listening sockets


def _net(root: Path, rel: str, rows: list[tuple[int, str, str]]) -> None:
    """rows: (port, state, inode)."""
    lines = ["  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
             "retrnsmt   uid  timeout inode"]
    for i, (port, state, inode) in enumerate(rows):
        lines.append(f"{i}: 00000000:{port:04X} 00000000:0000 {state} "
                     f"00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 x")
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_text("\n".join(lines) + "\n")


def _listening_proc(root: Path, pid: int, exe: str, inode: str) -> None:
    _proc(root, pid, exe)
    fd = root / f"proc/{pid}/fd"
    fd.mkdir(parents=True, exist_ok=True)
    os.symlink(f"socket:[{inode}]", fd / "3")


def test_an_unowned_listener_is_a_finding(tmp_path):
    """A port number means nothing; a listener nobody can account for means something."""
    _net(tmp_path, "proc/net/tcp", [(0x1F90, "0A", "55501")])
    _listening_proc(tmp_path, 300, "/opt/vendor/agent", "55501")
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-listener"]
    assert len(found) == 1
    assert found[0].severity == MEDIUM
    assert "tcp/8080" in found[0].detail


def test_an_unowned_listener_running_from_tmp_is_worse(tmp_path):
    _net(tmp_path, "proc/net/tcp", [(0x115C, "0A", "55502")])
    _listening_proc(tmp_path, 301, "/dev/shm/.x/backdoor", "55502")
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "unowned-listener"]
    assert [f.severity for f in found] == [HIGH]


def test_a_packaged_listener_is_silent(tmp_path):
    _net(tmp_path, "proc/net/tcp", [(0x0016, "0A", "55503")])
    _listening_proc(tmp_path, 302, "/usr/bin/sshd", "55503")
    res = processes.run(_Backend(owned=["/usr/bin/sshd"]), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-listener"] == []


def test_established_connections_are_not_listeners(tmp_path):
    """State 01 is ESTABLISHED. Only 0A is LISTEN."""
    _net(tmp_path, "proc/net/tcp", [(0x1F90, "01", "55504")])
    _listening_proc(tmp_path, 303, "/opt/vendor/agent", "55504")
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-listener"] == []


def test_unresolvable_sockets_are_blind_not_absent(tmp_path):
    """Unprivileged, 9 of 26 listeners resolved on the reference machine.

    Reporting "no unowned listeners" from a third of the data is a clean result over an
    unasked question — the failure this whole action exists to avoid.
    """
    _net(tmp_path, "proc/net/tcp", [(0x1F90, "0A", "99999")])   # no process owns it
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "unowned-listener"] == []
    assert any("listening socket" in what for what, _, _ in res.blind)


# -------------------------------------------------------------------- interfaces


def test_a_promiscuous_interface_is_reported(tmp_path):
    _iface(tmp_path, "eth0", 0x1303)
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "promiscuous-interface"]
    assert [f.severity for f in found] == [MEDIUM]
    assert "promiscuity" in found[0].fix, "ip's flag list does NOT show this — say so"


def test_bridge_ports_are_excluded_and_counted(tmp_path):
    """Without this the check fires on every VM host and every container host.

    Both promiscuous interfaces on the reference machine are bridge ports: the physical
    NIC enslaved to bridge0 for VMs, and a veth on a docker bridge. A bridge member has
    to accept frames not addressed to it — that is what bridging is.
    """
    _iface(tmp_path, "enp68s0", 0x1303, bridge_port=True)
    _iface(tmp_path, "veth9b83fe1", 0x1303, bridge_port=True)
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "promiscuous-interface"] == []
    assert any("bridge ports" in n and "enp68s0" in n for n in res.notes), (
        "excluded, but still counted — silent filtering is indistinguishable from "
        "having found nothing")


def test_a_normal_interface_is_silent(tmp_path):
    _iface(tmp_path, "eth0", 0x1003)          # up, broadcast, multicast; no promisc
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert res.findings == []
    assert res.checked >= 1


# ------------------------------------------------------------------- /dev contents


def test_a_regular_file_under_dev_is_a_finding(tmp_path):
    (tmp_path / "dev").mkdir()
    (tmp_path / "dev/.hidden-payload").write_text("x")
    found = [f for f in processes.run(_Backend(), _ctx(tmp_path)).findings
             if f.check == "dev-regular-file"]
    assert [f.severity for f in found] == [MEDIUM]
    assert ".hidden-payload" in found[0].detail


@pytest.mark.parametrize("exempt", ["shm", "pts", "mqueue", "hugepages"])
def test_the_filesystems_mounted_inside_dev_are_exempt(tmp_path, exempt):
    """/dev/shm is legitimately full of regular files — every browser uses it."""
    (tmp_path / f"dev/{exempt}").mkdir(parents=True)
    (tmp_path / f"dev/{exempt}/something").write_text("x")
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "dev-regular-file"] == []


def test_device_nodes_are_not_regular_files(tmp_path):
    """The check must not fire on /dev doing its actual job."""
    (tmp_path / "dev").mkdir()
    os.mkfifo(tmp_path / "dev/initctl")       # a FIFO is not a regular file
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert [f for f in res.findings if f.check == "dev-regular-file"] == []


# ------------------------------------------------------------------------ coverage


def test_an_unreadable_proc_is_blind_not_clean(tmp_path):
    res = processes.run(_Backend(), _ctx(tmp_path))
    assert any("running processes" in what for what, _, _ in res.blind)
    assert res.findings == []
