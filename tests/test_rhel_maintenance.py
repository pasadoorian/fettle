"""RHEL maintenance actions — refresh, pending upgrades, transaction preview.

Fixtures are real output: `_CU` from `dnf check-update` on a RHEL 10.1 / CentOS Stream
box (dnf 4.20, rootless), `_CU5` from the same command on Fedora 44 (dnf5 5.4.2). The
two formats differ in ways that broke a naive parser, so both are pinned here.
"""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.backends.rhel import RhelBackend
from fettle.config import Config
from fettle.output import Output

# dnf4, rootless. Note the "Not root" notice, the metadata-age line, and the
# "Obsoleting Packages" block that repeats fwupd (already listed above) with the
# obsoleted package indented beneath it.
_CU = """\
Not root, Subscription Management repositories not updated
Last metadata expiration check: 6:16:36 ago on Wed Jul 29 15:35:52 2026.

NetworkManager.x86_64                     1:1.58~rc1-1.el10           centos-stream-baseos
attr.x86_64                               2.6.0-2.el10                centos-stream-baseos
fwupd.x86_64                              2.1.6-1.el10                centos-stream-baseos
glibc.i686                                2.41-8.el10                 centos-stream-baseos
glibc.x86_64                              2.41-8.el10                 centos-stream-baseos

Obsoleting Packages
fwupd.x86_64                              2.1.6-1.el10                centos-stream-baseos
    fwupd-plugin-flashrom.x86_64          1.9.31-1.el10               @System
samba-ndr-libs.x86_64                     4.24.3-100.el10             centos-stream-baseos
    samba-common-libs.x86_64              4.22.4-106.el10_1           @System
"""

# dnf5 leads with a bare "Upgrades" section header, which dnf4 does not print.
_CU5 = """\
Upgrades
coreutils.x86_64                   9.10-4.fc44      updates
vim-minimal.x86_64                 2:9.2.843-1.fc44 updates
"""

# `rpm -qa --qf` — the epoch conditional renders NetworkManager as dnf does.
_RPM = """\
NetworkManager.x86_64 1:1.54.0-1.el10
attr.x86_64 2.5.2-5.el10
fwupd.x86_64 1.9.31-1.el10
glibc.i686 2.41-7.el10
glibc.x86_64 2.41-7.el10
samba-ndr-libs.x86_64 4.22.4-106.el10_1
"""


def _ctx(cfg=None, **kw):
    return Context(output=Output(color=False), config=cfg or Config(),
                   sudo_user="paul", user_home=Path("/home/paul"), **kw)


def _fake(responses, calls):
    """responses: {cmd-prefix tuple: (rc, stdout)} or {prefix: stdout}. Records calls."""
    def run(cmd, *, as_user=None, capture=False):
        calls.append((list(cmd), as_user))
        for key, val in responses.items():
            if list(cmd)[: len(key)] == list(key):
                rc, text = val if isinstance(val, tuple) else (0, val)
                return command.Proc(rc, text, "")
        return command.Proc(0, "", "")
    return run


def _run(responses, method="pending_upgrades", ctx=None, **kw):
    """Unprivileged run. `_have_root` is pinned False rather than left to the ambient
    euid, so a suite that happens to run as root does not quietly take the other
    branch and stop testing what these cases claim to test."""
    calls = []
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch("fettle.backends.rhel._have_root", return_value=False):
        result = getattr(RhelBackend(), method)(ctx or _ctx(**kw))
    return result, [c for c, _ in calls]


# -- pending_upgrades --------------------------------------------------------
def test_check_update_exit_100_is_success_not_failure():
    """dnf exits 100 when upgrades exist. Treating that as an error is the whole bug."""
    got, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    assert ("attr.x86_64", "2.5.2-5.el10", "2.6.0-2.el10") in got


def test_epoch_is_rendered_the_same_on_both_sides():
    """A bare %{EVR} would give `1.54.0-1.el10` against dnf's `1:1.58~rc1-1.el10`,
    making every epoch-bearing package look like an epoch change."""
    got, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    old, new = next((o, n) for name, o, n in got if name == "NetworkManager.x86_64")
    assert old == "1:1.54.0-1.el10" and new == "1:1.58~rc1-1.el10"


def test_multilib_arches_are_kept_separate():
    """glibc.i686 and glibc.x86_64 are two independent upgrades; keying on the bare
    name would report one and silently drop the other."""
    got, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    assert {n for n, _, _ in got if n.startswith("glibc")} == {"glibc.i686",
                                                               "glibc.x86_64"}


def test_obsoleting_block_does_not_double_count():
    """fwupd appears in the upgrade list AND again under "Obsoleting Packages"."""
    got, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    assert [n for n, _, _ in got].count("fwupd.x86_64") == 1
    # Rows past the header are not upgrades of themselves and must not appear.
    assert "samba-ndr-libs.x86_64" not in {n for n, _, _ in got}


def test_indented_obsoleted_rows_are_ignored():
    got, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    assert "fwupd-plugin-flashrom.x86_64" not in {n for n, _, _ in got}


def test_notices_and_headers_are_not_parsed_as_packages():
    """The "Not root" notice and the metadata-age line are on stdout, not stderr."""
    got, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    assert len(got) == 5  # the four col-0 rows above the header, plus glibc.i686


def test_dnf5_upgrades_header_is_skipped():
    got, _ = _run({("dnf", "check-update"): (100, _CU5), ("rpm", "-qa"): _RPM})
    assert {n for n, _, _ in got} == {"coreutils.x86_64", "vim-minimal.x86_64"}


def test_the_rpm_query_asks_for_the_epoch():
    """The fixtures pre-bake epoch-formatted versions, so parsing tests cannot catch a
    regression in the queryformat itself — assert the argv. `%{EVR}` alone omits the
    epoch and was verified against live rpm to produce `1.54.0-1.el10`, not `1:...`.
    """
    _, argvs = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM})
    qf = next(a[-1] for a in argvs if a[:2] == ["rpm", "-qa"])
    assert "%|EPOCH?" in qf and "%{EPOCH}" in qf


def test_an_unfamiliar_obsoletes_header_spelling_still_stops_the_parse():
    """dnf4 and dnf5 word the header differently; the prefix match must survive a
    third spelling rather than silently reading the block as upgrades."""
    text = _CU.replace("Obsoleting Packages", "OBSOLETING")
    got, _ = _run({("dnf", "check-update"): (100, text), ("rpm", "-qa"): _RPM})
    assert "samba-ndr-libs.x86_64" not in {n for n, _, _ in got}
    assert [n for n, _, _ in got].count("fwupd.x86_64") == 1


def test_no_updates_is_empty_not_an_error():
    got, _ = _run({("dnf", "check-update"): (0, ""), ("rpm", "-qa"): _RPM})
    assert got == []


def test_a_real_failure_yields_no_upgrades():
    got, _ = _run({("dnf", "check-update"): (1, ""), ("rpm", "-qa"): _RPM})
    assert got == []


def test_no_dnf_yields_no_upgrades():
    with patch("fettle.command.which", return_value=False):
        assert RhelBackend().pending_upgrades(_ctx()) == []


# -- pending_transaction -----------------------------------------------------
def test_transaction_states_that_new_deps_are_missing():
    """dnf has no rootless `apt-get -s`, so a partial preview must say it is partial —
    otherwise it is indistinguishable from a complete one."""
    tx, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                 method="pending_transaction")
    assert tx.ok and tx.items
    assert any("--full-preview" in n and "without root" in n for n in tx.notes)


def test_transaction_reports_the_obsoletes_it_cannot_express():
    tx, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                 method="pending_transaction")
    assert any("replace obsoleted" in n for n in tx.notes)


def test_transaction_warns_when_subscription_repos_were_skipped():
    tx, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                 method="pending_transaction")
    assert any("subscription-manager" in n for n in tx.notes)


def test_transaction_not_ok_when_check_update_fails():
    """ok=False means "could not determine", which the action runner reports as a
    warning; ok=True with no items would claim the system is up to date."""
    tx, _ = _run({("dnf", "check-update"): (1, "")}, method="pending_transaction")
    assert tx.ok is False and any("exit 1" in n for n in tx.notes)


def test_transaction_not_ok_without_dnf():
    with patch("fettle.command.which", return_value=False):
        tx = RhelBackend().pending_transaction(_ctx())
    assert tx.ok is False


def test_transaction_marks_an_uninstalled_package_as_a_new_dep():
    """check-update should only list installed packages, but if rpm has no record the
    item is a new install, not an upgrade from an empty version."""
    tx, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): ""},
                 method="pending_transaction")
    assert {i.kind for i in tx.items} == {"new-dep"}
    assert all(i.old is None for i in tx.items)


# -- the elevated full preview -----------------------------------------------
# Real `dnf upgrade --assumeno` output. dnf4 (AlmaLinux 10): one leading space per row,
# a `====` rule, and `Transaction Summary` with no colon.
_TX4 = """\
AlmaLinux 10 - BaseOS                            13 MB/s |  21 MB     00:01
Dependencies resolved.
================================================================================
 Package                   Arch      Version                    Repo       Size
================================================================================
Upgrading:
 glibc                     x86_64    2.39-128.el10_2.alma.1     baseos    2.1 M
 openssl-libs              x86_64    1:3.5.5-6.el10_2.alma.1    baseos    2.2 M
Installing dependencies:
 libxcrypt-compat          x86_64    4.4.36-8.el10              baseos     91 k
Removing:
 obsolete-thing            noarch    1.0-1.el10                 @System    12 k

Transaction Summary
================================================================================
Upgrade  2 Packages
"""

# dnf5 (Fedora 44): explicit `0:` epochs, `replacing` sub-rows indented by THREE
# spaces, no `====` rules, and `Transaction Summary:` WITH a colon.
_TX5 = """\
Package                     Arch   Version          Repository   Size
Upgrading:
 coreutils                  x86_64 0:9.10-4.fc44    updates   5.7 MiB
   replacing coreutils      x86_64 0:9.10-3.fc44    9dca760f  5.6 MiB
 vim-minimal                x86_64 2:9.2.843-1.fc44 updates   1.8 MiB
   replacing vim-minimal    x86_64 2:9.2.530-1.fc44 7d5aa1f4  1.8 MiB

Transaction Summary:
 Upgrading:         2 packages
 Replacing:         2 packages
"""

_RPM5 = "coreutils.x86_64 9.10-3.fc44\nvim-minimal.x86_64 2:9.2.530-1.fc44\n"


def _root_run(responses, **kw):
    """As _run, but with the process appearing to be root (dnf upgrade needs it)."""
    calls = []
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch("fettle.backends.rhel._have_root", return_value=True):
        tx = RhelBackend().pending_transaction(_ctx(**kw))
    return tx, [c for c, _ in calls]


def test_root_resolves_the_full_transaction_not_just_upgrades():
    """`-O` is already root, so the complete set costs nothing extra — the resolver
    branches on real privilege rather than on the flag."""
    tx, argvs = _root_run({("dnf", "upgrade", "--assumeno"): (1, _TX4),
                           ("rpm", "-qa"): _RPM})
    assert ["dnf", "upgrade", "--assumeno"] in argvs
    assert {i.kind for i in tx.items} == {"upgrade", "new-dep", "remove"}
    assert tx.ok


def test_full_preview_carries_no_partial_warning():
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"): (1, _TX4),
                       ("rpm", "-qa"): _RPM})
    assert not any("not shown" in n or "--full-preview" in n for n in tx.notes)


def test_assumeno_exit_1_is_a_declined_prompt_not_a_failure():
    """dnf exits 1 both when --assumeno declines and on a real error, so the resolved
    table — not the exit code — has to be the discriminator."""
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"): (1, _TX4),
                       ("rpm", "-qa"): _RPM})
    assert tx.ok and len(tx.items) == 4


def test_exit_1_with_no_resolved_table_is_a_real_failure():
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"):
                       (1, "Error: No packages marked for upgrade.")})
    assert tx.ok is False


def test_nothing_to_do_is_a_clean_empty_transaction():
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"):
                       (0, "Dependencies resolved.\nNothing to do.\nComplete!\n")})
    assert tx.ok is True and tx.items == []


def test_dnf5_replacing_subrows_are_not_counted_as_packages():
    """The `replacing` rows carry the version being REMOVED. Accepting them would
    double every upgrade and list the outgoing version as the incoming one."""
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"): (1, _TX5),
                       ("rpm", "-qa"): _RPM5})
    assert {i.name for i in tx.items} == {"coreutils.x86_64", "vim-minimal.x86_64"}
    new = {i.name: i.new for i in tx.items}
    assert new["coreutils.x86_64"] == "9.10-4.fc44"          # not 9.10-3
    assert new["vim-minimal.x86_64"] == "2:9.2.843-1.fc44"    # not 2:9.2.530


def test_a_zero_epoch_is_dropped_so_both_sides_match():
    """dnf5 writes `0:9.10-4.fc44`; rpm and check-update write `9.10-4.fc44`. Left
    alone, every package on a dnf5 host looks like it is gaining an epoch."""
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"): (1, _TX5),
                       ("rpm", "-qa"): _RPM5})
    item = next(i for i in tx.items if i.name == "coreutils.x86_64")
    assert item.old == "9.10-3.fc44" and item.new == "9.10-4.fc44"
    # A non-zero epoch is preserved on both sides.
    vim = next(i for i in tx.items if i.name == "vim-minimal.x86_64")
    assert vim.old == "2:9.2.530-1.fc44"


def test_transaction_summary_is_not_read_as_a_section():
    """dnf5 writes `Transaction Summary:` with a colon, which otherwise reads as a
    section header and would emit a bogus "unrecognised section" note."""
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"): (1, _TX5),
                       ("rpm", "-qa"): _RPM5})
    assert not any("does not itemise" in n for n in tx.notes)


def test_an_unrecognised_section_is_reported_not_dropped():
    """Downgrading:/Reinstalling: have no TxItem kind. Silently omitting them from a
    preview the user is about to act on is the failure mode to avoid."""
    text = _TX4.replace("Removing:", "Downgrading:")
    tx, _ = _root_run({("dnf", "upgrade", "--assumeno"): (1, text),
                       ("rpm", "-qa"): _RPM})
    assert any("downgrading" in n for n in tx.notes)


def test_no_sync_uses_cached_metadata_and_says_so():
    calls = []
    with patch("fettle.command.run", side_effect=_fake(
                {("dnf", "-C", "upgrade", "--assumeno"): (1, _TX4),
                 ("rpm", "-qa"): _RPM}, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch("fettle.backends.rhel._have_root", return_value=True):
        tx = RhelBackend().pending_transaction(_ctx(), sync=False)
    assert ["dnf", "-C", "upgrade", "--assumeno"] in [c for c, _ in calls]
    assert any("cached metadata" in n for n in tx.notes)


def test_full_preview_requested_but_not_root_says_elevation_failed():
    """Advising a flag the user already passed would be useless; the honest report is
    that elevation did not happen."""
    tx, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                 method="pending_transaction", ctx=_ctx(full_preview=True))
    assert any("not root despite --full-preview" in n for n in tx.notes)
    assert not any("add --full-preview" in n for n in tx.notes)


def test_without_root_the_full_resolver_is_never_invoked():
    """`dnf upgrade` refuses to run as a normal user; calling it anyway would print a
    privilege error into the middle of a preview."""
    _, argvs = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                    method="pending_transaction")
    assert not any(a[:2] == ["dnf", "upgrade"] for a in argvs)


# -- image-based (ostree / bootc) hosts --------------------------------------
def _ostree(tmp_path):
    (tmp_path / "run").mkdir()
    (tmp_path / "run/ostree-booted").touch()
    return tmp_path


def test_an_ostree_host_is_refused_not_previewed(tmp_path):
    """dnf will happily *list* upgrades on an image-based host, and that list is a lie:
    applying it writes into a deployment the next boot discards."""
    tx, argvs = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                     method="pending_transaction", ctx=_ctx(root=_ostree(tmp_path)))
    assert tx.ok is False
    assert any("ostree image" in n for n in tx.notes)
    assert not any(a[:1] == ["dnf"] for a in argvs)  # dnf is not even consulted


def test_the_refusal_names_the_command_that_works(tmp_path):
    tx, _ = _run({}, method="pending_transaction", ctx=_ctx(root=_ostree(tmp_path)))
    assert any("bootc upgrade" in n or "rpm-ostree upgrade" in n for n in tx.notes)


def test_a_normal_host_with_bootc_installed_is_not_refused(tmp_path):
    """The binary being present proves nothing — bootc and rpm-ostree can both be
    installed on an ordinary RHEL box. Refusing to upgrade one of those would be a
    worse failure than the one this guards against, so the marker is the boot state."""
    (tmp_path / "run").mkdir()  # no ostree-booted marker
    tx, _ = _run({("dnf", "check-update"): (100, _CU), ("rpm", "-qa"): _RPM},
                 method="pending_transaction", ctx=_ctx(root=tmp_path))
    assert tx.ok is True and tx.items


def test_rpm_ostree_is_suggested_without_sudo(tmp_path):
    """rpm-ostree authenticates through polkit over D-Bus and does not want sudo;
    bootc does. Telling someone to sudo rpm-ostree teaches the wrong habit."""
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", side_effect=lambda t: t != "bootc"), \
         patch("fettle.backends.rhel._have_root", return_value=False):
        tx = RhelBackend().pending_transaction(_ctx(root=_ostree(tmp_path)))
    hint = next(n for n in tx.notes if "rpm-ostree" in n)
    assert "sudo" not in hint.split("rpm-ostree")[0]


# -- kernels -----------------------------------------------------------------
# Real `rpm -q kernel-core --qf` output from the RHEL 10.1 VM: TWO kernels, the newer one
# running. `rpm -q kernel` on the same box reports only the OLDER one.
_KERNELS = "6.12.0-124.8.1.el10_1.x86_64\n6.12.0-218.el10.x86_64\n"


def _kernels(tmp_path, *, listing=_KERNELS, running="6.12.0-218.el10.x86_64",
             limit="installonly_limit=3\n", which=True):
    (tmp_path / "etc/dnf").mkdir(parents=True, exist_ok=True)
    (tmp_path / "etc/dnf/dnf.conf").write_text("[main]\n" + limit)
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        calls.append(cmd)
        if cmd[:2] == ["rpm", "-q"]:
            return command.Proc(0, listing, "")
        if cmd[:1] == ["uname"]:
            return command.Proc(0, running + "\n", "")
        return command.Proc(0, "", "")

    ctx = _ctx(root=tmp_path)
    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=which):
        RhelBackend().manage_kernels(ctx)
    return ctx, calls


def test_kernel_core_is_queried_not_kernel(tmp_path):
    """Measured on the VM: `rpm -q kernel` reported ONE version while `kernel-core`
    reported TWO, including the running one. Querying `kernel` hides the booted kernel."""
    _, calls = _kernels(tmp_path)
    q = next(c for c in calls if c[:2] == ["rpm", "-q"])
    assert q[2] == "kernel-core"


def test_kernels_are_sorted_numerically_not_as_strings(tmp_path, capsys):
    """A string sort ranks 6.12.0-218 BELOW 6.12.0-124.8.1, which would label the wrong
    kernel as the one that boots next."""
    _kernels(tmp_path, running="6.12.0-124.8.1.el10_1.x86_64")
    said = capsys.readouterr().out + capsys.readouterr().err
    assert "6.12.0-218.el10.x86_64" in said


def test_a_string_sort_would_pick_the_wrong_newest_kernel(tmp_path, capsys):
    """The fixture above does not discriminate: 124 and 218 sort the same either way.
    This one does — a string sort ranks `-99` ABOVE `-124` because '9' > '1', so it would
    call the running 99 kernel the newest and miss the pending reboot entirely.
    """
    listing = "6.12.0-99.el10.x86_64\n6.12.0-124.8.1.el10_1.x86_64\n"
    ctx, _ = _kernels(tmp_path, listing=listing, running="6.12.0-99.el10.x86_64")
    cap = capsys.readouterr()
    assert "newer kernel is installed but not running" in cap.err
    assert "6.12.0-124.8.1.el10_1.x86_64" in cap.err     # names the right one


def test_a_pending_reboot_is_flagged(tmp_path, capsys):
    """Running the older kernel with a newer one installed = reboot owed."""
    ctx, _ = _kernels(tmp_path, running="6.12.0-124.8.1.el10_1.x86_64")
    cap = capsys.readouterr()
    assert "newer kernel is installed but not running" in cap.err
    assert any("reboot" in s for s in ctx.output._next_steps)


def test_running_the_newest_kernel_is_not_flagged(tmp_path, capsys):
    _kernels(tmp_path, running="6.12.0-218.el10.x86_64")
    assert "not running" not in capsys.readouterr().err


def test_no_removal_is_ever_offered(tmp_path):
    """dnf enforces installonly_limit itself, so the most dangerous operation in the tool
    is simply not performed on this backend."""
    _, calls = _kernels(tmp_path)
    assert not any("remove" in " ".join(c) for c in calls)
    assert not any(c[:1] == ["dnf"] for c in calls)


def test_the_installonly_limit_is_read_from_dnf_conf(tmp_path, capsys):
    _kernels(tmp_path, limit="installonly_limit=5\n")
    assert "at most 5 kernel(s)" in capsys.readouterr().out


def test_an_absent_limit_falls_back_to_dnfs_own_default(tmp_path, capsys):
    _kernels(tmp_path, limit="")
    assert "at most 3 kernel(s)" in capsys.readouterr().out


def test_more_kernels_than_the_limit_names_the_cleanup(tmp_path, capsys):
    listing = _KERNELS + "6.12.0-100.el10.x86_64\n6.12.0-90.el10.x86_64\n"
    _kernels(tmp_path, listing=listing, limit="installonly_limit=3\n")
    assert "--oldinstallonly" in capsys.readouterr().out


def test_rpm_saying_not_installed_is_not_parsed_as_a_kernel(tmp_path, capsys):
    """rpm writes "package kernel-core is not installed" to STDOUT, not stderr."""
    _kernels(tmp_path, listing="package kernel-core is not installed\n")
    said = capsys.readouterr().out
    assert "no kernel-core package is installed" in said
    assert "kernel(s) installed" not in said


def test_a_running_kernel_rpm_does_not_know_is_flagged(tmp_path, capsys):
    """A hand-built kernel, or the package removed underneath it — not something to
    quietly ignore."""
    _kernels(tmp_path, running="6.99.0-custom.x86_64")
    assert "not owned by any installed kernel-core" in capsys.readouterr().err


# -- file -> package attribution ---------------------------------------------
def _mapfiles(paths, *, stdout, existing=None):
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        calls.append(list(cmd))
        return command.Proc(0, stdout, "")

    exists = set(existing if existing is not None else paths)
    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=True), \
         patch("pathlib.Path.exists", lambda self: str(self) in exists):
        got = RhelBackend().map_files_to_packages(paths)
    return got, calls


def test_files_map_to_their_owning_packages():
    got, _ = _mapfiles(["/usr/bin/bash", "/usr/bin/ls"], stdout="bash\ncoreutils\n")
    assert got == {"/usr/bin/bash": "bash", "/usr/bin/ls": "coreutils"}


def test_an_unowned_file_is_dropped_without_shifting_the_others():
    """rpm reports "not owned by any package" INLINE on stdout, so alignment holds — the
    unowned entry is dropped and the rest stay correctly attributed."""
    got, _ = _mapfiles(["/usr/bin/bash", "/usr/local/bin/x", "/usr/bin/ls"],
                       stdout="bash\nfile /usr/local/bin/x is not owned by any package\n"
                              "coreutils\n")
    assert got == {"/usr/bin/bash": "bash", "/usr/bin/ls": "coreutils"}


def test_missing_paths_are_never_sent_to_rpm():
    """The dangerous case: a MISSING file errors on stderr and rpm SKIPS the line, so
    every later result shifts up one and is blamed on the wrong file."""
    got, calls = _mapfiles(["/usr/bin/bash", "/gone", "/usr/bin/ls"],
                           stdout="bash\ncoreutils\n",
                           existing={"/usr/bin/bash", "/usr/bin/ls"})
    assert "/gone" not in calls[0]
    assert got == {"/usr/bin/bash": "bash", "/usr/bin/ls": "coreutils"}


def test_a_length_mismatch_refuses_to_guess():
    """If alignment is lost anyway, an empty map degrades the report to "no package
    named"; a shifted map would confidently blame the wrong package."""
    got, _ = _mapfiles(["/usr/bin/bash", "/usr/bin/ls"], stdout="bash\n")
    assert got == {}


def test_no_rpm_maps_nothing():
    with patch("fettle.command.which", return_value=False):
        assert RhelBackend().map_files_to_packages(["/usr/bin/bash"]) == {}


# -- rebuilds / restarts -----------------------------------------------------
# Real output. dnf4 `needs-restarting -r` and bare dnf5 `dnf needs-restarting` agree:
# exit 0 = nothing to do, exit 1 = reboot required, with the cores named.
_NR_CLEAN = ("No core libraries or services have been updated since boot-up.\n"
             "Reboot should not be necessary.\n")
_NR_REBOOT = ("Core libraries or services have been updated since boot-up:\n"
              "  * glibc\n  * systemd\n\n"
              "Reboot is required to fully utilize these updates.\n")


def _rebuilds(*, standalone=True, hint=(0, _NR_CLEAN, ""), services=(0, "", ""),
              root=True, dnf5=True):
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        calls.append(cmd)
        if cmd == ["dnf", "--version"]:
            # The generation must come from here, not from whether the standalone
            # binary happens to be installed — see test_dnf4_without_yum_utils_*.
            return command.Proc(0, "dnf5 version 5.4.2.1\n" if dnf5 else "4.14.0\n", "")
        if cmd[-1] == "-s":
            return command.Proc(*services)
        return command.Proc(*hint)

    def which(name):
        return standalone if name == "needs-restarting" else True

    ctx = _ctx()
    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", side_effect=which), \
         patch("fettle.backends.rhel._have_root", return_value=root):
        RhelBackend().check_rebuilds(ctx)
    return ctx, calls


def test_dnf4_uses_the_standalone_binary_with_r():
    _, calls = _rebuilds(standalone=True)
    assert ["needs-restarting", "-r"] in calls


def test_dnf5_uses_the_subcommand_without_r():
    """dnf5 ships no standalone binary, and its own -r is documented as having no effect
    — bare `dnf needs-restarting` is the reboot hint."""
    _, calls = _rebuilds(standalone=False)
    assert ["dnf", "needs-restarting"] in calls
    assert not any(c[:1] == ["needs-restarting"] for c in calls)
    assert not any("-r" in c for c in calls)


def test_dnf4_without_yum_utils_admits_it_cannot_tell(capsys):
    """A dnf4 host simply *without* yum-utils also lacks the standalone binary, and
    there `dnf needs-restarting` is a PROCESS LIST that exits 0 whether or not a reboot
    is owed. Measured on AlmaLinux 9 (dnf 4.14.0, no yum-utils) running kernel
    5.14.0-687.5.3 with 687.31.1 installed: fettle reported no reboot at all. Rocky 9 —
    same dnf, yum-utils present — got it right. Absence of the tool is not evidence of
    dnf5."""
    ctx, calls = _rebuilds(standalone=False, dnf5=False)
    said = capsys.readouterr()
    assert "NOT determined" in said.err and "yum-utils" in said.err
    assert "no reboot required" not in said.out
    # and it must not run the process-listing command as though it were the hint
    assert ["dnf", "needs-restarting"] not in calls


def test_exit_1_means_reboot_required(capsys):
    ctx, _ = _rebuilds(hint=(1, _NR_REBOOT, ""))
    said = capsys.readouterr()
    assert "reboot is required" in said.err
    assert "glibc" in said.out                       # names what changed
    # A reboot needs YOU to do something, so it is not a green tick.
    assert any("reboot required" in s for s in ctx.output._warnings)


def test_exit_0_is_the_only_way_to_report_no_reboot(capsys):
    ctx, _ = _rebuilds(hint=(0, _NR_CLEAN, ""))
    assert "no reboot required" in capsys.readouterr().out


def test_an_error_is_never_reported_as_no_reboot_needed(capsys):
    """The asymmetry that matters: a needless reboot is cheap, but wrongly reporting "no
    reboot" leaves a host running the libraries it just patched. `dnf -C` with no cache
    exits 1 with empty stdout, which must not read as clean."""
    ctx, _ = _rebuilds(hint=(1, "", 'Cache-only enabled but no cache for repository'))
    said = capsys.readouterr()
    assert "NOT assessed" in said.err
    assert "no reboot required" not in said.out
    assert "Cache-only" in said.err                  # says why


def test_a_localised_reboot_hint_still_warns(capsys):
    """The body is printed verbatim rather than matched against an English phrase, so a
    translated system still gets the warning."""
    ctx, _ = _rebuilds(hint=(1, "Es ist ein Neustart erforderlich:\n  * glibc\n", ""))
    said = capsys.readouterr()
    assert "reboot is required" in said.err
    assert "Neustart" in said.out


def test_services_are_listed_and_summarised(capsys):
    ctx, _ = _rebuilds(services=(1, "sshd.service\nchronyd.service\n", ""))
    said = capsys.readouterr()
    assert "sshd.service" in said.out
    assert any("2 service(s) need restarting" in s for s in ctx.output._warnings)
    assert any("systemctl restart" in s for s in ctx.output._next_steps)


def test_service_notices_are_not_counted_as_services(capsys):
    """As root on an unregistered RHEL box, the whole of `-s` output is subscription
    notices on stdout — three lines that would otherwise read as three services."""
    notices = ("Updating Subscription Management repositories.\n"
               "Unable to read consumer identity\n\n"
               "This system is not registered with an entitlement server. You can use "
               '"rhc" or "subscription-manager" to register.\n')
    ctx, _ = _rebuilds(services=(0, notices, ""))
    assert "no services need restarting" in capsys.readouterr().out


def test_without_root_the_service_list_says_it_could_not_look(capsys):
    """Measured on the VM: rootless `-s` prints no services at all while root prints the
    real answer, so an empty rootless result is not "nothing to restart"."""
    ctx, _ = _rebuilds(root=False)
    said = capsys.readouterr()
    assert "not root" in said.out
    assert "no services need restarting" not in said.out


def test_missing_needs_restarting_is_reported_not_silent(capsys):
    with patch("fettle.command.which", return_value=False):
        RhelBackend().check_rebuilds(_ctx())
    assert "needs-restarting not found" in capsys.readouterr().out


# -- automatic updates -------------------------------------------------------
# dnf-automatic's real defaults (dnf4 /etc/dnf/automatic.conf, dnf5 the /usr/share copy).
_AUTO_CONF_OFF = ("[commands]\nupgrade_type = default\ndownload_updates = yes\n"
                  "apply_updates = no\nreboot = never\n")
_AUTO_CONF_ON = _AUTO_CONF_OFF.replace("apply_updates = no", "apply_updates = yes")
_ALL_TIMERS = ("dnf-automatic-install.timer", "dnf-automatic-download.timer",
               "dnf-automatic-notifyonly.timer", "dnf-automatic.timer",
               "dnf5-automatic.timer")


def _auto(tmp_path, *, enabled=(), present=True, conf=_AUTO_CONF_OFF,
          conf_at="etc/dnf/automatic.conf", system="running", which=True):
    """Run check_auto_updates against a synthetic systemd + config state."""
    if conf is not None:
        path = tmp_path / conf_at
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(conf)
    ctx = _ctx(root=tmp_path)

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        if cmd[:2] == ["systemctl", "is-enabled"]:
            unit = cmd[2]
            if unit in enabled:
                return command.Proc(0, "enabled\n", "")
            if not present and unit in _ALL_TIMERS:
                # systemd reports not-found on stderr with a non-zero code.
                return command.Proc(1, "", "not-found\n")
            return command.Proc(1, "disabled\n", "")
        if cmd[:2] == ["systemctl", "is-system-running"]:
            return command.Proc(0 if system == "running" else 1, system + "\n", "")
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=which):
        RhelBackend().check_auto_updates(ctx)
    return ctx


def _said(capsys):
    cap = capsys.readouterr()
    return cap.out + cap.err


def test_install_timer_beats_apply_updates_no(tmp_path, capsys):
    """THE bug this action exists to avoid. `dnf-automatic-install.service` passes
    --installupdates, so the host upgrades itself nightly even though automatic.conf says
    apply_updates = no. Reading the config alone reports OFF on exactly that machine."""
    _auto(tmp_path, enabled=("dnf-automatic-install.timer",), conf=_AUTO_CONF_OFF)
    said = _said(capsys)
    assert "ENABLED" in said
    assert "regardless of apply_updates" in said


def test_download_only_timer_does_not_count_as_on(tmp_path, capsys):
    """The mirror image: -download passes --no-installupdates, so nothing is applied even
    with apply_updates = yes. Calling that ON would be just as wrong."""
    _auto(tmp_path, enabled=("dnf-automatic-download.timer",), conf=_AUTO_CONF_ON)
    said = _said(capsys)
    assert "DISABLED" in said
    assert "only downloads or notifies" in said


def test_plain_timer_defers_to_the_config(tmp_path, capsys):
    _auto(tmp_path, enabled=("dnf-automatic.timer",), conf=_AUTO_CONF_ON)
    assert "ENABLED" in _said(capsys)


def test_plain_timer_with_apply_updates_off_is_disabled(tmp_path, capsys):
    _auto(tmp_path, enabled=("dnf-automatic.timer",), conf=_AUTO_CONF_OFF)
    said = _said(capsys)
    assert "DISABLED" in said and "apply_updates is not set" in said


def test_dnf5_unit_name_is_recognised(tmp_path, capsys):
    """dnf5 ships dnf5-automatic.timer; checking only the dnf4 name misses it."""
    _auto(tmp_path, enabled=("dnf5-automatic.timer",), conf=_AUTO_CONF_ON)
    assert "ENABLED" in _said(capsys)


def test_dnf5_ghost_config_falls_back_to_the_shipped_copy(tmp_path, capsys):
    """On dnf5 both /etc paths are rpm *ghost* files that never exist on disk, so the
    effective config is the one under /usr/share."""
    _auto(tmp_path, enabled=("dnf5-automatic.timer",), conf=_AUTO_CONF_ON,
          conf_at="usr/share/dnf5/dnf5-plugins/automatic.conf")
    assert "ENABLED" in _said(capsys)


def test_not_installed_is_distinguished_from_installed_but_disabled(tmp_path, capsys):
    _auto(tmp_path, present=False, conf=None)
    said = _said(capsys)
    assert "not installed" in said

    _auto(tmp_path, present=True, enabled=())
    said2 = _said(capsys)
    assert "installed but none of its timers are enabled" in said2


def test_a_self_rebooting_host_is_warned_about(tmp_path, capsys):
    """A server that reboots itself after patching is a bigger operational fact than the
    patching. Only warned about when updates are actually applied."""
    conf = _AUTO_CONF_ON.replace("reboot = never", "reboot = when-needed")
    ctx = _auto(tmp_path, enabled=("dnf-automatic.timer",), conf=conf)
    said = _said(capsys)
    assert "REBOOT ITSELF" in said
    assert any("reboots itself" in s for s in ctx.output._summary)


def test_reboot_setting_is_not_warned_about_when_nothing_is_applied(tmp_path, capsys):
    conf = _AUTO_CONF_OFF.replace("reboot = never", "reboot = when-needed")
    _auto(tmp_path, enabled=("dnf-automatic.timer",), conf=conf)
    assert "REBOOT ITSELF" not in _said(capsys)


def test_a_container_says_the_timers_cannot_actually_fire(tmp_path, capsys):
    """`systemctl is-enabled` reads unit FILES, so it answers happily with no systemd —
    which is how a container can report a timer as enabled that will never run."""
    _auto(tmp_path, enabled=("dnf-automatic.timer",), conf=_AUTO_CONF_ON,
          system="offline")
    assert "not running as init" in _said(capsys)


def test_a_real_host_carries_no_such_caveat(tmp_path, capsys):
    _auto(tmp_path, enabled=("dnf-automatic.timer",), conf=_AUTO_CONF_ON, system="running")
    assert "not running as init" not in _said(capsys)


def test_no_systemctl_means_unknown_not_off(tmp_path, capsys):
    """A check that could not look must not read as a clean "off"."""
    _auto(tmp_path, which=False)
    said = _said(capsys)
    assert "cannot determine" in said
    assert "DISABLED" not in said


def test_auto_updates_runs_no_mutating_command(tmp_path):
    """It is in cli.READ_ONLY_ACTIONS."""
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        calls.append(list(cmd))
        return command.Proc(1, "disabled\n", "")

    (tmp_path / "etc/dnf").mkdir(parents=True)
    (tmp_path / "etc/dnf/automatic.conf").write_text(_AUTO_CONF_OFF)
    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=True):
        RhelBackend().check_auto_updates(_ctx(root=tmp_path))
    assert all(c[0] == "systemctl" for c in calls)
    assert all(c[1] in ("is-enabled", "is-system-running") for c in calls)


# -- config drift ------------------------------------------------------------
# Real `dnf check` bodies. dnf4 writes one line per problem; dnf5 writes the package on
# one line with an indented `missing require` beneath it. Both put the count on stderr.
_CHECK4 = ("httpd-2.4.63-13.el10_2.4.x86_64 has missing requires of "
           "httpd-core = 2.4.63-13.el10_2.4\n"
           "mod_lua-2.4.63-13.el10_2.4.x86_64 has missing requires of "
           "httpd-mmn = 20120211x8664\n")
_CHECK5 = ('httpd-0:2.4.68-1.fc44.x86_64\n missing require "httpd-core = 0:2.4.68-1.fc44"\n'
           'mod_lua-0:2.4.68-1.fc44.x86_64\n missing require "httpd-mmn = 20120211x8664"\n')


def _drift_root(tmp_path, names=()):
    etc = tmp_path / "etc"
    (etc / "dnf").mkdir(parents=True)
    for name in names:
        (etc / name).write_text("x")
    return tmp_path


def _drift(root, check=(0, "", ""), which=True):
    """Returns (ctx, calls) — ctx so a test can read `output._next_steps`, which are
    queued for the summary rather than printed as they happen."""
    calls = []
    ctx = _ctx(root=root)

    def run(cmd, *, as_user=None, capture=False):
        calls.append(list(cmd))
        if list(cmd)[:2] == ["dnf", "check"]:
            return command.Proc(*check)
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=which):
        RhelBackend().check_config_drift(ctx)
    return ctx, calls


def test_rpmnew_says_your_file_is_still_in_effect(tmp_path, capsys):
    _drift(_drift_root(tmp_path, ["sshd_config.rpmnew"]))
    shown = capsys.readouterr()
    text = shown.out + shown.err
    assert "YOUR file is still in effect" in text
    assert "sshd_config.rpmnew" in text


def test_rpmsave_warns_that_settings_are_no_longer_active(tmp_path, capsys):
    _drift(_drift_root(tmp_path, ["sshd_config.rpmsave"]))
    shown = capsys.readouterr()
    assert "NOT active" in shown.out + shown.err
    # It must be a warning, not a note: this is a silent loss of configuration.
    assert "rpmsave" in shown.err


def test_rpmorig_is_also_treated_as_a_displaced_file(tmp_path, capsys):
    _drift(_drift_root(tmp_path, ["hosts.rpmorig"]))
    assert "rpmorig" in capsys.readouterr().err


def test_a_clean_etc_reports_no_merges(tmp_path, capsys):
    _drift(_drift_root(tmp_path))
    assert "no pending config-file merges" in capsys.readouterr().out


def test_leftovers_are_found_in_nested_directories(tmp_path, capsys):
    root = _drift_root(tmp_path)
    (root / "etc/dnf/dnf.conf.rpmnew").write_text("x")
    _drift(root)
    assert "dnf.conf.rpmnew" in capsys.readouterr().out


def test_rpmconf_is_suggested_without_telling_you_to_install_it_twice(tmp_path):
    ctx, _ = _drift(_drift_root(tmp_path, ["a.rpmnew"]), which=True)
    steps = " ".join(ctx.output._next_steps)
    assert "rpmconf -a" in steps and "dnf install rpmconf" not in steps


def test_absent_rpmconf_is_named_as_something_to_install(tmp_path):
    ctx, _ = _drift(_drift_root(tmp_path, ["a.rpmnew"]), which=False)
    assert "dnf install rpmconf" in " ".join(ctx.output._next_steps)


# -- dnf check (the dpkg --audit analogue) ------------------------------------
def test_dnf_check_exit_1_with_output_means_problems_found(tmp_path, capsys):
    """Exit 1 means "problems found", not "the check failed" — the same trap as
    `rpm -Va` and `dnf check-update`."""
    _drift(_drift_root(tmp_path),
           check=(1, _CHECK4, "Error: Check discovered 4 problem(s)"))
    shown = capsys.readouterr()
    assert "found 4 package problem(s)" in shown.err
    assert "has missing requires of" in shown.out


def test_dnf_check_parses_the_count_from_either_generation(tmp_path, capsys):
    _drift(_drift_root(tmp_path),
           check=(1, _CHECK5, "Check discovered 4 problem(s) in 3 package(s)"))
    shown = capsys.readouterr()
    assert "found 4 package problem(s)" in shown.err
    assert 'missing require "httpd-core' in shown.out


def test_dnf_check_exit_1_with_no_output_is_not_a_clean_bill_of_health(tmp_path, capsys):
    """A broken dnf also exits 1 — measured: removing libxml2 breaks its Python bindings
    and it exits 1 with a traceback. Reporting that as "no problems" would be the worst
    possible answer."""
    _drift(_drift_root(tmp_path), check=(1, "", "ImportError: libxml2.so.2"))
    shown = capsys.readouterr()
    assert "NOT assessed" in shown.err
    assert "no package problems" not in shown.out


# Exactly what an unregistered RHEL 10.1 box writes to STDOUT — with exit code 0.
_UNREGISTERED = ("Updating Subscription Management repositories.\n"
                 "Unable to read consumer identity\n"
                 "\n"
                 "This system is not registered with an entitlement server. You can use "
                 '"rhc" or "subscription-manager" to register.\n'
                 "\n")


def test_an_unregistered_box_is_not_reported_as_having_package_problems(tmp_path, capsys):
    """Caught by running it for real, not by a unit test. dnf writes these notices to
    *stdout* and exits 0, so a bare "was there output?" test called a completely clean
    machine broken — and printed no problem count, because there were no problems."""
    _drift(_drift_root(tmp_path), check=(0, _UNREGISTERED, ""))
    shown = capsys.readouterr()
    assert "no package problems" in shown.out
    assert "problem(s):" not in shown.err


def test_the_rootless_notice_is_also_stripped(tmp_path, capsys):
    _drift(_drift_root(tmp_path),
           check=(0, "Not root, Subscription Management repositories not updated\n", ""))
    assert "no package problems" in capsys.readouterr().out


def test_real_problems_still_survive_the_notice_filter(tmp_path, capsys):
    """The filter must not swallow the signal it sits in front of."""
    _drift(_drift_root(tmp_path), check=(1, _UNREGISTERED + _CHECK4,
                                         "Error: Check discovered 4 problem(s)"))
    shown = capsys.readouterr()
    assert "found 4 package problem(s)" in shown.err
    assert "has missing requires of" in shown.out
    assert "not registered" not in shown.out          # notices are not echoed as problems


def test_dnf_check_clean_says_so(tmp_path, capsys):
    _drift(_drift_root(tmp_path), check=(0, "", ""))
    assert "no package problems" in capsys.readouterr().out


def test_config_drift_writes_nothing(tmp_path):
    """Read-only: it is in cli.READ_ONLY_ACTIONS, so it must not run a mutating command
    even without --dry-run."""
    _, calls = _drift(_drift_root(tmp_path, ["a.rpmnew"]))
    assert calls == [["dnf", "check"]]


# -- orphans -----------------------------------------------------------------
# Real `dnf repoquery --queryformat` output. dnf4 already terminates each record, so the
# `\n` dnf5 needs makes dnf4 double-space; and dnf puts its rootless notice on stdout.
_UNNEEDED4 = """\
Not root, Subscription Management repositories not updated
apr.x86_64

apr-util.x86_64

kernel-core.x86_64

kmod-nvidia.x86_64

libbrotli.x86_64

"""
_INSTALLONLY = ("kernel-core.x86_64\n\nkernel-modules.x86_64\n\n"
                "kmod-nvidia.x86_64\n\n")
_EXTRAS = "eclypsiumapp.x86_64\n\neclypsiumdriver.noarch\n\n"


def _orphans(responses, ctx=None, **kw):
    calls = []
    with patch("fettle.command.run", side_effect=_fake(responses, calls)), \
         patch("fettle.command.which", return_value=True), \
         patch("fettle.reports.write_report", return_value="/tmp/r.txt"):
        result = RhelBackend().check_foreign_orphans(ctx or _ctx(**kw))
    return result, [c for c, _ in calls]


_RQ_UNNEEDED = ("dnf", "repoquery", "--unneeded")
_RQ_INSTALLONLY = ("dnf", "repoquery", "--installonly")
_RQ_EXTRAS = ("dnf", "repoquery", "--extras")
_ALL_RQ = {_RQ_UNNEEDED: _UNNEEDED4, _RQ_INSTALLONLY: _INSTALLONLY, _RQ_EXTRAS: _EXTRAS}


def test_dnf4_blank_lines_and_the_not_root_notice_are_not_packages(capsys):
    """dnf4 double-spaces queryformat output and writes its rootless notice to stdout;
    both would otherwise become entries in the removal offer."""
    with patch("fettle.command.run",
               return_value=command.Proc(0, _UNNEEDED4, "")):
        names, ok = RhelBackend._repoquery("--unneeded")
    assert ok
    assert names == ["apr-util.x86_64", "apr.x86_64", "kernel-core.x86_64",
                     "kmod-nvidia.x86_64", "libbrotli.x86_64"]


def test_a_kernel_is_never_offered_for_removal(capsys):
    """The hazard this whole action is shaped around: dnf autoremove has been known to
    propose removing kernels when `dnf mark` reason data is incomplete, and removing the
    running one leaves a machine that does not boot."""
    ctx = _ctx(assume_yes=True)
    _, argvs = _orphans(_ALL_RQ, ctx=ctx)
    removal = next(a for a in argvs if a[:2] == ["dnf", "remove"])
    assert "kernel-core.x86_64" not in removal
    assert set(removal[2:]) == {"apr.x86_64", "apr-util.x86_64", "libbrotli.x86_64", "-y"}


def test_an_installonly_package_not_named_kernel_is_still_protected():
    """dnf's installonlypkgs covers installonlypkg(kernel-module), so a DKMS package
    like kmod-nvidia is installonly while matching no `kernel` name prefix. Without the
    query result being honoured, only the prefix net would guard anything — and this
    package would be offered for removal."""
    _, argvs = _orphans(_ALL_RQ, ctx=_ctx(assume_yes=True))
    removal = next(a for a in argvs if a[:2] == ["dnf", "remove"])
    assert "kmod-nvidia.x86_64" not in removal


def test_held_back_kernels_are_named_not_hidden(capsys):
    _orphans(_ALL_RQ, ctx=_ctx(assume_yes=True))
    shown = capsys.readouterr()
    assert "held back as installonly" in shown.out + shown.err
    assert "kernel-core.x86_64" in shown.out + shown.err


def test_a_kernel_is_protected_even_if_dnf_does_not_report_it_installonly():
    """Defence in depth: if installonlypkgs is misconfigured the name prefix still
    spares it. Over-protecting is the right direction to err in here."""
    resp = {**_ALL_RQ, _RQ_INSTALLONLY: ""}   # dnf claims nothing is installonly
    _, argvs = _orphans(resp, ctx=_ctx(assume_yes=True))
    removal = next(a for a in argvs if a[:2] == ["dnf", "remove"])
    assert "kernel-core.x86_64" not in removal


def test_a_failed_installonly_query_offers_nothing():
    """An empty result and a failed query look identical. dnf5 rejects
    `--installonly --installed` as mutually exclusive and complains on stderr, so the
    pair reads as a clean empty answer — which would offer a running kernel."""
    resp = {**_ALL_RQ, _RQ_INSTALLONLY: (1, "")}
    result, argvs = _orphans(resp, ctx=_ctx(assume_yes=True))
    assert not any(a[:2] == ["dnf", "remove"] for a in argvs)
    assert result.ok


def test_a_failed_unneeded_query_offers_nothing():
    resp = {**_ALL_RQ, _RQ_UNNEEDED: (1, "")}
    _, argvs = _orphans(resp, ctx=_ctx(assume_yes=True))
    assert not any(a[:2] == ["dnf", "remove"] for a in argvs)


def test_the_installonly_query_does_not_pass_installed():
    """`--installonly --installed` is a hard error on dnf5. `--installonly` alone means
    "installed installonly packages" on both generations."""
    _, argvs = _orphans(_ALL_RQ, ctx=_ctx(assume_yes=True))
    q = next(a for a in argvs if a[:3] == list(_RQ_INSTALLONLY))
    assert "--installed" not in q


def test_removal_uses_dnf_remove_not_autoremove():
    """Selection is per-package; autoremove is all-or-nothing by construction, so one
    'y' must not be able to trigger dnf's own resolution."""
    _, argvs = _orphans(_ALL_RQ, ctx=_ctx(assume_yes=True))
    assert not any("autoremove" in " ".join(a) for a in argvs)


def test_without_yes_dnf_confirms_the_real_transaction():
    """No -y, so dnf shows what it will actually remove — a cascade into dependents
    cannot happen unseen."""
    with patch("fettle.backends.base.Context.select",
               side_effect=lambda items, prompt: list(items)):
        _, argvs = _orphans(_ALL_RQ)
    removal = next(a for a in argvs if a[:2] == ["dnf", "remove"])
    assert "-y" not in removal


def test_keep_orphans_config_is_honored():
    cfg = Config()
    cfg.keep_orphans = ["apr*"]
    _, argvs = _orphans(_ALL_RQ, ctx=_ctx(cfg, assume_yes=True))
    removal = next(a for a in argvs if a[:2] == ["dnf", "remove"])
    assert "apr.x86_64" not in removal and "apr-util.x86_64" not in removal
    assert "libbrotli.x86_64" in removal


def test_foreign_packages_are_written_to_a_review_report():
    """The RPM analogue of Debian's obsolete-pkgs report — same report name, so
    `fettle report` picks it up either way. Real finding on the RHEL box: the Eclypsium
    sensor packages come from no enabled repository."""
    with patch("fettle.command.run", side_effect=_fake(_ALL_RQ, [])), \
         patch("fettle.command.which", return_value=True), \
         patch("fettle.reports.write_report", return_value="/tmp/r.txt") as wr:
        RhelBackend().check_foreign_orphans(_ctx(assume_yes=True))
    name, body = wr.call_args[0][0], wr.call_args[0][1]
    assert name == "obsolete-pkgs"
    assert "eclypsiumapp.x86_64" in body and "eclypsiumdriver.noarch" in body


def test_orphans_removes_nothing_under_dry_run():
    _, argvs = _orphans(_ALL_RQ, ctx=_ctx(dry_run=True))
    assert not any(a[:2] == ["dnf", "remove"] for a in argvs)
    assert all(a[:2] == ["dnf", "repoquery"] for a in argvs)   # read-only queries only


# -- clean -------------------------------------------------------------------
def _clean(ctx=None, which=True, **kw):
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=which):
        result = RhelBackend().clean_caches(ctx or _ctx(**kw))
    return result, [c for c, _ in calls]


def test_clean_removes_packages_but_keeps_metadata():
    """`clean all` would also drop the repo metadata (60M on the test box) and force
    the next dnf command to re-download it — a slow, network-dependent surprise in
    exchange for a rounding error of disk. `clean packages` freed 736M there."""
    _, argvs = _clean()
    assert ["dnf", "clean", "packages"] in argvs
    assert not any(a[:3] == ["dnf", "clean", "all"] for a in argvs)
    assert not any("expire-cache" in a or "metadata" in a for a in argvs)


def test_clean_removes_unused_flatpaks():
    _, argvs = _clean()
    assert ["flatpak", "uninstall", "--unused", "-y"] in argvs


def test_clean_skips_flatpak_when_absent():
    _, argvs = _clean(which=False)
    assert not any(a[:1] == ["flatpak"] for a in argvs)


def test_clean_honors_flatpak_updater_none():
    cfg = Config()
    cfg.updaters = {"rhel": {"flatpak_updater": "none"}}
    _, argvs = _clean(_ctx(cfg))
    assert ["dnf", "clean", "packages"] in argvs
    assert not any(a[:1] == ["flatpak"] for a in argvs)


def test_clean_deletes_nothing_under_dry_run():
    _, argvs = _clean(dry_run=True)
    # Only the read-only snap listing, which previews the disabled revisions a real run
    # would offer (dry-run declines every prompt). Nothing that changes the system.
    assert argvs == [["snap", "list", "--all"]]


# -- update + the unsigned-repo gate -----------------------------------------
# Real /etc/yum.repos.d content from the RHEL 10.1 box: all enabled CentOS Stream repos
# ship gpgcheck=0, so a `fettle -u` there would install ~341 packages unverified. The
# EPEL entry is signed, and epel-source is disabled — neither should trip the gate.
_REPOS = """\
[centos-stream-baseos]
name=CentOS Stream 10 - BaseOS
baseurl=https://mirror.stream.centos.org/10-stream/BaseOS/x86_64/os/
gpgcheck=0
enabled=1

[centos-stream-appstream]
name=CentOS Stream 10 - AppStream
baseurl=https://mirror.stream.centos.org/10-stream/AppStream/x86_64/os/
gpgcheck=0
enabled=1

[epel]
name=EPEL $releasever
metalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$releasever
gpgcheck=1
enabled=1

[old-unsigned]
name=disabled and unsigned
baseurl=https://vendor.example/rpm/
gpgcheck=0
enabled=0
"""


def _repo_root(tmp_path, repos=_REPOS, dnf_conf="[main]\ngpgcheck=1\n"):
    d = tmp_path / "etc/yum.repos.d"
    d.mkdir(parents=True)
    (d / "test.repo").write_text(repos)
    c = tmp_path / "etc/dnf"
    c.mkdir(parents=True)
    (c / "dnf.conf").write_text(dnf_conf)
    return tmp_path


def _update(ctx, responses=None):
    calls = []
    with patch("fettle.command.run", side_effect=_fake(responses or {}, calls)), \
         patch("fettle.command.which", return_value=True):
        result = RhelBackend().update_system(ctx)
    return result, [c for c, _ in calls]


def test_update_refreshes_metadata_in_the_same_command(tmp_path):
    """`--refresh` makes this the equivalent of apt-get update && full-upgrade."""
    _, argvs = _update(_ctx(assume_yes=True, root=_repo_root(tmp_path, repos="")))
    assert ["dnf", "upgrade", "--refresh", "-y"] in argvs


def test_without_yes_dnf_does_its_own_prompting(tmp_path):
    _, argvs = _update(_ctx(root=_repo_root(tmp_path, repos="")))
    assert ["dnf", "upgrade", "--refresh"] in argvs
    assert not any("-y" in a for a in argvs)


def test_unsigned_repos_block_the_upgrade_when_the_answer_is_no(tmp_path):
    """gpgcheck=0 means the upgrade itself delivers unverified code."""
    ctx = _ctx(root=_repo_root(tmp_path))
    with patch("fettle.backends.base.Context.confirm", return_value=False):
        result, argvs = _update(ctx)
    assert result.ok is False
    assert not any(a[:2] == ["dnf", "upgrade"] for a in argvs)


def test_unsigned_repos_are_named_and_the_upgrade_proceeds_on_yes(tmp_path, capsys):
    ctx = _ctx(root=_repo_root(tmp_path))
    with patch("fettle.backends.base.Context.confirm", return_value=True):
        _, argvs = _update(ctx)
    cap = capsys.readouterr()          # one read — a second returns an empty buffer
    shown = cap.out + cap.err
    assert "centos-stream-baseos" in shown and "centos-stream-appstream" in shown
    assert any(a[:2] == ["dnf", "upgrade"] for a in argvs)


def test_signed_and_disabled_repos_do_not_trip_the_gate(tmp_path):
    """EPEL is signed; old-unsigned is disabled and installs nothing today. A gate that
    fires on either would be ignored within a week."""
    assert RhelBackend()._unsigned_repos(_ctx(root=_repo_root(tmp_path))) == [
        "centos-stream-appstream", "centos-stream-baseos"]


def test_an_absent_gpgcheck_inherits_dnf_conf_and_does_not_trip_the_gate(tmp_path):
    """dnf.conf ships gpgcheck=1, so a repo omitting the key is fine. Treating absence
    as disabled would fire the gate on essentially every RHEL box."""
    repos = "[r]\nname=r\nbaseurl=https://mirror.stream.centos.org/x/\nenabled=1\n"
    assert RhelBackend()._unsigned_repos(_ctx(root=_repo_root(tmp_path, repos))) == []


def test_yes_proceeds_past_the_gate_but_says_so(tmp_path, capsys):
    """Automation must not be silently blocked — nor silently allowed."""
    result, argvs = _update(_ctx(assume_yes=True, root=_repo_root(tmp_path)))
    assert result.ok and any(a[:2] == ["dnf", "upgrade"] for a in argvs)
    assert "--yes" in capsys.readouterr().err


def test_dry_run_warns_but_still_shows_the_command(tmp_path, capsys):
    """ctx.confirm returns False under --dry-run, so a naive gate would swallow the very
    command the user asked to preview."""
    result, _ = _update(_ctx(dry_run=True, root=_repo_root(tmp_path)))
    combined = capsys.readouterr()
    assert result.ok
    assert "would run: dnf upgrade --refresh" in combined.out + combined.err


def test_an_unreadable_repo_tree_does_not_block_the_upgrade(tmp_path):
    """Best-effort, like the advisory gate: a broken audit path must not stop
    maintenance."""
    assert RhelBackend()._unsigned_repos(_ctx(root=tmp_path / "nope")) == []


def test_update_refuses_on_an_image_based_host(tmp_path):
    root = _repo_root(tmp_path, repos="")
    (root / "run").mkdir()
    (root / "run/ostree-booted").touch()
    result, argvs = _update(_ctx(assume_yes=True, root=root))
    assert result.ok is False
    assert not any(a[:2] == ["dnf", "upgrade"] for a in argvs)


def test_system_updater_none_skips_the_upgrade(tmp_path):
    cfg = Config()
    cfg.updaters = {"rhel": {"system_updater": "none"}}
    _, argvs = _update(_ctx(cfg, assume_yes=True, root=_repo_root(tmp_path, repos="")))
    assert not any(a[:2] == ["dnf", "upgrade"] for a in argvs)


def test_update_extras_covers_flatpak_and_snap():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        RhelBackend().update_extras(_ctx(assume_yes=True))
    argvs = [c for c, _ in calls]
    assert ["flatpak", "update", "-y"] in argvs
    assert ["snap", "refresh"] in argvs


def test_update_extras_skips_absent_tools():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=False):
        RhelBackend().update_extras(_ctx(assume_yes=True))
    assert calls == []


# -- refresh_metadata --------------------------------------------------------
def test_refresh_runs_makecache_and_flatpak_appstream():
    _, argvs = _run({}, method="refresh_metadata")
    assert ["dnf", "makecache"] in argvs
    assert ["flatpak", "update", "--appstream"] in argvs


def test_refresh_honors_system_updater_none():
    cfg = Config()
    cfg.updaters = {"rhel": {"system_updater": "none"}}
    _, argvs = _run({}, method="refresh_metadata", ctx=_ctx(cfg))
    assert ["dnf", "makecache"] not in argvs


def test_an_invalid_updater_warns_and_falls_back():
    cfg = Config()
    cfg.updaters = {"rhel": {"system_updater": "apt"}}  # wrong family
    _, argvs = _run({}, method="refresh_metadata", ctx=_ctx(cfg))
    assert ["dnf", "makecache"] in argvs


def test_refresh_changes_nothing_under_dry_run():
    calls = []
    with patch("fettle.command.run", side_effect=_fake({}, calls)), \
         patch("fettle.command.which", return_value=True):
        RhelBackend().refresh_metadata(_ctx(dry_run=True))
    assert calls == []


# -- firmware ----------------------------------------------------------------
# `firmware_updates` is the base class's, unchanged: fwupd is distro-neutral and the
# RPM family gets it from the `fwupd` package like everyone else. What was missing was
# the *claim* — `firmware_check` absent from `supported` made `fettle -f` on a RHEL box
# report "not supported by the rhel backend" and do nothing, and since firmware-check is
# in REMOTE_DEFAULT_ACTIONS, `fettle remote <rhel-host>` silently skipped it too.
def test_rhel_claims_firmware_check():
    """Guards the claim itself — the concrete base method is useless unadvertised.

    Deliberately not expressible in test_action_registry's
    `test_claimed_actions_are_actually_implemented`: that check asserts a backend
    *overrides* a method it claims, and firmware_check is exempt there precisely
    because inheriting it is correct. So nothing generic can notice the omission.
    """
    assert "firmware_check" in RhelBackend.supported


def test_firmware_no_updatable_devices_is_not_an_error(capsys):
    """`fwupdmgr get-updates` exits **2** with nothing to do, and on RHEL 10.1 says so
    on *stderr* while leaving stdout empty.

    Measured on the live host (fwupd 1.9.31, daemon active, get-devices exit 0 — so
    this is a real "nothing to update", not a broken install). Two traps in one:
    trusting the exit code would report a failure, and matching "No updatable devices"
    in *stdout* would miss it. The emptiness of stdout is what carries the result here.
    """
    err = ("Idle…: 0%\nWARNING: UEFI capsule updates not available or enabled in "
           "firmware setup\nNo updatable devices\n")

    def run(cmd, *, as_user=None, capture=False):
        if list(cmd)[:2] == ["fwupdmgr", "get-updates"]:
            return command.Proc(2, "", err)
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=run), \
         patch("fettle.command.which", return_value=True):
        RhelBackend().firmware_updates(_ctx())
    out = capsys.readouterr().out
    assert "no firmware updates" in out.lower()
    assert "available:" not in out  # never the "updates available" branch
