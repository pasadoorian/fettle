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
