import textwrap

import pytest

from fettle.backends.arch import ArchBackend
from fettle.backends.debian import DebianBackend
from fettle.distro import UnknownDistro, detect, parse_os_release


def _write_osr(root, content):
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "etc/os-release").write_text(textwrap.dedent(content))


def test_parse_os_release(tmp_path):
    _write_osr(tmp_path, '''
        ID=ubuntu
        ID_LIKE=debian
        PRETTY_NAME="Ubuntu 24.04 LTS"
    ''')
    osr = parse_os_release(tmp_path)
    assert osr["ID"] == "ubuntu"
    assert osr["PRETTY_NAME"] == "Ubuntu 24.04 LTS"


def test_detect_direct_match(tmp_path):
    _write_osr(tmp_path, "ID=arch\n")
    assert isinstance(detect(tmp_path), ArchBackend)


def test_detect_id_like_fallthrough(tmp_path):
    # 'neon' is not registered, but its ID_LIKE points at ubuntu/debian.
    _write_osr(tmp_path, 'ID=neon\nID_LIKE="ubuntu debian"\n')
    assert isinstance(detect(tmp_path), DebianBackend)


def test_detect_override_wins():
    assert isinstance(detect(override="manjaro"), ArchBackend)


def test_unknown_distro_raises(tmp_path):
    _write_osr(tmp_path, "ID=plan9\n")
    with pytest.raises(UnknownDistro):
        detect(tmp_path)


def test_bad_override_raises():
    with pytest.raises(UnknownDistro):
        detect(override="temple-os")


def test_missing_os_release_raises(tmp_path):
    with pytest.raises(UnknownDistro):
        detect(tmp_path)


# -- the enterprise RPM family ----------------------------------------------
# Each ID is registered explicitly rather than leaning on ID_LIKE. topgrade reaches
# Rocky/Alma only via an ID_LIKE token, which breaks the moment a release spells its
# ID_LIKE differently — and RHEL itself carries only ID_LIKE="fedora", which we do
# NOT register (Fedora's advisories are Bodhi FEDORA-*, not RHSA).
@pytest.mark.parametrize("osr", [
    'ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="10.1"\n',      # RHEL 10
    'ID="rhel"\nID_LIKE="fedora"\nVERSION_ID="9.4"\n',       # RHEL 9
    'ID="centos"\nID_LIKE="rhel fedora"\n',                  # CentOS Stream
    'ID="rocky"\nID_LIKE="rhel centos fedora"\n',            # Rocky
    'ID="almalinux"\nID_LIKE="rhel centos fedora"\n',        # Alma
    'ID="ol"\nID_LIKE="fedora"\n',                           # Oracle Linux
])
def test_detect_rhel_family(tmp_path, osr):
    from fettle.backends.rhel import RhelBackend
    _write_osr(tmp_path, osr)
    assert isinstance(detect(tmp_path), RhelBackend)


def test_rhel_id_alone_is_enough_without_id_like(tmp_path):
    """A derivative that drops ID_LIKE entirely must still resolve."""
    from fettle.backends.rhel import RhelBackend
    _write_osr(tmp_path, 'ID="rocky"\n')
    assert isinstance(detect(tmp_path), RhelBackend)


def test_fedora_is_not_claimed(tmp_path):
    """Deliberate: Fedora shares dnf but its advisories are Bodhi FEDORA-*, not
    RHSA, so claiming it would make the advisory provider approximate."""
    _write_osr(tmp_path, 'ID="fedora"\nVERSION_ID="41"\n')
    with pytest.raises(UnknownDistro):
        detect(tmp_path)


def test_rhel_backend_does_not_claim_unbuilt_actions():
    """`supported` is a promise: an action listed here runs, one omitted is reported as
    unsupported rather than raising NotImplementedError at the user. The maintenance
    half is landing wave by wave, so this asserts what is *not* claimed yet — the
    matching "everything claimed is implemented" direction is enforced for every
    backend by test_action_registry."""
    from fettle.backends.rhel import RhelBackend
    for absent in ("orphans", "kernel", "aur_audit", "python_rebuild_check"):
        assert absent not in RhelBackend.supported


def test_rhel_inherits_the_distro_agnostic_providers():
    """Registering the backend is what unlocks pkg-audit on RHEL — the six shared
    providers come from the base class with no RPM-specific code."""
    from fettle.backends.rhel import RhelBackend
    names = {p.source for p in RhelBackend().supply_chain_sources()}
    assert {"flatpak", "snap", "container", "gnome", "vscode", "gh"} <= names
