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
