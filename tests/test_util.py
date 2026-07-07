from fettle.util import matches_any


def test_exact_match():
    assert matches_any("mailspring", ["mailspring"])
    assert not matches_any("mailspring", ["firefox"])


def test_glob_match():
    assert matches_any("python-requests", ["python-*"])
    assert matches_any("foo-git", ["*-git"])
    assert not matches_any("foo-bin", ["*-git"])


def test_empty_patterns_never_match():
    assert not matches_any("anything", [])
    assert not matches_any("anything", ["", None] if False else [""])


def test_case_sensitive():
    assert not matches_any("Mailspring", ["mailspring"])
