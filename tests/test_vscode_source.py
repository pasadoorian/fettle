"""VS Code / VSCodium extension provider — install provenance."""

import json

from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import UNOFFICIAL_SOURCE, UNVERIFIABLE, Severity
from fettle.supplychain.vscode_source import VSCodeSource, parse_index


def _entry(ext_id, version="1.0.0", source="gallery", publisher="Someone"):
    e = {"identifier": {"id": ext_id}, "version": version,
         "metadata": {"publisherDisplayName": publisher}}
    if source is not None:
        e["metadata"]["source"] = source
    return e


def _profile(home, sub, entries, *, raw=None):
    d = home / sub / "extensions"
    d.mkdir(parents=True)
    (d / "extensions.json").write_text(
        raw if raw is not None else json.dumps(entries))


def _ctx(home):
    return Context(output=Output(color=False), config=Config(), user_home=home)


def _run(home):
    return VSCodeSource().findings(_ctx(home))


# -- provenance --------------------------------------------------------------
def test_sideloaded_vsix_is_flagged(tmp_path):
    _profile(tmp_path, ".vscode-oss", [
        _entry("ms-vscode.cpptools", source="vsix", publisher="Microsoft"),
        _entry("vscodevim.vim", source="gallery"),
    ])
    f = _run(tmp_path)
    assert len(f) == 1
    assert f[0].package == "vscodium:ms-vscode.cpptools"
    assert f[0].question == UNOFFICIAL_SOURCE and f[0].severity == Severity.WARN
    assert "bypassed the registry" in f[0].detail
    assert "Microsoft" in f[0].detail          # the claimed publisher is surfaced


def test_gallery_installs_are_not_flagged(tmp_path):
    _profile(tmp_path, ".vscode-oss", [_entry(f"pub.ext{i}") for i in range(5)])
    assert _run(tmp_path) == []


def test_missing_source_metadata_is_low_not_silent(tmp_path):
    _profile(tmp_path, ".vscode-oss", [_entry("pub.ext", source=None)])
    f = _run(tmp_path)
    assert len(f) == 1 and f[0].severity == Severity.LOW
    assert "no install source" in f[0].detail


# -- multiple editors --------------------------------------------------------
def test_vscode_and_vscodium_are_reported_separately(tmp_path):
    _profile(tmp_path, ".vscode-oss", [_entry("a.a", source="vsix")])
    _profile(tmp_path, ".vscode", [_entry("b.b", source="vsix")])
    assert {x.package for x in _run(tmp_path)} == {"vscodium:a.a", "vscode:b.b"}


# -- the audit must not look clean when it could not look --------------------
def test_unparseable_index_reports_instead_of_returning_clean(tmp_path):
    _profile(tmp_path, ".vscode-oss", None, raw="{not json at all")
    f = _run(tmp_path)
    assert len(f) == 1 and f[0].question == UNVERIFIABLE
    assert "NOT audited" in f[0].detail


def test_unexpected_shape_reports_instead_of_returning_clean(tmp_path):
    """A future format change must degrade to "I could not read this", not to
    "no extensions installed"."""
    _profile(tmp_path, ".vscode-oss", None, raw='{"extensions": []}')
    f = _run(tmp_path)
    assert len(f) == 1 and f[0].question == UNVERIFIABLE


def test_genuinely_empty_index_is_clean(tmp_path):
    _profile(tmp_path, ".vscode-oss", [])
    assert _run(tmp_path) == []


# -- presence ----------------------------------------------------------------
def test_absent_when_no_editor_profile_exists(tmp_path):
    assert VSCodeSource().is_present(_ctx(tmp_path)) is False
    assert _run(tmp_path) == []


def test_present_when_an_index_exists(tmp_path):
    _profile(tmp_path, ".vscode-oss", [])
    assert VSCodeSource().is_present(_ctx(tmp_path)) is True


# -- parsing tolerance -------------------------------------------------------
def test_parse_index_skips_malformed_entries():
    text = json.dumps([_entry("good.one"), {"no": "identifier"}, "not a dict",
                       {"identifier": {"id": ""}}])
    assert [e["id"] for e in parse_index(text)] == ["good.one"]


def test_parse_index_distinguishes_empty_from_unreadable():
    """`json.dumps([])` is the non-empty string "[]", so the emptiness of the raw
    text cannot tell these apart — the return value has to."""
    assert parse_index("[]") == []            # an editor with no extensions
    assert parse_index("{not json") is None   # a blind spot
    assert parse_index('{"extensions": []}') is None
