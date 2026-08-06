"""VS Code / VSCodium extension provider — install provenance."""

import json
from unittest.mock import patch

from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import (
    STALE_OR_ABANDONED,
    UNOFFICIAL_SOURCE,
    UNVERIFIABLE,
    Severity,
)
from fettle.supplychain.vscode_source import (
    VSCodeSource,
    gallery_kind,
    parse_index,
)


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


def _run(home, *, upstream=True, gallery="openvsx"):
    """`upstream`: True present / False withdrawn / None unreachable, or a dict keyed
    by the extension id. Patched by default so the suite never touches the network —
    without this every test id 404s for real and reads as withdrawn."""
    def fake(url, **kw):
        if not isinstance(upstream, dict):
            return upstream
        for ext_id, verdict in upstream.items():
            if ext_id in url:
                return verdict
        return True
    with patch("fettle.supplychain.vscode_source.still_upstream_url", side_effect=fake), \
         patch("fettle.supplychain.vscode_source.gallery_kind", return_value=gallery):
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
    assert f[0].question == UNOFFICIAL_SOURCE and f[0].severity == Severity.MEDIUM
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


# -- is it still listed? -------------------------------------------------------
#
# Withdrawal is what a marketplace DOES to a malicious extension, and an extension runs
# unsandboxed with the user's full privileges -- so this is the highest-value question
# in this provider. Measured 2026-08-06: Open VSX and the marketplace item page both
# answer 200 present / 404 absent. (The DOCUMENTED marketplace gallery endpoint answers
# 404 either way, so building on it would have called every extension withdrawn.)

def test_withdrawn_extension_is_reported(tmp_path):
    _profile(tmp_path, ".vscode-oss", [_entry("pub.gone")])
    f = _run(tmp_path, upstream=False)
    w = next(x for x in f if x.question == STALE_OR_ABANDONED)
    assert w.package == "vscodium:pub.gone"
    assert "no longer listed on Open VSX" in w.detail


def test_unreachable_registry_is_not_a_withdrawal(tmp_path):
    """A registry that is merely down must never read as "every extension you have was
    pulled" -- "could not look" rendering as "found a problem"."""
    _profile(tmp_path, ".vscode-oss", [_entry("pub.a"), _entry("pub.b")])
    f = _run(tmp_path, upstream=None)
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]
    gaps = [x for x in f if x.question == UNVERIFIABLE]
    assert len(gaps) == 1 and "2 item(s)" in gaps[0].detail


def test_sideloaded_vsix_is_never_asked_about(tmp_path):
    """It bypassed the registry, so it was never listed and would flag forever."""
    _profile(tmp_path, ".vscode-oss", [_entry("pub.local", source="vsix")])
    f = _run(tmp_path, upstream=False)
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]


def test_vscodium_asks_open_vsx_not_the_marketplace(tmp_path):
    """Asking the wrong registry would report every extension in the other ecosystem as
    withdrawn."""
    seen = []
    _profile(tmp_path, ".vscode-oss", [_entry("pub.ext")])

    def spy(url, **kw):
        seen.append(url)
        return True
    with patch("fettle.supplychain.vscode_source.still_upstream_url", side_effect=spy), \
         patch("fettle.supplychain.vscode_source.gallery_kind", return_value="openvsx"):
        VSCodeSource().findings(_ctx(tmp_path))
    assert seen and all("open-vsx.org" in u for u in seen), seen


def test_vscode_asks_the_marketplace(tmp_path):
    seen = []
    _profile(tmp_path, ".vscode", [_entry("pub.ext")])

    def spy(url, **kw):
        seen.append(url)
        return False if "canary" in url else True
    with patch("fettle.supplychain.vscode_source.still_upstream_url", side_effect=spy), \
         patch("fettle.supplychain.vscode_source.gallery_kind", return_value="marketplace"):
        VSCodeSource().findings(_ctx(tmp_path))
    assert seen and all("marketplace.visualstudio.com" in u for u in seen), seen


def test_broken_marketplace_discriminator_is_caught_by_the_canary(tmp_path):
    """The marketplace signal is a rendered web page, not an API contract. If it ever
    stops 404ing for an id that cannot exist, every extension looks present and the
    audit would report clean having detected nothing -- so each run proves it can still
    see a known-absent id first."""
    _profile(tmp_path, ".vscode", [_entry("pub.ext")])
    with patch("fettle.supplychain.vscode_source.still_upstream_url", return_value=True), \
         patch("fettle.supplychain.vscode_source.gallery_kind", return_value="marketplace"):
        f = VSCodeSource().findings(_ctx(tmp_path))
    gap = next(x for x in f if x.question == UNVERIFIABLE)
    assert "no longer answers 404" in gap.detail
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]


# -- which gallery is this editor actually wired to? ---------------------------
#
# THE PROFILE DIRECTORY DOES NOT DECIDE THIS. Measured on a real Arch box: `.vscode-oss`
# (Code - OSS) is patched to use Microsoft's marketplace, and inferring "oss => Open VSX"
# reported ms-vscode.cpptools and platformio.platformio-ide as withdrawn when both are
# present in the gallery the editor actually uses. They were simply never published to
# Open VSX. Asking the wrong registry does not give a weaker answer -- it gives a
# confident wrong one.

_MS_PRODUCT = json.dumps({"extensionsGallery": {
    "serviceUrl": "https://marketplace.visualstudio.com/_apis/public/gallery"}})
_VSX_PRODUCT = json.dumps({"extensionsGallery": {
    "serviceUrl": "https://open-vsx.org/vscode/gallery"}})


def test_gallery_kind_reads_the_user_product_json(tmp_path):
    d = tmp_path / ".config/VSCodium"
    d.mkdir(parents=True)
    (d / "product.json").write_text(_MS_PRODUCT)
    assert gallery_kind(tmp_path) == "marketplace"

    (d / "product.json").write_text(_VSX_PRODUCT)
    assert gallery_kind(tmp_path) == "openvsx"


def test_gallery_kind_is_empty_when_undetermined(tmp_path):
    """Empty means the removal check is skipped, not guessed."""
    assert gallery_kind(tmp_path / "nothing-here") in ("", "marketplace", "openvsx")


def test_undetermined_gallery_skips_the_removal_check(tmp_path):
    """A .vscode-oss profile whose editor points at the marketplace must NOT have its
    extensions checked against Open VSX -- the real false positive this guards."""
    _profile(tmp_path, ".vscode-oss", [_entry("ms-vscode.cpptools")])
    called = []
    with patch("fettle.supplychain.vscode_source.still_upstream_url",
               side_effect=lambda u, **k: called.append(u) or False), \
         patch("fettle.supplychain.vscode_source.gallery_kind", return_value=""):
        f = VSCodeSource().findings(_ctx(tmp_path))
    assert called == [], called
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]
    gap = next(x for x in f if x.question == UNVERIFIABLE)
    assert "could not determine which extension gallery" in gap.detail
