import textwrap

from fettle.config import Config, load


def test_missing_file_returns_defaults(tmp_path):
    cfg, warnings = load(tmp_path / "nope.toml")
    assert cfg == Config()
    assert warnings == []


def test_loads_known_keys(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(textwrap.dedent("""
        auto_rebuild = true
        keep_orphans = ["downgrade", "nvchecker"]
        default_actions = ["clean", "update"]
    """))
    cfg, warnings = load(p)
    assert cfg.auto_rebuild is True
    assert cfg.keep_orphans == ["downgrade", "nvchecker"]
    assert cfg.default_actions == ["clean", "update"]
    assert warnings == []


def test_unknown_key_warns_but_still_loads(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('auto_rebuild = true\nbogus = 1\n')
    cfg, warnings = load(p)
    assert cfg.auto_rebuild is True
    assert any("bogus" in w for w in warnings)


def test_world_writable_is_refused(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("auto_rebuild = true\n")
    p.chmod(0o666)
    cfg, warnings = load(p)
    assert cfg == Config()  # file ignored, defaults returned
    assert any("world-writable" in w for w in warnings)


def test_wrong_owner_is_refused(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("auto_rebuild = true\n")
    # No uid we are allowed to read as -> refused.
    cfg, warnings = load(p, allowed_uids={999999})
    assert cfg == Config()
    assert any("owned by uid" in w for w in warnings)


def test_malformed_toml_falls_back(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text("this is = = not toml\n")
    cfg, warnings = load(p)
    assert cfg == Config()
    assert any("invalid TOML" in w for w in warnings)
