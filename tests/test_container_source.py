"""Container image supply-chain provider — docker/podman inventory."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fettle import command
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain.base import (MUTABLE_REFERENCE, STALE_OR_ABANDONED,
                                     UNOFFICIAL_SOURCE, UNVERIFIABLE, Severity)
from fettle.supplychain.container_source import ContainerSource


def _ctx(**containers):
    cfg = Config()
    cfg.containers = containers
    return Context(output=Output(color=False), config=cfg)


def _at(days_ago: int) -> str:
    """A CreatedAt string in docker's format, including the trailing zone name."""
    d = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return d.strftime("%Y-%m-%d %H:%M:%S %z") + " UTC"


def _img(repo, tag, days_ago=1, **extra):
    return {"Repository": repo, "Tag": tag, "CreatedAt": _at(days_ago),
            "ID": "abc123", "Size": "100MB", **extra}


def _run(images, *, rc=0, stderr="", tools=("docker",), **containers):
    import json as _json
    stdout = "\n".join(_json.dumps(i) for i in images)

    def fake_run(cmd, *, as_user=None, capture=False):
        if list(cmd)[:2] in (["docker", "images"], ["podman", "images"]):
            return command.Proc(rc, stdout, stderr)
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n in tools):
        return ContainerSource().findings(_ctx(**containers))


# -- the mutable-tag question ------------------------------------------------
def test_latest_tag_is_flagged():
    f = _run([_img("cvetool", "latest")])
    assert any(x.question == MUTABLE_REFERENCE and x.package == "cvetool:latest"
               and x.severity == Severity.WARN for x in f)


def test_only_latest_counts_as_mutable():
    """Decision: `:latest` only. Other rolling-ish tags are not flagged."""
    f = _run([_img("a", "main"), _img("b", "dev"), _img("c", "nightly"),
              _img("d", "3.12-slim"), _img("e", "latest-dev")])
    assert not [x for x in f if x.question == MUTABLE_REFERENCE]


# -- age ---------------------------------------------------------------------
def test_old_image_is_stale():
    f = _run([_img("pyemba-f_phase", "1.0", days_ago=120)])
    stale = [x for x in f if x.question == STALE_OR_ABANDONED]
    assert len(stale) == 1 and "120 days ago" in stale[0].detail


def test_fresh_image_is_not_stale():
    assert not [x for x in _run([_img("fresh", "1.0", days_ago=3)])
                if x.question == STALE_OR_ABANDONED]


def test_max_age_days_is_configurable():
    assert not [x for x in _run([_img("x", "1.0", days_ago=120)], max_age_days=365)
                if x.question == STALE_OR_ABANDONED]


def test_unparseable_created_at_does_not_crash_or_claim_staleness():
    f = _run([_img("weird", "1.0", CreatedAt="not a date")])
    assert not [x for x in f if x.question == STALE_OR_ABANDONED]


# -- registry provenance -----------------------------------------------------
def test_unknown_registry_flagged_known_ones_are_not():
    f = _run([_img("ghcr.io/onekey-sec/unblob", "1.0"),
              _img("cgr.dev/chainguard/python", "1.0"),
              _img("shady.example.net/thing/img", "1.0")])
    unofficial = [x for x in f if x.question == UNOFFICIAL_SOURCE]
    assert len(unofficial) == 1
    assert unofficial[0].package == "shady.example.net/thing/img:1.0"


def test_bare_name_is_not_treated_as_a_registry():
    """`cvetool` is a local build or a Docker Hub library image — docker images
    cannot tell them apart, so neither is claimed."""
    assert not [x for x in _run([_img("cvetool", "1.0")])
                if x.question == UNOFFICIAL_SOURCE]


# -- dangling ----------------------------------------------------------------
def test_dangling_image_is_informational():
    f = _run([_img("<none>", "<none>")])
    assert len(f) == 1 and f[0].severity == Severity.INFO and "prune" in f[0].detail


# -- the audit must never look clean when it could not look ------------------
def test_daemon_failure_reports_loudly_instead_of_returning_nothing():
    """Not in the docker group / daemon down. Returning [] here would render
    identically to 'no problems found' — the v0.22.0 lesson."""
    f = _run([], rc=1, stderr="permission denied while trying to connect to the "
                              "Docker daemon socket")
    assert len(f) == 1
    assert f[0].question == UNVERIFIABLE and f[0].severity == Severity.WARN
    assert "NOT audited" in f[0].detail and "permission denied" in f[0].detail


def test_no_runtime_installed_yields_nothing():
    assert _run([_img("x", "latest")], tools=()) == []
    with patch("fettle.command.which", side_effect=lambda n: False):
        assert ContainerSource().is_present(_ctx()) is False


def test_podman_is_used_when_docker_is_absent():
    seen = []

    def fake_run(cmd, *, as_user=None, capture=False):
        seen.append(list(cmd))
        return command.Proc(0, "", "")

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n == "podman"):
        ContainerSource().findings(_ctx())
    assert seen and seen[0][0] == "podman"


# -- misc --------------------------------------------------------------------
def test_ignore_globs_skip_images():
    f = _run([_img("scratch-build", "latest"), _img("real", "latest")],
             ignore=["scratch-*"])
    assert {x.package for x in f} == {"real:latest"}


def test_malformed_json_lines_are_skipped():
    def fake_run(cmd, *, as_user=None, capture=False):
        return command.Proc(0, 'not json\n{"Repository":"ok","Tag":"latest",'
                               '"CreatedAt":"bad","ID":"i","Size":"1MB"}\n', "")

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n == "docker"):
        f = ContainerSource().findings(_ctx())
    assert [x.package for x in f] == ["ok:latest"]


# -- podman compatibility (verified against real podman output) --------------
# RHEL ships podman, not docker, so podman-only hosts are the main new platform.
# An earlier version of this file asserted the two runtimes agreed, based on
# podman's manual listing .Repository/.Tag/.ID/.CreatedAt as --format placeholders.
# Those are the accessors you may WRITE, not the JSON tags the struct serialises
# to: `podman images --format "{{json .}}"` really emits lowercase repository/tag
# plus Id and Created. Reading it as docker's shape produced NO findings at all,
# silently. Fixtures below are real `podman images --format json` output.
_PODMAN_JSON = """[
    {
     "Id": "d529dd0c6e5597ac7e4a3e2dea65c3fcc6173f4cae713c409265c1dd9914a11b",
     "Repository": "docker.io/library/alpine",
     "Tag": "latest",
     "Created": 1781568089,
     "CreatedAt": "2026-06-16T00:01:29Z",
     "Size": 8709729,
     "Names": ["docker.io/library/alpine:latest"],
     "Digest": "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
    }
]"""


def test_podman_uses_a_different_flag_than_docker():
    """podman's `{{json .}}` has the wrong keys; its plain `--format json` is right."""
    from fettle.supplychain.container_source import images_argv
    assert images_argv("docker")[-1] == "{{json .}}"
    assert images_argv("podman")[-1] == "json"


def test_parse_images_reads_podmans_json_array():
    from fettle.supplychain.container_source import parse_images
    imgs = parse_images(_PODMAN_JSON)
    assert len(imgs) == 1
    assert imgs[0]["Repository"] == "docker.io/library/alpine"
    assert imgs[0]["Tag"] == "latest"
    assert imgs[0]["ID"].startswith("d529dd0c")        # podman spells it `Id`
    assert imgs[0]["Size"] == "9MB"                    # podman gives raw bytes


def test_parse_images_normalises_podmans_lowercase_template_keys():
    """`{{json .}}` on podman emits lowercase repository/tag — accepted defensively
    so a host that somehow produces that shape is not silently empty."""
    from fettle.supplychain.container_source import parse_images
    imgs = parse_images('{"repository":"quay.io/x/y","tag":"1.0","Id":"abc","Size":5000000}')
    assert imgs[0]["Repository"] == "quay.io/x/y" and imgs[0]["Tag"] == "1.0"
    assert imgs[0]["ID"] == "abc"


def test_created_at_parses_both_runtimes():
    """docker `2026-06-15 10:30:30 -0400 EDT`; podman ISO `2026-06-16T00:01:29Z`."""
    from fettle.supplychain.container_source import _created
    assert _created("2026-06-15 10:30:30 -0400 EDT") is not None
    assert _created("2026-06-16T00:01:29Z") is not None
    assert _created("") is None and _created("not a date") is None


def test_podman_output_produces_real_findings_end_to_end():
    """The regression that matters: podman's own output must yield findings, not
    an empty list."""
    def fake_run(cmd, *, as_user=None, capture=False):
        return command.Proc(0, _PODMAN_JSON, "")

    with patch("fettle.command.run", side_effect=fake_run), \
         patch("fettle.command.which", side_effect=lambda n: n == "podman"):
        f = ContainerSource().findings(_ctx(max_age_days=1))
    pkgs = {x.package for x in f}
    assert "docker.io/library/alpine:latest" in pkgs
    assert any(x.question == MUTABLE_REFERENCE for x in f)     # :latest
    assert any(x.question == STALE_OR_ABANDONED for x in f)    # age parsed from ISO
