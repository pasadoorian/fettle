"""HS1: risk scoring, privilege weighting, banding, scored rollup."""

from unittest.mock import patch

from fettle.config import Config
from fettle.hardening import report, score
from fettle.hardening.engine import Deviation


def _dev(path, check):
    return Deviation(path=path, check=check, got="x", want=("good",))


# -- weights & score ---------------------------------------------------------
def test_binary_score_sums_weights():
    s = score.Scorer()
    # canary(3) + relro(3) = 6, not privileged
    assert s.binary_score({"canary", "relro"}, privileged=False) == 6.0
    # runpath is the mildest
    assert s.binary_score({"runpath"}, privileged=False) == 0.5


def test_privilege_multiplies_the_score():
    s = score.Scorer(priv_mult=3.0)
    assert s.binary_score({"canary", "relro"}, privileged=True) == 18.0  # 6 * 3


def test_unknown_check_defaults_to_weight_one():
    assert score.Scorer().binary_score({"mystery"}, privileged=False) == 1.0


# -- bands (calibrated) ------------------------------------------------------
def test_band_thresholds():
    assert score.band(18.0) == "Critical"   # setuid canary+relro
    assert score.band(14.0) == "Critical"
    assert score.band(13.9) == "High"
    assert score.band(8.0) == "High"
    assert score.band(6.0) == "Medium"
    assert score.band(3.0) == "Medium"
    assert score.band(2.0) == "Low"
    assert score.band(0.5) == "Low"
    assert score.band(0.0) == "none"        # conforms — not shown


# -- privilege detection -----------------------------------------------------
def test_is_privileged_via_setuid():
    s = score.Scorer()
    with patch("fettle.hardening.score.is_setuid", return_value=True):
        assert s.is_privileged("/usr/bin/whatever", "somepkg")
    with patch("fettle.hardening.score.is_setuid", return_value=False):
        assert not s.is_privileged("/usr/bin/whatever", "somepkg")


def test_is_privileged_via_sensitive_package_glob():
    s = score.Scorer(sensitive_packages=["avahi", "cups*"])
    with patch("fettle.hardening.score.is_setuid", return_value=False):
        assert s.is_privileged("/usr/bin/avahi-daemon", "avahi")
        assert s.is_privileged("/usr/bin/cupsd", "cups")     # glob
        assert not s.is_privileged("/usr/bin/ls", "coreutils")


def test_is_setuid_reads_the_mode(tmp_path):
    f = tmp_path / "suid"
    f.write_bytes(b"x")
    f.chmod(0o4755)
    assert score.is_setuid(str(f))
    plain = tmp_path / "plain"
    plain.write_bytes(b"x")
    plain.chmod(0o755)
    assert not score.is_setuid(str(plain))
    assert not score.is_setuid(str(tmp_path / "missing"))  # never raises


# -- config -----------------------------------------------------------------
def test_scorer_from_config_reads_overrides():
    cfg = Config()
    cfg.hardening = {"weights": {"canary": 10}, "priv_multiplier": 5,
                     "sensitive_packages": ["avahi"]}
    s = score.Scorer.from_config(cfg)
    assert s.weights["canary"] == 10.0
    assert s.weights["relro"] == 3.0            # unspecified keeps default
    assert s.priv_mult == 5.0
    assert s.sensitive_packages == ["avahi"]


def test_scorer_from_config_tolerates_garbage():
    cfg = Config()
    cfg.hardening = {"priv_multiplier": "nope", "weights": "notadict",
                     "sensitive_packages": "notalist"}
    s = score.Scorer.from_config(cfg)
    assert s.priv_mult == score.DEFAULT_PRIV_MULT
    assert s.weights == score.DEFAULT_WEIGHTS
    assert s.sensitive_packages == []
    # no [hardening] table at all
    assert isinstance(score.Scorer.from_config(Config()), score.Scorer)


# -- scored rollup in report.apply -------------------------------------------
def test_apply_scores_and_sorts_by_worst_binary():
    # netpbm: many binaries, each one mild miss -> low per-binary score.
    # xorg-server: one binary missing canary+relro -> score 6, should rank FIRST
    # even though netpbm has more total deviations.
    devs = [_dev(f"/usr/bin/np{i}", "canary") for i in range(20)]        # netpbm
    devs += [_dev("/usr/lib/Xorg.wrap", "canary"), _dev("/usr/lib/Xorg.wrap", "relro")]
    pkgmap = {**{f"/usr/bin/np{i}": "netpbm" for i in range(20)},
              "/usr/lib/Xorg.wrap": "xorg-server"}
    with patch("fettle.hardening.score.is_setuid", return_value=False):
        reports, _ = report.apply(devs, pkgmap, report.Exclusions())
    assert reports[0].package == "xorg-server"     # worst binary wins the sort
    assert reports[0].score == 6.0
    assert reports[0].band == "Medium"
    assert reports[0].worst_binary == "/usr/lib/Xorg.wrap"
    netpbm = next(r for r in reports if r.package == "netpbm")
    assert netpbm.score == 3.0                     # worst single binary, not the sum
    assert netpbm.binaries == 20


def test_apply_privilege_boosts_score_and_band():
    devs = [_dev("/usr/lib/Xorg.wrap", "canary"), _dev("/usr/lib/Xorg.wrap", "relro")]
    pkgmap = {"/usr/lib/Xorg.wrap": "xorg-server"}
    with patch("fettle.hardening.score.is_setuid", return_value=True):  # setuid
        reports, _ = report.apply(devs, pkgmap, report.Exclusions())
    assert reports[0].score == 18.0                # 6 * 3
    assert reports[0].band == "Critical"
    assert reports[0].has_privileged is True


def test_apply_sensitive_package_marks_privileged():
    devs = [_dev("/usr/bin/avahi-daemon", "canary")]
    scorer = score.Scorer(sensitive_packages=["avahi"])
    with patch("fettle.hardening.score.is_setuid", return_value=False):
        reports, _ = report.apply(devs, {"/usr/bin/avahi-daemon": "avahi"},
                                  report.Exclusions(), scorer)
    assert reports[0].has_privileged is True
    assert reports[0].score == 9.0                 # canary(3) * 3


def test_apply_excluded_checks_do_not_count_toward_score():
    # runpath excluded -> the binary scores only on canary
    devs = [_dev("/usr/bin/x", "canary"), _dev("/usr/bin/x", "runpath")]
    excl = report.Exclusions(checks=["runpath"])
    with patch("fettle.hardening.score.is_setuid", return_value=False):
        reports, _ = report.apply(devs, {"/usr/bin/x": "p"}, excl)
    assert reports[0].score == 3.0                 # canary only, runpath dropped
