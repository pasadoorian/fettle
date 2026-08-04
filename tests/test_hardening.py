"""Hardening audit engine + baseline resolver.

Fixtures are real checksec 3.2.0 output captured on an Arch box, trimmed to the
keys under test — so the four accuracy corrections are exercised against the
wording checksec actually emits.
"""

from pathlib import Path
from unittest.mock import patch

from fettle import command
from fettle.hardening import baseline as bl
from fettle.hardening import engine


def _checks(**kw):
    """Build a checks dict; every value is {"value": ..., "status": ...}."""
    return {k: {"value": v, "status": "green"} for k, v in kw.items()}


# /usr/bin/ls — a correctly built Arch binary (note safestack is red even here)
LS = {"name": "/usr/bin/ls", "checks": _checks(
    relro="Full RELRO", pie="PIE Enabled", canary="Canary Found",
    fortify_source="Yes", fortifyable="15", fortified="10", cfi="SHSTK & IBT",
    nx="NX enabled", rpath="No RPATH", runpath="No RUNPATH",
    stack_clash="Likely Enabled", safestack="No SafeStack Found")}

# /usr/bin/grype — static Go: fortify N/A, no canary/PIE/RELRO (correction 2)
GRYPE = {"name": "/usr/bin/grype", "checks": _checks(
    relro="No RELRO", pie="PIE Disabled", canary="No Canary Found",
    fortify_source="N/A", fortifyable="0", fortified="0", cfi="Unknown",
    nx="NX enabled", rpath="No RPATH", runpath="No RUNPATH",
    stack_clash="No Probes", safestack="No SafeStack Found")}

# /usr/bin/parallel — a Perl script: checksec errors on every key (correction 1)
SCRIPT = {"name": "/usr/bin/parallel", "checks": _checks(
    relro="Error checking relro", pie="Error checking PIE",
    canary="Error checking canary", fortify_source="Error checking Fortify",
    fortifyable="N/A", cfi="Error checking CFI", nx="Error checking NX",
    rpath="Error checking RPATH", runpath="Error checking RUNPATH",
    stack_clash="Error checking StackClash", safestack="Error")}

# a real offender: Xorg.wrap is setuid-root with no RELRO and no canary
XORGWRAP = {"name": "/usr/lib/Xorg.wrap", "checks": _checks(
    relro="Partial RELRO", pie="PIE Enabled", canary="No Canary Found",
    fortify_source="Yes", fortifyable="4", fortified="2", cfi="SHSTK & IBT",
    nx="NX enabled", rpath="No RPATH", runpath="No RUNPATH",
    stack_clash="No Probes", safestack="No SafeStack Found")}

ARCH_BASE = bl.Baseline(name="test", criteria={
    "relro": bl.GOOD_RELRO_FULL, "pie": bl.GOOD_PIE, "canary": bl.GOOD_CANARY,
    "fortify_source": bl.GOOD_FORTIFY, "cfi": bl.GOOD_CFI, "nx": bl.GOOD_NX,
    "rpath": bl.GOOD_NO_RPATH, "runpath": bl.GOOD_NO_RUNPATH})


# -- the four accuracy corrections -------------------------------------------
def test_clean_binary_yields_no_deviations():
    devs, stats = engine.evaluate([LS], ARCH_BASE)
    assert devs == []
    assert stats["analyzed"] == 1


def test_non_elf_script_is_dropped_not_flagged():
    # correction 1: without this every Perl/shell script fails all 9 criteria
    devs, stats = engine.evaluate([SCRIPT], ARCH_BASE)
    assert devs == []
    assert stats["unreadable"] == 1 and stats["analyzed"] == 0


def test_static_go_binary_is_skipped():
    # correction 2: grype would otherwise report no-relro/no-pie/no-canary
    devs, stats = engine.evaluate([GRYPE], ARCH_BASE)
    assert devs == []
    assert stats["static"] == 1 and stats["analyzed"] == 0


def test_fortify_no_is_ignored_when_nothing_was_fortifyable():
    # correction 3: "No" + fortifyable=0 says nothing about build flags
    entry = {"name": "/usr/bin/x", "checks": _checks(
        fortify_source="No", fortifyable="0", relro="Full RELRO", pie="PIE Enabled",
        canary="Canary Found", cfi="SHSTK & IBT", nx="NX enabled",
        rpath="No RPATH", runpath="No RUNPATH")}
    assert engine.evaluate([entry], ARCH_BASE)[0] == []


def test_fortify_no_is_reported_when_something_was_fortifyable():
    entry = {"name": "/usr/bin/x", "checks": _checks(
        fortify_source="No", fortifyable="12", relro="Full RELRO", pie="PIE Enabled",
        canary="Canary Found", cfi="SHSTK & IBT", nx="NX enabled",
        rpath="No RPATH", runpath="No RUNPATH")}
    devs, _ = engine.evaluate([entry], ARCH_BASE)
    assert [d.check for d in devs] == ["fortify_source"]


def test_stack_clash_is_never_a_criterion():
    # correction 4: passwd is built WITH -fstack-clash-protection yet reports
    # "No Probes"; making it pass/fail is ~83% false positives.
    base = bl.Baseline(name="t", criteria={**ARCH_BASE.criteria,
                                           "stack_clash": ("Likely Enabled",)})
    devs, _ = engine.evaluate([XORGWRAP], base)
    assert "stack_clash" not in {d.check for d in devs}


def test_never_criteria_documents_a_reason_for_each_key():
    assert "safestack" in engine.NEVER_CRITERIA and "stack_clash" in engine.NEVER_CRITERIA
    assert all(v for v in engine.NEVER_CRITERIA.values())


# -- real deviations ---------------------------------------------------------
def test_real_offender_reports_exactly_its_gaps():
    devs, _ = engine.evaluate([XORGWRAP], ARCH_BASE)
    assert {d.check for d in devs} == {"relro", "canary"}
    relro = next(d for d in devs if d.check == "relro")
    assert relro.got == "Partial RELRO" and relro.want_str == "Full RELRO"


def test_evaluate_tolerates_garbage_entries():
    devs, stats = engine.evaluate(["nonsense", None, {}, {"checks": 5}], ARCH_BASE)
    assert devs == [] and stats["total"] == 0


def test_unknown_key_absent_from_output_is_not_a_deviation():
    entry = {"name": "/usr/bin/x", "checks": _checks(relro="Full RELRO")}
    assert engine.evaluate([entry], ARCH_BASE)[0] == []  # missing keys are skipped


# -- checksec invocation -----------------------------------------------------
def test_run_checksec_uses_listfile_and_json():
    calls = []

    def fake(cmd, *, as_user=None, capture=False):
        calls.append(list(cmd))
        return command.Proc(0, "[]", "")

    engine.run_checksec(["/usr/bin/ls"], runner=fake)
    argv = calls[0]
    assert argv[0] == "checksec" and argv[1] == "listfile"
    assert "-o" in argv and argv[argv.index("-o") + 1] == "json"
    assert "--no-banner" in argv


def test_run_checksec_survives_bad_json_and_missing_tool():
    bad = lambda cmd, **kw: command.Proc(0, "not json", "")          # noqa: E731
    assert engine.run_checksec(["/usr/bin/ls"], runner=bad) == []
    gone = lambda cmd, **kw: command.Proc(127, "", "not found")      # noqa: E731
    assert engine.run_checksec(["/usr/bin/ls"], runner=gone) == []


def test_run_checksec_no_paths_does_not_spawn():
    calls = []
    engine.run_checksec([], runner=lambda c, **k: calls.append(c))
    assert calls == []


def test_run_checksec_cleans_up_its_temp_file():
    seen = {}

    def fake(cmd, *, as_user=None, capture=False):
        seen["listfile"] = cmd[2]
        return command.Proc(0, "[]", "")

    engine.run_checksec(["/usr/bin/ls"], runner=fake)
    assert not Path(seen["listfile"]).exists()


# -- ELF gate ----------------------------------------------------------------
def test_is_elf_accepts_elf_rejects_script(tmp_path):
    elf = tmp_path / "bin"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 40)
    script = tmp_path / "s.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    assert engine.is_elf(str(elf))
    assert not engine.is_elf(str(script))
    assert not engine.is_elf(str(tmp_path / "missing"))
    assert not engine.is_elf(str(tmp_path))  # a directory


def test_is_elf_ignores_symlinks(tmp_path):
    elf = tmp_path / "bin"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 40)
    link = tmp_path / "link"
    link.symlink_to(elf)
    assert not engine.is_elf(str(link))  # scanned once, via its real path


def test_default_targets_finds_elf_and_setuid(tmp_path):
    (tmp_path / "usr/bin").mkdir(parents=True)
    (tmp_path / "usr/lib").mkdir(parents=True)
    good = tmp_path / "usr/bin/prog"
    good.write_bytes(b"\x7fELF" + b"\x00" * 40)
    (tmp_path / "usr/bin/script.sh").write_text("#!/bin/sh\n")
    suid = tmp_path / "usr/lib/helper"
    suid.write_bytes(b"\x7fELF" + b"\x00" * 40)
    suid.chmod(0o4755)
    plain = tmp_path / "usr/lib/libfoo.so"
    plain.write_bytes(b"\x7fELF" + b"\x00" * 40)

    found = engine.default_targets(tmp_path)
    assert str(good) in found          # /usr/bin ELF
    assert str(suid) in found          # setuid under /usr/lib
    assert str(plain) not in found     # non-setuid lib is out of scope (HA F2)
    assert not any(f.endswith(".sh") for f in found)


# -- baseline resolver -------------------------------------------------------
_MAKEPKG = '''
CFLAGS="-march=x86-64 -O2 -pipe -fno-plt \\
        -Wp,-D_FORTIFY_SOURCE=3 -Wformat \\
        -fstack-clash-protection -fcf-protection"
LDFLAGS="-Wl,-O1 -Wl,--sort-common -Wl,-z,relro -Wl,-z,now"
'''


def _gcc(pie=True, ssp=True):
    flags = " ".join(f for f, on in (("--enable-default-pie", pie),
                                     ("--enable-default-ssp", ssp)) if on)
    # gcc writes -v output to stderr, which the resolver must read
    return lambda cmd, **kw: command.Proc(0, "", f"Configured with: {flags}\n")


def test_arch_baseline_from_makepkg_and_gcc_defaults(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/makepkg.conf").write_text(_MAKEPKG)
    with patch("fettle.command.which", return_value=True):
        base = bl.resolve("arch", root=tmp_path, runner=_gcc())
    assert base.criteria["relro"] == bl.GOOD_RELRO_FULL   # -z relro + -z now
    assert base.criteria["fortify_source"] == bl.GOOD_FORTIFY
    assert base.criteria["cfi"] == bl.GOOD_CFI            # -fcf-protection
    assert base.criteria["pie"] == bl.GOOD_PIE            # from gcc, NOT makepkg
    assert base.criteria["canary"] == bl.GOOD_CANARY      # from gcc, NOT makepkg
    assert "stack_clash" not in base.criteria             # never a criterion


def test_arch_baseline_without_gcc_defaults_drops_pie_and_canary(tmp_path):
    # the whole point of consulting gcc: makepkg.conf has no -fstack-protector*,
    # so a gcc without default-ssp means the distro never promised a canary.
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/makepkg.conf").write_text(_MAKEPKG)
    with patch("fettle.command.which", return_value=True):
        base = bl.resolve("arch", root=tmp_path, runner=_gcc(pie=False, ssp=False))
    assert "pie" not in base.criteria and "canary" not in base.criteria
    assert base.criteria["relro"] == bl.GOOD_RELRO_FULL   # still from LDFLAGS


def test_arch_baseline_notes_where_pie_and_canary_came_from(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/makepkg.conf").write_text(_MAKEPKG)
    with patch("fettle.command.which", return_value=True):
        base = bl.resolve("arch", root=tmp_path, runner=_gcc())
    assert any("GCC supplies" in n for n in base.notes)


def test_arch_baseline_partial_relro_when_no_bindnow(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/makepkg.conf").write_text('LDFLAGS="-Wl,-z,relro"\nCFLAGS=""\n')
    with patch("fettle.command.which", return_value=True):
        base = bl.resolve("arch", root=tmp_path, runner=_gcc())
    assert base.criteria["relro"] == bl.GOOD_RELRO_ANY


def test_arch_baseline_missing_makepkg_conf_degrades(tmp_path):
    with patch("fettle.command.which", return_value=True):
        base = bl.resolve("arch", root=tmp_path, runner=_gcc())
    assert any("unreadable" in n for n in base.notes)
    assert base.criteria["nx"] == bl.GOOD_NX  # still usable


def test_debian_baseline_uses_dpkg_buildflags():
    def fake(cmd, **kw):
        if cmd[:2] == ["dpkg-buildflags", "--get"]:
            if cmd[2] == "CFLAGS":
                return command.Proc(0, "-fstack-protector-strong -D_FORTIFY_SOURCE=2", "")
            return command.Proc(0, "-Wl,-z,relro -Wl,-z,now", "")
        return command.Proc(0, "", "Configured with: --enable-default-pie\n")

    with patch("fettle.command.which", return_value=True):
        base = bl.resolve("debian", runner=fake)
    assert base.criteria["relro"] == bl.GOOD_RELRO_FULL
    assert base.criteria["canary"] == bl.GOOD_CANARY
    assert base.criteria["fortify_source"] == bl.GOOD_FORTIFY
    assert "cfi" not in base.criteria  # Debian doesn't set -fcf-protection here


def test_debian_baseline_falls_back_without_dpkg_dev():
    with patch("fettle.command.which", return_value=False):
        base = bl.resolve("debian", runner=lambda c, **k: command.Proc(0, "", ""))
    assert any("documented defaults" in n for n in base.notes)
    assert base.criteria["relro"] == bl.GOOD_RELRO_FULL


def test_unknown_distro_gets_generic_baseline():
    base = bl.resolve("temple-os")
    assert base.name == "generic" and base.criteria["nx"] == bl.GOOD_NX
    assert any("generic baseline" in n for n in base.notes)


def test_baseline_wants_accessor():
    assert ARCH_BASE.wants("relro") == bl.GOOD_RELRO_FULL
    assert ARCH_BASE.wants("nope") is None


# -- RHEL baseline -----------------------------------------------------------
# The hardening flags live in redhat-rpm-config, a BUILD-time package absent from a
# stock running system: a real RHEL 10.1 box and a stock AlmaLinux container both
# lack it, leaving `%{build_cflags}` as a bare `-O2 -g` and `%{build_ldflags}`
# UNEXPANDED (it evaluates to its own literal text, not an error or empty string).
def _rpm_runner(macros):
    from fettle import command

    def run(cmd, *, as_user=None, capture=False):
        c = list(cmd)
        if c[:2] == ["rpm", "--eval"]:
            key = c[2].strip("%{}")
            return command.Proc(0, macros.get(key, c[2]), "")   # undefined -> literal
        return command.Proc(0, "", "")
    return run


def test_rhel_baseline_uses_real_macros_when_present():
    from unittest.mock import patch
    from fettle.hardening.baseline import resolve
    macros = {
        "build_cflags": "-O2 -flto=auto -Wp,-D_FORTIFY_SOURCE=3 "
                        "-fstack-protector-strong -fPIE",
        "build_ldflags": "-Wl,-z,relro -Wl,-z,now -pie",
    }
    with patch("fettle.command.which", return_value=True):
        b = resolve("rhel", runner=_rpm_runner(macros))
    assert "rpm build macros" in b.name
    assert not any("documented" in n for n in b.notes)     # real values were found


def test_rhel_baseline_detects_an_unexpanded_macro():
    """`%{build_ldflags}` evaluates to its own literal text when undefined — the only
    signal that redhat-rpm-config is missing."""
    from unittest.mock import patch
    from fettle.hardening.baseline import resolve
    with patch("fettle.command.which", return_value=True):
        b = resolve("rhel", runner=_rpm_runner({"build_cflags": "-O2 -g"}))
    assert any("redhat-rpm-config not installed" in n for n in b.notes)
    assert b.criteria                                       # still yields criteria


def test_rhel_is_no_longer_the_generic_baseline():
    from unittest.mock import patch
    from fettle.hardening.baseline import resolve
    with patch("fettle.command.which", return_value=True):
        b = resolve("rhel", runner=_rpm_runner({}))
    assert b.name != "generic"
    assert not any("no build-flag source" in n for n in b.notes)


def test_unknown_distro_still_gets_the_generic_baseline():
    from fettle.hardening.baseline import resolve
    assert resolve("gentoo").name == "generic"


# -- checksec 2.x (Fedora ships 2.7.1, dated 2015) ---------------------------
# Real output, measured on a Fedora 44 guest:
#   checksec --format=json --file=/usr/bin/bash
_V2_JSON = ('{ "/usr/bin/bash": { "relro":"full","canary":"yes","nx":"yes","pie":"yes",'
            '"rpath":"no","runpath":"no","symbols":"no","fortify_source":"partial",'
            '"fortified":"21","fortify-able":"37" } }')
_V2_WEAK = ('{ "/usr/bin/weak": { "relro":"partial","canary":"no","nx":"yes","pie":"no",'
            '"rpath":"no","runpath":"no","fortify_source":"no","fortify-able":"12" } }')


def _run_v2(payloads):
    """Fake a host where only the 2.x interface works: the 3.x call yields nothing."""
    calls = []

    def run(cmd, *, as_user=None, capture=False):
        cmd = list(cmd)
        calls.append(cmd)
        if "listfile" in cmd:
            return command.Proc(1, "", "unrecognised option")
        for path, payload in payloads.items():
            if any(c == f"--file={path}" for c in cmd):
                return command.Proc(0, payload, "")
        return command.Proc(0, "{}", "")

    return run, calls


def test_checksec_2x_is_understood_when_the_3x_call_yields_nothing():
    """Fedora ships checksec 2.7.1, whose command line and JSON schema share nothing
    with 3.x. The 3.x invocation against it produces no parseable output at all."""
    run, calls = _run_v2({"/usr/bin/bash": _V2_JSON})
    got = engine.run_checksec(["/usr/bin/bash"], runner=run)
    assert any("listfile" in c for c in calls)          # 3.x tried first
    assert any("--format=json" in c for c in calls)      # then 2.x
    assert len(got) == 1 and got[0]["name"] == "/usr/bin/bash"


def test_2x_values_are_mapped_into_the_3x_vocabulary():
    """The baselines are written in 3.x wording ("Canary Found", "PIE Enabled"). 2.x
    says "yes"/"no". Normalising at the edge keeps one comparison vocabulary."""
    run, _ = _run_v2({"/usr/bin/bash": _V2_JSON})
    checks = engine.run_checksec(["/usr/bin/bash"], runner=run)[0]["checks"]
    assert checks["relro"]["value"] == "Full RELRO"
    assert checks["canary"]["value"] == "Canary Found"
    assert checks["pie"]["value"] == "PIE Enabled"
    assert checks["fortifyable"]["value"] == "37"       # 2.x spells it "fortify-able"


def test_a_2x_weak_binary_still_produces_deviations():
    """The point of the mapping: findings must survive it, not just parse."""
    from fettle.hardening import baseline as bl
    run, _ = _run_v2({"/usr/bin/weak": _V2_WEAK})
    results = engine.run_checksec(["/usr/bin/weak"], runner=run)
    base = bl.Baseline(name="t", criteria={"pie": bl.GOOD_PIE,
                                           "canary": bl.GOOD_CANARY,
                                           "relro": bl.GOOD_RELRO_FULL})
    devs, stats = engine.evaluate(results, base)
    assert stats["analyzed"] == 1
    assert {d.check for d in devs} == {"pie", "canary", "relro"}


# -- the summary mark has to match what was found ------------------------------
def _run_audit(tmp_path, **patches):
    from unittest.mock import patch as _p
    from fettle.backends.arch import ArchBackend
    from fettle.backends.base import Context
    from fettle.config import Config
    from fettle.hardening import audit
    from fettle.output import Output

    ctx = Context(output=Output(color=False), config=Config(), dry_run=True,
                  root=tmp_path, user_home=tmp_path)
    stack = []
    for target, kw in patches.items():
        stack.append(_p(target, **kw))
    for s in stack:
        s.start()
    try:
        audit.run(ArchBackend(), ctx)
    finally:
        for s in stack:
            s.stop()
    ctx.output.print_summary()
    return ctx


def test_missing_checksec_is_not_a_silent_skip(tmp_path, capsys):
    """It was a note with an empty summary — which is how "not audited" comes to look
    like "nothing wrong", the exact confusion the analysed-zero guard prevents in the
    harder case."""
    ctx = _run_audit(tmp_path, **{"fettle.command.which": {"return_value": None}})
    out = capsys.readouterr()
    assert "NOT audited" in out.err
    assert "did NOT run" in out.out          # and it reaches the summary
    assert ctx.output.had_failures is False  # a missing tool is not fettle failing


def test_no_binaries_found_is_not_a_clean_result(tmp_path, capsys):
    ctx = _run_audit(tmp_path, **{
        "fettle.command.which": {"return_value": "/usr/bin/checksec"},
        "fettle.hardening.engine.default_targets": {"return_value": []},
    })
    assert "did NOT run" in capsys.readouterr().out
    assert ctx.output.had_failures is False


def test_deviations_are_not_reported_with_a_green_tick(tmp_path, capsys):
    """Measured on a real workstation: "✓ 1 Critical, 7 High, 130 Medium, 95 Low
    (816 deviations across 233 packages)". A green tick over a Critical band reads as
    a pass at a glance."""
    from fettle.hardening import audit
    from fettle.backends.arch import ArchBackend
    from fettle.backends.base import Context
    from fettle.config import Config
    from fettle.output import Output
    from unittest.mock import patch as _p

    ctx = Context(output=Output(color=False), config=Config(), dry_run=True,
                  root=tmp_path, user_home=tmp_path)
    with _p("fettle.command.which", return_value="/usr/bin/checksec"), \
         _p("fettle.hardening.engine.default_targets", return_value=["/usr/bin/x"]), \
         _p("fettle.hardening.engine.scan", return_value=([], {"analyzed": 1})), \
         _p("fettle.hardening.report.apply",
            return_value=(["a-report"], {"excluded_check": 0, "excluded_package": 0,
                                         "excluded_path": 0})), \
         _p("fettle.hardening.report.render_screen", return_value=["row"]), \
         _p("fettle.hardening.report.band_summary", return_value="1 Critical, 7 High"):
        audit.run(ArchBackend(), ctx)
    ctx.output.print_summary()
    out = capsys.readouterr().out
    assert "! 1 Critical, 7 High" in out
    assert "✓ 1 Critical" not in out
    # Deliberately not a failure: "Critical" here is a scoring band every real desktop
    # has, unlike pkg-audit's CRITICAL which means a known-malicious package.
    assert ctx.output.had_failures is False
