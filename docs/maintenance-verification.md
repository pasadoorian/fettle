# Maintenance verification

Date: 2026-10-02. Branch: `codex/fettle-maintenance`. This is current execution
evidence, separate from the historical QA pass under `docs/qa/`.

| Check | Outcome |
| --- | --- |
| Advisory test isolation | 64 tests passed, including the formerly failing real-home case. |
| Six confirmed bugs | Regression tests reproduced 20 failures before source fixes; 343 focused tests passed afterward. |
| Core suite after initial fixes | 1,691 passed; six optional-web tests skipped because NiceGUI was absent. Ruff passed. |
| Related fixes with reviewed web dependencies | 271 focused tests passed with local socket access. |
| Broader suite with upgraded dependencies | 1,730 passed; one documentation guard false positive on the setup script's option. Corrected and rechecked. |
| Subsequent source/config/report/packaging checks | 133 passed; Ruff passed. |
| Dependency resolver | Fresh Python 3.14.7 environment; `pip check` passed. |
| Dependency advisory lookup | All 60 pinned versions queried against the [OSV API](https://google.github.io/osv.dev/post-v1-querybatch/); no advisories returned. This describes the database's response at this date, not a guarantee of safety. |
| Final Python 3.14.7 suite, including optional web | 1,781 passed, one Starlette test-client deprecation warning; Ruff and pip check passed. One subsequent smoke-check regression was verified in the 72-test packaging/regression run. |
| Fresh Python 3.11 core container | 1,763 passed, 17 skipped; Ruff and pip check passed. Minimal-image gaps include optional web dependencies, Lua/zip tools and permission fixtures that require a non-root user. |
| Fresh Python 3.11 optional web and final regressions | 75 passed; pip check passed. Same framework deprecation warning; local socket access enabled. |
| Final packaging/dashboard regressions | 72 packaging/maintenance tests and 91 dashboard/maintenance tests passed. Numeric ordering also applies to historical text reports. |
| Python sdist/wheel | Setuptools 84 built both 1.21.0 artifacts. Fresh core-only wheel install reports 1.21.0 and runs scanner help; no runtime dependency required. SPDX/Python metadata, included constraints/fixtures/packaging inputs, excluded private files and documentation links verified. |
| Debian package and zipapp | Built and installed in a clean Python 3.12 Debian-based container with distro Python metadata; version and hardening dry-run passed. Zipapp extraction and invocation passed. |
| Rocky 9 RPM | Built and installed in a clean Rocky 9 container; package dependencies selected a supported versioned interpreter despite system python3 being 3.9. Version and hardening dry-run passed. |
| Arch package | Built using unprivileged makepkg and installed in a clean Arch container; version and hardening dry-run passed. |
| Native rolling-host build | Python 3.14/Nuitka 4 artifact passed host smoke but failed on clean Debian 13 because a bundled extension requires GLIBC_2.44. This disproves the old fixed 2.38 claim; floor measurement and controlled release runner added. |
| Native controlled-base build | Debian 12 / Python 3.11 / Nuitka 4 build passed smoke; all bundled ELF requirements measured a 2.36 floor. Generated tar/zip include that metadata. Extracted tar passed full smoke and scanner help on clean Debian 13 with no Python or locale installed. This verifies those artifacts, not every possible target or future Ubuntu-runner artifact. |
| Extracted sdist checks | 81 packaging, scanner and documentation-flag tests passed from the extracted sdist, verifying its included wrapper/template, constraints and regression fixtures. |
| Shared AUR review | Focused scanner/caller/Lua checks passed. Four real cached trees yielded two heuristic hits and eight unresolved-input gaps; small corpus only, no scripts executed. |
| Focused browser | Harmless NiceGUI fixture exercised read-only -P --user, metadata preview, confirmation, single-run rejection and clearing a submitted synthetic value. Runner was replaced; no subprocess or sudo command ran. Same-origin WebSocket connected; rejection cases are automated HTTP/WS tests. |
| Disposable VM matrix | Arch: 13 PASS. Debian: 12 PASS plus one unsupported AUR action classified ISSUE by the text-marker harness. Rocky: 13 pre-execution FAIL because the existing snapshot lacks Python 3.11+. Those Rocky cells are blocked coverage, not action regressions. |

The sandbox denied networking for dependency downloads and blocked the web
test client's local sockets. The network-enabled reruns succeeded. Optional-web
tests must be run with local socket access; a hanging restricted run is not a
framework failure or a pass. Starlette emits a test-client deprecation warning;
track a future client migration in the issue index.

VM PASS is the harness's coarse result, not proof that every subcheck had tools or
hardware. Full transcripts include findings and coverage notes. Six guests were
reachable with pristine snapshots; only Arch, Debian and Rocky were rerun here.
The lab's classification limitation is LAB-01 in [issues](issues.md). Raw transcripts
remain in ignored local matrix logs because they contain private connection details.
Firmware update availability, physical Chipsec checks, eBPF interception visibility,
and historical interactive/corruption/service cases remain unverified in this pass.
No new guests were built to fill gaps; package installation and mutation ran in
containers or disposable guests, not on the workstation.

The web UI and static build scanner remain experimental. Existing multi-range OSV
fixed-version interpretation and custom remote report-directory discovery remain open;
the issue index gives follow-up acceptance criteria. Separate wiki edits, merge, tags
and release publication are outside this delivery.

## Follow-up: merge readiness

The first GitHub core jobs on Python 3.11–3.14 exposed a test-only import failure:
`tests.test_aur_source` was available under `python -m pytest` but absent from the
import path under the workflow's `pytest` entry point. All jobs failed on that same
fixture, while optional-web and distro-package jobs passed. Reproduced locally with
`env -u PYTHONPATH .../bin/pytest`; the scanner integration fixture is now self-contained.
All 46 scanner/provider tests pass with that entry point, and Ruff passes. Current
remote check outcomes are available on [PR #1](https://github.com/pasadoorian/fettle/pull/1).
The unreleased version remains 1.21.0, consistent in project/package metadata and
the changelog; this fixture correction does not require another version increment.
