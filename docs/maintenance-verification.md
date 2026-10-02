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
| Packaging backend | Setuptools 84 built an sdist and wheel; editable install reports the correct 1.20.0 baseline version. SPDX metadata update is being verified with final packaging. |
| VM availability | Six configured disposable guests reachable, with pristine snapshots. No workstation mutation used. |
| Python 3.11, container installation, browser and VM checks | In progress; final outcomes will replace this row. |

The sandbox denied networking for dependency downloads and blocked the web
test client's local sockets. The network-enabled reruns succeeded. Optional-web
tests must be run with local socket access; a hanging restricted run is not a
framework failure or a pass. Starlette emits a test-client deprecation warning;
track a future client migration in the issue index.
