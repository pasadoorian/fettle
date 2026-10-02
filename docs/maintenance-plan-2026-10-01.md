# Fettle maintenance and improvement plan

Date: 2026-10-01  
Last updated: 2026-10-02  
Baseline: fettle 1.20.0  
Status: **Implementation in progress on `codex/fettle-maintenance`. All phase decisions are recorded.**

## Purpose and working agreement

Identify bugs, make general recommendations, update documentation, and update code
and dependencies. This file records the plan and Paul's decisions for all four phases.
The planning questions are complete as of 2026-10-02. Accepted decisions govern the
implementation; investigation targets and upgrade candidates remain subject to evidence
and verification within those decisions.

Question forms were not reliably visible during planning. If a new material decision
arises, ask directly in chat and record the answer here. Do not treat unanswered
questions or preselected recommendations as decisions.

The implementation order is test isolation, correctness fixes, security and
shared-contract improvements, dependency upgrades, AUR build-script scanning after
the maintenance work, then final documentation reconciliation. Update relevant
documentation within each implementation change.
The numbered phases below follow the four areas requested; they are not a requirement
to postpone documentation until all code changes are complete.

## Review baseline

The planning review inventoried first-party code and local documentation and reviewed
architecture and failure-prone paths, including `CLAUDE.md`, the local-only `PLAN.md`,
QA records, packaging, and CI. It included targeted reproductions, but was not a
completed line-by-line audit. No project source was changed during that review.

- Tests: **1,671 passed, 1 failed, 6 skipped** in the existing development environment.
- Ruff: **passed** with the repository's existing rule selection.
- The failing advisory test reaches the real home directory despite setting a temporary
  `HOME`. It passes when user-identity lookup is isolated. Fix the fixture rather than
  depending on the reviewing machine's identity or permissions.
- Live distro, firmware, SSH, and browser verification remains part of implementation.
- Existing untracked `CLAUDE.md` and ignored `PLAN.md` retain their current status.

## Existing constraints to preserve

These come from current repository design and guidance; proposed changes to them must
be recorded explicitly during planning.

- Keep the CLI pure standard library and preserve the remote zipapp's operation with
  a supported bare Python interpreter. NiceGUI remains optional and confined to the web UI.
- Keep Python 3.11 as the supported floor unless a change is explicitly selected.
- Preserve the distinctions between `FAILED`, `BLIND`, and `FOUND`. A single action
  currently exits nonzero on any failure; `--everything` exits nonzero only on `FAILED`.
- Preserve the rule that an unperformed check must not appear clean.
- Compromise checks report anomalies and do not offer fixes that could destroy evidence.
- Run mutating QA in disposable environments. The real workstation is not a mutation target.
- Preserve historical QA evidence and handwritten release history.
- Keep Ruff's existing rule selection unless expansion is selected as its own change.

## Execution record

| Milestone | Status | Evidence |
| --- | --- | --- |
| Test isolation | Complete, 2026-10-02 | Reproduced the real-home SQLite failure; isolated the test's invoking identity. All 64 advisory tests and Ruff for the changed test pass. |
| Six confirmed bugs | In progress | Regression coverage and corrections are being implemented. |
| Related investigations and targeted improvements | Pending | Follow the initial correctness fixes. |
| Dependency constraints and compatible upgrades | Pending | Recheck upstream candidates and verify chosen pins. |
| AUR build-script scanning | Pending | Follows maintenance work. |
| Documentation reconciliation and wiki handoff | Pending | Update related documentation throughout implementation. |
| Final verification and draft PR | Pending | Commit and push verified milestones on the implementation branch. |

## Phase 1 — Identify and fix bugs

Decision status: **Planning decisions complete — implementation in progress.**

### Accepted direction

Fix the six confirmed bugs (BUG-01 through BUG-06) first, then investigate related
paths. Establish test isolation before those fixes. Include focused checks for the
same failure pattern with each fix; the broader investigation follows the initial
bug-fix batch.

For valid TOML containing invalid setting types or values, **keep valid settings and
replace only invalid settings with their defaults, with warnings**. Validate nested
settings independently where their containing table is valid, preserving valid sibling
settings. Warnings identify the affected configuration keys and the fallback applied
without exposing secret values. A file that cannot be parsed as TOML still uses the
existing whole-file fallback; this decision concerns validation after parsing.

**Preserve the current exit-code policy and fix violations.** Individual actions
return nonzero on recorded failures. `--everything` returns nonzero only for
operational failures (`FAILED`), while still reporting blindness (`BLIND`) and
findings (`FOUND`). Keep these categories distinct and preserve existing intentional
warning behavior; this phase does not redesign exit codes.

### Reproduced findings

| ID | Priority | Finding and source | Proposed correction |
| --- | --- | --- | --- |
| BUG-01 | High | The dispatcher discards backend results, allowing a failed check to end with “nothing to report” and exit zero. [actions.py](../fettle/actions.py) | Handle returned results consistently while preserving failure categories and avoiding duplicate summaries. |
| BUG-02 | High | A failed apt transaction simulation can become a successful empty update list. [debian.py](../fettle/backends/debian.py) | Preserve query status and distinguish “no updates” from “could not determine updates”; audit equivalent backend paths. |
| BUG-03 | Medium | Incorrect TOML value types can crash configuration loading or turn an action string into individual characters. [config.py](../fettle/config.py) | Validate types, nested tables, ranges, and action names. Preserve valid settings; replace invalid settings with defaults and warnings (accepted D-006). |
| BUG-04 | Medium | Remote upgrade analysis exits successfully when authentication or analysis is unavailable. [cli.py](../fettle/cli.py) | Align remote failure reporting with the local command. |
| BUG-05 | Medium | With retention set to one, two reports written in the same second delete the newer report. [reports.py](../fettle/reports.py) | Correct ordering and collision handling; rotate text/JSON pairs together. |
| BUG-06 | Medium | A report containing valid JSON of an unexpected shape, such as `[]`, crashes dashboard loading. [htmlreport.py](../fettle/htmlreport.py) | Validate envelopes and handle malformed or incompatible entries without crashing the dashboard. |

For each fix, add a regression test for the observable failure, then inspect related
callers for the same pattern. Test outcomes, summaries, and saved artifacts where relevant.

### Further investigation

These are review targets, not all confirmed defects:

- Advisory matching, incomplete feed responses, cache freshness, and coverage reporting.
- Invoking-user identity under sudo, particularly per-user stores and language environments.
- Noninteractive logs recording an unknown exit status that web history displays as “ok.”
- Remote interpreter selection, custom report directories, cleanup, and cancellation.
- HTTP and WebSocket Origin handling. Local `PLAN.md` phase 20 records an unfinished
  review. The installed NiceGUI configuration permits all socket origins; exploitability
  has not been established. Verify HTTP and WebSocket behavior with a harmless fake runner.
- Packaging shell portability and a draft-only guard before release-upload retries can
  replace assets.

### Acceptance criteria

- The advisory test is isolated from the real user's home and identity.
- Each accepted bug has a reproducer that fails before its fix and passes afterward.
- Mixed valid/invalid configuration preserves valid settings, defaults invalid settings,
  and emits useful warnings; cover nested settings as well as top-level fields.
- Failed or incomplete checks do not become clean summaries or empty successful results.
- Existing deliberate exit-code distinctions remain intact.
- Reports retain the newest entries and malformed input cannot crash the entire dashboard.
- Investigations end with evidence, a confirmed issue, or a documented reason for deferral.

### Decisions resolved

- Initial order: fix BUG-01 through BUG-06, then investigate related paths (D-002).
- Invalid configuration: keep valid settings and default invalid settings with warnings (D-006).
- Exit codes: preserve the current policy and fix violations (D-007).

## Phase 2 — General improvements

Decision status: **Planning decisions complete — implementation has not started.**

### Accepted direction

Use **targeted consolidation**: share duplicated logic where it contributes to bugs.
Keep structural changes tied to a demonstrated failure pattern and its regression
coverage. Defer a broader redesign of action metadata, result types, and dispatch.
The improvement candidates below should be evaluated within this scope; they do not
authorize a wholesale architecture refactor.

Keep the **web UI experimental**. Fix security and correctness issues and add tests,
including focused browser checks where needed to verify those fixes. Preserve its
experimental labeling in documentation and the UI. This effort does not promote it
to full support or undertake a general usability redesign.

**Include AUR build-script scanning in this effort, after the maintenance fixes.**
Inspect `PKGBUILD` and install-script content for suspicious behavior without executing
the files. Keep this new feature in separately reviewable changesets, following the
accepted maintenance and consolidation work.

**Preserve backward compatibility.** Continue accepting valid existing configurations
and reading older supported report formats without requiring migration. Prefer additive
fields and tolerant readers when extending report data. Configuration validation still
follows D-006 for invalid settings; compatibility does not require preserving crashes or
misleading results. Exercise representative existing configurations and historical
reports in regression tests.

### Improvement candidates within the accepted scope

- Consolidate action metadata where drift causes defects in names, help, privilege
  requirements, or mutation behavior across CLI, remote execution, and web controls.
- Make command status, coverage, and failure reasons propagate consistently through
  existing result contracts, summaries, and reports; avoid a wholesale result-type redesign.
- Share invoking-user and path resolution where divergent implementations cause bugs.
- Add validated report schemas and atomic private-file writes.
- Make cache freshness and partial coverage explicit in text and JSON.
- Expand behavior-based tests for missing tools, permissions, malformed output, offline
  services, interruption, and concurrent writes.
- Add optional-web CI coverage while retaining a core-only installation test.

For the included AUR scanner, reconcile the earlier design in local `PLAN.md` with the
current code before implementation. Use shared scanning logic for its integration
points and explain findings with the existing severity vocabulary. Report unavailable
or unreadable input as incomplete coverage. Persistence and eBPF work has already
shipped in other components; do not rebuild those features from outdated plan entries.

### Acceptance criteria

- Shared metadata stays consistent across CLI, remote, and web entry points.
- Optional web dependencies do not leak into the core or remote zipapp.
- Web security and correctness fixes have regression coverage; experimental status
  remains clear and browser verification is focused on the changed behavior.
- Refactoring preserves accepted CLI behavior and is supported by behavior tests.
- Each consolidation addresses a demonstrated bug or recurring failure pattern and stays
  small enough to review with the associated fix.
- File writes preserve privacy and remain consistent under interrupted or concurrent runs.
- AUR scanning has positive fixtures for suspicious patterns and representative benign
  fixtures to check false positives. No finding does not imply a guarantee of safety;
  unreadable input is distinguishable from an inspected file with no matches.
- Scanner tests verify that inspected scripts are never executed.
- Valid existing configurations and older supported reports remain usable without a
  migration, with representative compatibility fixtures covering changed readers.

### Decisions resolved

- Refactoring: targeted consolidation tied to bugs (D-010).
- Web UI: remain experimental, with security/correctness fixes and tests (D-011).
- AUR scanning: include it after the maintenance work (D-012).
- Compatibility: preserve valid existing configurations and older report formats (D-013).

## Phase 3 — Documentation

Decision status: **Planning decisions complete — implementation has not started.**

### Accepted direction

**Keep the existing documentation layout.** Correct current documentation in place,
add current architecture guidance under `docs/`, and add a repository issue index
covering confirmed defects and unresolved QA gaps. Link these additions from the
existing documentation. Preserve historical QA records and their permanent case IDs;
the index should point to their evidence and current status.

**Update repository documentation and prepare a list of required wiki changes.**
The separate GitHub wiki will not be edited or migrated in this effort. Record affected
wiki pages and sections, the corrections needed, and links to the matching repository
documentation so the changes can be applied separately.

**Keep `CLAUDE.md` and the local `PLAN.md` local.** Update their guidance and status
as implementation proceeds, without adding either file to version control. Put
reusable architectural and contributor guidance in tracked documentation, excluding
private lab details and machine-specific information. Preserve historical local
decisions while clearly marking superseded guidance.

### Planned updates

Update documentation alongside behavior changes, followed by a repository-wide
consistency pass. Review all current documents; preserve historical records rather
than rewriting them as if they describe the current release.

| Documentation | Planned work |
| --- | --- |
| Architecture guidance and issue index | Add current architecture documentation and a concise index of confirmed defects and unresolved QA gaps, with evidence links and next steps. |
| README and CLI help | Correct capabilities, privilege requirements, Python requirements, report paths, and experimental-feature status. Some help still describes six hardening axes instead of ten. |
| `fettle.toml.example` | Match current defaults; document missing options, accepted types, and failure behavior. |
| Packaging and lab docs | Verify installation commands, interpreter selection, artifact contents, tested platforms, and generated `RUNNING.md` text. |
| `docs/qa/` | Reconcile old open findings with current code. Preserve original evidence and add dated resolutions and remaining gaps. |
| `CLAUDE.md` and local `PLAN.md` | Update guidance and status locally without tracking either file; put reusable guidance in tracked documentation and preserve historical decisions. |
| `PARITY.md` and `CHANGELOG.md` | Label historical material clearly and append release evidence without rewriting history. |
| Documentation links and wiki references | Check links and prepare a page/section-specific list of required wiki changes, linked to the updated repository docs; do not edit the wiki. |

Use the accepted repository issue index so outstanding work does not depend entirely
on the external scratchpad referenced by QA documents. Keep private lab details and
machine-specific information out of public documentation.

### Acceptance criteria

- Current commands, options, defaults, capabilities, and paths agree across documentation.
- Every previously open QA item has a current status or an explicit unresolved entry.
- Documentation accurately distinguishes tested behavior from planned or unverified work.
- Examples and links are checked, and relevant documentation-convention tests pass.
- Historical evidence and release-note extraction remain intact.
- Architecture guidance describes the implemented system, and the issue index links
  outstanding work to evidence and a next step without duplicating historical QA records.
- A wiki change list identifies affected pages, sections, and required corrections;
  repository documentation is updated without publishing wiki changes.
- Both memory files are updated locally and excluded from commits; reusable guidance
  is available in tracked docs without publishing private local details.

### Decisions resolved

- Structure: preserve the layout and add architecture guidance and an issue index (D-014).
- Wiki: prepare a change list without editing or migrating the wiki (D-015).
- Local memory: update both files locally and put reusable guidance in tracked docs (D-016).

## Phase 4 — Code, libraries, dependencies, and delivery

Decision status: **Planning decisions complete — implementation has not started.**

Correctness changes are described in phase 1; shared code improvements are in phase 2.
This phase governs dependency upgrades, compatibility, build reproducibility, and delivery.

### Accepted direction

**Prefer compatible dependency and build-tool updates.** Adopt new major versions only
when they provide a demonstrated benefit, such as a needed security fix, a confirmed
bug fix, or required platform support. Document that benefit and the migration impact,
then validate the upgrade against the agreed compatibility and test requirements.
Do not upgrade solely to match the newest version number. Preserve the Python 3.11
floor, the stdlib-only core, and the existing Ruff rule selection.

**Use pinned constraints with deliberate, reviewed updates.** Record tested dependency
versions for development, optional-web, and build environments, including the relevant
transitive dependencies. Use those constraints in documented setup and CI so the
verified environments can be recreated. Keep package dependency metadata consistent
with the supported compatibility range and ensure constraints work across supported
Python versions. Update pins in separately reviewed changes with relevant verification;
automated dependency-update PRs are not part of this plan.

**Run local tests, package-container checks, and available VM/browser checks.** Fix
test failures rather than classifying them as coverage gaps. When a required runtime,
lab target, browser, or hardware prerequisite is genuinely unavailable, record the
unverified behavior, the reason, and a follow-up verification step; never count that
check as passed. Use disposable environments for mutating QA and keep it off the real
workstation. Browser verification remains focused on the experimental UI's changed
security and correctness behavior. Completion does not require provisioning an entirely
new VM or hardware lab solely to fill unavailable coverage.

**Deliver verified milestone commits on a `codex/` branch, push them, and open a draft
pull request.** Keep each commit focused on a reviewable milestone and include its
relevant documentation and regression coverage. Stage only intended project changes;
keep `CLAUDE.md`, local `PLAN.md`, and private lab information out of commits. Include
this maintenance plan in the branch so reviewers can follow the accepted scope.
The draft PR should describe the delivered behavior, verification results, and any
genuine coverage gaps. This delivery choice does not include merging, release tagging,
or publishing a release.

### Upgrade candidates

The following versions were checked against upstream sources during the 2026-10-01
planning review. They are evaluation candidates, not approved pins. Recheck availability,
compatibility, and advisories when implementing.

| Component | Proposed work |
| --- | --- |
| NiceGUI | Evaluate [3.17.1](https://pypi.org/project/nicegui/), newer than installed 3.14.0, with browser, privilege, cancellation, and Origin tests. |
| Ruff | Evaluate [0.16.10](https://pypi.org/project/ruff/) while preserving existing selected rules. |
| pytest | Installed [9.1.1](https://pypi.org/project/pytest/) matched the checked current release. Prioritize isolation and reproducible development constraints. |
| Nuitka and setuptools | Pin a tested build environment. Evaluate [Nuitka 4.2.2](https://pypi.org/project/Nuitka/); recheck binary compatibility and bundled modules. |
| GitHub Actions | Review upstream versions and migration requirements, pin immutable revisions, and limit release-write permission to the publishing job. |
| Python | Add 3.14 to CI while retaining the declared 3.11 floor. |

Audit the resolved optional-web dependencies for known vulnerabilities. Test the selected
supported minimum and chosen upgrade versions. Separate web, development, and release-tool
upgrades so failures can be attributed and changes can be reverted independently.

### Delivery sequence

1. Create a `codex/` branch while preserving existing local changes and local-only files.
2. Isolate the failing test and record the baseline.
3. Fix accepted correctness defects in small changesets with regression tests.
4. Complete selected security investigations and shared-contract improvements.
5. Upgrade dependencies in separate tested changesets.
6. Implement and validate the included AUR build-script scanner after the maintenance work.
7. Finish documentation reconciliation and the issue index, including scanner documentation.
8. Run the agreed release-verification matrix and record remaining limitations.
9. Open a draft pull request describing the delivered scope and verification evidence.

Commit and push each verified milestone as the work progresses. Keep the plan and
relevant documentation current with the implementation, and report the draft PR link
at handoff.

### Completion criteria

- Local core and optional-web tests and lint pass; test the supported Python matrix
  wherever runtimes are available and record any genuinely unavailable coverage.
- Core-only installation and remote zipapp remain independent of NiceGUI.
- Run distro-package container checks and zipapp/binary smoke tests; fix observed
  failures and explicitly record any checks blocked by unavailable prerequisites.
- Available disposable-VM and focused browser checks verify actual effects and failure
  reporting; mutating tests do not run against the real workstation.
- Genuine VM, browser, runtime, or hardware coverage gaps include a reason and follow-up
  verification step rather than being counted as passes.
- Documentation and changelog match delivered behavior.
- Upgrades preserve the agreed compatibility requirements, and any major-version
  adoption has a documented benefit, migration assessment, and relevant verification.
- Development, optional-web, and build environments can be recreated from tested
  constraints; setup instructions and CI use the corresponding constraints consistently.
- Verified milestones are committed and pushed on a `codex/` branch, with a draft PR
  explaining changes and validation. Local-only files remain untracked; no merge,
  release tag, or release publication is performed as part of this delivery.

### Decisions resolved

- Upgrades: compatible updates; major versions only for a demonstrated benefit (D-017).
- Reproducibility: tested pinned constraints and deliberate reviewed updates (D-018).
- Verification: local tests, package containers, available VM/browser checks, and
  explicitly documented genuine coverage gaps (D-019).
- Delivery: commit and push verified milestones on a `codex/` branch and open a draft PR (D-020).

## Decision log

| ID | Phase | Decision | Status |
| --- | --- | --- | --- |
| D-001 | Planning | Save this plan in a new Markdown file and revise it from Paul's answers before implementation. | Accepted — user request, 2026-10-01 |
| D-002 | Phase 1 | Fix the six confirmed bugs first, then investigate related paths. | Accepted — user answer, 2026-10-01 |
| D-003 | Phase 2 | Targeted consolidation, experimental web support, AUR scanner inclusion, and backward compatibility accepted in D-010 through D-013. | Planning decisions complete |
| D-004 | Phase 3 | Existing layout, architecture guidance, repository issue index, wiki handoff, and local-memory handling accepted in D-014 through D-016. | Planning decisions complete |
| D-005 | Phase 4 | Compatible updates, pinned constraints, verification scope, and delivery workflow accepted in D-017 through D-020. | Planning decisions complete |
| D-006 | Phase 1 | Keep valid settings; replace invalid settings with defaults and warnings. | Accepted — user answer, 2026-10-01 |
| D-007 | Phase 1 | Preserve the current exit-code policy and fix violations; no exit-code redesign. | Accepted — user answer, 2026-10-01 |
| D-008 | Planning | Present all remaining phase questions together and update the plan as answers arrive. | Accepted — user request, 2026-10-01 |
| D-009 | Planning | Ask questions directly in chat because the prompt forms are not reliably visible. | Planning interview complete; retain for future material questions |
| D-010 | Phase 2 | Use targeted consolidation where duplicated logic contributes to bugs; defer a broader architecture refactor. | Accepted — user answer, 2026-10-01 |
| D-011 | Phase 2 | Keep the web UI experimental; fix security and correctness issues and add tests. | Accepted — user answer, 2026-10-01 |
| D-012 | Phase 2 | Include AUR PKGBUILD and install-script scanning in this effort, after the maintenance fixes. | Accepted — user answer, 2026-10-01 |
| D-013 | Phase 2 | Preserve valid existing configurations and continue reading older supported report formats without requiring migration. | Accepted — user answer, 2026-10-01 |
| D-014 | Phase 3 | Keep the existing documentation layout; correct documentation and add current architecture guidance and a repository issue index. | Accepted — user answer, 2026-10-01 |
| D-015 | Phase 3 | Update repository documentation and prepare a list of required wiki changes; do not edit or migrate the separate wiki. | Accepted — user answer, 2026-10-01 |
| D-016 | Phase 3 | Keep CLAUDE.md and local PLAN.md local; update them and put reusable guidance in tracked documentation. | Accepted — user answer, 2026-10-02 |
| D-017 | Phase 4 | Prefer compatible dependency and build-tool updates; adopt new major versions only for a demonstrated benefit. | Accepted — user answer, 2026-10-02 |
| D-018 | Phase 4 | Use pinned constraints for tested development, optional-web, and build environments; update them deliberately in reviewed changes. | Accepted — user answer, 2026-10-02 |
| D-019 | Phase 4 | Run local tests, package-container checks, and available VM/browser checks; document genuine coverage gaps and keep mutating QA off the real workstation. | Accepted — user answer, 2026-10-02 |
| D-020 | Phase 4 | Commit and push verified milestones on a codex/ branch, then open a draft pull request. | Accepted — user answer, 2026-10-02 |
