# Issue index and improvement recommendations

Reconciled 2026-10-02 for 1.21.0. Historical QA IDs and evidence remain in `qa/`;
this index records current source status, not a claim that every historical live case
was rerun. Current execution evidence is in [verification](maintenance-verification.md).
The [approved plan](maintenance-plan-2026-10-01.md) records scope and decisions.

## Fixed in this maintenance effort

| ID | Outcome | Regression evidence |
| --- | --- | --- |
| BUG-01 | Backend failures retain summary category and exit status. | `test_maintenance_regressions.py`, `test_actions.py` |
| BUG-02 | Failed apt/pacman transaction queries cannot become clean previews. | backend transaction regressions |
| BUG-03 | Invalid settings default independently, preserving valid siblings. | config and mixed-invalid regressions |
| BUG-04 | Unsuccessful remote upgrade analysis reports blindness and exits nonzero. | remote-upgrade regressions |
| BUG-05 | Same-second retention, allocation, concurrent writers and dashboard selection use numeric ordering. | report/concurrency/dashboard regressions |
| BUG-06 | Bad JSON envelopes cannot crash collection; malformed known payload containers show unknown coverage. | malformed envelope and nested-payload regressions |
| REL-01 | HTTP/WS origin guard, serialized/cancellable web runs and password clearing. | `test_maintenance_related.py`, optional-web and focused browser checks |
| REL-02 | Actual noninteractive log exit codes; unknown old codes remain unknown. | log and CLI subprocess regressions |
| REL-03 | OSV paging/inventory freshness, package identity and incomplete-feed coverage. | `test_advisory_coverage.py` |
| REL-04 | Remote Python 3.11+ selection, safe baseline/fetch writes and draft-only upload repairs. | remote, baseline and packaging regressions |
| REL-06 | Native archives measure bundled ELF glibc requirements; missing floor metadata is refused. A controlled release runner replaces a floating artifact-build host. | build/target portability and archive regression checks |
| REL-05 | Root-independent test fixtures and exclusion of local data from source staging. | advisory/Arch fixtures and package inspection |

## Remaining recommendations, highest value first

| ID | Status and reason | Recommended next step |
| --- | --- | --- |
| ADV-01 | Open: OSV fixed-version extraction chooses the first fixed event; branch/range interpretation is incomplete. Package identity and feed completeness are now checked. | Add multi-range/multi-branch fixtures and ecosystem-correct version comparison before changing pending/fixable classification. Preserve standard-library runtime. |
| REM-01 | Open: remote fetch-back assumes `~/.fettle`; a remote `[reports].dir` override is not discovered. | Design a structured remote output-location handshake with ownership/path checks and backward compatibility; test local and remote overrides together. |
| AUTO-01 | Open: Arch's curated timer-name heuristic can label an unknown custom updater OFF. [A-02](qa/auto-updates.md) | First qualify the summary as “no recognized timer”; separately review broader timer inspection if needed. |
| AUTO-02 | Open: missing `systemctl`/`apt-config`, and failed posture queries, can leave an undetermined answer. [A-03](qa/auto-updates.md) | Propagate explicit coverage state across all three backends, including query failure fixtures. Do not broaden detection incidentally. |
| AUR-01 | Experimental limitation: token heuristics cannot interpret arbitrary shell or dynamic source/install declarations; cache revision may differ from installed revision. | Gather a larger benign corpus, tune measured false positives, and design optional revision provenance before deeper parsing. No execution as a parsing shortcut. |
| LAB-01 | Open: matrix text markers can classify unsupported actions as ISSUE and miss coverage wording under a PASS. | Derive expected backend applicability and structured coverage in a separately tested harness change; current verification interprets full transcripts explicitly. |
| WEB-01 | Deferred: framework test client emits a Starlette deprecation warning; UI still has no full manual QA sweep. | Review a supported client migration independently and expand browser scenarios with harmless runners. |
| AI-01 | Deferred improvement: upgrade verdict JSON is a prompt contract, not API-enforced structured output. [UC-03](qa/upgrade-check.md) | Verify the provider's current structured-output API and model compatibility, then test refusal/malformed responses. No API/model migration in this pass. |
| PA-02 | Deferred by decision: resolved findings have no explicit provider ledger; disappearance alone may mean unchecked. [P-02](qa/pkg-audit.md) | Use recorded per-provider coverage plus stable identities when designing a resolution ledger; do not infer resolution from an absent provider. |
| PI-01 | Open: Debian `dpkg --verify` fallback does not separate edited config files from other discrepancies. [pkg-integrity](qa/pkg-integrity.md) | Add representative `c`-marked output fixtures and preserve distinct drift/blind/finding states. MD5 is a dpkg manifest limitation; an expected-list suppression knob remains declined. |
| KRN-03 | Open on Manjaro: successful `mhwd-kernel` install/removal still lacks an explicit resulting summary. Plain Arch now inventories instead of removing. [K-03](qa/kernel.md) | Add consent/result-state fixtures and a disposable Manjaro run before revising summaries. |
| CLI-01 | Deferred by decision: `only-update` name is misleading; legacy naming is preserved. [O-06](qa/only-update.md) | Consider additive aliases in a separately reviewed CLI change. |
| CLI-02 | Deferred: quiet behavior varies by family; changing every command's output contract is outside targeted consolidation. [S-03](qa/selection-and-output.md) | Specify desired quiet output and test all entry points before migration. Compromise output's separate quiet defect was already fixed. |
| REM-02 | Open: remote group selection has no controller `--config`; `sys-audit remote` has no `--ssh-arg`. [remote](qa/remote.md), [sys-audit](qa/sys-audit.md) | Design unambiguous pre-host options and completion together; retain forwarding grammar. |
| REPORT-01 | Deferred presentation: long uncovered-package and AUR removal lists need collapsible display with counts/caveats retained. [D1/D2](qa/report.md) | Add focused browser fixtures before changing those lists. |
| REPORT-02 | Deferred migration: local and remote aliases may represent one machine as separate hosts; existing fragmented history is operator data. [reports/logs](qa/reports-logs.md), [report](qa/report.md) | Offer an explicit reviewed migration/export, never silently rewrite historical trees. |
| OUT-01 | Deferred: summaries print warnings before failures. [sys-audit](qa/sys-audit.md) | Review shared summary ordering and snapshots as a cross-cutting output change. |
| FED-01 | Deliberate support policy: Fedora is not auto-detected because its advisory feed differs; forced RHEL maintenance remains available. [F-10](qa/clean.md) | Separate backend maintenance support from native advisory-provider eligibility before claiming Fedora support. |

## Historical items reconciled with current source

| Historical item | Current status |
| --- | --- |
| Clean F-05 / F-07 / F-08 / F-09 / F-11 | Already corrected: pacman lock is never deleted; version retention uses paccache; logs begin private; redundant apt autoclean removed; unsupported distro exits nonzero. This pass adds safer collision/write handling and root-independent permission fixtures. Empty abandoned logs remain a retention concern, not a permissions regression. |
| Clean QA-CLEAN-25 / update QA-UP-26 | Old run-log permission deferrals are superseded by private creation, current regression coverage and safe replacement. Historical counts are not rewritten. |
| Orphans O-04 / QA-ORPH-18 | Already corrected: Arch dry-run says its report would be saved; guarded by `test_dry_run_announces_the_review_report_it_would_write`. |
| Only-update O-05 / QA-ONLY-12 and rebuild R-06 / Q7 | Already corrected by Arch `extra_no_root`; Debian/RHEL retain required elevation. `test_arch_read_only_actions_need_no_root` guards it. |
| Hardening H-06 | Already corrected by lazy remote privilege selection; see [privilege P-03](qa/privilege.md). Hardening itself intentionally elevates unless `--user`. |
| Package audit P-03/P-05 rootless podman/flatpak | Already corrected per runtime/store in 1.15.0; do not reopen from earlier paragraphs that predate the later sweep. |
| Local PLAN phase 20 | Implemented HTTP/WS origin guard and runner lifecycle tests; experimental UI status retained. |
| Local PLAN R3/R4 persistence/eBPF proposal | Superseded by shipped compromise groups and startup inventory. No duplicate implementation added. R1/R2 now share the experimental AUR engine. |
| Retired AUR IoC action | Remains folded into pkg-audit; historical report names still render. |

## Coverage gaps that are not passes

- Firmware QA-FW-03 needs genuinely updatable hardware; VM “nothing available” cannot
  exercise an available-update branch. QA-FW-07 needs an appropriate unprivileged daemon run.
- Chipsec firmware checks still need configured tooling and supported physical hardware;
  mocks and guests do not close that gap. The command is explicitly configured, not auto-detected.
- eBPF checks need bpftool/root for full inventory and cannot see an implant intercepting
  the inspection API. Memory-capture investigation remains outside scope. Proc/sys behavior
  cannot be validated with a scratch `--root` tree alone.
- Historical snapd/systemd service, corruption, permission and interactive prompt cases
  not repeated here retain their recorded status. No new VM was built to fill these gaps.
- The existing Rocky 9 snapshot has no Python 3.11+; remote refusal is correct and its
  action matrix is blocked by that prerequisite. Container installation separately verifies
  a supported interpreter. Debian's AUR-only action is not applicable, not a broken backend.
- The new static scanner has positive and benign fixtures and a small local cached corpus;
  this is not broad real-world malware/false-positive validation or a safety guarantee.

Do not bulk-close these entries because unit tests pass. Prioritize ADV-01, REM-01
and AUTO-01/02 for a subsequent correctness pass; retain broader registry, output and
history redesigns as explicit projects with their own acceptance criteria.
