# fettle QA test plan

Manual, black-box QA — **separate from the unit tests in `tests/`**. The unit tests prove
the code does what the code says. This plan asks a different question: *when a person runs
this on a real machine, do they get a true and comprehensible answer?*

Those are not the same question, and the gap between them is where fettle's worst bugs have
lived. The hardening audit passed its unit tests for months while reporting a clean system
after examining zero binaries on four distros.

## What we are testing for

Every case is judged on three axes, not one. A case only passes if all three hold.

| Axis | The question |
|---|---|
| **Correct** | Did it do the right thing to the system? |
| **Truthful** | Does the output match what actually happened? Never let *"could not look"* render as *"clean"*, and never let *"nothing ran"* render as *"done"*. |
| **Clear** | Would a competent sysadmin who has never read the source understand the output, the prompt, and the terminology — first time, without guessing? |

**The Clear axis was the stated priority**, and it was swept in the terminology row: every
summary line now names the action that produced it, a green tick means "nothing needed from
you", and the naming rule is written down and enforced by test. A case that works perfectly
but explains itself badly is still a **FAIL**, recorded as such.

## Where the pass finished (2026-08-06)

**24 of 25 features swept**, `web` on hold by decision and marked experimental. (`compromise-check` arrived after this pass and was swept on its own at v1.6.1.) **All ten
cross-cutting rows swept.** Roughly 90 findings fixed across the pass, at v0.110.0 with
1172 unit tests.

**This pass is what 1.0.0 rests on.** The release that followed it has a plan, packaging
for four distro families, and GitHub Actions building and verifying every artifact — see
`packaging/README.md`. Two known items were deliberately left: the `web` sweep, and the
`--quiet` refactor recorded in [selection-and-output.md](selection-and-output.md).

### The one finding that recurred more than any other

*Every subcommand with its own entry point independently forgot to print a summary and
compute an exit code.* Found six times — `sys-audit`, `advisory-check`, `upgrade-check`,
`aur-precheck`, the remote zipapp wrapper, and finally `report`. It is not a bug in any one
place; it is what happens by default each time someone adds a subcommand, which is why it
ends in a guard rather than a sixth fix.

## Targets

Seven. Named by role, never by hostname — this repo is public and lab specifics live in
`tests/lab/lab.conf` (gitignored).

| Target | Distro | Package manager | Mutating tests? |
|---|---|---|---|
| `arch` | Arch | pacman + yay (AUR) | yes |
| `debian` | Debian 13 | apt | yes |
| `ubuntu` | Ubuntu 26.04 | apt + snap | yes |
| `rocky9` | Rocky 9 | dnf4 | yes |
| `alma9` | AlmaLinux 9 | dnf4 | yes |
| `fedora` | Fedora | **dnf5** | yes |
| `manjaro-local` | Manjaro (the author's workstation) | pacman + AUR | **NO — read-only and `--dry-run` only** |

The six lab targets are snapshot-pinned VMs that revert in about 17 seconds
(`tests/lab/lab.py`), so mutating tests are free there.

**`manjaro-local` is a real workstation and is never mutated by QA.** It earns its place by
being the one target with a live user config, `mhwd-kernel`, checksec 3.x, a large AUR
install base, and years of accumulated state that no fresh cloud image can imitate. That
value disappears the moment a test breaks it.

Planned, to remove that asymmetry: a **Manjaro VM** and a **CachyOS VM**, after which QA
moves to VMs entirely and no workstation is in the loop. Tracked in the outstanding-issues
file; deliberately not blocking QA from starting.

## Case conventions

- **IDs are `QA-<FEATURE>-NN`** and are permanent. Never renumber, never reuse — a retired
  case is struck through and keeps its number, so an old result never points at a
  different test than the one that produced it.
- **Smallest unit of measure.** One case asserts one observable behaviour. If an expected
  result needs the word "and", it is probably two cases.
- **Expected results are derived from the source, then verified against reality** — never
  written from memory of how it ought to work. Where they disagree, that disagreement is
  the finding.
- **Every case states how it is verified**, and verification is independent of fettle's own
  output wherever possible. "fettle said it cleaned the cache" is not evidence the cache is
  gone; `du` before and after is.
- **Applicability is explicit.** A case that does not apply to a target is marked **n/a with
  a reason**, never left blank. A blank cell is indistinguishable from an untested one.

## Result states

| State | Meaning |
|---|---|
| **PASS** | Correct, truthful, and clear. |
| **FAIL** | Any axis failed. Wording that misleads counts. |
| **BLOCKED** | Could not run (prerequisite absent, needs hardware we lack). Reason mandatory. |
| **n/a** | Genuinely does not apply to this target. Reason mandatory. |
| *(empty)* | Not yet run. Never leave a run case empty. |

Every FAIL becomes an entry in `~/src/claude-scratchpad/qa-runs-outstanding-issues-questions.md`
with a next step, so no defect lives only inside a results table.

## Workflow per feature

1. **Read the source** for every backend that implements it, and write down what it actually
   runs — differences between families are usually the first finding.
2. **Write the cases** here before running anything, so results cannot rationalise the spec.
3. **Run** across all seven targets; revert lab VMs between mutating cases.
4. **Record** results with evidence.
5. **Fix** bugs and UX/terminology problems found, following the usual milestone discipline:
   tests + ruff + live re-run, version bump, CHANGELOG, commit, push.
6. **Re-run** the failed cases to confirm the fix, and record the second result.

## Coverage matrix

Status of each feature's QA pass. `—` = not started.

| Feature | Flag | QA file | Status |
|---|---|---|---|
| clean | `-c` | [clean.md](clean.md) | **DONE — 2 sweeps, 98 PASS / 0 FAIL; 8 findings fixed, 3 deferred by decision** |
| orphans | `-o` | [orphans.md](orphans.md) | **swept — 3 findings fixed, 1 open** |
| update | `-u` | [update.md](update.md) | **swept — 6 findings, all fixed** |
| only-update | `-O` | [only-update.md](only-update.md) | **swept — 4 findings fixed, 2 open for decision** |
| rebuild-check | `-r` | [rebuild-check.md](rebuild-check.md) | **swept — 4 fixed, 1 withdrawn, 1 open (R-06)** |
| python-rebuild-check | `-y` | [python-rebuild-check.md](python-rebuild-check.md) | **swept — 4 findings, all fixed** |
| config-drift | `-d` | [config-drift.md](config-drift.md) | **swept — 4 findings, all fixed** |
| auto-updates | `-x` | [auto-updates.md](auto-updates.md) | **swept — 1 fixed, 2 open** |
| firmware | `-f` | [firmware.md](firmware.md) | **swept — 3 fixed (incl. B1), 1 blocked** |
| kernel | `-k` | [kernel.md](kernel.md) | **swept — 2 fixed, 1 open (Arch-only)** |
| aur-audit | `-A` | [aur-audit.md](aur-audit.md) | **swept — 2 findings, both fixed** |
| ~~aur-ioc-scan~~ | ~~`-I`~~ | [aur-ioc-scan.md](aur-ioc-scan.md) | **RETIRED v0.73.0 — folded into `-P`; its feed-coverage reporting moved with it** |
| pkg-audit | `-P` | [pkg-audit.md](pkg-audit.md) | **swept — 1 fixed, 1 open** |
| hardening-audit | `-H` | [hardening-audit.md](hardening-audit.md) | **swept — 4 fixed; a recorded EL gap disproved** |
| container-update | `-C` | [container-update.md](container-update.md) | **swept — 5 fixed, 2 of them in the audit half too** |
| pkg-integrity | `-V` | [pkg-integrity.md](pkg-integrity.md) | **new in v0.72.0 — split out of sys-audit, swept on 4 targets** |
| sys-audit | `-S` | [sys-audit.md](sys-audit.md) | **swept — 7 fixed, incl. one affecting every `fettle remote` run; + chipsec config v0.84.x** |
| upgrade-check | `-U` | [upgrade-check.md](upgrade-check.md) | **reviewed (no live run, by decision) — 2 fixed, 1 recorded** |
| aur-precheck | `-p` | [aur-precheck.md](aur-precheck.md) | **swept — 4 fixed, incl. the malware gate passing on blind feeds** |
| advisory-check | — | [advisory-check.md](advisory-check.md) | **swept — 5 fixed (2 raised by Paul on sight); pre-update gate redesigned** |
| advisory-update | — | [advisory-update.md](advisory-update.md) | **swept — 3 fixed; a failing timer looked healthy** |
| report | — | [report.md](report.md) | **swept — 4 fixed, then a UX pass: card verdict, delta, severity filter, links** |
| compromise-check | `-M` | [compromise-check.md](compromise-check.md) | **swept at v1.6.1 — 5 findings, all fixed; 2 of them not specific to it** |
| web | — | — | **ON HOLD — marked experimental (v0.87.0); the one feature not swept** |
| remote | — | [remote.md](remote.md) | **swept — 4 fixed, on top of 3 found while sweeping other features** |

### Cross-cutting behaviour — QA'd once, not per feature

| Area | QA file | Status |
|---|---|---|
| Default action set (`-a` / bare `fettle`) | [selection-and-output.md](selection-and-output.md) | **swept — 1 fixed: it inspected before it updated** |
| `--dry-run` semantics across all actions | [dry-run.md](dry-run.md) | **swept — 3 fixed, incl. a dry run DELETING run-logs** |
| `--yes` semantics across all actions | [yes.md](yes.md) | **swept — 1 fixed: `--yes` auto-purged an inferred orphan list** |
| `--only` / `--skip` selection | [selection-and-output.md](selection-and-output.md) | **swept — 1 fixed: a typo ran nothing and exited 0** |
| Privilege escalation and the sudo re-exec | [privilege.md](privilege.md) | **swept — 3 fixed, incl. H-06 (remote elevated for everything)** |
| Config file loading, safety gate, `--print-config` | — | — |
| Reports and run-logs (paths, permissions, rotation) | [reports-logs.md](reports-logs.md) | **swept — 2 fixed (F-08 closed); 1 recorded, not changed** |
| Output framing, colour, `--quiet`, `--verbose` | [selection-and-output.md](selection-and-output.md) | **swept — sound; `--quiet` inversion recorded, needs a refactor** |
| **Terminology consistency across the whole CLI** | [terminology.md](terminology.md) | **swept — 10 findings fixed; naming rule written down and enforced by test** |
| **Exit codes** | [exit-codes.md](exit-codes.md) | **swept — 5 milestones, 4 findings fixed; the last instance of the entry-point defect closed and guarded** |

At the close of the effort, this matrix is the answer to *"did we miss anything?"* — any row
without a QA file is a gap by definition.
