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

**And a fourth wave, 2026-08-26 (v1.13.0-1.16.0), from Paul reading his own run logs.**
Four bugs of one family — *software that belongs to a person, checked as if it belonged to
the machine*: GNOME extensions (asked as root, so the session bus refused), rootless podman
(11 images invisible to every elevated run), `--user` flatpak, and providers that examined
things and then said nothing at all. Plus a fifth that was a different animal entirely: a
stopped `snapd` **hung fettle forever**, `--dry-run` included, because nothing in
`command.run` had a timeout.

**The pattern in it worth keeping:** an action in the **no-root set still runs as root
inside `-a`**. Being in that set means it does not *elevate on its own*, not that it
executes unprivileged — and that is what put three per-user checks in front of the wrong
identity for months. Ask, for any new check, *whose* data this is.

**A sixth family and a code review came after.** `compromise-check` (`-M`) was built and
swept at v1.6.1. Then an external code review on 2026-08-12 reopened four already-swept
features — `clean`, `update`, `pkg-integrity` and `report` — and found a false-assurance
bug in each that the sweeps had missed, plus one destructive bug. All five are fixed
(v1.8.0-1.12.0) and recorded as extra sweeps in the files above. **Worth drawing the
lesson:** every one was a case of *reading a tool's silence or its exit status as good
news*, which is the same defect class the whole pass was organised around — so a feature
being "swept" is not proof it is clean, only that it was looked at once.

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

## Pre-release sweep, v1.19.0, 2026-08-27

Full lab matrix, 13 actions across 6 snapshot-pinned guests, reverted between runs:

**71 pass · 7 issue · 0 FAIL · 0 skip**

All seven issues were examined and none is a defect:

* **5 x `aur-audit` on debian, ubuntu, rocky9, alma9, fedora.** The action correctly
  declines: *"no requested action ran, rhel implements none of aur_audit"*. AUR is
  Arch-only and the harness counts a non-zero exit as an issue.
* **ubuntu `clean` and `update`.** Both failed on `Could not get lock
  /var/lib/apt/lists/lock. It is held by process 3708 (apt-get)`, which is `apt-daily`
  running concurrently with the matrix. fettle reported both truthfully rather than
  claiming success: clean said *"did NOT complete, apt-get failed (39.0 MiB reclaimed
  before it stopped)"* and update said *"upgrade SKIPPED, the package lists could not be
  refreshed"*. Re-run with apt free, both pass: `caches cleaned, 39.0 MiB reclaimed` and
  `packages updated (apt, snap)`.

Worth noting which guards fired there. The v1.10.0 refresh guard stopped the upgrade
rather than running `full-upgrade` against stale lists, and the v1.9.0 extras guard then
skipped snap and flatpak. Neither condition was staged.

Also in this sweep: 1595 unit tests pass, ruff clean, `check-tag.sh` and
`release-notes.sh` both succeed for 1.19.0.

## Coverage matrix

Status of each feature's QA pass. `—` = not started.

| Feature | Flag | QA file | Status |
|---|---|---|---|
| clean | `-c` | [clean.md](clean.md) | **DONE — 2 sweeps, 98 PASS / 0 FAIL; 10 findings fixed, 2 deferred** *(F-05 v1.8.0: it deleted pacman's db lock; F-13 v1.16.0: a stopped snapd hung the action, `--dry-run` included)* |
| orphans | `-o` | [orphans.md](orphans.md) | **swept — 3 findings fixed, 1 open** |
| update | `-u` | [update.md](update.md) | **swept — 8 findings, all fixed** *(sweep 3, v1.9.0-1.10.0: extras ran after a failed upgrade; an unreachable repo upgraded to success)* |
| only-update | `-O` | [only-update.md](only-update.md) | **swept — 4 findings fixed, 2 open for decision** |
| rebuild-check | `-r` | [rebuild-check.md](rebuild-check.md) | **swept — 4 fixed, 1 withdrawn, 1 open (R-06)** |
| python-rebuild-check | `-y` | [python-rebuild-check.md](python-rebuild-check.md) | **swept — 4 findings, all fixed** |
| config-drift | `-d` | [config-drift.md](config-drift.md) | **swept — 4 findings, all fixed** |
| auto-updates | `-x` | [auto-updates.md](auto-updates.md) | **swept — 1 fixed, 2 open** |
| firmware | `-f` | [firmware.md](firmware.md) | **swept — 3 fixed (incl. B1), 1 blocked** |
| kernel | `-k` | [kernel.md](kernel.md) | **swept — 2 fixed, 1 open (Arch-only)** |
| aur-audit | `-A` | [aur-audit.md](aur-audit.md) | **swept — 2 findings, both fixed** |
| ~~aur-ioc-scan~~ | ~~`-I`~~ | [aur-ioc-scan.md](aur-ioc-scan.md) | **RETIRED v0.73.0 — folded into `-P`; its feed-coverage reporting moved with it** |
| pkg-audit | `-P` | [pkg-audit.md](pkg-audit.md) | **swept — 5 fixed, 1 open** *(P-03..P-05, v1.13.0-1.15.0: three sources audited as the wrong identity, and providers that found nothing said nothing)* |
| hardening-audit | `-H` | [hardening-audit.md](hardening-audit.md) | **swept — 4 fixed; a recorded EL gap disproved** *(v1.17.0-1.19.0: now elevates with `--user` to opt out, and gained axes for AppArmor and SELinux)* |
| container-update | `-C` | [container-update.md](container-update.md) | **swept — 5 fixed, 2 of them in the audit half too** |
| pkg-integrity | `-V` | [pkg-integrity.md](pkg-integrity.md) | **3 sweeps — split out of sys-audit v0.72.0; sweep 3 (v1.11.0) found a failed verifier reporting a clean system on every backend** |
| sys-audit | `-S` | [sys-audit.md](sys-audit.md) | **swept — 7 fixed, incl. one affecting every `fettle remote` run; + chipsec config v0.84.x** |
| upgrade-check | `-U` | [upgrade-check.md](upgrade-check.md) | **reviewed (no live run, by decision) — 2 fixed, 1 recorded** |
| aur-precheck | `-p` | [aur-precheck.md](aur-precheck.md) | **swept — 4 fixed, incl. the malware gate passing on blind feeds** |
| advisory-check | — | [advisory-check.md](advisory-check.md) | **swept — 5 fixed (2 raised by Paul on sight); pre-update gate redesigned** |
| advisory-update | — | [advisory-update.md](advisory-update.md) | **swept — 3 fixed; a failing timer looked healthy** |
| report | — | [report.md](report.md) | **2 sweeps — 4 fixed + a UX pass; sweep 2 (v1.12.0): a fixed finding never cleared, and run logs alone earned `OK`** |
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
