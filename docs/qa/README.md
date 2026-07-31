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

**The Clear axis is currently the priority.** Terminology across fettle is inconsistent and
in places actively misleading; fixing that is the point of this exercise as much as finding
bugs. A case that works perfectly but explains itself badly is a **FAIL**, recorded as such.

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
| clean | `-c` | [clean.md](clean.md) | **2 sweeps · 96 PASS / 2 FAIL · 7 findings fixed, 4 open (3 deferred)** |
| orphans | `-o` | — | — |
| update | `-u` | — | — |
| only-update | `-O` | — | — |
| rebuild-check | `-r` | — | — |
| python-rebuild-check | `-y` | — | — |
| config-drift | `-d` | — | — |
| auto-updates | `-x` | — | — |
| firmware | `-f` | — | — |
| kernel | `-k` | — | — |
| aur-audit | `-A` | — | — |
| aur-ioc-scan | `-I` | — | — |
| pkg-audit | `-P` | — | — |
| hardening-audit | `-H` | — | — |
| container-update | `-C` | — | — |
| sys-audit | `-S` | — | — |
| upgrade-check | `-U` | — | — |
| aur-precheck | `-p` | — | — |
| advisory-check | — | — | — |
| advisory-update | — | — | — |
| report | — | — | — |
| web | — | — | — |
| remote | — | — | — |

### Cross-cutting behaviour — QA'd once, not per feature

| Area | QA file | Status |
|---|---|---|
| Default action set (`-a` / bare `fettle`) | — | — |
| `--dry-run` semantics across all actions | — | — |
| `--yes` semantics across all actions | — | — |
| `--only` / `--skip` selection | — | — |
| Privilege escalation and the sudo re-exec | — | — |
| Config file loading, safety gate, `--print-config` | — | — |
| Reports and run-logs (paths, permissions, rotation) | — | — |
| Output framing, colour, `--quiet`, `--verbose` | — | — |
| **Terminology consistency across the whole CLI** | — | — |
| Exit codes | — | — |

At the close of the effort, this matrix is the answer to *"did we miss anything?"* — any row
without a QA file is a gap by definition.
