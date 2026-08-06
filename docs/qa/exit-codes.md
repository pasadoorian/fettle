# QA — exit codes (cross-cutting)

**The question a user is really asking:** *"can I put this in a cron job / CI step and
trust the status it returns?"*

Today the honest answer is "not without reading the source", and this is the row with the
most accumulated evidence behind it — six instances found while sweeping individual
features, plus one defect I knowingly left in place while shipping `--everything`.

Status: **X1, X1a and X2 done.** X3-X5 planned.

---

## What the code actually does today

### One boolean over three different meanings

`Output.had_failures` is `bool(self._failures)`, and `_failures` is fed by
`summary_fail()` — **15 call sites**, carrying three unrelated meanings:

| meaning | example call site | should it fail a run? |
|---|---|---|
| **The action could not do its job** | `update did NOT complete — apt-get failed` | yes, always |
| **The check could not look** | `could not refresh package metadata — the pending list above is from stale data`; `advisory cache: … FAILED to refresh`; `upgrade check did NOT run — no API key` | **yes** — this is the invariant |
| **The check looked and found something** | `sys-audit: N finding(s) needing attention`; `pkg-integrity: …`; `N CRITICAL with a fix available` | *depends on the caller* |

The third is the only one that is genuinely a matter of taste, and it is currently
indistinguishable from the other two.

### The entry points disagree with each other

| entry point | returns |
|---|---|
| `main` (pipeline, single action) | `1 if out.had_failures else 0` |
| `main` (`--everything`) | `1 if ctx.failed_commands else 0` — a stopgap, see below |
| `_run_advisory` | `1 if out.had_failures else 0` |
| `_run_upgrade_check` | mixed: `1`, `0`, `1 if out.had_failures else rc` |
| `sys-audit main` | `1 if out.had_failures else 0` |
| `aur-precheck main` | `1 if any CRIT else 0` — its own rule |
| `_run_group` | `1 if any host failed else 0` |
| `_run_web` | `0` / `1` |
| **`_run_report`** | **hardcoded `0`, and no `print_summary()` at all** |

`_run_report` is the **sixth confirmed instance** of the structural defect this pass has
been chasing: *every subcommand with its own entry point independently forgot to print a
summary and compute an exit code.* Folding `sys-audit` and `advisory-check` into the
pipeline (v0.95.0) fixed two; `report` is still live. A report that fails to write exits
0 and says nothing.

### The defect I shipped deliberately

`--everything` (v0.95.0) returns `1 if ctx.failed_commands else 0`. That was the only
way to honour "findings warn, failures fail" without the classification below — and it
means **a check that could not look does not colour the status**, which is exactly
backwards for this project's governing invariant. It is documented in the code and the
changelog as a known limit. This plan is how it gets paid off.

---

## Proposal

**Do not add more channels.** The three display channels (`✓` / `!` / `✗`) are right and
users understand them. What is missing is an orthogonal *classification* on the failure
channel, so the exit code can be computed per question without changing what anything
looks like:

```python
summary_fail(line, kind="failed")   # the action could not do its job   (default)
summary_fail(line, kind="blind")    # the check could not look
summary_fail(line, kind="found")    # the check looked and found something
```

Rendering is unchanged — all three still print `✗`. Only the exit code branches:

| invocation | exits non-zero on |
|---|---|
| a single action (`fettle -V`, `fettle -S`) | `failed` **or** `blind` **or** `found` — unchanged, strict, what automation gates on |
| `--everything` | `failed` only; `blind` and `found` are reported, not failed on |

`--everything`'s status then means *"the run completed and could see everything it
claimed to check"*, which is a defensible thing for a fourteen-action sweep to assert —
and it stops being wrong about blindness.

`ctx.failed_commands` stays as the mechanism it already is (it tracks commands that
exited non-zero) but stops being the exit-code source.

---

## Milestones

Each is separately committable, with tests, per the usual rhythm.

### X1 — classify the 15 call sites (no behaviour change)
Add `kind` with a `"failed"` default, then walk every call site and label it. Ship with
exit codes computed exactly as they are now, so this milestone is provably inert: the
test is that the full suite passes untouched.

The value is that the classification is then *visible and reviewable* — several of the 15
are arguable, and getting them wrong is much cheaper to spot in a diff than in behaviour.

### X1a — the two rolled-up lines that mix *found* with *could not look*

**Found while doing X1, and it must be settled before X2 makes the labels matter.**

`pkg-integrity` and `sys-audit` each build one summary line by rolling up every record
they marked `error`. That bucket is not homogeneous — it contains genuine findings *and*
checks that could not run:

    UNKNOWN — the rpm database could not be queried; packages were NOT verified
    UNKNOWN — rpm -Va failed (exit N); packages were NOT verified
    UNKNOWN — mokutil failed (exit N)
    UNKNOWN — <tool> failed (exit N)
    rpm: Not installed

So both are labelled `FOUND` today, and both are wrong whenever the underlying reason was
blindness. Under X2's rule that is the **unsafe** direction: a sweep would report success
on a host where the integrity database could not be opened at all.

Fix: emit two lines instead of one where both are present — the findings as `FOUND`, the
unreadable checks as `BLIND` — rather than deciding the whole roll-up by majority. That
changes visible output (an extra `✗` line in the rare mixed case), which is why it is not
part of X1's inert labelling pass.

### Decided (Paul, 2026-08-06): blindness is made *visible*, not fatal

The open question above was answered, and the answer is better than the proposal: **leave
the exit status alone and serve the invariant through visibility instead.**

- A missing tool stays a warning. A check that tried and failed does not fail a sweep
  either — on this workstation chipsec cannot run at all, so failing on it would put
  `--everything` permanently in the red for a condition nobody can fix, which is how an
  exit code stops being read.
- In exchange, **everything that could not be examined is listed at the end of the run**,
  under `Not checked`, with the install command where a missing tool is the cause and the
  reason where fettle knows it — including chipsec's unsupported-platform case by name.

The invariant is "a check that cannot look must never render identically to a clean
result". A summary of what *was* found cannot satisfy that: a short list of ticks reads
identically whether nine checks passed or one passed and eight never ran. The coverage
block is what makes the difference legible, and it does it without spending the exit
code on it.

### X2 — key the exit codes on the classification
Single actions strict, `--everything` on `failed | blind`. Delete the
`ctx.failed_commands` stopgap and the "known limit" comment with it.

Regression test: an action that reports `blind` must fail `--everything`; one that reports
`found` must not.

### X3 — the entry points that still return a hardcoded 0
`_run_report` first (no summary, no code). Then audit the remaining early-return paths in
`_run_upgrade_check` and `aur-precheck` for the same shape. Add the **permanent guard**:
a test that enumerates every entry point and asserts none of them `return 0` literally at
the end of a run — the registry-guard pattern that already stopped the action table
drifting.

### X4 — the cross-cutting cases already on the tracker
- **F-11 / QA-M5**: an unsupported distro exits 0. It should not.
- **B8**: `--dry-run` exit-code inconsistency between actions.
- Remote: does a remote failure propagate? `remote.py`'s zipapp `main` discards a return
  value via `zipapp.create_archive(main=...)` — fixed once, worth re-proving.
- Group: `1 if any host failed` — correct, but does a host that could not be *reached*
  count the same as one whose update failed? They are different answers.

### X5 — document and close
A short table in the README saying what each exit code means, per invocation. Then the
matrix row in `docs/qa/README.md` gets a status for the first time.

---

## Cases

| ID | Test | Expected |
|---|---|---|
| QA-EXIT-01 | `fettle -V` on a host with an altered packaged file | non-zero |
| QA-EXIT-02 | `fettle -V` on a clean host | 0 |
| QA-EXIT-03 | An audit whose tool is missing | non-zero — *could not look* |
| QA-EXIT-04 | `--everything` with findings but no failures | **0** |
| QA-EXIT-05 | `--everything` where one check could not look | **non-zero** |
| QA-EXIT-06 | `--everything` where the update failed | non-zero |
| QA-EXIT-07 | `fettle report` when the report cannot be written | non-zero |
| QA-EXIT-08 | An unsupported distro | non-zero |
| QA-EXIT-09 | `--dry-run` on any action | 0 unless it genuinely could not look |
| QA-EXIT-10 | `fettle remote` where the remote run failed | the remote's code, not ssh's |
| QA-EXIT-11 | A group where one host is unreachable | non-zero, distinguishable from a failed action |
| QA-EXIT-12 | Every entry point returns a computed value | permanent test |

---

## Why this row first

- It is the only row with a **known-wrong** behaviour already shipped and documented.
- Its structural cause is understood and half-dismantled, so the work is bounded.
- It absorbs two open tracker items (F-11, B8) rather than leaving them to a later row.
- Every other cross-cutting row improves what a human reads. This one is the only one
  that decides whether fettle can be automated at all — which is the difference between
  a tool you run and a tool you rely on.
