# QA — `aur-audit` (`-A`)

**Purpose as advertised:** *"AUR health census: age/votes/out-of-date/orphan →
~/.fettle/reports/"*.

**Purpose as a user understands it:** *"which of the packages I installed from the AUR
should I be worried about?"*

Arch-only, read-only, and **not** in the default set. It exists to surface supply-chain
signals: a package whose maintainer changed hands, one flagged out-of-date, one that has
been orphaned — and one that has **vanished from the AUR entirely**, which is what a
deleted-for-malware package looks like from the outside.

Status: **swept and fixed.** Two findings fixed in v0.64.0.

---

## What it actually runs

`pacman -Qm` for foreign packages → AUR RPC (`fetch_info`) → `pacman -Qi` for reverse
dependents → `pacman -Ql` for public `.so` files. Everything is printed, a full report is
written to `~/.fettle/reports/`, and a baseline of maintainers is saved for next time.

### The finding, measured before writing these cases

Run on `manjaro-local`, which carries 77 real AUR packages:

| What the audit found | |
|---|---|
| **not found in the AUR at all** | **9** — `claude-desktop-bin`, `eclypsiumapp`, `littlesnitch`, `vanta`, `vino`, … |
| flagged out-of-date | 4 |
| removal candidates (nothing depends on them) | 59 |
| orphaned (no maintainer) | 0 |

What the summary said:

```
✓ AUR audit of 77 package(s)
```

**The summary reports that the audit ran, not what it found.** The nine packages that no
longer exist upstream are the single most alarming datum the action produces — its own report
labels them *"deleted/renamed - investigate"* — and they appear only in the body text.
Anyone reading the digest of a `fettle -A` run, or the run-log, sees a green tick and a
count of packages examined. → **QA-AUR-05**

---

## Cases

`manjaro-local` (77 AUR packages, read-only) and the `arch` guest (yay installed).

| ID | Test | Expected | Verified by |
|---|---|---|---|
| QA-AUR-01 | Foreign packages enumerated | Matches `pacman -Qm` | independent query |
| QA-AUR-02 | No foreign packages installed | Says so; does nothing else | fresh guest |
| QA-AUR-03 | Out-of-date / orphaned packages present | Flagged per package | real data |
| QA-AUR-04 | Package absent from the AUR | Listed as "deleted/renamed — investigate" | real data |
| QA-AUR-05 | **Summary content** | Carries what was *found*, not just that it ran | summary vs report body |
| QA-AUR-06 | Maintainer change since last run | Flagged `[REVIEW BEFORE UPGRADE]` | seeded baseline |
| QA-AUR-07 | First run vs genuinely no changes | Distinguishable | run twice |
| QA-AUR-08 | **AUR RPC unreachable** | Says the audit could not run; not silent in the summary | break DNS |
| QA-AUR-09 | Report written | 0600, path stated | `ls -l` |
| QA-AUR-10 | `--dry-run` | No report written, nothing claimed | report dir |
| QA-AUR-11 | Removal candidates | Caveated — pacman tracks only *packaged* dependents | transcript |
| QA-AUR-12 | Runs unprivileged | No sudo prompt | run as user |

---

## Results

**Sweep 1 — v0.63.0 → v0.64.0, 2026-08-03**, on `manjaro-local`.

| ID | Verdict | Evidence |
|---|---|---|
| QA-AUR-01 | PASS | 77 packages, matches `pacman -Qm` |
| QA-AUR-02 | PASS *(by construction)* | early return with a plain message |
| QA-AUR-03 | PASS | 4 flagged out-of-date, correctly per package |
| QA-AUR-04 | PASS | 9 correctly listed as absent from the AUR |
| QA-AUR-05 | **FAIL → fixed** | A-01 |
| QA-AUR-06 | not run | needs a seeded baseline with a changed maintainer |
| QA-AUR-07 | **FAIL → fixed** | A-02: "none (or first run - baseline saved)" conflates the two |
| QA-AUR-08 | **FAIL → fixed** | A-01: RPC failure left the summary empty |
| QA-AUR-09 | PASS | report written 0600 |
| QA-AUR-10 | PASS | `--dry-run` wrote nothing and claimed no path |
| QA-AUR-11 | PASS | the unpackaged-software caveat is printed with the candidates |
| QA-AUR-12 | PASS | already in the read-only set; no prompt |

## Findings

### A-01 — the summary said the audit ran, not what it found. FIXED v0.64.0
Measured above: 9 packages absent from the AUR and 4 flagged out-of-date, summarised as
`AUR audit of 77 package(s)`. The same shape fixed in `only-update` (which omitted the
pending count) and `config-drift` (which omitted the displaced count) — and here the omitted
datum is the security-relevant one.

The summary now carries the counts, and packages that have vanished from the AUR are a
**warning** rather than a line of report text, because "installed, but no longer exists
upstream" is the investigate case.

A failed RPC also left the summary silent — an audit that could not run was indistinguishable
in the digest from one that found nothing.

### A-02 — "no changes" and "first run" were the same sentence. FIXED v0.64.0
`none (or first run - baseline saved)` — so on the run that matters most, the first one, the
user cannot tell whether the baseline was just created or genuinely nothing moved. Now
distinguished.
