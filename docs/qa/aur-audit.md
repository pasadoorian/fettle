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

---

## Sweep 2 — v0.89.0 → v0.92.0, 2026-08-06

Prompted by a plain user question rather than a sweep: *"how would I know if something I
have installed was pulled upstream?"* — with `claude-desktop-bin`, a 404 on the AUR, as the
worked example. Answering it exposed a defect in this action and a gap in two others.

| ID | Test | Verdict |
|---|---|---|
| QA-AA-08 *(new)* | Summary mark matches the summary text | **FAIL → fixed** (A-04) |
| QA-AA-09 *(new)* | A disappearance is distinguishable from a package that was never there | **FAIL → fixed** (A-05) |
| QA-AA-10 *(new)* | A disappearance is still reported on later runs | PASS — the snapshot retains it |
| QA-AA-11 *(new)* | The snapshot cannot grow without bound | PASS — uninstalled packages drop out |

### A-04 — a green tick over nine removed packages. FIXED v0.90.0
Measured on wopr:

```
✓ AUR audit of 79 package(s) — 9 no longer in the AUR, 7 flagged out-of-date
EXIT=0
```

The body carried a `!` warning, but the summary — the part people read, and the part the
dashboard and exit code key off — was green. An earlier fix had corrected the summary
*text* to say what was found and left the *mark* alone; the comment above the code still
says "say what was FOUND, not merely that the audit ran". **Fixing the words is not fixing
the mark**, and that is why it survived.

### A-05 — "absent" is a standing state, and standing states make bad alarms. FIXED v0.92.0
The count stood at **9 every single run** on wopr, most of them work packages built
in-house that were never in the AUR at all. A warning that is permanently on is one nobody
reads — the same failure as a red tripwire on a clean machine, arrived at from the opposite
direction.

Now split: **vanished since the last run** warns (it was there when fettle last looked —
that is what deletion for malware looks like), while *not in the AUR and never seen there*
is listed quietly. "Installed from elsewhere" and "deleted before fettle first ran" are
genuinely indistinguishable, so it does not pretend otherwise. The vanished entry is
retained while the package stays installed, or the alarm would fire once — on a run nobody
reads — and then silently downgrade itself forever.

**The cost, recorded rather than glossed:** on an existing host the alarm starts empty. The
snapshot only ever recorded packages that *were* in the AUR, so anything that disappeared
before v0.92.0 — including the `claude-desktop-bin` that prompted all this — is in the
quiet bucket and cannot be recovered. yay's build cache was checked as an alternative
provenance record and holds one entry. This alarm is prospective by nature.

### What the question exposed elsewhere
Of fettle's eight install channels, **only the AUR was asked this question at all.** Flatpak
and Snap gained it in v0.91.0, against the app's own remote rather than flathub by
assumption. GNOME, VS Code and `gh` extensions are still not asked — tracked as item G in
the matrix follow-up plan, VS Code first, since Microsoft pulls malicious extensions from
the Marketplace and that removal *is* the signal.
