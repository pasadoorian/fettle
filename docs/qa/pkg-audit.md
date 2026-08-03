# QA — `pkg-audit` (`-P`)

**Purpose as advertised:** *"cross-ecosystem supply-chain audit"*.

**Purpose as a user understands it:** *"where did everything on this machine come from, and
is any of it something I shouldn't trust?"*

The only audit in the default set, and the broadest thing fettle does: seven providers
covering AUR, apt/dnf, flatpak, snap, containers, GNOME extensions, VS Code/VSCodium
extensions and `gh` extensions.

Status: **swept and fixed.** One finding fixed in v0.67.0, one open by decision.

---

## What it does well, and is worth not breaking

Measured on a workstation with 46 findings across five providers:

- **Absent providers are named**: `[gh] not present on this system — nothing to audit`.
  Without that, "flatpak is clean" and "flatpak was never looked at" are the same output —
  the invariant this whole QA plan is organised around, already handled here.
- **Every provider states its own coverage limits** before its findings, including what it
  explicitly does *not* do (`Does NOT scan image contents`, `does NOT verify that a
  publisher is who they claim`, `No malware/IOC feed exists for extensions.gnome.org`).
- Findings are sorted by severity, and CRITs are counted separately.

## Cases and results

**Sweep 1 — v0.66.0 → v0.67.0, 2026-08-03**, on `manjaro-local` (46 findings) and the lab
guests.

| ID | Test | Verdict |
|---|---|---|
| QA-PA-01 | Every present provider runs and reports | PASS — 5 of 7 present, both absentees named |
| QA-PA-02 | Absent provider is reported, not skipped silently | PASS |
| QA-PA-03 | `skip_sources` silences a provider entirely | PASS *(by construction)* |
| QA-PA-04 | Coverage limits stated per provider | PASS |
| QA-PA-05 | Findings sorted by severity | PASS |
| QA-PA-06 | **Summary mark matches what was found** | **FAIL → fixed** (P-01) |
| QA-PA-07 | A CRITICAL finding fails an automated run | **FAIL → fixed** (P-01) |
| QA-PA-08 | Sideloaded `.vsix` detected | PASS — verified against the editor index |
| QA-PA-09 | **A resolved finding is distinguishable from one never checked** | **open** (P-02) |
| QA-PA-10 | Unreadable extension index is not reported as clean | PASS *(by construction)* |
| QA-PA-11 | Report written 0600 | PASS |
| QA-PA-12 | Runs unprivileged | PASS — already in the read-only set |

## Findings

### P-01 — 46 open items under a green tick. FIXED v0.67.0
The summary read `✓ 46 supply-chain finding(s)`. Findings are a to-do list, not an
accomplishment, and a green mark over them reads as "all good" at a glance — the opposite of
the point. It now uses the three-state vocabulary:

```
✓ no supply-chain findings              nothing to do
! N supply-chain finding(s)             open items, exit 0
✗ N supply-chain finding(s), M CRITICAL — INVESTIGATE     exit 1
```

The CRIT case now fails the run. This is the one read-only audit where that is right: a
package on a known-malicious list is not a to-do item, and a scripted run should stop.

### P-02 — you can only tell you fixed something by noticing an absence. OPEN
Raised from real use: two VSCodium extensions were flagged as sideloaded `.vsix`,
`codium --update-extensions` re-fetched them from Open VSX, and the findings simply stopped
appearing. Verified that this is **correct** — the index entries genuinely changed from
`source: vsix` to `source: gallery`, so the provenance concern no longer applies.

But nothing said so. A finding vanishing could equally mean the check broke, the detection
is flaky, or the extension was uninstalled. The audit has no notion of *resolved*.

`pkg-audit` already writes a full JSON report of every finding on each run, so diffing
against the previous one is feasible — but a findings-diff is a feature with its own design
questions (which report is the baseline, how to handle a first run, whether to report
resolutions on every run or only when asked) and does not belong in a QA sweep. Recorded for
a decision.

**Documented in the meantime**: the sideload finding describes *the copy currently
installed*, not the extension's history, and the finding now tells you how to clear it —
`re-install it from the registry to clear this (codium --update-extensions, …)`.
