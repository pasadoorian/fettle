# QA — `--dry-run` semantics (cross-cutting)

**The promise:** *show what would run; change nothing.* This is the only row where being
wrong means fettle altered a machine after saying it would not — which is the whole reason
anyone types it on a production box.

Status: **swept — 3 findings fixed.**

---

## What holds

The execution gate itself is sound. `Context.execute` is the single choke point, and under
`--dry-run` it prints `would run: …` and runs nothing — including when privileges are
being dropped with `as_user`. `confirm()` and `select()` both return "no" without
prompting, so a preview cannot hang waiting for input in automation. `failed_commands`
stays empty, so the exit code cannot key off work that never happened.

A survey of every mutating verb (`pacman`/`apt`/`dnf`/`yay`/`flatpak`/`snap`/`docker`/
`podman`) found **nothing bypassing the gate** — the three direct calls outside it are
read-only (`flatpak remotes`, `dnf check`, `pacman -Sup --print-format`).

## Findings

### D-01 — `--dry-run` deleted your run history. FIXED — the serious one
Writing a run-log rotates the directory to `keep` entries, so a dry run **removed older
real run-logs**. Measured on a seeded tree: **eleven real logs before, nine after**, from a
single `fettle -d --dry-run`.

The command whose entire promise is "change nothing" was destroying history — and quietly,
because rotation is silent and the evicted logs are the oldest ones nobody is looking at.

Dry runs are no longer recorded. That is right on a second ground too: a dry run appearing
in `fettle report` as a *run* is misleading on its own, since the dashboard would show
maintenance happening on a host where nothing was touched. A preview's output belongs on
your terminal.

### D-02 — `pkg-integrity` wrote a report under `--dry-run`. FIXED
Measured across the audits: `-P` and `-A` write nothing under `--dry-run`; `-V` wrote two
files. So this was the outlier rather than the convention. It now announces
*"report would be saved to ~/.fettle/reports/"* — matching what `--dry-run` does
everywhere else, and matching what `orphans` was fixed to do in the terminology row.

### D-03 — `sys-audit` would write a report under `--everything --dry-run`. FIXED
Standalone `fettle sys-audit` has no `--dry-run` flag, so this never came up. Becoming a
pipeline action made it reachable, and it would have written a report inside a command
that promised no changes. Guarded, with the same announcement.

## Cases

| ID | Test | Verdict |
|---|---|---|
| QA-DRY-01 | No mutating command bypasses the gate | PASS — surveyed |
| QA-DRY-02 | `would run:` is printed instead of executing | PASS |
| QA-DRY-03 | Privilege-dropped commands are gated too | PASS |
| QA-DRY-04 | No prompt appears under `--dry-run` | PASS |
| QA-DRY-05 | `failed_commands` stays empty | PASS |
| QA-DRY-06 | No run-log is written | **FAIL → fixed** (D-01) |
| QA-DRY-07 | Real runs are still recorded | PASS — the other half of D-01 |
| QA-DRY-08 | No report is written by any audit | **FAIL → fixed** (D-02, D-03) |
| QA-DRY-09 | Real runs still write their reports | PASS |
| QA-DRY-10 | The intent is announced, not silently skipped | PASS — settled in the terminology row (B8) |

## The shape worth remembering

Every finding here was **state fettle keeps about itself**, not a package-manager command.
The gate around the dangerous operations has been solid since it was written; what leaked
were reports, logs and rotation — the bookkeeping nobody thinks of as "changing the
system". D-01 is the sharpest form of it: not a file created, but files *deleted*, by the
one command that exists to be safe.
