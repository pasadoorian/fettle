# QA — `advisory-check`

**Purpose as advertised:** *"installed pkgs with known CVEs (fix available, or no fix
yet)"*.

**Purpose as a user understands it:** *"what on this box has a published CVE, and can I
do anything about it?"*

Read-only, opt-in, subcommand-only (no short flag), backed by a rebuildable SQLite cache.
The largest surface of any single feature: four distro trackers plus OSV for language
environments the distro does not manage.

Status: **swept and fixed.** Five findings, two of them raised by Paul on sight.

---

## Cases and results

**Sweep 1 — v0.73.1 → v0.74.0, 2026-08-05**, on `manjaro-local` (1547 system packages,
46 Python environments, 34 pending + 142 fix-available).

| ID | Test | Verdict |
|---|---|---|
| QA-AD-01 | **It is clear what was examined** | **FAIL → fixed** (AC-01) |
| QA-AD-02 | **A finding names where to act** | **FAIL → fixed** (AC-02) |
| QA-AD-03 | **Summary matches what was found** | **FAIL → fixed** (AC-03) |
| QA-AD-04 | **A stale/unfetchable feed is not a clean result** | **FAIL → fixed** (AC-04) |
| QA-AD-05 | **The summary is rendered; the exit code is real** | **FAIL → fixed** (AC-05) |
| QA-AD-06 | Advice given points at commands that exist | **FAIL → fixed** (AC-06) |
| QA-AD-07 | Grouping does not hide occurrences | PASS — the count note states the pre-grouping total |
| QA-AD-08 | Two environments never collapse into one finding | PASS — and now by construction (AC-02) |
| QA-AD-09 | Uncovered packages are named, not silently skipped | PASS — 77 AUR/foreign listed |
| QA-AD-10 | Manjaro's sync lag is explained rather than alarming | PASS *(prior work)* |
| QA-AD-11 | Cache schema change forces a rebuild | **FAIL → fixed** (AC-02, upgrade path) |

## Findings

### AC-01 — you could not tell the package database from a walk of your home. FIXED
The report interleaved rows sourced from the distro's package database with rows sourced
from **a recursive walk of the user's filesystem**, distinguished only by an `arch/` vs
`osv/` prefix you had to already know how to read. A tool that walks your home directory
should say so, and say where it looked:

```
What was checked:
  arch   installed system packages, matched against the Arch Linux security tracker
  osv    49 Python environment(s) found on disk — a walk of ~/src (depth 5) plus
         uv/pipx apps and pip --user; environments the distro does NOT manage
```

Each provider now answers for itself via `AdvisoryProvider.scope()`.

### AC-02 — `jetkvm (25.3.0)` never said where jetkvm was. FIXED
Acting on a finding began with running `find`. The cause was structural: the **label was
the identity**. Environments were stored as a short name derived from the directory, and
because two environments can shrink to the same label, there was collision-widening logic
to stop findings silently collapsing into one another.

Identity is now the **absolute path**, which is unique by construction and is the thing
you actually need. Labels became display-only — short on the finding lines, resolved once
at the end:

```
Environments (46) — the short names above, in full:
  ALEAPP     /home/paulda/src/ALEAPP/venv
  jetkvm     /home/paulda/src/jetkvm/venv
```

The mapping is in the JSON sibling too, so a consumer can act without re-deriving it.

**Upgrade path, nearly missed:** the cached row's `package` field changed shape, so
existing caches would have rendered `ALEAPP  ALEAPP` — a label pointing at itself — until
the 6-hour TTL happened to expire. Caught by running it. `SCHEMA_VERSION` is bumped to 4:
the row *format* is part of the schema even when the columns are not.

### AC-03 — a green tick over 176 unpatched CVEs. FIXED
`✓ advisories: 34 pending, 142 fix-available`. Now:

- **Critical with a fix available** → `✗`, exit 1. The one case that should stop an
  automated run, and consistent with `security_gate`, which already blocks `-u`/`-a` on it.
- Anything else outstanding → `!`.
- Genuinely nothing → `✓ advisories: nothing known-vulnerable`.

### AC-04 — a CVE check on stale data reported like a fresh one. FIXED
An unfetchable feed warned inline and then contributed a normal-looking summary. Same
shape as the dead fwupd daemon (v0.61.0) and the unreadable container runtime (v0.69.0).
Now `! … — but advisory data is NOT current: arch (and NONE is cached)`.

### AC-05 — the summary was written and thrown away, and the exit code was a constant. FIXED
`_run_advisory` called `check.run(ctx)` and `return 0`, never calling `print_summary()`.
So every `summary_*` line in this feature — including the ones added above — went to a
channel nobody rendered, and a Critical-with-a-fix could not be reported to a script.

**This is exactly sys-audit's S-01/S-02 pair**, in a different subcommand, found one
release later. Both are subcommands with their own entry point rather than pipeline
actions, which is what the pipeline's `print_summary()` covers — so the shape is
"anything routed outside `actions.run()` has to remember to do this itself". Worth a
cross-cutting check of the remaining entry points (`upgrade-check`, `aur-precheck`,
`report`, `web`).

### AC-06 — advice pointing at a retired flag. FIXED
The uncovered-packages footer said *"vet via `fettle -A`/`-P`/`-I`"*. `-I` was retired
the previous day. Two more copies were live: the **web UI still offered `-I` as a
runnable action** (it would now exit 2 with a retirement message), and the lab matrix
still carried a label for it.

Retiring the flag and grepping for `aur_ioc_scan` was not enough — these three spell it
`-I`. The project's own notes call this "the post-v0.4.0 stale-flag class of bug" and say
to grep for the *flag letters* after any rename. That instruction existed, and I did not
follow it.

## Not exercised

- **Debian/Ubuntu/RHEL trackers** were not re-run in this sweep; the findings above are
  in shared code (`check.py`, `base.py`) or Arch/OSV-specific. The per-distro feed
  parsing was verified during Phase 19 and by the lab matrix.
- **The `-u`/`-a` Critical warn-gate** (`security_gate`) is untouched here and still
  unswept — it is the one path where advisory data can *block* a mutating action.
