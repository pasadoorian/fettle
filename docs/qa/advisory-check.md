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

---

## The pre-update gate — swept separately (v0.75.0)

`security_gate` was the one path where advisory data could **block a mutating action**:
`fettle -u` / `-a` called it before a real upgrade, and it could return `False` to abort.

| ID | Test | Verdict |
|---|---|---|
| QA-AD-12 | **The question it asks is the right one** | **FAIL → redesigned** (SG-01) |
| QA-AD-13 | **Its count agrees with the report it cites** | **FAIL → fixed** (SG-02) |
| QA-AD-14 | **Aborting is not reported as success** | **FAIL → fixed by removal** (SG-03) |
| QA-AD-15 | Severity detection matches the rest of the codebase | **FAIL → fixed** (SG-04) |
| QA-AD-16 | Never fetches; a network problem cannot delay an upgrade | PASS *(by design)* |
| QA-AD-17 | Never raises; an advisory bug cannot break an update | PASS *(by design)* |
| QA-AD-18 | `--yes` is never silently blocked | PASS — and now unreachable by construction |

### SG-01 — the prompt argued for the harmful answer. REDESIGNED v0.75.0
On an unpatched Critical it asked:

> `Continue with the update despite unpatched Critical CVEs?`

Measured on the QA host: **732 of 770 findings had a fix already released.** So the
update it offered to abort was precisely the thing that installs those fixes, and
answering "no" left the machine both unpatched *and* still vulnerable. For a Critical
with **no** fix released, aborting does not help either — the update is unrelated to it.
There is no state of the world in which the abort is the better answer.

**The codebase already contained the argument against its own behaviour.** RHEL's
`_signature_gate` docstring explains the asymmetry it observes with the advisory gate:
*"an unpatched CVE is a pre-existing condition that blocking does not fix — refusing to
upgrade leaves you unpatched, which is worse."* That was written as a contrast, while
the advisory side did the opposite. The two agree now.

`security_gate` is now `security_note`: it prints the posture and returns nothing. It
separates Criticals **with** a fix released (a note — this upgrade should install them,
named so you can verify afterwards) from Criticals with **none** (a warning — the one
thing the upgrade genuinely cannot address). `[advisories] warn_gate` is retired, and a
config that still sets it is told so rather than silently believing it is guarded.

### SG-02 — the note contradicted the document it cited. FIXED v0.75.0
```
security: 770 advisory finding(s) affect installed packages … see `fettle advisory-check`
```
Running `fettle advisory-check` then showed **176**. The note counted raw findings; the
report groups by package+CVE. Both numbers were correct and no one could reconcile them.
The note now counts what the report shows.

### SG-03 — an aborted update wore a green tick. FIXED v0.75.0
`summary_add("update SKIPPED at the security gate")` — `✓` on an upgrade that did not
happen. Removed along with the abort path it described.

### SG-04 — `f.severity == "Critical"`
String equality where the rest of the module uses `severity_rank`. Correct against
today's providers and silently wrong against any that spells it differently. Now ranked.

## Not exercised

- **Debian/Ubuntu/RHEL trackers** were not re-run in this sweep; the findings above are
  in shared code (`check.py`, `base.py`) or Arch/OSV-specific. The per-distro feed
  parsing was verified during Phase 19 and by the lab matrix.
- **The `-u`/`-a` Critical warn-gate** (`security_gate`) is untouched here and still
  unswept — it is the one path where advisory data can *block* a mutating action.
