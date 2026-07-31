# QA — `only-update` (`-O`)

**Purpose as advertised:** *"refresh repo metadata + report upgradable (no upgrade; safe)"*.

**Purpose as a user understands it:** *"tell me what's waiting, without changing anything."*

Status: **swept and fixed.** One sweep across all seven targets at v0.52.0, five findings, all fixed in v0.53.0 except two raised for decision.

---

## What it actually runs

`actions._only_update` is three steps: announce, `backend.refresh_metadata(ctx)`, then
`_preview_transaction(...)`, which calls `backend.pending_transaction(ctx, sync=ctx.sync)`.

| Step | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| refresh | **nothing is run** — deliberately no `pacman -Sy` | `apt-get update` (or `nala`) | `dnf makecache` |
| refresh (flatpak) | — | `flatpak update --appstream` *(if present)* | same |
| refresh (snap) | — | skipped — snapd refreshes itself | skipped |
| preview | private temp DB (`checkupdates` trick), rootless | `apt-get -s dist-upgrade` | `dnf upgrade --assumeno` as root, else upgrades-only + a note |
| needs root | **no** — but elevates anyway | yes (`/var/lib/apt/lists`) | yes (`/var/cache/dnf`) |

### Confirmed: `update` already refreshes, so `-O` is not a prerequisite

Checked in source, because the whole framing depends on it — `pacman -Syuu` (the `-y`),
`apt-get update` before the upgrade, and `dnf upgrade --refresh` respectively. `-O` is the
standalone *look without touching*, not a step you must run first.

### Four observations that become test cases

1. **Arch deliberately does not sync the system database.** Syncing without a full upgrade
   is the partial-upgrade footgun, so the preview is resolved against a private temp DB and
   the system DB is left alone. Correct — but the action announces *"refreshing package
   metadata"* and the backend then says *"system database left untouched"*, which reads as a
   contradiction to anyone who has not read the source. → **QA-ONLY-16**
2. **A refresh that fails still produces a confident preview.** `_only_update` calls
   `refresh_metadata` and then previews regardless. If `apt-get update` or `dnf makecache`
   failed — no network, a dead mirror, an expired repo key — the preview is computed from
   *stale* metadata and presented as current. The machinery to notice now exists
   (`ctx.failed_commands`, added for F-12) but this action does not consult it.
   → **QA-ONLY-06, QA-ONLY-07**
3. **`-O` elevates on Arch for work that needs no privileges.** `only_update` is outside
   `cli.NO_ROOT_ACTIONS`, which is right for apt and dnf (both write under `/var`) and
   pointless on Arch, where nothing is run and the preview is rootless by design.
   → **QA-ONLY-12**
4. **The name says the opposite of what it does.** "only-update" reads as *update, but only
   some of it*; it means *do not update — just look*. Every other action is named for what it
   does. → **QA-ONLY-17**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### Core behaviour

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ONLY-01 | `fettle -O` on a stale system | Repo metadata is actually refreshed | mtime of `/var/lib/apt/lists` or `/var/cache/dnf` metadata before/after | D, U, E, F |
| QA-ONLY-02 | Same run | **Nothing is upgraded** | installed-package versions identical before/after; pending-upgrade count unchanged | all |
| QA-ONLY-03 | Same run | The upgradable list matches reality | compare against `apt list --upgradable` / `dnf check-update` / `pacman -Qu` run independently | all |
| QA-ONLY-04 | Same run | Exit 0 | `echo $?` | all |
| QA-ONLY-05 | `-O` on a fully up-to-date system | Says plainly there is nothing to install — not an empty list the user has to interpret | output | all |

### Truthfulness when the refresh fails

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ONLY-06 | Break the network, run `-O` | The preview must **not** be presented as current. Stale data must be labelled stale. | output after `ip link set <dev> down` or a bogus proxy | D, U, E, F |
| QA-ONLY-07 | Same run | Non-zero exit **or** an explicit failure in the summary — never a green sign-off over a refresh that did not happen | `echo $?` + summary | D, U, E, F |
| QA-ONLY-08 | Break one repo only (bad URL), run `-O` | Partial failure disclosed; the preview says which repos it could not reach | output | D, E |

### Arch family specifics

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ONLY-09 | `-O` on Arch | **`pacman -Sy` is never run** — the system DB must not be synced without a full upgrade | mtime of `/var/lib/pacman/sync` unchanged | A, M |
| QA-ONLY-10 | Same run | The preview is genuinely fresh (temp DB), and says so | output + upgradable list matches a `checkupdates` run | A, M |
| QA-ONLY-11 | Temp DB unavailable (no `fakeroot`) | Falls back to the existing sync DB **and warns the preview may be stale** | remove/mask fakeroot, observe | A |

### Privilege

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ONLY-12 | `-O` as an unprivileged user on Arch | Should not demand a password for work that needs none | does a sudo prompt appear? | A, M |
| QA-ONLY-13 | `-O` as an unprivileged user on Debian/RHEL | Elevates exactly once; the refresh genuinely needs it | transcript | D, U, E, F |

### Dry-run and flags

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ONLY-14 | `-O --dry-run` | Refreshes nothing; shows what it would run | metadata mtime unchanged | all |
| QA-ONLY-15 | Same run | Summary does not claim a refresh happened | summary text | all |
| QA-ONLY-20 | `-O --no-sync` | Coherent: either it refuses (the flag contradicts the action) or it clearly reports using cached data | output | all |

### Clarity and terminology

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ONLY-16 | Read the Arch output as a first-timer | "refreshing package metadata" followed by "system database left untouched" must not read as self-contradiction | wording review | A, M |
| QA-ONLY-17 | Read the action name | The name should describe what it does. "only-update" reads as *a partial update*; it performs no update at all. | naming review | all |
| QA-ONLY-18 | snap present, `-O` run | Snap being skipped is either disclosed or genuinely irrelevant — not silently absent | output | U |
| QA-ONLY-19 | `-O`, then `-u --dry-run` | The two previews agree — `-O` must not promise a different transaction from the one `update` would perform | diff the two lists | all |

---

## Results

**Sweep 1 — v0.52.0, 2026-07-31.** Six lab guests plus manjaro-local (dry-run only).

| ID | Verdict | Evidence |
|---|---|---|
| QA-ONLY-01 | PASS | debian metadata mtime advanced; upgradable count went 3 → 4 as a result |
| QA-ONLY-02 | PASS | installed-package hash identical before/after on all six |
| QA-ONLY-03 | PASS | counts match the independent query on every target (arch 27, ubuntu 13, rocky9 67) |
| QA-ONLY-04 | PASS | exit 0 on the healthy path |
| QA-ONLY-05 | PASS | manjaro-local: "nothing to install — system is up to date" |
| QA-ONLY-06 | **FAIL → fixed** | O-01: every non-Arch family presented stale data as current |
| QA-ONLY-07 | **FAIL → fixed** | O-01: exit 0 over a refresh that never happened |
| QA-ONLY-08 | not run | needs a single broken repo rather than a broken network |
| QA-ONLY-09 | PASS | arch + manjaro sync-DB mtime unchanged — **no `pacman -Sy`** |
| QA-ONLY-10 | PASS | fresh temp DB; matches `checkupdates`, and honours IgnorePkg where a naive `pacman -Qu` does not |
| QA-ONLY-11 | **FAIL → fixed** | O-04: warned correctly, but blamed missing tools that were installed |
| QA-ONLY-12 | **open** | O-05: `-O` elevates on Arch for work needing no privileges |
| QA-ONLY-13 | BLOCKED | guests have passwordless sudo — a double elevation leaves no symptom |
| QA-ONLY-14 | PASS | metadata untouched under `--dry-run` on all seven |
| QA-ONLY-15 | **FAIL → fixed** | O-03: "refreshing package metadata" printed under `--dry-run` |
| QA-ONLY-16 | **FAIL → fixed** | O-03/O-04: see the note-ordering finding below |
| QA-ONLY-17 | **open** | O-06: the name describes the opposite of the behaviour |
| QA-ONLY-18 | n/a | no snapd on any guest |
| QA-ONLY-19 | PASS | arch: `-O` and `-u --dry-run` both report 27 |
| QA-ONLY-20 | PASS | `--no-sync` runs, reports from cached data |

**Re-verified after the fixes (v0.53.0)** on Ubuntu 26.04 and Rocky 9, healthy and with DNS
broken: healthy → `✓ 13 / 67 package(s) pending`, EXIT=0; broken → `✓ N package(s) pending
(from stale metadata)` plus `✗ could not refresh package metadata`, EXIT=1.

## Findings

### O-01 — a failed refresh yielded a confident preview. FIXED v0.53.0
The headline. With DNS broken, all five non-Arch targets printed a full pending list with no
caveat and exit 0. The two package managers fail differently:

| | offline exit | fettle before |
|---|---|---|
| `apt-get update` | **0** — apt does not fail on unreachable repos | printed `✓ apt package lists refreshed` |
| `apt-get update --error-on=any` | **100** | now used (apt ≥ 2.1, version-probed) |
| `dnf makecache` | **1** — honest | recorded the failure, then ignored it |

Arch was the only family that already warned.

### O-02 — the summary omitted the count. FIXED v0.53.0
`-O` exists to report a number, and the summary said `nothing to report` with up to 179
packages pending. Now `✓ N package(s) pending`.

### O-03 — `--dry-run` announced a refresh. FIXED v0.53.0
Same shape as F-01 in `clean`: the note sat outside the dry-run gate.

### O-04 — the Arch staleness note blamed the wrong thing. FIXED v0.53.0
`_temp_synced_db` fails three unrelated ways; the caller reported the first regardless.
Measured telling a user to install `fakeroot` and `pacman-contrib` — both present — when an
unreachable mirror was the actual cause. It now returns and quotes the real reason.

### O-05 — `-O` elevates on Arch for work that needs no root. OPEN
`only_update` sits outside `cli.NO_ROOT_ACTIONS`, correct for apt and dnf (both write under
`/var`) and pointless on Arch, where `refresh_metadata` runs nothing and the preview is
rootless by design. Needs per-backend root requirements rather than one global set.

### O-06 — the name says the opposite of what it does. OPEN, Paul's call
"only-update" reads as *update, but only part of it*; it performs no update at all. Every
other action is named for what it does. `check`, `check-updates` or `preview` would say it.
A rename is a breaking change, so an alias plus a doc change is the cheap version.

### Not a finding, worth recording
`pacman -Qu` reported one more upgradable package than fettle on manjaro-local. fettle was
right: the extra entry was marked `[ignored]` (an `IgnorePkg` package), which `pacman -Sup`
honours and a naive `-Qu` count does not. Cross-checking against a "simpler" command is not
automatically cross-checking against the truth.
