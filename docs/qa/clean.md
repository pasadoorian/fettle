# QA — `clean` (`-c`)

**Purpose as advertised:** *"clean package-manager caches (asks first; `--yes` to skip)"*.

**Purpose as a user understands it:** reclaim disk space taken by downloaded packages,
without breaking anything.

Status: **spec written, not yet run.** Cases derived from source
(`fettle/actions.py:_clean`, `backends/{arch,debian,rhel}.py:clean_caches`) at v0.49.1.

---

## What it actually runs

Ground truth from the source, because the differences between families are themselves a
finding.

| Step | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| 1 | `rm -f /var/lib/pacman/db.lck` | — | — |
| 2 | `pacman -Scc --noconfirm` | `apt-get clean` | `dnf clean packages` |
| 3 | — | `apt-get autoclean -y` | — |
| 4 | `pamac clean --no-confirm` *(if pamac, as invoking user)* | — | — |
| 5 | `rm -rf ~/.cache/{pamac,yay,paru}` | — | — |
| 6 | `rm -rf /var/tmp/pamac-build-<user>` | — | — |
| 7 | prune disabled snap revisions | prune disabled snaps *(if `snap` updater ≠ none)* | prune disabled snaps *(same)* |
| 8 | — | `flatpak uninstall --unused -y` *(if flatpak present and ≠ none)* | same as debian |
| 9 | `summary_add("caches cleaned")` | same | same |

### Three observations that become test cases

1. **The three families are not equally aggressive, and only one of them says so.**
   `dnf clean packages` deliberately keeps repo metadata — there is a docstring explaining
   that `clean all` would force a slow re-download for a rounding error of disk.
   `pacman -Scc` goes the other way and removes **every** cached package, including the
   versions currently installed. On Arch, `/var/cache/pacman/pkg` is the primary way to roll
   back a bad upgrade offline; `-Scc` removes that ability with no warning. The same
   subcommand therefore means "conservative" on one family and "irreversible" on another.
   → **QA-CLEAN-12, QA-CLEAN-18**

2. **`apt-get autoclean` after `apt-get clean` can never do anything** — `clean` has already
   emptied the archive directory. Harmless, but it prints a second status line implying a
   second thing happened. → **QA-CLEAN-09**

3. **The prompt asks about "build dirs" on every platform**, but build directories are only
   touched on Arch. Debian and RHEL users are asked to consent to something that will not
   happen. → **QA-CLEAN-05**

---

## Cases

Applicability: **A** arch · **M** manjaro-local · **D** debian · **U** ubuntu ·
**E** rocky9/alma9 · **F** fedora. "all" = all seven.

Several cases are observed from one run — the run column groups them, so this is ~8 runs per
target, not 26.

### Consent and the prompt

| ID | Run | Test | Expected | Verified by | Applies |
|---|---|---|---|---|---|
| QA-CLEAN-01 | R1 | `fettle -c`, press Enter at the prompt | Default is **No**. Nothing is executed. A note says cleaning was skipped. | Cache size unchanged (`du -sb` before/after), no package-manager process ran | all |
| QA-CLEAN-02 | R2 | `fettle -c`, answer `y` | Cleaning proceeds, exit 0 | exit code + cache emptied | all except M |
| QA-CLEAN-03 | R3 | `fettle -c --yes` | No prompt at all; cleans | no prompt in transcript | all except M |
| QA-CLEAN-04 | R4 | `fettle -c < /dev/null` | Declines safely, does **not** clean, does **not** hang | exit within seconds, cache unchanged | all |
| QA-CLEAN-05 | R1 | Read the prompt as a first-time user | Prompt names only what this platform will actually remove | wording review — "build dirs" must not appear where no build dir is touched | all |

### Dry-run

| ID | Run | Test | Expected | Verified by | Applies |
|---|---|---|---|---|---|
| QA-CLEAN-06 | R5 | `fettle -c --dry-run` | Executes nothing | cache byte-identical before/after | all |
| QA-CLEAN-07 | R5 | Read the end of the dry-run output | Must **not** claim caches were cleaned. Summary must distinguish "would clean" from "cleaned". | summary text | all |
| QA-CLEAN-08 | R5 | Same run | No prompt appears; no hang | transcript | all |
| QA-CLEAN-09 | R5 | Compare `would run:` lines against a real run's commands | The two lists match exactly — a dry-run that under- or over-states the real command set is a lie | diff R5 vs R2 command lists | all |

### Effect on the system

| ID | Run | Test | Expected | Verified by | Applies |
|---|---|---|---|---|---|
| QA-CLEAN-10 | R2 | Package cache after a real clean | Downloaded package files are gone | `du -sb` of the cache dir, independent of fettle output | all except M |
| QA-CLEAN-11 | R2 | Does the user learn how much was reclaimed? | Space freed is reported. A clean command whose entire value is disk space should say how much it recovered. | output review | all except M |
| QA-CLEAN-12 | R2 | Repo metadata after a real clean | Matches what the user was told, and is consistent in *intent* across families | metadata dir present/absent vs the message shown | all except M |
| QA-CLEAN-13 | R6 | Run `-c --yes` twice in a row | Second run exits 0 and says something **true** — not the same "caches cleaned" line as when it actually freed 700 MB | output of run 2 | all except M |
| QA-CLEAN-14 | R6 | `fettle -O` immediately after a clean | Package operations still work; no broken state; any metadata re-download is expected and explained | exit code of the follow-up | all except M |

### Arch family specifics

| ID | Run | Test | Expected | Verified by | Applies |
|---|---|---|---|---|---|
| QA-CLEAN-15 | R7 | Stale `db.lck` present, no pacman running | Lock removed, action proceeds | file absent after | A |
| QA-CLEAN-16 | R7 | **`db.lck` held by a genuinely running pacman** | Lock is **not** removed; user is told why. Deleting a live lock invites two concurrent pacman processes and a corrupted database. | hold the lock with a sleeping pacman, observe | A |
| QA-CLEAN-17 | R2 | AUR helper caches after a clean run under sudo | `~/.cache/{yay,paru,pamac}` removed for the **invoking user**, not root's home | path check as the user | A, M(dry-run only) |
| QA-CLEAN-18 | R2 | Offline rollback after a clean | Either the currently-installed versions survive in the cache, **or** the user is warned before losing them | attempt an offline `pacman -U` of a cached package after cleaning | A |

### Extras gating

| ID | Run | Test | Expected | Verified by | Applies |
|---|---|---|---|---|---|
| QA-CLEAN-19 | R2 | flatpak not installed | Step skipped silently; no error, no scary line | transcript | all except M |
| QA-CLEAN-20 | R8 | `[updaters.<family>] flatpak = "none"` | flatpak step skipped, and the config is visibly honoured | transcript vs `--print-config` | D, U, E, F |
| QA-CLEAN-21 | R2 | Disabled snap revisions present | Superseded revisions pruned, each confirmed individually | `snap list --all` before/after | U |
| QA-CLEAN-22 | R8 | `[updaters.<family>] snap = "none"` | snap step skipped | transcript | U |

### Privilege, integration, exit codes

| ID | Run | Test | Expected | Verified by | Applies |
|---|---|---|---|---|---|
| QA-CLEAN-23 | R2 | Invoke unprivileged | Elevates exactly once; no double password prompt | transcript | all except M |
| QA-CLEAN-24 | R9 | `fettle -c -O` | Single elevation, clean runs first, both complete, summary lists both | transcript + exit code | all except M |
| QA-CLEAN-25 | R2 | Run-log after a clean | The run is recorded under `~/.fettle/logs/<host>/` with 0600 | `ls -l` | all |
| QA-CLEAN-26 | R10 | Underlying tool fails (simulate: unreadable cache dir) | Non-zero exit **or** an explicit warning — never a green summary over a failed clean | exit code + summary | A, D, E |
| QA-CLEAN-27 | R2 | Count the success lines against the operations that could have had an effect | Every `✓` line corresponds to something that actually could happen. `apt-get autoclean` after `apt-get clean` cannot, so its tick is noise. | transcript | D, U |
| QA-CLEAN-28 | R0 | Run on a distro fettle does not claim | Refuses clearly **and exits non-zero** — a run that did nothing must not report success to a script | `echo $?` | F (Fedora is unregistered) |

---

## Results

`—` = not yet run. Fill with PASS / FAIL / BLOCKED / n/a + reason. Record the fettle version
and date of the sweep.

**Sweep 1 — v0.49.1, 2026-07-31.**
28 cases × 7 targets = 196 cells — **77 PASS · 35 FAIL · 6 BLOCKED · 65 n/a · 13 not run**.
11 distinct findings (F-01 … F-11), of which one (**F-07**) means the action has never
worked at all on the Arch family. Raw transcripts: `qa-clean-logs/` in the session
scratchpad.

| ID | arch | manjaro-local | debian | ubuntu | rocky9 | alma9 | fedora |
|---|---|---|---|---|---|---|---|
| QA-CLEAN-01 | **PASS** | — | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-02 | **FAIL** (F-07) | n/a (read-only target) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-03 | **PASS** | n/a (read-only target) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-04 | **PASS** | — | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-05 | **PASS** (build dirs are real here) | **PASS** | **FAIL** (F-02) | **FAIL** (F-02) | **FAIL** (F-02) | **FAIL** (F-02) | **FAIL** (F-02) |
| QA-CLEAN-06 | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-07 | **FAIL** (F-01) | **FAIL** (F-01) | **FAIL** (F-01) | **FAIL** (F-01) | **FAIL** (F-01) | **FAIL** (F-01) | **FAIL** (F-01) |
| QA-CLEAN-08 | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-09 | **PASS** | n/a (no real run to compare) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-10 | **FAIL** (F-07) | n/a (read-only target) | **PASS** (41 MB→0) | **PASS** (42 MB→0) | **PASS** (3 rpms→0) | **PASS** (3 rpms→0) | **PASS** (3 rpms→0) |
| QA-CLEAN-11 | **FAIL** (F-03) | n/a (read-only target) | **FAIL** (F-03) | **FAIL** (F-03) | **FAIL** (F-03) | **FAIL** (F-03) | **FAIL** (F-03) |
| QA-CLEAN-12 | **FAIL** (F-07) | n/a (read-only target) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-13 | **FAIL** (F-04) | n/a (read-only target) | **FAIL** (F-04) | **FAIL** (F-04) | **FAIL** (F-04) | **FAIL** (F-04) | **FAIL** (F-04) |
| QA-CLEAN-14 | **PASS** | n/a (read-only target) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-15 | **PASS** | n/a (read-only target) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) |
| QA-CLEAN-16 | — (needs a held lock) | n/a (read-only target) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) |
| QA-CLEAN-17 | **PASS** | — (dry-run only) | n/a (no AUR helper) | n/a | n/a | n/a | n/a |
| QA-CLEAN-18 | **PASS by accident** (F-07) | n/a (read-only target) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) | n/a (no pacman) |
| QA-CLEAN-19 | **PASS** | n/a (read-only target) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-20 | n/a (no flatpak key for arch) | n/a (read-only target) | — | — | — | — | — |
| QA-CLEAN-21 | n/a (no snapd in image) | n/a (read-only target) | n/a (no snapd) | n/a (minimal image has no snapd) | n/a (no snapd) | n/a (no snapd) | n/a (no snapd) |
| QA-CLEAN-22 | n/a | n/a (read-only target) | n/a (no snapd) | n/a (no snapd) | n/a (no snapd) | n/a (no snapd) | n/a (no snapd) |
| QA-CLEAN-23 | BLOCKED — guests have passwordless sudo, so a double elevation leaves no symptom | n/a (read-only target) | BLOCKED (same) | BLOCKED (same) | BLOCKED (same) | BLOCKED (same) | BLOCKED (same) |
| QA-CLEAN-24 | **PASS** | n/a (read-only target) | **PASS** | **PASS** | **PASS** | **PASS** | **PASS** |
| QA-CLEAN-25 | **FAIL** (F-08) | — | **FAIL** (F-08) | **FAIL** (F-08) | **FAIL** (F-08) | **PASS** (no stray file this run) | **FAIL** (F-08) |
| QA-CLEAN-26 | — | n/a (read-only target) | — | n/a (same apt path as debian) | — | n/a (same dnf path as rocky9) | n/a (same dnf path) |
| QA-CLEAN-27 | n/a (no autoclean step) | n/a | **FAIL** (F-09) | **FAIL** (F-09) | n/a | n/a | n/a |
| QA-CLEAN-28 | n/a (registered) | n/a (registered) | n/a | n/a | n/a | n/a | **FAIL** (F-10, F-11) |

**Re-test after the F-07 fix — v0.50.0, arch target only**

| ID | before | after | evidence |
|---|---|---|---|
| QA-CLEAN-02 | FAIL | **PASS** | 10 cached files for uninstalled packages removed |
| QA-CLEAN-07 | FAIL | **PASS** | dry-run now ends `✓ would clean caches` |
| QA-CLEAN-10 | FAIL | **PASS** | 204 → 194 files |
| QA-CLEAN-11 | FAIL | **PASS** | `✓ caches cleaned — 353 KiB reclaimed` |
| QA-CLEAN-12 | FAIL | **PASS** | `bash` kept both cached versions |
| QA-CLEAN-13 | FAIL | **PASS** | second run: `caches already clean — nothing to reclaim` |
| QA-CLEAN-18 | PASS by accident | **PASS on purpose** | installed versions deliberately retained |

**Re-test after the F-01/02/03/04/09 fixes — v0.51.0**

Verified live on **debian** and **rocky9**, one per affected backend:

| ID | finding | evidence |
|---|---|---|
| QA-CLEAN-05 | F-02 | prompt is now `remove downloaded package caches?` — no build dirs |
| QA-CLEAN-07 | F-01 | dry-run ends `✓ would clean caches` |
| QA-CLEAN-11 | F-03 | `39.2 MiB reclaimed` (debian), `3.0 MiB reclaimed` (rocky9) |
| QA-CLEAN-13 | F-04 | second run: `caches already clean — nothing to reclaim` |
| QA-CLEAN-27 | F-09 | one apt line, no `autoclean` tick |

**ubuntu, alma9 and fedora were not re-run.** They share the backend and code path with
the target that was, so they are *expected* to pass — but expected is not measured, and
this table does not pretend otherwise. Fold them into the next full sweep.

Still open on `clean`: **F-05** (QA-CLEAN-16 — untested, needs a held pacman lock),
**F-08** (QA-CLEAN-25 — run-log permissions, not clean-specific), and **F-10/F-11**
(QA-CLEAN-28 — Fedora unsupported, exits 0).

---

## Findings

Filled as the sweep runs. Each FAIL is copied into
`~/src/claude-scratchpad/qa-runs-outstanding-issues-questions.md` with a next step.

### F-07 — `clean` has never cleaned the pacman cache. CONFIRMED, arch, v0.49.1  ⚠ headline

`ArchBackend.clean_caches` runs **`pacman -Scc --noconfirm`**. `--noconfirm` makes pacman
take the *default* answer to its own prompts, and the default for `-Scc` is **No**, because
the operation is destructive:

```
:: Do you want to remove ALL files from cache? [y/N]     <- --noconfirm answers N
:: Do you want to remove unused repositories? [Y/n]      <- --noconfirm answers Y
removing unused sync repositories...
```

Exit code **0**. Not one cached package is removed. fettle prints `✓ pacman cache cleared`
and `✓ caches cleaned`.

Measured on the arch target, primed with 194 packages / 174,740,911 bytes:

| After | files | bytes |
|---|---|---|
| prime | 194 | 174,740,911 |
| `-c` answered **y** | 194 | 174,740,911 |
| `-c --yes` again | 194 | 174,740,911 |

Verified independently of fettle by running `pacman -Scc --noconfirm` by hand: 194 files
before, 194 after.

**Consequences.** Every Arch/Manjaro user of fettle has a cache that has only ever grown.
It also explains why several other cases "passed": QA-CLEAN-18 (offline rollback still
possible) passes *only because the clean does nothing*, and would have failed had it worked.
A green summary over a no-op is the exact failure mode this QA plan exists to catch, and it
survived the automated matrix — which only asserts that actions do not crash.

**Fix direction — not simply "add `yes |`".** The right retention policy is the question
`-Scc` was never the answer to. Measured on manjaro-local's real 59 GB cache:

| Policy | Frees |
|---|---|
| `paccache -rk2` — keep last 2 versions of everything | **18.28 GiB** |
| `paccache -rk1` — keep last 1 version | **37.44 GiB** |
| `paccache -ruk0` — drop packages no longer installed at all | **31.12 GiB** |

`paccache` also prints the space it reclaimed, which would close **F-03** at the same time.
`pacman -Sc --noconfirm` (default **Yes**, keeps installed versions) is the no-new-dependency
fallback when `pacman-contrib` is absent.

### F-08 — run-logs are world-readable while being written. CONFIRMED, arch, v0.49.1

`runlog.py` creates the log with `open(path, "wb")` — mode from the process umask, so
**0644** — and only calls `os.chmod(path, 0o600)` later, in `_finalize`. The log is
therefore world-readable for the entire duration of the run, and permanently so if the run
is interrupted before finalisation.

Observed on the guest: two abandoned zero-byte logs left at `-rw-r--r--` alongside the
finalised ones at `-rw-------`. They are empty, so nothing leaked here — but they are proof
that the finalise step does not always run, and a real run-log carries the host's package
inventory, hostname and command line.

Two defects in one: **(a)** the mode should be set at creation
(`os.open(..., O_CREAT|O_EXCL, 0o600)`), making the later `chmod` belt-and-braces; **(b)**
empty logs should not be left behind at all — they also consume rotation slots, so under
`[reports] keep = 5` a handful of empty files can push real logs out.

### F-09 — a success tick for an operation that cannot do anything. CONFIRMED, debian + ubuntu

`apt-get autoclean` runs immediately after `apt-get clean`, which has already emptied the
archive directory. It can never remove anything, yet prints `✓ apt autoclean done` — so the
user counts two successful operations where one happened. Measured: cache 41,106,784 bytes
→ 0 after `clean`; `autoclean` then reports success against an empty directory.

### F-10 — Fedora is unsupported, and the reason covers one action out of fifteen

`fettle -c` on Fedora 44: *"no fettle backend for this distro … Known: almalinux, arch,
centos, debian, endeavouros, linuxmint, manjaro, ol, pop, rhel, rocky, ubuntu."*

The exclusion is deliberate and documented in `backends/rhel.py`: Fedora's advisories come
from Bodhi as `FEDORA-*` rather than Red Hat's `RHSA-*`, so an RHSA-tuned provider would be
approximate there. That reasoning is sound — **for `advisory-check`**. It currently withholds
all fifteen actions, including `clean`, `update`, `pkg-audit` and `hardening-audit`, none of
which touch advisories. The same file states the maintenance verbs were *measured* to behave
identically on dnf4 and dnf5-on-Fedora, and this QA run confirms it: forced on with
`--distro rhel`, Fedora's clean removed 3 rpms and preserved 103 MB of metadata, exactly as
Rocky and Alma did.

fettle already has a well-used pattern for this — decline one capability with a reason and
keep the rest (`checksec` absent, `deborphan` absent, `mhwd-kernel` absent). Fedora is the
upstream of the entire family fettle does support.

### F-11 — an unsupported distro exits **0**. CONFIRMED, fedora

The refusal above returned exit status **0**. A run that did nothing at all reports success
to the caller, so a cron job, CI step or wrapper script sees a clean maintenance run on a
machine fettle never touched. Should be non-zero; see **QA-CLEAN-28**.

---

**Predicted from source review, confirmed or refuted by the run:**

- **F-01 (QA-CLEAN-07): CONFIRMED LIVE**, manjaro-local, v0.49.1, 2026-07-31.
  `fettle -c --dry-run` printed seven accurate `would run:` lines and then
  `▸ Summary  ✓ caches cleaned`. Independently verified that nothing was touched: the
  package cache still held **59 GB across 15,859 files** afterwards. `clean_caches` calls
  `summary_add("caches cleaned")` unconditionally, outside the dry-run gate, so a run that
  deleted nothing reports success in past tense with a green tick. The *actions* are honest;
  the *outcome* is not.
  **Fix direction:** the summary line must be produced by the same gate that runs the
  commands — either skipped entirely under dry-run, or worded "would clean". Worth checking
  every other backend action for the same unconditional `summary_add` pattern, since this is
  a shape bug, not a one-off.
- **F-02 (QA-CLEAN-05): CONFIRMED, 5 of 7 targets.** Every non-Arch target printed
  *"remove package-manager caches and build dirs? [y/N]"* and then touched no build
  directory, because none exists. Users are asked to consent to something that cannot
  happen — and on Debian/RHEL the phrase makes the prompt sound more destructive than it is,
  which is the wrong direction for a prompt whose safe default is No.
- **F-03 (QA-CLEAN-11): CONFIRMED, all 7.** No family reports space reclaimed. Debian freed
  41 MB and said `✓ apt cache cleared`; Rocky freed 3 MB of rpms and said `✓ dnf package
  cache cleared`; both messages are identical to the ones printed when nothing is freed. The
  single number a user wants from this command is the one number it never prints.
- **F-04 (QA-CLEAN-13): CONFIRMED, all 7.** A second consecutive `-c --yes` against an
  already-empty cache produces byte-identical output to the run that emptied it. There is no
  way to tell "freed 41 MB" from "there was nothing to free".
- **F-05 (QA-CLEAN-16): UNTESTED.** `rm -f /var/lib/pacman/db.lck` is unconditional and the
  message calls the lock "stale" without establishing that it is. QA-CLEAN-15 passed (a
  genuinely stale lock is removed), but the case that matters — a lock held by a *running*
  pacman — was not exercised. Needs a follow-up run holding the lock.
- **F-06 (QA-CLEAN-18): masked by F-07, and becomes live the moment F-07 is fixed.**
  QA-CLEAN-18 "passed" on Arch only because the clean removes nothing. `pacman -Scc` removes
  cached copies of currently-installed packages — the standard offline rollback path on Arch
  — with no warning, while the RHEL backend goes out of its way to be conservative about a
  far smaller cost. **Fixing F-07 without also fixing F-06 would turn a harmless no-op
  straight into a destructive default.** These two must ship together.
  **Scale measured on manjaro-local:** that cache is **59 GB / 15,859 files**. A single
  `fettle -c` would delete all of it, report one line of past-tense prose, name no figure,
  and leave no way to reinstall or downgrade any installed package without the network.
  `paccache -rk2` (pacman-contrib, already a dependency of the Arch lab target) would
  reclaim most of the same space while keeping the last two versions of everything — the
  conventional Arch answer, and much closer in spirit to what the RHEL backend already does.
