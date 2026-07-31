# QA — `clean` (`-c`)

**Purpose as advertised:** *"reclaim disk from downloaded package files; keeps rollback
versions on Arch (asks first; `--yes` to skip the prompt)"*.

**Purpose as a user understands it:** reclaim disk space taken by downloaded packages,
without breaking anything.

Status: **two sweeps run.** Sweep 1 (v0.49.1) produced 11 findings, 7 since fixed
(v0.50.0 / v0.51.0 / v0.51.1). Sweep 2 (v0.51.1) confirmed those fixes on all six lab guests
and found one more. Four findings are open, three of them deferred by Paul pending research
(see `qa-runs-outstanding-issues-questions.md`).

---

## What it actually runs

Ground truth from the source, because the differences between families are themselves a
finding.

| Step | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| 1 | `rm -f /var/lib/pacman/db.lck` | — | — |
| 2 | `paccache -r -u -k0` — drop packages no longer installed | `apt-get clean` | `dnf clean packages` |
| 3 | `paccache -r -k<n>` — keep `n` versions of installed ones (`[clean] keep_versions`, default 2) | — | — |
| 3b | *fallback with no `pacman-contrib`:* `pacman -Sc --noconfirm` | — | — |
| 4 | `pamac clean --no-confirm` *(if pamac, as invoking user)* | — | — |
| 5 | `rm -rf ~/.cache/{pamac,yay,paru}` | — | — |
| 6 | `rm -rf /var/tmp/pamac-build-<user>` | — | — |
| 7 | prune disabled snap revisions | prune disabled snaps *(if `snap` updater ≠ none)* | prune disabled snaps *(same)* |
| 8 | — | `flatpak uninstall --unused -y` *(if flatpak present and ≠ none)* | same as debian |
| 9 | summary from `actions._clean`, sized from `cache_paths()` | same | same (both `/var/cache/dnf` **and** `/var/cache/libdnf5`) |

*(This table described the pre-fix commands until sweep 2. Keeping it current is part of the
QA pass — a stale description of behaviour is the same defect class as a stale summary.)*

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
| QA-CLEAN-29 | R12 | `[clean] keep_versions = 1` | The configured count reaches the command — `paccache -r -k1`, not `-k2` | `--dry-run` command list | A, M |

---

## Results

`—` = not yet run. Fill with PASS / FAIL / BLOCKED / n/a + reason. Record the fettle version
and date of the sweep.

**Sweep 1 — v0.49.1, 2026-07-31.** 28 cases × 7 targets — **77 PASS · 35 FAIL · 6 BLOCKED
· 65 n/a · 13 not run**, 11 findings. Superseded by sweep 2; kept as the record of what the
first pass found. Raw transcripts in the session scratchpad.

**Sweep 2 — v0.51.1, 2026-07-31.** Full re-run on all six lab guests after the F-01…F-09
fixes, plus the local Manjaro box (dry-run only). Two case groups that had never been run —
config gating and the failure path — were added.

| ID | arch | manjaro-local | debian | ubuntu | rocky9 | alma9 | fedora |
|---|---|---|---|---|---|---|---|
| QA-CLEAN-01 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-02 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-03 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-04 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-05 | PASS | not run (needs a real prompt; wopr is dry-run only) | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-06 | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-07 | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-08 | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-09 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-10 | PASS (204→194) | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-11 | PASS (353 KiB) | n/a | PASS (39.2 MiB) | PASS (40.1 MiB) | PASS (3.0 MiB) | PASS (3.0 MiB) | PASS (3.3 MiB) |
| QA-CLEAN-12 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-13 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-14 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-15 | PASS | n/a | n/a (no pacman) | n/a | n/a | n/a | n/a |
| QA-CLEAN-16 | **DEFERRED** (F-05) | n/a | n/a | n/a | n/a | n/a | n/a |
| QA-CLEAN-17 | PASS | not run | n/a | n/a | n/a | n/a | n/a |
| QA-CLEAN-18 | PASS (on purpose now) | n/a | n/a | n/a | n/a | n/a | n/a |
| QA-CLEAN-19 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-20 | n/a | n/a | BLOCKED¹ | BLOCKED¹ | BLOCKED¹ | BLOCKED¹ | BLOCKED¹ |
| QA-CLEAN-21 | n/a (no snapd) | n/a | n/a | n/a (minimal image) | n/a | n/a | n/a |
| QA-CLEAN-22 | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| QA-CLEAN-23 | BLOCKED² | n/a | BLOCKED² | BLOCKED² | BLOCKED² | BLOCKED² | BLOCKED² |
| QA-CLEAN-24 | PASS | n/a | PASS | PASS | PASS | PASS | PASS |
| QA-CLEAN-25 | **DEFERRED** (F-08) | not run | **DEFERRED** | **DEFERRED** | **DEFERRED** | **DEFERRED** | **DEFERRED** |
| QA-CLEAN-26 | BLOCKED³ | n/a | BLOCKED³ | BLOCKED³ | **FAIL (F-12)** | **FAIL (F-12)** | BLOCKED³ |
| QA-CLEAN-27 | n/a | n/a | PASS | PASS | n/a | n/a | n/a |
| QA-CLEAN-28 | n/a | n/a | n/a | n/a | n/a | n/a | **DEFERRED** (F-10/F-11) |
| QA-CLEAN-29 | PASS (`-k1`) | n/a | n/a | n/a | n/a | n/a | n/a |

**29 cases × 7 = 203 cells — 96 PASS · 2 FAIL · 12 BLOCKED · 9 DEFERRED · 80 n/a · 4 not run.**

¹ **Inconclusive, not passing.** `flatpak_updater = "none"` was set and no flatpak step ran
— but flatpak is not installed on any guest, so "config honoured" and "tool absent" produce
identical output. The case needs a guest with flatpak present to mean anything.

² Guests have passwordless sudo, so a double elevation leaves no visible symptom.

³ The failure injection (an immutable cached file) did not actually block anything on these
targets: on arch the file was an *installed* package, which retention keeps by design, and
on debian/ubuntu/fedora apt/dnf removed everything else and exited 0 regardless. Only the
EL9 pair genuinely blocked. Needs a better injection to be a real test elsewhere.

**Harness errors found and corrected during this sweep** — recorded because a bad test that
reports PASS is worse than no test:
- The arch prime downloaded only *installed* packages, one version each, so there was
  nothing for retention to remove. "Nothing to reclaim" was the truthful answer and the case
  proved nothing. Fixed by priming with packages that are not installed.
- Piping the failure-path output through `tail -6` cut off the `✗ … failed` line, which
  briefly looked like fettle swallowing an error entirely. It does not — see F-12 for what
  it actually does.

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

### F-12 — a *blocked* clean reports "already clean". NEW in sweep 2, rocky9 + alma9

Found by QA-CLEAN-26, a case that had never been run before. With one cached RPM made
undeletable (`chattr +i`), the full output is:

```
✗ dnf package cache cleared failed (exit 1):
[Errno 1] Operation not permitted: '/var/cache/dnf/.../bash-5.1.8-9.el9.x86_64.rpm'

▸ [1/1] Cleaning caches

▸ Summary
  ✓ caches already clean — nothing to reclaim
EXIT=0
```

**The step-level report is correct** — `run_quiet` prints `✗ … failed (exit 1)` with dnf's
error. Three problems follow it:

1. **The summary contradicts the failure with a green tick.** Nothing was reclaimed because
   the clean was *blocked*, not because there was nothing to do. Three RPMs remain. A user
   reading only the summary — which is what a summary is for — is told the machine is fine.
2. **Exit status is 0**, so automation sees a successful clean.
3. **The error is printed before the section header**, because `err()` writes to stderr
   unbuffered while stdout is block-buffered when piped. On a terminal it interleaves
   correctly; over ssh or into a log the failure is detached from the step it belongs to.

Same invariant as the finding that started all this: *could not do it* must not render as
*nothing to do*. The distinction the summary now draws between "cleaned N" and "already
clean" needs a third state for "tried and failed".

**Fix direction:** `clean_caches` must report whether its commands succeeded — `ctx.execute`
already returns the `Proc`, so the backends can track it — and `actions._clean` should
choose the summary and the exit status from that rather than from the byte delta alone.

Not reproduced on arch, debian, ubuntu or fedora: the injected immutable file was not a
removal target there, so nothing was actually blocked. The defect is in shared code and
almost certainly applies to all of them; it simply was not measured. See QA-CLEAN-26 note ³.

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
