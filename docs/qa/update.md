# QA — `update` / `upgrade` (`-u`)

**Purpose as advertised:** *"update everything (asks before upgrading; `--yes` to skip)"*.

**Purpose as a user understands it:** *"bring this machine up to date, and tell me the
truth about what happened."*

The riskiest action fettle has: it is the only one that installs software. Lab guests take
the full mutating set and are reverted between cases; `manjaro-local` is `--dry-run` only.

Status: **swept and fixed.** One sweep across all seven targets at v0.54.1; six findings, all fixed by v0.55.2.

---

## What it actually runs

`actions._update` is: security gate (real runs only) → `backend.update_system` →
`backend.update_extras`.

| Step | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| gate | advisory `security_gate` — warns; confirms only if `warn_gate` **and** unpatched Critical | same | same, plus the `gpgcheck=0` signature gate |
| mirrors | `pacman-mirrors -f[ N]` *(Manjaro; `[updaters.arch] refresh_mirrors`)* | — | — |
| repos | `pacman -Syuu` (`--noconfirm` under `--yes`) | `apt-get update` then `full-upgrade` | `dnf upgrade --refresh` (`-y` under `--yes`) |
| extras | `yay -Sua --devel --cleanafter` behind the AUR IoC pre-check gate | flatpak, then snap | flatpak, then snap |

Note `-Syuu`, not `-Syu`: the second `u` permits **downgrades**, which Manjaro needs when a
repo rolls a package back.

### Four things the source predicts, to confirm or refute

1. **The summary claims success unconditionally.** `update_extras` ends with
   `summary_add("packages updated (…)")` outside any check — so a `--dry-run` that installed
   nothing, and an upgrade whose command *failed*, both sign off as "packages updated". This
   is the third appearance of the shape fixed in `clean` (F-01) and `only-update` (O-03).
   → **QA-UP-10, QA-UP-11**
2. **Nothing consumes the failure signals.** `_update` discards the `Result` from both
   backend calls — including `Result(ok=False)` when `yay` is missing — and never consults
   `ctx.failed_commands`. A failed upgrade should not exit 0. → **QA-UP-12, QA-UP-13**
3. **Steps announce inconsistently.** `updating official repos (pacman)...` prints *before*
   its command; the mirror refresh prints only a ✓ *after* its own, because it runs
   `quiet=True`. With bare `-f` probing every known mirror that is a long silence that reads
   as a hang. → **QA-UP-03**
4. **`--yes` silently changes the security posture of AUR builds.** It adds
   `--diffmenu=false --editmenu=false`, skipping PKGBUILD review entirely. The note does say
   "UNATTENDED — PKGBUILD review skipped", so this is a wording check, not a defect.
   → **QA-UP-16**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### It actually updates

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-UP-01 | `fettle -u --yes` on an out-of-date guest | Pending packages are actually installed | installed-package set differs; pending count drops to 0 | all but M |
| QA-UP-02 | Same run | Exit 0 | `echo $?` | all but M |
| QA-UP-03 | Watch the ordering | Every step that takes time announces itself **before** it runs, not only after | transcript ordering | A, M |
| QA-UP-04 | Same run | Repo metadata was refreshed as part of it (no separate `-O` needed) | metadata mtime advanced | all but M |
| QA-UP-05 | `-u` a second time immediately | Says there is nothing to do; changes nothing | second transcript + package set | all but M |

### Consent

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-UP-06 | `fettle -u` with no `--yes`, decline at the prompt | Nothing is installed | package set unchanged | all but M |
| QA-UP-07 | `fettle -u < /dev/null` | Does not hang; does not install unattended | exit + package set | all but M |
| QA-UP-08 | `--yes` | No prompt from fettle **or** the package manager | transcript | all but M |
| QA-UP-09 | Unpatched Critical CVEs present, `warn_gate` on | Asks one extra confirmation naming the packages | seeded advisory DB | D, E |

### Truthfulness

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-UP-10 | `-u --dry-run` | Must **not** report "packages updated" — nothing was installed | summary text | all |
| QA-UP-11 | Upgrade command fails (unwritable lock / broken repo) | Summary says it failed; never a green "packages updated" | summary + package set | A, D, E |
| QA-UP-12 | Same run | **Exit non-zero** | `echo $?` | A, D, E |
| QA-UP-13 | `aur_updater = yay` with yay absent | Reported as a failure, not a note; exit non-zero | transcript + exit | A |
| QA-UP-14 | `-u --dry-run` preview vs what a real `-u` then installs | The preview named the same packages | diff preview against the real transaction | all but M |
| QA-UP-15 | Partial success: repos upgrade, extras fail | Summary distinguishes "repos updated, AUR failed" from full success | transcript | A |

### Security posture

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-UP-16 | `--yes` on Arch with AUR updates pending | Clearly states PKGBUILD review is being skipped | wording review | A, M |
| QA-UP-17 | AUR IoC pre-check gate with a seeded bad package | Blocks the build and says why | seeded IoC feed | A |
| QA-UP-18 | `gpgcheck=0` repo enabled | Asks one extra confirmation before installing unverified packages | transcript | E |
| QA-UP-19 | `--yes` with a `gpgcheck=0` repo | Proceeds but warns loudly — automation must not be silently degraded | transcript | E |

### Extras and configuration

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-UP-20 | `[updaters.*] system_updater = "none"` | Repo upgrade skipped, stated plainly, extras still run | transcript | A, D, E |
| QA-UP-21 | `aur_updater = "none"` | AUR skipped with a note; summary says "repos only" | transcript | A |
| QA-UP-22 | flatpak/snap present | Updated after the repos, each announced | transcript | U |
| QA-UP-23 | `[updaters.arch] refresh_mirrors = false` | Mirror step skipped and said so; upgrade still runs | transcript | A, M |

### After the upgrade

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-UP-24 | Kernel upgraded | A reboot is recommended, not assumed | transcript | all but M |
| QA-UP-25 | Run `-r` after `-u` | Services needing restart are reported | follow-up run | D, E |
| QA-UP-26 | Run-log after `-u` | Records the full transcript at 0600 | `ls -l` | all |

---

## Results

**Sweep 1 — v0.54.1, 2026-07-31.** Six lab guests took the full mutating set (reverted
between runs); `manjaro-local` was `--dry-run` only. **340 packages were genuinely
installed across the fleet.**

| Target | Pending before | After | Package set changed | Dry-run installed |
|---|---|---|---|---|
| arch | 27 | **0** | yes | nothing |
| debian | 3 | **0** | yes | nothing |
| ubuntu | 13 | **0** | yes | nothing |
| rocky9 | 67 | **0** | yes | nothing |
| alma9 | 57 | **0** | yes | nothing |
| fedora | **173** | **0** | yes | nothing |

| ID | Verdict | Evidence |
|---|---|---|
| QA-UP-01 | PASS | pending → 0 on all six; package-set hash changed on all six |
| QA-UP-02 | PASS | exit 0 on the healthy path |
| QA-UP-03 | **FAIL → fixed** | U-05: the mirror step announced only after finishing |
| QA-UP-04 | PASS | metadata mtime advanced during `-u` — no separate `-O` needed |
| QA-UP-05 | **FAIL → fixed** | U-01: a second run with nothing to do said `✓ packages updated` |
| QA-UP-06 | PASS | declined run left the package set byte-identical |
| QA-UP-07 | PASS | `< /dev/null` did not hang and installed nothing |
| QA-UP-08 | PASS | `--yes` prompted nowhere |
| QA-UP-09 | not run | needs a seeded advisory DB with unpatched Criticals |
| QA-UP-10 | **FAIL → fixed** | U-01: `--dry-run` claimed `✓ packages updated` |
| QA-UP-11 | **FAIL → fixed** | U-02: a failed upgrade claimed success |
| QA-UP-12 | **FAIL → fixed** | U-02: exit 0 over a failed upgrade |
| QA-UP-13 | not run | needs a guest with `yay` deliberately removed |
| QA-UP-14 | PASS | arch: `-O`, `-u --dry-run` and the real run all named 27 |
| QA-UP-15 | PASS (by design) | `Result.summary` composes "repos: pacman, AUR: yay" |
| QA-UP-16 | PASS | `--yes` states "UNATTENDED — PKGBUILD review skipped" |
| QA-UP-17 | not run | needs a seeded IoC feed |
| QA-UP-18 | PASS | EL: the gate names the repo and asks |
| QA-UP-19 | **FAIL → fixed** | U-04: proceeded and warned, then logged it as a green ✓ |
| QA-UP-20 | not run | — |
| QA-UP-21 | not run | — |
| QA-UP-22 | n/a | no flatpak or snapd on any guest |
| QA-UP-23 | PASS | manjaro-local: `refresh_mirrors = false` skips and says so |
| QA-UP-24 | not run | needs a kernel upgrade followed by a reboot check |
| QA-UP-25 | not run | belongs to the `rebuild-check` sweep |
| QA-UP-26 | **DEFERRED** | run-log permissions — see B4, deferred by decision |

**Not measured, and worth stating plainly:** the in-sweep failure injection (step S5) was
partly void. By the time it ran, each guest had already been fully upgraded, so a broken
repository had nothing left to fail on. The failure path was instead verified separately on
freshly-reverted Arch and Rocky guests with updates still pending — those results are the
trustworthy ones, and the S5 numbers are not.

## Findings

### U-01 — the summary claimed success unconditionally. FIXED v0.55.0
`update_extras` ended with `summary_add("packages updated (…)")` outside any check. Three
runs that installed nothing all signed off green:

| Run | Installed | Reported |
|---|---|---|
| `-u --dry-run` | nothing | `✓ packages updated (repos: pacman, AUR: yay)` |
| `-u`, **declined at the prompt** | nothing | `✓ packages updated` |
| `-u --yes`, nothing to do | nothing | `✓ packages updated` |

On an up-to-date Manjaro box the dry-run printed `✓ no updates pending` and
`✓ packages updated` in the same summary. The declined case is the worst of the three: the
user said no, and fettle recorded the upgrade as done.

Backends now describe what they did via `Result.summary`; `actions._update` decides whether
the description was earned.

### U-02 — a failed upgrade reported success and exited 0. FIXED v0.55.0
`_update` discarded both backends' `Result` and never consulted `ctx.failed_commands`.
Measured on Rocky with an unreachable repo: dnf errored, summary said
`✓ packages updated (dnf)`, exit 0.

### U-03 — the first fix reported *declined* upgrades as failures. FIXED v0.55.0
Introduced and caught within the same pass. pacman, apt and dnf all exit non-zero both when
the user answers "no" and when they genuinely break — an ambiguity this codebase already
documented for dnf and then walked into. `--yes` is the discriminator: with it there was no
prompt to decline. Hence `Output.summary_warn()` and a third summary state.

### U-04 — installing unverified packages was logged as an achievement. FIXED v0.55.1
`✓ upgraded from 1 unsigned repo(s)`, in green, for installing code whose signature was
never checked. Now `! installed packages from N repo(s) WITHOUT signature verification`.

### U-05 — the mirror step announced only after it finished. FIXED v0.55.2
Reported by Paul from a live `fettle -a`. It runs `quiet=True`, so it printed a tick once
complete while every other step announces beforehand — and with a bare `-f` it probes every
known mirror, so the user watches a silent terminal for the duration and reasonably reads it
as a hang. It now says `regenerating the mirror list (probing mirrors — this can take a
while)...` first. Under `--dry-run` the existing `would run:` line is the announcement, so
nothing extra is printed and nothing false is claimed.

### U-06 — diagnostics jumped ahead of the output they belonged to. FIXED v0.55.2
stderr is unbuffered; stdout is *block*-buffered whenever it is not a terminal. Over ssh, in
a run-log or through a pipe, every warning therefore appeared **before** its own section
header — measured with the signature warning printed above the `▸ Updating packages` line it
was warning about. `Output` now flushes stdout before writing any diagnostic. Not specific
to `update`: it affects every warning fettle has ever emitted into a log.
