# QA — `update` / `upgrade` (`-u`)

**Purpose as advertised:** *"update everything (asks before upgrading; `--yes` to skip)"*.

**Purpose as a user understands it:** *"bring this machine up to date, and tell me the
truth about what happened."*

The riskiest action fettle has: it is the only one that installs software. Lab guests take
the full mutating set and are reverted between cases; `manjaro-local` is `--dry-run` only.

Status: **spec written from source at v0.54.1, not yet run.**

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

*(to be filled by the sweep)*

## Findings

*(to be filled by the sweep)*
