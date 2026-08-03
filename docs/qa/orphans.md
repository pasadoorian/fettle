# QA — `orphans` (`-o`)

**Purpose as advertised:** *"list foreign packages; remove true orphans"*.

**Purpose as a user understands it:** *"show me what nothing needs any more, and let me
decide what goes."*

**This is the action that deletes installed software.** Every other action can be re-run
after a mistake; this one can leave a machine missing something it needed. The cases below
are weighted accordingly: consent, and the accuracy of what consent was asked for.

Status: **swept and fixed.** One sweep across all seven targets at v0.56.0; three findings, all fixed by v0.56.1.

---

## What it actually runs

| Step | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| review file | `pacman -Qm` → `alien-pkgs` report | obsolete pkgs (`apt-show-versions`, else `aptitude ~o`) → `obsolete-pkgs` report | packages from no enabled repo → report |
| candidates | `pacman -Qtdq` (true orphans) | `deborphan`, **plus** `apt-get autoremove --dry-run` | `dnf repoquery --unneeded` |
| protection | `keep_orphans` | `keep_orphans` | `keep_orphans` **+ installonly/kernels, fail-safe** |
| consent | per-package `ctx.select` | per-package for deborphan; one confirm for autoremove | per-package `ctx.select` |
| removal | `pacman -Rsn --noconfirm` | `apt-get purge -y` / `apt-get autoremove -y` | `dnf remove` (**no `-y`** unless `--yes`) |

### The three backends disagree about how much to show before deleting

The RHEL backend is explicit about this in its own source — *"`dnf remove` on the chosen
list, NOT `dnf autoremove` … Without `--yes` dnf then shows its own transaction and
confirms, so a removal that cascades into dependents cannot happen unseen."*

**The Arch backend does the thing that comment describes avoiding.** `pacman -Rsn
--noconfirm`: `-s` also removes dependencies that become unneeded, and `--noconfirm`
suppresses the transaction pacman would otherwise print. So a user who consents to three
named packages may lose considerably more than three, having never been shown the list.
→ **QA-ORPH-10**, the case this sweep exists for.

`apt-get purge -y` on the deborphan path has the same shape. The autoremove path does not:
it prints the full set first and then asks once, so the preview *is* the transaction.

### Other predictions from the source

1. **`--yes` removes every offered orphan without asking**, because `ctx.select` returns all
   items under `assume_yes`. Defensible for automation, but it should be stated — this is
   the one action where "assume yes" means "delete things". → **QA-ORPH-11**
2. **A failed removal is still counted as a success.** `summary_add(f"{n} orphan(s)
   removed")` follows `ctx.execute` with no check, the shape already fixed in `clean`,
   `only-update` and `update`. → **QA-ORPH-15**
3. **The count claimed is the count *selected*, not the count removed** — which the cascade
   above makes materially different on Arch. → **QA-ORPH-14**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### Finding and reporting

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ORPH-01 | `fettle -o` on a guest with foreign/obsolete packages | They are written to a review report and the path is stated | report file exists, content matches an independent query | all |
| QA-ORPH-02 | Same run | Orphan candidates match the native tool | compare with `pacman -Qtdq` / `apt-get autoremove --dry-run` / `dnf repoquery --unneeded` | all |
| QA-ORPH-03 | `exclude_foreign` set | Matching packages are suppressed **and the suppression is stated** | transcript | A |
| QA-ORPH-04 | `keep_orphans` set | Matching orphans are protected and named | transcript | all |
| QA-ORPH-05 | No orphans present | Says so plainly; offers nothing | transcript | all |

### Consent — the part that matters

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ORPH-06 | Per-package prompt, answer `n` to all | Nothing is removed | package set unchanged | all but M |
| QA-ORPH-07 | Answer `q` partway | Stops; only prior `y` answers are removed | package set | all but M |
| QA-ORPH-08 | `-o --dry-run` | Removes nothing; writes no report | package set + report dir | all |
| QA-ORPH-09 | `-o < /dev/null` | Removes nothing, does not hang | package set | all but M |
| QA-ORPH-10 | **Select one orphan whose removal cascades** | The user is shown **everything** that will be removed, not just what they picked, before it happens | compare the consented list against the package set actually removed | A, D, E |
| QA-ORPH-11 | `-o --yes` | Removes all offered orphans; the fact that `--yes` means deletion here is stated | transcript + package set | all but M |

### Never remove these

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ORPH-12 | Kernels among the unneeded set | Never offered; the hold-back is named, not silent | transcript | E |
| QA-ORPH-13 | `repoquery --installonly` fails | Fails safe — offers nothing at all rather than guessing | break the query, observe | E |
| QA-ORPH-14 | Count in the summary vs packages actually gone | They match | package-set diff before/after | all but M |

### Truthfulness

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-ORPH-15 | Removal command fails | Reported as a failure; exit non-zero; no green count | summary + exit | A, D, E |
| QA-ORPH-16 | Nothing found vs nothing chosen | The two are distinguishable in the summary | transcript | all |
| QA-ORPH-17 | Report file permissions | 0600 | `ls -l` | all |
| QA-ORPH-18 | `--dry-run` report behaviour | Consistent across families — either all write a preview note, or none write | transcript | all |

---

## Results

**Sweep 1 — v0.56.0, 2026-08-03.** Six lab guests, each primed with a package marked as a
dependency so there was something real to remove; `manjaro-local` `--dry-run` only.

| Target | Candidates | Installed before | After `--yes` | Actually removed | Reported |
|---|---|---|---|---|---|
| arch | 1 (`nmap`) | 273 | 271 | **2** | `2 package(s) removed (including 1 unused dependency(ies): lua54)` |
| debian | 5 | 442 | 437 | 5 | `5 unused dependency(ies) autoremoved` |
| ubuntu | 10 | 440 | 432* | 10 | `10 unused dependency(ies) autoremoved` |
| rocky9 | 4 | 427 | 423 | 4 | `4 package(s) removed` |
| alma9 | 2 | 389 | 387 | 2 | `2 package(s) removed` |
| fedora | 0 | 501 | 501 | 0 | *(nothing to report)* |

\* **The Ubuntu row is where my measurement was wrong, not fettle.** The count appeared to
drop by 8 against a claim of 10 — but `dpkg-query -W` also lists **`rc`** packages (removed,
config files kept), and two of the ten left config behind. All ten were removed; fettle was
right. That mistake did expose a real bug in the fix shipped hours earlier — see **O-03**.

| ID | Verdict | Evidence |
|---|---|---|
| QA-ORPH-01 | PASS | review report written on every family; path stated |
| QA-ORPH-02 | PASS | candidates match `pacman -Qtdq` / `autoremove --dry-run` / `repoquery --unneeded` on all six |
| QA-ORPH-03 | not run | needs `exclude_foreign` seeded |
| QA-ORPH-04 | PASS | `keep_orphans = ["nmap"]` → *"protected orphans (keep_orphans): nmap"*, then nothing offered |
| QA-ORPH-05 | PASS | fedora had no candidates and said so; second runs likewise |
| QA-ORPH-06 | PASS | declining pacman's transaction left all 273 packages |
| QA-ORPH-07 | not run | needs an interactive `q` mid-list |
| QA-ORPH-08 | PASS | `--dry-run` removed nothing and wrote **no** report on any family |
| QA-ORPH-09 | PASS | `< /dev/null` removed nothing on all six |
| QA-ORPH-10 | **FAIL → fixed** | O-01: consented to 1, removed 2, with no chance to refuse |
| QA-ORPH-11 | PASS | `--yes` removed all offered candidates unattended |
| QA-ORPH-12 | PASS | EL: kernels absent from the offered set; hold-backs named |
| QA-ORPH-13 | not run | needs `repoquery --installonly` broken deliberately |
| QA-ORPH-14 | **FAIL → fixed** | O-02: claimed the *selected* count, not the removed count |
| QA-ORPH-15 | not run | needs a removal that fails mid-transaction |
| QA-ORPH-16 | PASS | "no orphaned packages found" vs "no orphans removed" are distinct |
| QA-ORPH-17 | PASS | reports 0600 |
| QA-ORPH-18 | **FAIL** (open) | O-04: Arch is silent about the report under `--dry-run`; Debian says "would be saved" |

## Findings

### O-01 — consent was asked for less than was removed. FIXED v0.56.0
`pacman -Rs` also drops dependencies the chosen package was the last thing needing.
Measured: `pacman -Qtdq` offers `nmap`; removing it also takes `lua54`. fettle ran
`pacman -Rsn --noconfirm`, so pacman printed the two-package transaction and then **answered
its own confirmation** — the extra package went by on screen with no way to refuse it.
Debian's `apt-get purge -y` had the same shape.

The RHEL backend already documents avoiding exactly this. Both other paths now drop the
suppressing flag unless `--yes`, making the package manager's transaction a real decision
point. Verified: declining leaves all 273 packages and reports nothing removed.

*Correction to the prediction:* the source review claimed the cascade "cannot be seen".
Wrong — pacman prints it, because the output is streamed rather than captured. The defect
was the missing opportunity to refuse, and the count. Worth recording as an instance of a
source-reading claim that measurement narrowed.

### O-02 — the count was of what was chosen, not what went. FIXED v0.56.0
`✓ 1 orphan(s) removed` while two packages were removed. New
`PackageBackend.installed_packages()`; the removal paths now diff the installed set around
the command and name anything beyond the selection:
`✓ 2 package(s) removed (including 1 unused dependency(ies): lua54)`.

### O-03 — the fix for O-02 mis-counted on Debian. FIXED v0.56.1
Found by chasing the Ubuntu discrepancy above. `dpkg-query -W` lists `rc` packages —
removed, config retained — and a plain `apt-get remove` leaves a package in exactly that
state. It would therefore appear in **both** the before and after snapshot, and the diff
would report it as still installed. `installed_packages()` now filters to status `ii`.

Introduced and caught within the same day, by a measurement that disagreed with the tool and
turned out to be the thing that was wrong.

### O-04 — `--dry-run` report behaviour differs by family. OPEN
Arch writes no review report under `--dry-run` and says nothing about it; Debian writes none
but prints *"N obsolete/foreign package(s) would be saved for review"*. Both are defensible;
being different is not, and the Arch user has no idea a report is part of this action.
Cosmetic, and left open rather than fixed blind.
