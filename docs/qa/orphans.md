# QA — `orphans` (`-o`)

**Purpose as advertised:** *"list foreign packages; remove true orphans"*.

**Purpose as a user understands it:** *"show me what nothing needs any more, and let me
decide what goes."*

**This is the action that deletes installed software.** Every other action can be re-run
after a mistake; this one can leave a machine missing something it needed. The cases below
are weighted accordingly: consent, and the accuracy of what consent was asked for.

Status: **spec written from source at v0.55.2, not yet run.**

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

*(to be filled by the sweep)*

## Findings

*(to be filled by the sweep)*
