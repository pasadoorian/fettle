# QA — `rebuild-check` (`-r`)

**Purpose as advertised:** *"find packages/services needing a rebuild or restart"*.

**Purpose as a user understands it:** *"I just patched this box — is the patch actually in
effect, or is something still running the old code?"*

That second framing is the one that matters. A security update you have installed but not
activated is not a security update. `-r` is in the **default action set**, so it is the step
a routine `fettle -a` relies on to answer it.

Status: **spec written from source at v0.56.1; the headline case already measured.**

---

## What it actually runs

| | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| tool | `checkrebuild` (rebuild-detector) | `needrestart -b -r l`, else `checkrestart` | `needs-restarting -r` (dnf4) / `dnf needs-restarting` (dnf5) |
| finds | packages built against since-upgraded libraries | services running old libraries | **reboot required**, plus services (`-s`) |
| reboot reported? | n/a | **no — see R-01** | **yes**, with an explicit exit-code asymmetry |
| can act? | `-R` rebuilds via yay/pamac | no, points at `sudo needrestart` | no, points at reboot |

The RHEL implementation has already been through this scrutiny and documents it:
*"wrongly saying 'reboot required' costs a needless reboot; wrongly saying 'no reboot
required' leaves a machine running the old libraries it just patched. So only exit 0 is
allowed to mean 'no reboot'."* The other two backends have not had that treatment.

### R-01 — measured before writing these cases

`needrestart` reports kernel state and fettle reads only the service lines:

```
NEEDRESTART-KCUR: 6.12.96+deb13-cloud-amd64    <- running
NEEDRESTART-KEXP: 6.12.100+deb13-cloud-amd64   <- installed
NEEDRESTART-KSTA: 3                            <- needrestart's "reboot required"
```

fettle's answer on that same machine:

```
✓ 3 service(s) need restarting
→ restart them: sudo needrestart
```

The advice is wrong, not merely incomplete: restarting those services cannot help, because
the running kernel is the old one. And `kernel` (`-k`) is **not** in the default set, so a
routine `fettle -a` that upgrades the kernel on Debian/Ubuntu tells nobody to reboot — while
the identical run on Rocky says "reboot required". → **QA-REB-01**

### Other predictions from the source

1. **A check that could not run reads as a clean result.** On Arch, `checkrebuild` absent →
   a `note` and an empty summary; `checkrebuild` *failing* → empty stdout → *"no packages
   need rebuilding."* Neither the exit code nor the distinction reaches the user. Debian's
   `needrestart` parse has the same shape. → **QA-REB-05, QA-REB-06**
2. **A failed rebuild is reported as a success.** `summary_add("rebuilt packages with
   outdated deps")` follows `self._rebuild(...)` with no check — the shape fixed in `clean`,
   `only-update`, `update` and `orphans`. → **QA-REB-09**
3. **`-R` may rebuild nothing while claiming to.** The package list comes from
   `parts[1]` of each `checkrebuild` line, keeping only lines with ≥2 fields. If the tool
   prints one field per line, the list is silently empty. → **QA-REB-08**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### Does it answer the question that matters

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-REB-01 | Upgrade the kernel, then `-r` | **Says a reboot is required**, on every family | `needrestart` KSTA / `needs-restarting -r` cross-check | all but M |
| QA-REB-02 | `-r` with services running old libraries | Lists them, and says how to act | compare against the native tool | all but M |
| QA-REB-03 | `-r` on a freshly-booted, fully-patched box | Says plainly that nothing is pending | transcript | all but M |
| QA-REB-04 | `fettle -a` after a kernel upgrade | The reboot is mentioned in the run, not only under `-k` | full `-a` transcript | D, U, E |

### Could-not-look must not read as clean

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-REB-05 | Tool absent | Says the check did **not** run; the summary must not be silent | remove/mask the tool | all |
| QA-REB-06 | Tool present but fails (exit non-zero) | Reported as "could not determine", never "nothing needs rebuilding" | break the tool | A, D |
| QA-REB-07 | Run unprivileged | Any list that needs root says so rather than reporting an empty one | run as a non-root user | all |

### Acting on it

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-REB-08 | `-r -R` with rebuild candidates | Rebuilds the packages it listed — the count acted on matches the count shown | transcript + package versions | A |
| QA-REB-09 | Rebuild fails | Reported as a failure; exit non-zero; no green claim | summary + exit | A |
| QA-REB-10 | `-r --dry-run` | Changes nothing; does not claim to have rebuilt | package set + summary | all |
| QA-REB-11 | `-r` without `-R` | Never rebuilds; only reports and suggests | package set | A, M |

### Consistency

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-REB-12 | Compare the three families' output for the same situation | The same state produces the same *kind* of answer everywhere | side-by-side transcripts | all |
| QA-REB-13 | Summary content | Reflects what was found, including "reboot required" | summary text | all |

---

## Results

*(to be filled by the sweep)*

## Findings

*(to be filled by the sweep)*
