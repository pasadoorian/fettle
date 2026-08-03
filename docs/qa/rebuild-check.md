# QA — `rebuild-check` (`-r`)

**Purpose as advertised:** *"find packages/services needing a rebuild or restart"*.

**Purpose as a user understands it:** *"I just patched this box — is the patch actually in
effect, or is something still running the old code?"*

That second framing is the one that matters. A security update you have installed but not
activated is not a security update. `-r` is in the **default action set**, so it is the step
a routine `fettle -a` relies on to answer it.

Status: **swept and fixed.** One sweep across all seven targets; five findings, four fixed by v0.58.0, one withdrawn as never real.

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

**Sweep 1 — v0.57.0, 2026-08-03.** Each guest was upgraded mid-sweep to create a genuine
reboot-pending state, then asked. `manjaro-local` read-only.

| Target | Running kernel | Installed | Reboot owed? | fettle said (before fixes) |
|---|---|---|---|---|
| arch | 7.1.3-arch1-3 | 7.1.5-arch1-2 | **yes** | *"no packages need rebuilding"* — **missed** |
| debian | 6.12.96 | 6.12.100 | **yes** | `reboot required (kernel)` ✓ *(0.57.0 fix)* |
| ubuntu | 7.0.0-28 | 7.0.0-28 | no | services only ✓ **correct** |
| rocky9 | 687.10.1 | 687.33.1 | **yes** | `reboot required` ✓ |
| alma9 | 687.5.3 | 687.31.1 | **yes** | services only — **missed** |
| fedora | 6.19.10 | — | **yes** | `reboot required` ✓ |
| manjaro-local | 7.1.4-1-MANJARO | present on disk | no | quiet ✓ (13 module dirs, no false positive) |

| ID | Verdict | Evidence |
|---|---|---|
| QA-REB-01 | **FAIL → fixed** | R-01 (debian), R-02 (arch), R-03 (alma9) |
| QA-REB-02 | PASS | service lists match `needrestart` / `needs-restarting -s` |
| QA-REB-03 | PASS | arch before upgrade: `checkrebuild` 0 lines, fettle agreed |
| QA-REB-04 | **FAIL → fixed** | `-r` is in the default set; the reboot now surfaces in a routine run |
| QA-REB-05 | **FAIL → fixed** | R-04: absent tool was a silent note with an empty summary |
| QA-REB-06 | PASS *(after fix)* | arch: `checkrebuild failed (exit 3) — NOT determined`; rocky the same |
| QA-REB-07 | PASS | RHEL states it when an unprivileged run cannot read other users' processes |
| QA-REB-08 | **withdrawn** | R-05 — see below; the defect was never real |
| QA-REB-09 | PASS *(by construction)* | failed rebuild now `summary_fail`; not exercised live |
| QA-REB-10 | PASS | `--dry-run` left 2381 packages untouched on manjaro-local |
| QA-REB-11 | PASS | `-r` without `-R` never rebuilt anything on any guest |
| QA-REB-12 | **FAIL → fixed** | three families gave three different answers to one situation |
| QA-REB-13 | PASS *(after fix)* | the summary now carries "reboot required" |

## Findings

### R-01 — Debian never reported a required reboot. FIXED v0.57.0
`needrestart` supplies `NEEDRESTART-KSTA` and fettle read only the service lines. On a box
running 6.12.96 with 6.12.100 installed it advised restarting three services — advice that
cannot help while the running kernel is the unpatched one. `-k` is not in the default set,
so a routine `fettle -a` said nothing about it.

### R-02 — Arch never reported it either, and the consequence is worse. FIXED v0.58.0
`checkrebuild` looks only at libraries. Meanwhile the `linux` package owns
`/usr/lib/modules/<release>` and an upgrade **replaces** that directory, so the running
kernel cannot load any module it has not already loaded — a USB device plugged in after the
upgrade simply does not work. Measured: `/usr/lib/modules/7.1.3-arch1-3` was gone while the
machine was still running it.

Detected by comparing `uname -r` against the directories present, not by parsing versions:
the package version and the kernel release are punctuated differently
(`7.1.5.arch1-2` vs `7.1.5-arch1-2`).

### R-03 — a dnf4 host without `yum-utils` got a false all-clear. FIXED v0.58.0
The backend picked its command by asking whether the standalone `needs-restarting` existed,
treating absence as dnf5. A dnf4 host merely lacking `yum-utils` also has no such binary, and
there `dnf needs-restarting` is a **process list that exits 0** regardless. Rocky and Alma —
identical dnf 4.14.0, differing only in whether that package happened to be installed —
therefore gave opposite answers to the same question.

The generation now comes from `dnf --version`. This is exactly the failure the backend's own
docstring set out to prevent; the guard was right, the guarded command was wrong.

### R-04 — "could not look" read as clean, twice. FIXED v0.57.0
Absent `checkrebuild` → a quiet note and an empty summary. Failing `checkrebuild` → empty
stdout → *"no packages need rebuilding."* Empty `needrestart` output → *"no services need
restarting"*, though it always prints a header, so nothing at all means it did not run.

### R-05 — WITHDRAWN: `-r -R` rebuilding nothing while offering to
Predicted from source: the package list took field 2 of each `checkrebuild` line and dropped
shorter ones, so a one-field format would silently empty it. **It does not happen.**
`checkrebuild` emits `repo<TAB>pkgname` — its source ends `awk '{ print $2 "\t" $1 }'`, and
a live run prints `foreign⇥zoom`. The original parse was correct.

The code change (fall back to field 1 when only one exists) is harmless and stays as a
guard, but it fixed a defect that was never there. Recorded rather than deleted, and
corrected in the 0.57.0 changelog entry too — a claim written from reading rather than from
measurement, which is the mistake this whole plan exists to catch.

### Harness notes
- The sweep's "make the tool fail" step overwrote `/usr/bin/needs-restarting`, which on
  Rocky is a **symlink to `/usr/libexec/dnf-utils`** — that clobbered the real tool and the
  restore did not take. Repaired with `dnf reinstall yum-utils`. Simulating failure by
  overwriting a binary is a bad idea when the binary may be a symlink.
- The sweep's "native says" cross-check ran `sudo needs-restarting -r` and read exit 1 as
  *"reboot required"*. On Alma, where the binary does not exist, exit 1 was
  **command-not-found**. The finding was real, but that particular evidence was not.
