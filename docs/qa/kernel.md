# QA — `kernel` (`-k`)

**Purpose as advertised:** *"manage installed kernels (running one protected)"*.

**Purpose as a user understands it:** *"clear out old kernels without breaking my ability
to boot."*

**The highest-stakes action in the tool.** Every other mistake can be undone from a shell;
this one can remove the shell. It is deliberately **not** in the default action set, and the
RHEL backend deliberately does not remove anything at all.

Status: **swept and fixed.** Two findings fixed in v0.62.0; the prior hardening verified intact.

---

## What it actually runs

| | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| lists | `mhwd-kernel -li` / `-l` | `dpkg -l 'linux-image-*'`, versioned images only | `rpm -q kernel-core` |
| removes | `mhwd-kernel -r linux<N>` — **user types the version** | `apt-get purge -y <chosen>` | **nothing — by design** |
| protects | the running series, refused outright | **running ∪ newest** | n/a (dnf enforces `installonly_limit` itself) |
| reboot nudge | — | yes | yes |

Two pieces of prior hardening are visible and worth preserving:

- **Debian protects `running ∪ newest`, not just `running`.** After a kernel upgrade but
  before the reboot, the running kernel is the *old* one — protecting only what is running
  would offer to purge the newer next-boot kernel, which is a rollback. Versions are
  compared numerically because a string sort ranks `6.8.0-99` above `6.8.0-124`.
- **RHEL removes nothing**, because dnf already enforces `installonly_limit`. Its docstring
  is explicit that the most dangerous operation in the tool is simply not performed there.
  It also queries `kernel-core` rather than `kernel`, having measured that `rpm -q kernel`
  can miss the kernel you actually booted.

### Predictions from the source

1. **The `orphans` fix was never applied here.** `orphans` was changed in v0.56.0 to drop the
   blanket `-y` — so the package manager shows its own transaction and a cascade cannot
   happen unseen — and to report the count *measured* from the installed set. `kernel` still
   runs `apt-get purge -y <chosen>` and still reports `len(chosen)`. The more dangerous of
   the two actions did not get the safety change. → **QA-KRN-05, QA-KRN-06**
2. **A failed purge is reported as a success**, the shape fixed everywhere else.
   → **QA-KRN-07**
3. **The running kernel is identified by string construction** — `"linux-image-" + uname -r`.
   If the installed package is named differently (`linux-image-unsigned-…`, a mainline or
   vendor kernel), that string matches nothing, and the *actual* running kernel is then just
   another entry in the removable list. → **QA-KRN-03**
4. **Arch's removal produces no summary at all** — neither on success nor on failure, so a
   kernel removal leaves no trace in the digest. → **QA-KRN-08**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### Never break the boot

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-KRN-01 | Running kernel among the installed set | Never offered for removal; labelled "running" | transcript vs `uname -r` | all |
| QA-KRN-02 | Newer kernel installed, older one running | **Both** protected; the newer is labelled "boots next" and a reboot is advised | upgrade, do not reboot, run `-k` | D, U, E |
| QA-KRN-03 | Running kernel's package named unexpectedly | Still protected — protection must not depend on a constructed name matching | inspect the real package name for `uname -r` | D, U |
| QA-KRN-04 | Arch: try to remove the running series | Refused outright, with a reason | type the running version | A, M |

### Consent and honesty about what went

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-KRN-05 | Purge a removable kernel | The package manager shows its transaction and can be declined — a cascade cannot happen unseen | package set before/after | D, U |
| QA-KRN-06 | Count in the summary | Matches what actually went, and names anything beyond the selection | package-set diff | D, U |
| QA-KRN-07 | Purge fails | Reported as a failure; no green count | stub a failure | D, U |
| QA-KRN-08 | Arch removal outcome | Appears in the summary, success or failure | remove a kernel | A |

### Behaviour

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-KRN-09 | `-k --dry-run` | Lists and explains; removes nothing; claims nothing | package set + summary | all |
| QA-KRN-10 | `-k` with nothing removable | Says so plainly and explains what is protected | fresh guest | all |
| QA-KRN-11 | `-k --yes` | Does not silently purge kernels the user never named | package set | all |
| QA-KRN-12 | RHEL: `-k` | Reports only; removes nothing whatever the answer | package set | E, F |
| QA-KRN-13 | `kernel-core` vs `kernel` | The running kernel appears in the list | compare both queries | E, F |

---

## Results

**Sweep 1 — v0.61.0 → v0.62.0, 2026-08-03**, on Debian 13. The guest was **rebooted
mid-sweep** so an older kernel became genuinely removable — before that, `running ∪ newest`
correctly protected everything and there was nothing to exercise.

| ID | Verdict | Evidence |
|---|---|---|
| QA-KRN-01 | PASS | running kernel labelled and never offered, before and after the reboot |
| QA-KRN-02 | PASS | pre-reboot: `.100` "newest — boots next", `.96` "running", **neither offered**, reboot advised |
| QA-KRN-03 | PASS *(this configuration)* | `linux-image-$(uname -r)` matched the installed package exactly; see the note below |
| QA-KRN-04 | not run | needs an Arch/Manjaro guest with `mhwd-kernel` |
| QA-KRN-05 | **FAIL → fixed** | K-01: `-y` meant apt's transaction was never shown |
| QA-KRN-06 | **FAIL → fixed** | K-02: the count was of what was *chosen* |
| QA-KRN-07 | **FAIL → fixed** | covered by the same change — a purge that removes nothing now says so |
| QA-KRN-08 | **open** | K-03: Arch's removal produces no summary line at all |
| QA-KRN-09 | PASS | `--dry-run` lists and explains, removes nothing |
| QA-KRN-10 | PASS | pre-reboot: "no kernel images to remove (running + newest are protected)" |
| QA-KRN-11 | PASS | `--yes` removed only the one kernel that was eligible |
| QA-KRN-12 | PASS *(by construction)* | RHEL removes nothing at all — dnf enforces `installonly_limit` |
| QA-KRN-13 | PASS *(by construction)* | `kernel-core` is queried, per the earlier RHEL measurement |

**After the fix, measured on the guest:** declining apt's transaction left all 438 packages
and reported `no kernels were removed`; `--yes` removed exactly 1, reported `1 package(s)
purged`, and left the running kernel and the meta-package intact.

## Findings

### K-01 — the `orphans` safety change was never applied here. FIXED v0.62.0
`orphans` was changed in v0.56.0 to drop the blanket `-y`, so the package manager shows its
own transaction and a cascade cannot happen unseen. `kernel` — **the more dangerous of the
two** — still ran `apt-get purge -y <chosen>`, so the user saw nothing and could refuse
nothing.

That two sibling actions with the same hazard were fixed one release apart, and only because
one of them happened to be swept first, is the more useful lesson: a fix applied to one
action is not a fix applied to the pattern.

### K-02 — the count was of what was chosen. FIXED v0.62.0
`len(chosen)`, not what actually went — the same defect as ORPH O-02, fixed the same way by
diffing the installed set around the command.

### K-03 — Arch's kernel removal leaves no trace in the summary. OPEN
`mhwd-kernel -r` runs through `ctx.execute` with no summary line on success or failure, so a
kernel removal — the most consequential thing fettle can do — produces an empty digest.
Not fixed here because it cannot be exercised: `mhwd-kernel` is Manjaro-only, the lab has no
Manjaro guest, and `manjaro-local` is read-only. Tracked with **Q1/Q5**.

### Correction to a claim made during this sweep
While measuring, `apt-get purge --dry-run` on a kernel image also purged
**`linux-image-cloud-amd64`**, the meta-package that pulls in future kernel upgrades, and I
described that as what fettle was about to do. **That was wrong.** The meta-package depends
on the *newest* image, which fettle protects and never offers — so for the packages fettle
actually offers, the meta is not at risk in this configuration.

The cascade is real, the consent problem was real, and the specific alarming consequence was
not. The guard that warns when a meta-package goes stays in as defence, correctly labelled
as defence rather than as a bug that was occurring.

### Prior hardening verified intact
The v0.4.3 fix — protect `running ∪ newest`, compare versions numerically — is working.
Pre-reboot the guest was running `6.12.96` with `6.12.100` installed, and **neither** was
offered, with the newer one labelled "boots next" and a reboot advised. That is precisely the
rollback the old bug would have proposed.
