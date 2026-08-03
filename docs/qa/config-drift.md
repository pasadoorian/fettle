# QA — `config-drift` (`-d`)

**Purpose as advertised:** *"list pending config-file merges (.pacnew / .dpkg-dist /
.rpmnew)"*.

**Purpose as a user understands it:** *"did an upgrade change how this machine is
configured behind my back?"*

Status: **swept and fixed.** Four findings, all fixed in v0.59.0.

---

## What it actually runs

| | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| finds | `pacdiff -o` | `/etc` walk for 3 suffixes | `/etc` walk for 3 suffixes |
| suffixes | whatever pacdiff returns — `.pacnew`, `.pacorig`, `.pacsave`, `.pacsave.N` | `.dpkg-dist`, `.dpkg-new`, `.ucf-dist` | `.rpmnew`, `.rpmsave`, `.rpmorig` |
| distinguishes displaced configs? | **no** | **no — and does not look for them** | **yes** |
| package-DB check | — | `dpkg --audit` | `dnf check` |

### The distinction that only one backend makes

These suffixes are not interchangeable, and the difference is the whole point:

| Meaning | Arch | Debian | RHEL |
|---|---|---|---|
| Package shipped a new default, **your file still in effect** | `.pacnew` | `.dpkg-dist`, `.ucf-dist` | `.rpmnew` |
| **Your file was moved aside — the package's version is now in effect** | `.pacorig` | **`.dpkg-old`, `.ucf-old`** | `.rpmsave`, `.rpmorig` |
| Your file kept when the package was removed | `.pacsave` | — | — |

The second row is the one that matters: a setting somebody deliberately made has silently
stopped applying. The RHEL backend treats it as a **warning**, separately from the merely
informational `.rpmnew`, and its docstring says why — *"Lumping them together (as the Debian
backend does for its own three suffixes) would hide the case where a machine quietly stopped
honouring settings someone deliberately made."*

**Measured, and worse than that comment claims:**

1. **Debian never looks for `.dpkg-old` or `.ucf-old` at all.** It is not lumping them
   together; it is not finding them. A config replaced by an upgrade is invisible to `-d`.
   → **QA-DRIFT-02**
2. **Arch lumps four kinds into one.** `pacdiff` scans `.pacnew`, `.pacorig`, `.pacsave` and
   `.pacsave.N` (confirmed in its source, line 235), and fettle labels the lot *"pacnew
   files needing attention"* — or, when there are none, *"no .pacnew files to merge."*
   → **QA-DRIFT-01, QA-DRIFT-03**

### Also predicted from the source

3. **`pacdiff` absent or failing reads as clean.** Absent → a quiet note and an empty
   summary. Failing → `_query` returns empty stdout → *"no .pacnew files to merge."* The
   shape already fixed in `rebuild-check`. → **QA-DRIFT-06, QA-DRIFT-07**
4. **`dpkg --audit` failing is invisible** — `_query` again, no exit check, so a broken dpkg
   produces no warning. RHEL's `dnf check` equivalent handles this explicitly.
   → **QA-DRIFT-08**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### Finding drift, and saying what kind it is

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-DRIFT-01 | Seed a "new default" file (`.pacnew`/`.dpkg-dist`/`.rpmnew`) | Found, and described as *your file still in effect* | seeded file + transcript | all |
| QA-DRIFT-02 | Seed a **displaced-config** file (`.pacorig`/`.dpkg-old`/`.rpmsave`) | Found, and **warned** — your setting is no longer applying | seeded file + transcript | all |
| QA-DRIFT-03 | Seed both kinds at once | Reported separately, not as one undifferentiated list | transcript | all |
| QA-DRIFT-04 | No drift present | Says so plainly | transcript | all |
| QA-DRIFT-05 | Cross-check the file list | Matches an independent `find /etc` for the same suffixes | `find` | all |

### Could-not-look must not read as clean

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-DRIFT-06 | `pacdiff` absent | Says the check did not run; summary not silent | move the binary | A |
| QA-DRIFT-07 | `pacdiff` fails | "Could not determine", never "no files to merge" | stub it to exit non-zero | A |
| QA-DRIFT-08 | `dpkg --audit` / `dnf check` fails | Reported as not assessed | stub it | D, E |

### Behaviour

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-DRIFT-09 | `-d --dry-run` | Read-only anyway; changes nothing and claims nothing | file set + summary | all |
| QA-DRIFT-10 | `-d` unprivileged | Either works, or says what it could not read — never a silent partial list | run as non-root | all |
| QA-DRIFT-11 | Summary content | Carries the counts, and the displaced ones are distinguishable | summary | all |
| QA-DRIFT-12 | Next-step advice | Names a real tool available on that distro | transcript | all |

---

## Results

**Sweep 1 — v0.58.2 → v0.59.0, 2026-08-03.** Each family had one "new default" and one
"displaced config" file seeded into `/etc`, then was asked.

| Target | `.…new` found | displaced found | distinguished | summary names the displaced |
|---|---|---|---|---|
| arch | yes | **no → now yes** | **no → now yes** | **no → now yes** |
| debian | yes | **never looked → now yes** | **no → now yes** | **no → now yes** |
| ubuntu | as debian | as debian | as debian | as debian |
| rocky9 / alma9 / fedora | yes | yes | yes | **no → now yes** |

| ID | Verdict | Evidence |
|---|---|---|
| QA-DRIFT-01 | PASS | all three families found the seeded "new default" file |
| QA-DRIFT-02 | **FAIL → fixed** | D-01 (debian never looked), D-02 (arch could not see it) |
| QA-DRIFT-03 | **FAIL → fixed** | D-01: one undifferentiated list on arch and debian |
| QA-DRIFT-04 | PASS | "no pending config-file merges" on a clean guest |
| QA-DRIFT-05 | **FAIL → fixed** | D-02: `pacdiff -o` returned **none** of three seeded files |
| QA-DRIFT-06 | **FAIL → fixed** | D-03: absent `pacdiff` was a silent note — now moot, see below |
| QA-DRIFT-07 | **FAIL → fixed** | D-03: failing `pacdiff` produced "no .pacnew files to merge" |
| QA-DRIFT-08 | not run | needs `dpkg`/`dnf` stubbed to fail |
| QA-DRIFT-09 | PASS | read-only action; nothing written on any target |
| QA-DRIFT-10 | not run | needs an unprivileged run against a root-only path |
| QA-DRIFT-11 | **FAIL → fixed** | D-04: no family's summary distinguished the two kinds |
| QA-DRIFT-12 | PASS | `pacdiff` / `rpmconf` suggested, with install hints when absent |

## Findings

### D-01 — the difference that matters was not reported. FIXED v0.59.0
These suffixes are not interchangeable. One means *the package shipped a new default and
your file is still in effect*; the other means *your file was moved aside and the package's
version is in effect now* — a setting somebody deliberately made that has silently stopped
applying.

Only the RHEL backend drew that line. Its docstring even names the offender: *"Lumping them
together (as the Debian backend does for its own three suffixes) would hide the case where a
machine quietly stopped honouring settings someone deliberately made."*

**Measured, and worse than that comment claims: Debian was not lumping them together, it was
never looking for them.** `.dpkg-old` and `.ucf-old` appeared in no pattern list, so a config
replaced by an upgrade was invisible to `-d`. Arch had all four kinds arriving from `pacdiff`
and labelled the lot *"pacnew files needing attention"*.

Both now classify, and the displaced ones **warn** rather than note.

### D-02 — `pacdiff` cannot see the files that matter most. FIXED v0.59.0
Arch delegated detection entirely to `pacdiff -o`. That is a *merge* tool: measured, it
lists only leftovers whose **base file still exists**, because with nothing to merge against
it has nothing to do. Three files seeded into `/etc` — `.pacnew`, `.pacorig`, `.pacsave` —
and `pacdiff -o` returned **none of them**.

A `.pacsave` is created when a package is *removed*, so its base file is gone **by
definition**. Every one of them was invisible on Arch, while Debian and RHEL found their
equivalents with a plain directory walk.

Arch now walks `/etc` like the other two. `pacdiff` is still suggested as the merge tool, but
detection no longer depends on `pacman-contrib` being installed — which also retires D-03
entirely rather than patching it.

### D-03 — an unrunnable check read as clean. FIXED v0.59.0 (by removal)
Absent `pacdiff` → a quiet note and an empty summary; failing `pacdiff` → empty stdout →
*"no .pacnew files to merge."* Both were fixed to report "not determined", and then made
unreachable by D-02's change: there is no longer an external tool that can be absent.

### D-04 — the summary hid the distinction it had just drawn. FIXED v0.59.0
Even RHEL, which classified correctly on screen, summarised as a flat `N config file(s) to
review`. All three now carry the count that matters:

```
✓ 4 config file(s) to review — 1 where YOUR version is no longer in effect
```

### Harness note
Seeding `/etc/qa-drift.pacnew` with no base file is invisible to `pacdiff` — which is how
D-02 was found, but it also meant an earlier verification run appeared to "work" while
actually reporting a pre-existing `.pacnew` elsewhere on the guest and not the seeded file at
all. The path in the output, not the count, is what settles that.
