# QA — `pkg-integrity` (`-V`)

**Purpose as advertised:** *"do installed files still match what the package shipped?"*

**Purpose as a user understands it:** *"has anything on this box been changed since I
installed it?"*

New in **v0.72.0**, split out of `sys-audit`'s `packages` category. It asked a *package*
question inside the *firmware and boot chain* scanner, and it made every `-S` run pay for
a 35-second hashing pass. Read-only, **not** in the default set, and wants root.

Status: **shipped with the sweep's findings already applied** — the defects were found
during the [sys-audit](sys-audit.md) sweep (S-06) and the split carried the fixes.

---

## What it compares against

Every backend reads a manifest the package manager wrote **at install time**:

| | source of truth | comparison | fallback |
|---|---|---|---|
| Arch | pacman MTREE, `/var/lib/pacman/local/<pkg>/mtree` | `paccheck --sha256sum` | `pacman -Qkk` |
| Debian | `/var/lib/dpkg/info/<pkg>.md5sums` | `debsums` (MD5) | `dpkg --verify` |
| RHEL | file digests in the rpmdb | `rpm -Va` | *(none — rpm is always there)* |

**This is a tripwire, not proof of authenticity.** The manifest came from the same
package, and root can rewrite both. It catches what does not think to cover its tracks —
which is most intruders and every interrupted upgrade — and the docs say so rather
than implying more (the wiki's
[Package supply-chain](https://github.com/pasadoorian/fettle/wiki/Package-supply-chain)
page since v1.0.1; the README before that).

## Cases and results

**Sweep 1 — v0.71.0 → v0.72.0, 2026-08-04**, on `manjaro-local` and (through the
sys-audit sweep) Debian 13, Rocky 9, AlmaLinux 9.

| ID | Test | Verdict |
|---|---|---|
| QA-PI-01 | Differing files are reported | PASS |
| QA-PI-02 | **Unreadable files are not counted as findings** | fixed in v0.71.0 (S-06) |
| QA-PI-03 | **Machine-regenerated files are separated** | **FAIL → fixed** (I-01) |
| QA-PI-04 | Debian: packages with no checksums are a gap, not a finding | fixed in v0.71.0 |
| QA-PI-05 | RHEL: config/ghost/doc markers honoured | PASS *(prior work)* |
| QA-PI-06 | No silent truncation | fixed in v0.71.0 — counts come from the whole output |
| QA-PI-07 | Owns its summary and exit status | PASS — `✗` on differences, `!` on gaps |
| QA-PI-08 | Writes its own report | PASS — `~/.fettle/reports/<host>/pkg-integrity-*` |
| QA-PI-09 | Elevates (it must, to read what it hashes) | **FAIL → fixed** (I-02) |
| QA-PI-10 | Not in the default set | PASS — 35.6s measured; opt-in |
| QA-PI-11 | Gone from `sys-audit` | PASS — not in `--list`, not in `-S --all` |

## Findings

### I-01 — the signal was 3 files in 82 lines. FIXED v0.72.0
Measured on the workstation, `paccheck --sha256sum` reports **17 differing files**. Of
those, **14 are rewritten after install by a tool, never by a person**: depmod's
`modules.dep` / `modules.dep.bin` / `modules.alias` / `modules.alias.bin` for each of
three installed kernels (12), VLC's plugin cache, and `pacman-mirrors`' `mirrors.json`.
They differ on every machine that has those packages, so they carry no information — and
a check that is red everywhere is a check nobody reads.

They are now counted separately, listed under `-v`. What is left is worth the name:

```
✗ Package Integrity: 3 file(s) differ from their package
    grub: '/etc/grub.d/30_os-prober'
    networkmanager: '/usr/lib/NetworkManager/conf.d/20-connectivity.conf'
    vscodium-bin: '/opt/vscodium-bin/resources/app/product.json'
  Expected differences: 14 file(s) regenerated after install
! Not verified: 65 file(s) could not be read (run as root to check them)
```

The pattern list is deliberately short, and **every entry names the tool that
regenerates the file** rather than merely a path that happened to be noisy. The three
survivors above were *not* added to it: they may be benign, but nothing establishes that,
and inventing a justification to quiet an unexplained difference is exactly the failure
this check exists to prevent.

RHEL already had the equivalent, using rpm's own `c`/`g`/`d` file-type markers; it now
also consults the regenerated-file list, so all three backends triage the same way.

### Timing, measured (Manjaro workstation, 233 packages with differences)

| mode | time | output |
|---|---|---|
| `paccheck --quiet` (existence only) | 1.8s | 48 lines |
| `--file-properties` (MTREE properties) | 4.2s | 414 lines |
| **`--sha256sum` (content)** | **35.6s** | 82 lines |

Content hashing is the only mode that answers the question, and 35s is cheap enough that
a "quick mode" would be a knob nobody should reach for. `--file-properties` is the reason
mtime-based verification is not used: 414 lines of noise.

### I-02 — it was shipped in the no-root set, so it never elevated. FIXED v0.72.1
Caught by Paul on first use: *"how do we run pkg-integrity as root?"* — the answer was
`sudo fettle -V`, because `fettle -V` never asked.

`NO_ROOT_ACTIONS` was derived as `READ_ONLY_ACTIONS | {"container_update"}`, encoding
**read-only ⟹ needs no root**. A test asserted it. But the two questions come apart in
*both* directions, and `pkg-integrity` is the second direction: it changes nothing and
still needs root, because it must hash every installed file and cannot read ~65 of them
unprivileged. Adding it to the read-only set — which is true — silently put it in the
no-root set, which is not.

The set is now built from two explicitly-listed exception sets rather than derived, and
the test asserts that every difference between the two is one of them. The changelog claim
that it "elevates, because unprivileged it cannot read a large share of the files it must
hash" described the intent and not the code; it does now.

## Open

- **Debian's `debsums` is MD5 only.** That is dpkg's manifest format, not a fettle
  choice, but it is worth stating: on Debian this detects accident and casual tampering,
  not a prepared collision.
- **No user-extensible expected list.** Decided against for now — a config knob to
  silence integrity findings is a knob that gets used to silence real ones.
- **A verifier's exit status was never read.** Closed in v1.11.0 — see Sweep 3.

---

## Sweep 2 — v0.88.0 → v0.89.0, 2026-08-05, from the full lab matrix

The matrix reported `pkg-integrity` as the only action with a finding on more than one
target — three of six, all of them freshly built cloud images that nobody had touched.

**Every one was a false alarm.** Across all 13 findings there was not a single content
change: mtimes on EFI/shim binaries and grub fonts, and mode bits on `/`, `/boot` and
`/run/cloud-init`. `rpm -Va` flags a content mismatch with `5`; none of these had one.

| ID | Test | Verdict |
|---|---|---|
| QA-PI-11 *(new)* | mtime-only difference is not a finding | **FAIL → fixed** (I-05) |
| QA-PI-12 *(new)* | permission drift is visible but not an integrity error | **FAIL → fixed** (I-05) |
| QA-PI-13 *(new)* | a real digest mismatch still alarms | PASS — the guard on the fix |
| QA-PI-14 *(new)* | `/run` is not treated as packaged content | **FAIL → fixed** |

### I-05 — a tripwire that is red on a clean machine. FIXED v0.89.0
The count was of *rows*, not of *events*. `rpm -Va` compares all nine attributes, while
`debsums` and `paccheck --sha256sum` compare content alone — so the RPM path, and only the
RPM path, was summing "the mtime moved" together with "the bytes changed".

Now classified by what differs: content (digest/size/symlink/missing) is the finding,
permission drift (mode/owner/group/caps) warns, and timestamp-only is expected. `/run`
joins the regenerated list, being a tmpfs rebuilt every boot.

**Measured after the fix:** AlmaLinux 9 is completely clean; Rocky 9 and Fedora 44 report
zero content findings with 2 and 1 permission drifts respectively, at exit 0.

### Why this one mattered more than its size
Of everything found in this pass, this is the finding most likely to have caused real harm.
The others made fettle look broken; this one made a *clean* machine look compromised, on
the single check whose output is meant to be believed. A user who sees a red integrity
error on a box they built an hour ago learns, correctly, that the check is noise — and
that lesson is still in force on the day the digest mismatch is real.

### A false alarm of my own, worth recording
While verifying, I ran `-V` against the Fedora guest without `--distro rhel` and got
`✗ no fettle backend for this distro`. That is **not** a defect: Fedora is deliberately
not a claimed distro (its advisories are Bodhi `FEDORA-*`, not RHSA), the lab names the
backend explicitly, and fettle's refusal listed every distro it knows and how to override.
Correct behaviour, clearly explained — the mistake was in my command.

---

## Sweep 3 — v1.11.0, 2026-08-17, from the 2026-08-12 code review (H-08)

The two previous sweeps asked whether the *findings* were trustworthy. This one asks the
prior question: **was the verifier running at all?** The answer, on every backend, was
that fettle could not tell — and defaulted to reassurance.

### The exit codes, measured

None of them mean what you would guess, so every one was measured in a container rather
than read off a man page:

| command | clean | found a discrepancy | could not run |
|---|---|---|---|
| `paccheck` | 0 | **1** | **1** (`error: failed to initialize alpm.`) |
| `pacman -Qkk` | 0 | 1 (`warning:` rows) | 1 (`error:` rows) |
| `debsums` | 0 *(also when a package ships no md5sums)* | **2** | 255 |
| `dpkg --verify` | 0 | **0** | **0, with no output at all** |

Three consequences:

- **`paccheck` cannot be classified by status** — 1 means both "found" and "failed". What
  separates them is that a per-file verdict quotes its path and a diagnostic does not.
- **`debsums` can** — anything outside `{0, 2}` is the tool failing.
- **`dpkg --verify` cannot be classified at all.** It is the `rpm -Va` trap again: silence
  has to be earned, so the dpkg database is now proven to list packages first. `dpkg-query`
  cannot be probed by status either — `--admindir=/nonexistent` also exits 0 — so its
  *output* is what gets checked.

### Cases

| ID | Test | Expected | Applies |
|---|---|---|---|
| QA-PI-15 | Verifier exits non-zero having printed **nothing** | Reported as blindness; never "no unexplained differences" | A, D |
| QA-PI-16 | Verifier fails with a diagnostic on stderr | Blindness — **not** counted as an altered file | A, D |
| QA-PI-17 | Verifier exits non-zero **with real findings** | Still findings; the status must not erase them | A, D |
| QA-PI-18 | `dpkg --verify` with an empty package database | Blindness, not "No issues detected" | D |
| QA-PI-19 | `dpkg --verify` conffile rows (`??5?????? c /etc/…`) | Counted; the file-type marker is optional | D |
| QA-PI-20 | A run where **nothing** could be verified | One answer, not two — no "installed files match their packages" | all |
| QA-PI-21 | `pacman` absent | Blindness, not a finding | A |

### Verdicts — all live in containers, before and after

| ID | Verdict | Before the fix |
|---|---|---|
| QA-PI-15 | **FAIL → fixed** | Arch, paccheck exit 1 with no output: `✓ Package Integrity: no unexplained differences` + `✓ installed files match their packages`, **exit 0** |
| QA-PI-16 | **FAIL → fixed** | Arch: `✗ 1 file(s) differ from their package` — the finding was `error: failed to initialize alpm.` Debian: the same, from `Unknown option`, at **exit 0** |
| QA-PI-17 | PASS | guard on the fix — proved to pass before and after |
| QA-PI-18 | **FAIL → fixed** | Debian, `/var/lib/dpkg/status` emptied: `✓ Package Files: No issues detected`, **exit 0** |
| QA-PI-19 | PASS | guard on the fix — the marker is real, measured on dpkg 1.21.23 |
| QA-PI-20 | **FAIL → fixed** | AlmaLinux, `rpm` removed: `✓ installed files match their packages` printed **directly above** `✗ did NOT verify: rpm: Not installed` |
| QA-PI-21 | **FAIL → fixed** | recorded as an `error` with no `blind` flag, so it read as a finding |

### Still open after this sweep

- **The `dpkg --verify` fallback does not separate expected drift.** RHEL treats a
  `c`-marked row as an edited config file rather than a tripwire hit; the Debian fallback
  still counts every row as a discrepancy line. Out of scope for H-08, which was about
  false cleans, and the fallback only runs when `debsums` is absent — but it means an
  edited `/etc` file inflates that count.
