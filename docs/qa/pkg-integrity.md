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
which is most intruders and every interrupted upgrade — and the README says so rather
than implying more.

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
