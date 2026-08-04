# QA — `sys-audit` (`-S`)

**Purpose as advertised:** *"firmware/boot/hardware security scan"*.

**Purpose as a user understands it:** *"is this machine's firmware and boot chain
sound?"*

Ten categories, its own subcommand, self-elevating, and the deepest thing fettle does.
It is also the only action whose whole job is to *report* — every other action changes
something, so its output is checked against a system change. Here the output **is** the
product.

Status: **swept and fixed.** Seven findings, including one that made every remote fettle
run — not just sys-audit — report success regardless of outcome.

---

## Cases and results

**Sweep 1 — v0.70.0 → v0.71.0, 2026-08-04.** Run on `manjaro-local` (`--user`, 10
categories, 4424-binary workstation) and on **all six lab guests** via
`fettle sys-audit remote --sudo <host> --all`.

| ID | Test | Verdict |
|---|---|---|
| QA-SA-01 | **The scan produces a verdict** | **FAIL → fixed** (S-01) |
| QA-SA-02 | **Exit status reflects what was found** | **FAIL → fixed** (S-01) |
| QA-SA-03 | **Remote exit status reaches the caller** | **FAIL → fixed** (S-02 — affects *all* remote runs) |
| QA-SA-04 | fwupd status is correct | **FAIL → fixed** (S-03) |
| QA-SA-05 | Unreadable storage devices are reported | **FAIL → fixed** (S-04) |
| QA-SA-06 | Skipped subsections say they were skipped | **FAIL → fixed** (S-05) |
| QA-SA-07 | Integrity: "differs" vs "could not read" | **FAIL → fixed** (S-06) |
| QA-SA-08 | A definite "no Secure Boot" is not a failure | **FAIL → fixed** (S-07) |
| QA-SA-09 | Missing optional tools do not fail the run | **FAIL → fixed** (S-07) |
| QA-SA-10 | Advice given is applicable | **FAIL → fixed** (S-05) |
| QA-SA-11 | Report written and picked up by `fettle report` | PASS |
| QA-SA-12 | `--list` needs no elevation | PASS |
| QA-SA-13 | `--user` runs unprivileged and says results are partial | PASS *(and now says how partial — S-04, S-05)* |
| QA-SA-14 | Runs on all six guests | PASS — Arch, Debian 13, Ubuntu 26.04, Rocky 9, Alma 9, Fedora |

**Measured before → after, `manjaro-local`:**

| | before | after |
|---|---|---|
| summary | `nothing to report` | `! 22 warning(s) … / ✗ 1 finding(s) …` |
| exit | 0 | **1** |
| package integrity | `Issues found` (82 lines) | **17 differ** + **65 could not be read** |
| firmware | `✗ UNKNOWN — fwupdmgr failed (exit 2)` | `✓ System is up to date` |
| storage | 8 device names, no data, no warning | 12 devices reported unreadable |

**Measured on the guests, after:** Debian **exits 0** (7 warnings, nothing needing
attention); Rocky 9 **exits 1** (10 packaged files differ). Before the sweep both exited
0 with `nothing to report`.

## Findings

### S-01 — the security scan had no verdict, and always exited 0. FIXED v0.71.0
Every check reported through `scan.status(...)`, which prints a line and records it.
**Nothing anywhere in `fettle/secure/` ever called `summary_add` / `summary_warn` /
`summary_fail`** — so `run()` ended with `print_summary()` printing:

```
▸ Summary
  nothing to report
```

Measured on a workstation with **Secure Boot disabled, 17 files failing integrity
verification, and a dead-looking firmware check** — 8 warnings and 2 errors in the body,
and *nothing to report* underneath. `main()` then returned a hardcoded `0`.

`error` now sets the exit status and `warn` does not: a missing TPM or a disabled Secure
Boot is a fact about the machine that its operator may have chosen, and making every run
exit non-zero would teach people to ignore the code.

### S-02 — every remote fettle run reported success, whatever happened. FIXED v0.71.0
**Found only because S-01 gave the remote something non-zero to return.** A scan that
correctly exited 1 on the guest arrived back as 0.

`build_zipapp` used `zipapp.create_archive(..., main="fettle.cli:main")`, and zipapp's
generated entry point is:

```python
import fettle.cli
fettle.cli.main()
```

It **calls** the entry point and discards what it returns, so the interpreter always
exits 0. This is not a sys-audit bug — it is every `fettle remote` run ever made: a
failed upgrade, an unsupported distro, an audit full of findings, all reported to the
caller as success. The entry point is now written by hand with `sys.exit(...)`.
Verified end-to-end on a guest: `REMOTE_RC=0` → `REMOTE_RC=1`.

The lesson is about *where* bugs hide: this one sat behind another bug. Nothing could
return non-zero, so nothing revealed that non-zero was being swallowed.

### S-03 — fwupd: the v0.61.0 fix never reached this copy. FIXED v0.71.0
The `-f` maintenance action was fixed in v0.61.0 to decide from fwupd's exit code rather
than its prose. sys-audit's `fwupd` category has **its own copy**, which still matched
the English string `"no updates"` — and fwupd actually prints *"Devices with no available
firmware updates:"* with exit 2. So a fully up-to-date machine was reported by the
security scan as:

```
✗ Firmware Updates: UNKNOWN — fwupdmgr failed (exit 2)
```

Its comment even explains the exit-code trap and then works around it with the string
match the trap defeats. Third instance this QA pass of *a fix applied to one action is
not a fix applied to the pattern* — and the first where both copies live in the same
repository under different subsystems.

### S-04 — a disk that could not be read printed nothing at all. FIXED v0.71.0
`smartctl` merges its error onto stdout, so `Permission denied` is a *non-empty string*:
the `if not info` guard passed, no field matched, and the device printed **nothing** —
identical to a device with nothing to report. Unprivileged, that is every disk on the
machine: 12 devices on the QA host, silently. Now each says it could not be queried and
why.

### S-05 — "try as root", told to root. FIXED v0.71.0
The certificate check reported `Skipped: Could not read UEFI variables (try as root)` on
five guests **running under `--sudo`**, with `/sys/firmware/efi/efivars` readable and
populated. The one hint it gave was the one thing already done, and the real reason —
this firmware ships no KEK/db store — went unsaid. The TPM DMI subsection had the same
shape in its purest form: unprivileged it printed *nothing at all* beneath its own
header, which reads as "checked, found nothing".

### S-06 — 65 admissions of blindness, filed as 82 problems. FIXED v0.71.0
Unprivileged, `paccheck` emits `warning: <pkg>: '<path>' read error (Permission denied)`
for every file it cannot open. All of it went under one `Package Integrity: Issues found`
error, so **65 of the 82 "issues" were the scan admitting it could not look.** The
governing invariant inverted: "could not look" rendered as "found a problem", which cries
wolf exactly as badly as the reverse. Now 17 differ (error) and 65 unreadable (warning).

Debian had its own version: `debsums` logs `no md5sums for <pkg>` to **stderr**, which
`run_text` merges in, so packages that simply ship no checksums counted as integrity
issues.

The RHEL implementation, written later, already did all of this correctly — it proves the
database is readable before trusting emptiness, and separates expected differences from
packaged files. **The pattern was learned in one backend and never carried back to the
other two.** Both now follow it, including its counts-not-silent-slices rule: the old
code cut output at 50 lines with nothing saying so.

### S-07 — the exit code had to be worth trusting. FIXED v0.71.0
Two things would have made the new exit status noise:

- **`mokutil --sb-state` exits 255 saying "This system doesn't support Secure Boot"** —
  a *definite negative*, reported as `UNKNOWN — mokutil failed`. Narrowly matched, because
  *"EFI variables are not supported"* is a different message that genuinely cannot answer,
  and an existing test guards it.
- **A missing optional tool was an `error`** — `smartctl`, `dmidecode`, `fwupd` — so every
  minimal server would exit 1 for lacking smartmontools. An absent diagnostic is a
  coverage gap (`warn`); a tool that ran and failed is an error. The package manager
  itself stays an error: `rpm` missing on an RPM system is genuinely broken.

## Open / not fixed here

- **The summary prints warnings before failures**, so `!` lines appear above `✗` ones.
  Most-severe-first would read better, but `print_summary` is shared by every action and
  changing the order belongs with the cross-cutting rows, not inside one feature's sweep.
- **`fettle sys-audit remote` has no `--ssh-arg`**, unlike `fettle remote`. This sweep
  needed one and worked around it with a PATH shim.
- **`chipsec` is absent everywhere**, so the `firmware` category has never run for real on
  any target. Stated, not papered over.

## Harness note
The lab guests' host keys were not trusted on the controller, which `scp -q` reports only
as `Connection closed` — a symptom `lab.py` documents in its own source. Worked around
with `ssh`/`scp` shims in the scratchpad pointing at a scratch `known_hosts`, leaving the
user's own file untouched.
