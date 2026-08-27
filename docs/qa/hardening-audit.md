# QA — `hardening-audit` (`-H`)

**Purpose as advertised:** *"flag pkgs whose binaries miss the distro's build hardening"*.

**Purpose as a user understands it:** *"is anything on this box built without the
protections my distro says it builds with?"*

Read-only, **elevating since v1.17.0** (`--user` opts out), and **opt-in** — not in the default set, because it produces a long
list by design and the user prunes it via config.

Status: **swept and fixed.** Three findings fixed in v0.68.0, plus a documented gap that
turned out not to exist.

---

## Prior hardening this sweep had to not break

This is the action the VM lab caught first, back when it was built: it reported *"no
deviations"* after analysing **zero** binaries on Fedora, Debian and Ubuntu, because
checksec 2.x and 3.x share no command line and the audit was written against 3.x on Manjaro.
Fixed in v0.48.0/0.48.1 with 2.x support and the analysed-zero guard. Both verified intact
here — the guard still fires, and checksec 2.5.0 on EL9 and 3.2.0 on Manjaro both produce
findings.

## Cases and results

**Sweep 1 — v0.67.0 → v0.68.0, 2026-08-04**, on `manjaro-local` (checksec 3.2.0, 4424
binaries) and Rocky 9 (checksec 2.5.0 from EPEL).

| ID | Test | Verdict |
|---|---|---|
| QA-HA-01 | Deviations found and banded | PASS — 816 across 233 packages on manjaro-local |
| QA-HA-02 | checksec 2.x understood | PASS — 147 deviations on EL9 with 2.5.0, but checksec was installed **by hand** for the run and did not survive the reset; see "a fix that was not a fix" |
| QA-HA-03 | checksec 3.x understood | PASS |
| QA-HA-04 | Analysed-zero guard | PASS *(by construction, v0.48.1)* |
| QA-HA-05 | **Summary mark matches what was found** | **FAIL → fixed** (H-01) |
| QA-HA-06 | **checksec absent is not a silent skip** | **FAIL → fixed** (H-02) |
| QA-HA-07 | **No binaries found is not a clean result** | **FAIL → fixed** (H-03) |
| QA-HA-08 | Install advice is correct for the distro | **FAIL → fixed** (H-04) |
| QA-HA-09 | Exclude lists honoured and their effect stated | PASS — "752 deviation(s) hidden by your [hardening] exclude lists" |
| QA-HA-10 | Report written, matrix saved | PASS |
| QA-HA-11 | Runs unprivileged | **changed v1.17.0** — `-H` now elevates for the AppArmor axis; `--user` keeps the old behaviour |
| QA-HA-15 *(new)* | Elevating does not change what the other five axes report | PASS — same host, root and `--user` both give 3 High / 32 Medium / 13 Low (debian 13) |
| QA-HA-16 *(new)* | Elevating does not make `-H` slower | PASS — 28 s root vs 27 s `--user` on debian 13; the checksec-as-root sleep fixed in QA-HA-13 still holds |
| QA-HA-17 *(new)* | `--user` refuses to disarm a mutating action | PASS — `-u --user` exits 1 and says why |

## Findings

### H-01 — a green tick over a Critical band. FIXED v0.68.0
Measured on a real workstation:

```
✓ 1 Critical, 7 High, 130 Medium, 95 Low  (816 deviations across 233 packages)
```

Deviations are open items. Now `!`.

**Deliberately a warning and not a failure**, unlike `pkg-audit`'s CRITICAL. There, critical
means a known-malicious package is installed — rare and actionable. Here "Critical" is the
worst band of a scoring scheme and every real desktop has some, so failing the run would
make `-H` exit non-zero forever and teach people to ignore it.

### H-02 / H-03 — "not audited" looked like "nothing wrong". FIXED v0.68.0
`checksec` absent, or no ELF binaries found, were both a `note` with an **empty summary** —
which is precisely the confusion the analysed-zero guard exists to prevent, left unhandled in
the two easier cases. Both now warn and reach the summary.

### H-04 — the install advice was wrong on the RHEL family. FIXED v0.68.0
It offered `pacman -S checksec / apt install checksec / dnf install checksec` on every
distro. On EL, `dnf install checksec` fails: the package is in **EPEL**, not the base
repositories. The hint is now chosen from the backend, and the RHEL one says
`dnf install epel-release && dnf install checksec`.

### A documented gap that did not exist
The lab notes and this plan both recorded *"`checksec` is not packaged for EL at all, EPEL
included — Fedora is the only dnf target that can run it"*, and two lab targets were marked
as permanently blocked on the strength of it.

**It is false for EL9.** Measured here: `dnf install epel-release && dnf install checksec`
installs checksec 2.5.0 on Rocky 9, and `fettle -H` then reports **147 deviations across 35
packages**, including a Critical on `grub2-tools-minimal`.

The original observation was made on the **EL10** box, where checksec genuinely is absent
from every repository, and was generalised to "EL" without retesting on EL9 — which is 53%
of the EL fleet.

The lesson is the one this plan keeps relearning in a new costume: **a measurement is true of
the thing measured.** EL10 is not EL.

### …and a fix that was not a fix
The paragraph above used to end *"`rocky9` and `alma9` now install `epel-release` +
`checksec`, converting two permanent SKIPs into real coverage."* **That was false when it
was written, and it stayed false for a release.** The two targets still SKIP.

Two independent reasons, both found on 2026-08-05 when the skips were finally checked:

1. The guests are **snapshot-pinned**. Editing a target's `packages` list changes what a
   *future* `build` installs; it does nothing to a snapshot that already exists. This is
   the exact mirror of the trap the lab notes already record in the other direction —
   installing something by hand after the snapshot means the next `reset` loses it. Which
   is also how the sweep above got its Rocky 9 evidence: checksec was installed by hand
   for that run, so **QA-HA-02's measurement is real, but it did not persist.**
2. Even a rebuild would have failed. Measured on the guest:
   `dnf -y install epel-release checksec` → **`No match for argument: checksec`**.
   checksec is unresolvable until EPEL is installed *and enabled*, and cloud-init runs
   `packages:` as a single transaction whose failure takes every other package with it.

Fixed in the spec by splitting the stages — `epel-release` in `packages`, `checksec` in
`runcmd` — verified two-stage on the live guest (checksec 2.5.0). **The SKIPs were closed
on 2026-08-05**, once Paul asked for the two VMs to be rebuilt — that re-baselines their
pinned snapshots, so it was his call and not a thing to do quietly mid-sweep. See Sweep 2.

The lesson, which cost a release: **a change is not a fix until it has been run.** Claiming
coverage is exactly as harmful as the blind spots this whole plan exists to find — it is a
`✓` over a check that never happened.


---

## Sweep 2 — v0.87.0 → v0.88.0, 2026-08-05, on Rocky 9 and AlmaLinux 9

The two EL SKIPs are closed. Rebuilding the guests with the staged EPEL spec gave them
`checksec 2.5.0`, and the audit then ran — except the first elevated attempt **took over 30
minutes and was killed by the harness timeout**, which is why this row had never produced a
result through `fettle remote`.

**checksec 2.x sleeps 2 seconds per invocation when run as root.** Its own line 6 re-execs
with an empty environment (`exec -c`), wiping `PATH`, and it then repairs
`/sbin`:`/usr/sbin` **only for non-root**. As root it cannot find `sysctl`, warns "Not all
necessary commands found", and sleeps. Measured: **61 ms as a user, 2063 ms as root** —
and `fettle remote` elevates everything except `--dry-run`.

| ID | Verdict | Evidence |
|---|---|---|
| QA-HA-02 | **PASS — now durable** | 885 binaries on Rocky 9 from a rebuilt snapshot, not a by-hand install |
| QA-HA-13 *(new)* | **FAIL → fixed** | H-05: 30+ min elevated (timed out) → 81 s |
| QA-HA-14 *(new)* | PASS | elevated reports 149 deviations vs 147 unprivileged — the root retry recovers 2 |

**Results.** Rocky 9: 885 binaries, **149 deviations across 35 packages** — 1 Critical
(`grub2-tools-minimal`: canary and fortify_source missing on 5 binaries), 1 High
(`kernel-tools`), 24 Medium, 9 Low, in 81 s. AlmaLinux 9: 877 binaries, **147 across 33
packages**, same Critical and High, in 76 s. Nearly identical, as two rebuilds of the same
EL9 base should be.

The unprivileged pass sees 872 binaries / 145 deviations on AlmaLinux and 885 / 147 on
Rocky — the gap in both cases is the root-only files the retry recovers.

### H-05 — the audit was asleep, not working. FIXED v0.88.0
Fixed by running checksec unprivileged when fettle is root. Nothing else works: the
environment we would repair is discarded by checksec's own re-exec, and `--listfile` does
not help because checksec implements it by invoking itself per file anyway — an earlier
batching attempt was measured to change nothing and was withdrawn rather than shipped with
a claim it had not earned.

Coverage does not shrink, which mattered: **12 of 2318 bin-dir entries on Rocky 9 are
root-only readable**, so dropping privileges wholesale would have quietly returned a
smaller answer that looked like a cleaner one. Those are retried as root, detected by their
*absence* — checksec answers an unreadable file with coloured text on stdout and exit 0,
not an error entry.

### H-06 — `fettle remote` elevates everything. OPEN
`sudo=not dry_run`, ignoring the read-only/needs-root knowledge the CLI already keeps in
`_MUTATES_BUT_NO_ROOT` and `_READ_ONLY_BUT_NEEDS_ROOT`. That blanket elevation is what
exposed H-05 — a read-only audit had no need of root in the first place. Larger than one QA
fix should carry; tracked for the `remote` row.

### The lesson this row is the third example of
A permanent SKIP is a claim, and this one was wrong twice: first that checksec could not be
installed on EL at all, then that installing it had closed the gap. Both times the SKIP was
believed rather than retested. **A skip needs re-earning, not inheriting** — the reason it
was taken can expire, and nothing announces when it has.
