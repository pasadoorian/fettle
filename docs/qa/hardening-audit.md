# QA — `hardening-audit` (`-H`)

**Purpose as advertised:** *"flag pkgs whose binaries miss the distro's build hardening"*.

**Purpose as a user understands it:** *"is anything on this box built without the
protections my distro says it builds with?"*

Read-only, rootless, and **opt-in** — not in the default set, because it produces a long
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
| QA-HA-11 | Runs unprivileged | PASS |

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
`runcmd` — verified two-stage on the live guest (checksec 2.5.0). **The SKIPs stand until
those two VMs are rebuilt**, which re-baselines their pinned snapshots and is therefore the
operator's call, not a thing to do quietly in the middle of a QA sweep.

The lesson, which cost a release: **a change is not a fix until it has been run.** Claiming
coverage is exactly as harmful as the blind spots this whole plan exists to find — it is a
`✓` over a check that never happened.
