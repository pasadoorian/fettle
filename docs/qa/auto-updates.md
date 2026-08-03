# QA — `auto-updates` (`-x`)

**Purpose as advertised:** *"report whether automatic/unattended updates are enabled"*.

**Purpose as a user understands it:** *"is this machine keeping itself patched, or am I
responsible for it?"*

Read-only and informational — it changes nothing and deliberately does not nag. That makes
truthfulness the entire value: the only thing it produces is an answer, and a wrong answer
here means somebody stops checking a machine that stopped patching itself.

Status: **swept and fixed.** The headline finding measured and fixed in v0.60.0; three cases remain open for a later pass.

---

## What it actually runs

| | arch / manjaro | debian / ubuntu | rocky9 / alma9 / fedora |
|---|---|---|---|
| source | `systemctl is-enabled` against a **curated list of 8 known timer names** | `apt-config dump` + is `unattended-upgrades` installed + `apt-daily-upgrade.timer` | `systemctl is-enabled` on **all four** `dnf-automatic` timers + `automatic.conf` |
| subtlety handled | — | auto-*install* needs all three conditions | **the timer overrides the config** — `-install` applies updates even with `apply_updates=no`; `-download`/`-notifyonly` never apply them however the file reads |
| also reports | — | Ubuntu Pro / ESM coverage | which units were found but not enabled |

The RHEL implementation is again the most careful, and its docstring explains why: *"A check
that reads only the config, or only the plain timer, gets both cases backwards."*

### Predictions from the source

1. **All three report configuration, not effect.** Every backend stops at *is the timer
   enabled*. A timer that is enabled but whose service fails on every run — a broken mirror,
   a full disk, an expired key — reports `auto-updates: ON` while the machine has not
   actually been patched for months. That is the same class as every other finding in this
   plan: the state that was checked is not the state the user is asking about.
   → **QA-AUTO-05**, the case this sweep exists for.
2. **Arch's answer is name-matching, and "OFF" is stated as fact.** The list is 8 known
   community timers; the docstring concedes a custom-named timer will not be detected. But
   the summary says `auto-updates: OFF` flatly, where the honest claim is *none that I
   recognise*. → **QA-AUTO-06**
3. **A missing tool produces an empty summary.** `systemctl`/`apt-config` absent → a `note`
   and nothing in the summary, so a run that could not determine the posture is
   indistinguishable in the digest from one that found nothing enabled.
   → **QA-AUTO-07**
4. **Nobody checks for a *masked* unit.** `is-enabled` returns `masked` for a unit that
   cannot start at all; Arch's equality test against `"enabled"` treats that as off (right
   answer, by luck), while RHEL's `_UNIT_ON` set decides explicitly. → **QA-AUTO-08**

---

## Cases

**A** arch · **M** manjaro-local · **D** debian · **U** ubuntu · **E** rocky9/alma9 ·
**F** fedora.

### Does it get the answer right

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-AUTO-01 | No automatic updates configured | Reports OFF, and says what would enable it | transcript | all |
| QA-AUTO-02 | Automatic updates properly enabled | Reports ON, naming the mechanism | enable it, then ask | all but M |
| QA-AUTO-03 | Enabled to **download only** (not install) | Distinguished from ON — nothing is being applied | `dnf-automatic-download.timer` / `Unattended-Upgrade=0` with lists on | E, D |
| QA-AUTO-04 | Timer enabled but config says don't apply | RHEL: the timer wins where it passes `--installupdates`; reported accordingly | seeded conf + timer | E |

### Configured is not the same as working

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-AUTO-05 | Timer enabled, **its service fails every run** | Must not report a bare `ON`. The machine is not being patched. | break the updater, trigger the timer, ask | all but M |
| QA-AUTO-09 | Timer enabled but has **never fired** | Distinguished from one that runs and succeeds | freshly enabled timer | all but M |

### Could-not-look must not read as an answer

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-AUTO-06 | Arch with a **custom-named** update timer | Not claimed as OFF — it is *unrecognised* | enable a timer under another name | A |
| QA-AUTO-07 | `systemctl` / `apt-config` absent | Says the posture was not determined; summary not silent | hide the binary | all |
| QA-AUTO-08 | Unit **masked** | Treated as off, and said so explicitly | `systemctl mask` | A, E |

### Behaviour

| ID | Test | Expected | Verified by | Applies |
|---|---|---|---|---|
| QA-AUTO-10 | `-x` unprivileged | Works, or says what it could not read — it is documented as rootless | run as non-root | all |
| QA-AUTO-11 | `-x --dry-run` | Identical to a real run; it changes nothing either way | diff the two | all |
| QA-AUTO-12 | Summary wording | An unfamiliar reader can tell ON from OFF from "could not tell" | summary text | all |

---

## Results

**Sweep 1 — v0.59.1 → v0.60.0, 2026-08-03.**

| ID | Verdict | Evidence |
|---|---|---|
| QA-AUTO-01 | PASS | rocky9 before setup: OFF, with the enabling steps named |
| QA-AUTO-02 | PASS | `dnf-automatic.timer` + `apply_updates=yes` → `ON (dnf-automatic)` |
| QA-AUTO-03 | not run | needs a download-only timer configured |
| QA-AUTO-04 | PASS *(by construction)* | RHEL's timer-overrides-config logic, already unit-tested |
| QA-AUTO-05 | **FAIL → fixed** | A-01 — the case this sweep existed for |
| QA-AUTO-06 | **open** | A-02 — Arch's name-matching states OFF as fact |
| QA-AUTO-07 | **open** | A-03 — absent `systemctl`/`apt-config` leaves an empty summary |
| QA-AUTO-08 | not run | needs a masked unit |
| QA-AUTO-09 | PASS | "enabled but has not run yet" is distinguished from working |
| QA-AUTO-10 | PASS | read-only and rootless as documented |
| QA-AUTO-11 | PASS | `--dry-run` identical — the action changes nothing either way |
| QA-AUTO-12 | PASS *(after fix)* | ON / OFF / "enabled but failing" are now three different answers |

## Findings

### A-01 — "enabled" was reported as "working". FIXED v0.60.0
Every backend stopped at *is the timer enabled*, which answers a different question from the
one the user is asking. Measured on Rocky 9 — `dnf-automatic.timer` enabled,
`apply_updates=yes`, and its service failing on every run against a dead repository:

```
  systemctl: timer enabled, service Result=exit-code, exit 1
  fettle:    ✓ auto-updates: ON (dnf-automatic)
```

A host that has not been patched for months was indistinguishable from one patching itself
nightly — and this is the action whose *entire output* is that one answer, read by someone
deciding whether they still need to check the machine themselves.

New shared `PackageBackend.timer_health()`, used by all three backends. The timer names its
own service in `Unit=`, so there is no basename guessing; `Result` is empty until the service
has ever run, which is why **"never run" is a separate answer rather than a failure** — a
freshly enabled timer is not broken, and reporting it as such would cry wolf on every machine
that just turned automatic updates on. Now:

```
  ! but automatic updates are NOT working: dnf-automatic.service last finished with
    exit-code (exit 1). This host is not being patched — check the unit's logs
    (journalctl -u dnf-automatic).
  ▸ Summary
    ✓ auto-updates: ON (dnf-automatic)
    ! auto-updates: enabled but the last run FAILED — this host is NOT being patched
```

Verified in both directions on the same guest: failing warns, and once the service succeeds
the warning disappears.

### A-02 — Arch states OFF as fact when it means "none I recognise". OPEN
Detection is a curated list of 8 community timer names, and the docstring concedes a
custom-named timer will not be found. The summary nonetheless says `auto-updates: OFF`
flatly. The honest claim is *no recognised auto-update timer* — same shape as the
"could not look" invariant, in the one action whose whole output is a single verdict.

Left open rather than fixed blind: the alternative is scanning every enabled timer's
`ExecStart` for a package manager, which is a different and more invasive design that the
existing docstring explicitly weighed and rejected. Worth revisiting with that trade-off in
front of us rather than changing it in passing.

### A-03 — an undeterminable posture leaves an empty summary. OPEN
`systemctl` or `apt-config` absent → a `note` and nothing in the summary, so a run that could
not tell is indistinguishable in the digest from one that found nothing enabled. The same
shape fixed in `rebuild-check` and `config-drift`; not fixed here only because it is
bundled with A-02's wording question and both want deciding together.
