# QA — `firmware` (`-f`)

**Purpose as advertised:** *"check for firmware updates (fwupd)"*.

**Purpose as a user understands it:** *"is my firmware current?"*

The one action that is identical on every distribution — `fwupd` is distro-neutral, so this
lives in the base backend and all seven targets run the same code. It is also in the default
action set.

Status: **swept and fixed.** Three findings, all fixed in v0.61.0 — including **B1**, the highest-priority item in the outstanding-issues tracker.

---

## What it actually runs

```
fwupdmgr refresh          # through ctx.execute, quiet
fwupdmgr get-updates      # captured, and the exit code discarded
```

The verdict is then decided by **string matching on stdout**:

```python
if text and "no updates" not in text.lower() and "No updatable" not in text:
    ... updates available
else:
    out.ok("no firmware updates available.")
```

### F-01 — the highest-priority item in the tracker, now measured

`fwupdmgr` documents its exit codes: *"0 success, 1 generic failure, **2 for commands that
have no actions but were successfully executed**, 3 resource not found."* Measured on Debian
13 with fwupd 2.0.20:

| State | stdout | exit |
|---|---|---|
| healthy, nothing to update | *(empty)* | **2** |
| **daemon masked — cannot answer at all** | *(empty)* | **1** |

fwupd distinguishes those perfectly. fettle discards the exit code, so both land in the
`else` branch and produce the same sentence:

```
✓ no firmware updates available.
```

A machine whose firmware update service is dead reports as up to date. This is **B1** in the
outstanding-issues tracker, carried since the RHEL work, and the reason it stayed open was
that it needed a live daemon to stop — which the lab now provides. → **QA-FW-01**

### Also predicted from the source

1. **The match is English-only.** `"no updates"` and `"No updatable"` are compared against
   the tool's own prose. On a localised system neither matches, so a clean result would be
   reported as *"firmware updates available"* with the message printed beneath it. The RHEL
   backend explicitly avoids this — *"Printing the body verbatim also keeps this working on
   a localised system, where matching an English phrase would not."* → **QA-FW-04**
2. **A failed `refresh` is invisible.** It runs through `ctx.execute`, so since v0.52.0 the
   failure lands in `ctx.failed_commands` — but `firmware_updates` never consults it, and a
   stale metadata cache silently produces an answer about yesterday's firmware.
   → **QA-FW-05**
3. **`fwupdmgr` absent is a `note` with an empty summary** — the same "could not look" shape
   fixed in `rebuild-check` and `config-drift`. → **QA-FW-06**

---

## Cases

All seven targets run identical code, so applicability is "all" unless stated.

### Does it give a true answer

| ID | Test | Expected | Verified by |
|---|---|---|---|
| QA-FW-01 | **fwupd daemon stopped or masked** | Must **not** report "no firmware updates available" — it could not answer | mask the unit, compare against `fwupdmgr get-updates` exit 1 |
| QA-FW-02 | Healthy, no updatable devices | Reports nothing pending — distinguishable from the above | exit 2 |
| QA-FW-03 | Updates genuinely available | Lists them and says how to apply | needs updatable firmware — see coverage note |
| QA-FW-04 | Localised output (non-English locale) | Verdict unchanged; it must not depend on matching English prose | `LC_ALL` set to a translated locale |

### Could-not-look must not read as clean

| ID | Test | Expected | Verified by |
|---|---|---|---|
| QA-FW-05 | `fwupdmgr refresh` fails (no network) | Says the metadata is stale; the answer is qualified | break DNS, run |
| QA-FW-06 | `fwupdmgr` not installed | Says the check did not run; summary not silent | hide the binary |
| QA-FW-07 | Run unprivileged | Works, or says what it could not read | run as non-root |

### Behaviour

| ID | Test | Expected | Verified by |
|---|---|---|---|
| QA-FW-08 | `-f --dry-run` | Refreshes nothing, applies nothing, claims nothing | transcript |
| QA-FW-09 | `-f` never applies updates | Only reports; `fwupdmgr update` is advice, not an action | transcript |
| QA-FW-10 | Summary wording | "up to date", "updates available" and "could not tell" are three different answers | summary |

### Coverage note

**QA-FW-03 cannot be exercised in this lab.** No VM has updatable firmware, so the
updates-available branch rests on unit tests — as recorded in the changelog for v0.43.3.
The container fleet cannot close it either: those images have neither fwupd nor dbus. This
is stated rather than papered over.

---

## Results

**Sweep 1 — v0.60.0 → v0.61.0, 2026-08-03**, on Debian 13 with fwupd 2.0.20. All seven
targets run identical code, so one host with a controllable daemon settles it.

| ID | Verdict | Evidence |
|---|---|---|
| QA-FW-01 | **FAIL → fixed** | F-01/B1: masked daemon reported "no firmware updates available" |
| QA-FW-02 | PASS | exit 2 → "no firmware updates available", now distinguishable |
| QA-FW-03 | **BLOCKED** | no updatable firmware in any VM — see the coverage note |
| QA-FW-04 | **FAIL → fixed** | F-03: verdict depended on matching English prose |
| QA-FW-05 | **FAIL → fixed** | F-02: a routine "already current" was rendered as a failure |
| QA-FW-06 | **FAIL → fixed** | absent `fwupdmgr` was a note with an empty summary |
| QA-FW-07 | not run | needs an unprivileged run against the daemon |
| QA-FW-08 | PASS | `--dry-run` refreshes nothing and claims nothing |
| QA-FW-09 | PASS | `-f` only reports; `fwupdmgr update` stays advice |
| QA-FW-10 | PASS *(after fix)* | up-to-date / available / UNKNOWN are three answers |

## Findings

### F-01 — a dead fwupd daemon reported firmware as up to date. FIXED v0.61.0
**This is B1**, carried in the outstanding-issues tracker since the RHEL work and left open
because it needed a live daemon to stop. The lab now provides one.

`fwupdmgr` documents its exit codes and uses them correctly — measured:

| State | stdout | exit |
|---|---|---|
| healthy, nothing to update | *(empty)* | **2** — "no actions but successfully executed" |
| **daemon masked, cannot answer** | *(empty)* | **1** |

fettle discarded the code and decided from stdout, so both produced
`✓ no firmware updates available.` The verdict is now taken from the exit code:

```
! could not determine firmware status (fwupdmgr exited 1) — firmware was NOT assessed.
  Failed to connect to daemon: … Unit fwupd.service is masked.
▸ Summary
  ! firmware status UNKNOWN — the check could not run
```

### F-02 — every healthy machine was shown a failure. FIXED v0.61.0
The opposite error, in the same action. `fwupdmgr refresh` returns **2** whenever the
metadata is already current, which is the normal state on any machine that ran recently —
and `run_quiet` treated every non-zero code as failure, so a routine condition printed
`✗ firmware metadata refreshed failed (exit 2)`.

"Non-zero" and "failed" are not synonyms. `Context.execute` and `Output.run_quiet` now take
`ok_codes`, and firmware declares `(0, 2)`. Worth noting the pair: F-01 was false calm and
F-02 was crying wolf, both from the same habit of not reading what the tool actually said.

### F-03 — the verdict depended on matching English. FIXED v0.61.0
`"no updates" not in text.lower() and "No updatable" not in text` — against the tool's own
prose. On a localised system neither matches, so a clean result would have been announced as
*"firmware updates available"* with the translated "nothing to update" message printed
beneath it as though it were a list of pending updates. The RHEL backend had already learned
this: *"Printing the body verbatim also keeps this working on a localised system."*
Now decided by exit code, so the language is irrelevant.

### Coverage note — stated, not papered over
**QA-FW-03 is BLOCKED and stays blocked.** No VM has updatable firmware, so the
updates-available branch still rests on unit tests, exactly as recorded for v0.43.3. The
container fleet cannot close it either — those images have neither fwupd nor dbus. What
changed is that the *other three* branches are now measured rather than assumed.
