# QA — `python-rebuild-check` (`-y`)

**Purpose as advertised:** *"rebuild packages stranded on an old Python"*.

**Purpose as a user understands it:** *"a Python upgrade just happened — what did it
break?"*

Arch-only: apt and dnf handle interpreter transitions themselves.

Status: **swept and fixed.** Three findings fixed in v0.63.0, plus the elevation problem
that this sweep turned from two instances into a pattern worth fixing properly.

---

## What it actually runs

1. `python3 -c "…version_info…"` for the current version
2. glob `/usr/lib/python3.*`, keeping directories that are not the current one
3. `pacman -Qoq <dir>` for owners — **recursive**, which is the point: it finds modules
   stranded under an old stdlib
4. `pacman -Qoq <dir>/os.py` for the *interpreter* owning that stdlib, which is not a
   rebuild target

Two pieces of prior hardening (v0.4.4) are visible: the `os.py` sentinel, because an
interpreter package like the foreign `python312` **owns** `/usr/lib/python3.12` and was
being flagged as needing a rebuild against itself; and a name-pattern fallback,
`^python3?\d*$`.

---

## Cases and results

**Sweep 1 — v0.62.0 → v0.63.0, 2026-08-03**, on `manjaro-local` (read-only), which happened
to carry a real leftover `/usr/lib/python3.10` against a current 3.14.

| ID | Test | Verdict | Evidence |
|---|---|---|---|
| QA-PY-01 | Old dir with an owning package | PASS *(unit)* | owners collected and reported |
| QA-PY-02 | Old dir with **no** owner | PASS | `/usr/lib/python3.10` correctly reported as leftover; cross-checked — `pacman -Qoq` returns nothing for it |
| QA-PY-03 | Interpreter package owning its own stdlib | PASS *(by construction)* | the `os.py` sentinel, v0.4.4 |
| QA-PY-04 | No old directories | PASS | says so plainly |
| QA-PY-05 | Stranded packages appear in the summary | **FAIL → fixed** | P-01 |
| QA-PY-06 | Rebuild fails | **FAIL → fixed** | P-02 |
| QA-PY-07 | Current Python version undeterminable | **FAIL → fixed** | P-03 |
| QA-PY-08 | `-y` without `-R` never rebuilds | PASS | reports and suggests only |
| QA-PY-09 | `-y` needs no root | **FAIL → fixed** | P-04 |
| QA-PY-10 | `-y --dry-run` | PASS | changes nothing |

## Findings

### P-01 — stranded packages never reached the summary. FIXED v0.63.0
The action printed them and added a next-step, but no summary line — so a `fettle -a` run
with packages stranded on an old Python produced a digest identical to one with none, in the
action whose entire purpose is surfacing them. Its sibling `check_rebuilds`, in the same
file, always had one.

### P-02 — a failed rebuild was reported as a success. FIXED v0.63.0
`summary_add(f"rebuilt packages for Python {current}")` ran unconditionally after
`self._rebuild(...)`. This is **the guard added to `check_rebuilds` in v0.57.0**, never
applied to the adjacent method — the second consecutive sweep to find a fix that had not
reached its sibling, after `kernel` inherited nothing from `orphans`.

So this time the codebase was searched for the whole shape rather than the instance:

```
summary_add claiming an outcome, with no failure check in the preceding lines
  fettle/backends/arch.py:722  rebuilt packages for Python {current}
```

One hit, now fixed. The pattern is otherwise clear — which is worth more than the fix.

### P-03 — an undeterminable Python version made everything look stranded. FIXED v0.63.0
`current` fell back to the literal string `"unknown"`, and the filter then compared
directory names against `"pythonunknown"` — matching nothing, so **every** `python3.*`
directory counted as old and every package owning one would have been reported as needing a
rebuild. It now says the check did not run.

### P-04 — `-y` demanded a password for work needing none. FIXED v0.63.0
`python3 -c`, a glob and `pacman -Qoq` are all rootless, and the action prompted for sudo
anyway — making it unusable anywhere a password cannot be typed.

**This was the third instance** (after `-O` and `-r`, both recorded as Q7), which is what
justified fixing the cause rather than the symptom. `cli.NO_ROOT_ACTIONS` was one global set
where the correct answer is per-family: on Arch these three genuinely need nothing, while on
apt and dnf the same three write under `/var`. Backends now declare `extra_no_root`, and
only Arch does. Verified on the workstation — `-y`, `-r` and `-O` all run unprivileged now,
and the Debian/RHEL backends still elevate.
