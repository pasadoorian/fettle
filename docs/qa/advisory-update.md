# QA — `advisory-update`

**Purpose as advertised:** *"refresh the advisory cache"*.

**Purpose as a user understands it:** *"go and fetch the current CVE data now."*

The smallest feature in the tool — one function, no findings to render, no report. It is
also **the one most likely to be run by a timer**, which turns out to be the whole story.

Status: **swept and fixed.** Two findings.

---

## Cases and results

**Sweep 1 — v0.77.0 → v0.78.0, 2026-08-05**, on `manjaro-local` (arch + osv providers).

| ID | Test | Verdict |
|---|---|---|
| QA-AU-01 | **A failed refresh sets the exit status** | **FAIL → fixed** (AU-01) |
| QA-AU-02 | **A successful refresh reaches the digest** | **FAIL → fixed** (AU-02) |
| QA-AU-03 | **"No provider" is not reported as success** | **FAIL → fixed** (AU-03) |
| QA-AU-04 | Always fetches; never TTL-gated | PASS — calls `refresh()` directly, not `_ensure_fresh()` |
| QA-AU-05 | Row counts reported per provider | PASS — measured: arch 2523, osv 1428 |
| QA-AU-06 | Retired config keys are reported | PASS *(after fix — shares `_warn_retired_keys` with `advisory-check`)* |
| QA-AU-07 | Partial failure is distinguished from total | PASS *(after fix — names what failed **and** what refreshed)* |

## Findings

### AU-01 — the failure printed and the process exited 0. FIXED v0.78.0
```python
if n < 0:
    out.err(f"failed to fetch {p.source} advisory data.")
```

`err()` writes a line to stderr. `summary_fail()` is what sets the exit status. Only the
first was called, so a run where every feed failed printed `✗` three times and exited
**0** with `nothing to report` underneath.

That is the same shape as the rest of this QA pass, but it lands harder here than
almost anywhere else: **refreshing a cache is exactly the job you put in a systemd
timer**, and a timer never reads stdout. A permanently-failing refresh would look
identical to a healthy one for as long as nobody ran it by hand — while
`advisory-check` quietly answered from ageing data.

Partial failure now names both halves, because a cache that refreshed one feed and not
the other is stale in a way the next `advisory-check` cannot see.

### AU-02 — a successful refresh said nothing either. FIXED v0.78.0
Measured: it cached **3951 rows across two providers** and the digest read `nothing to
report`. Now `✓ advisory cache refreshed: arch 2523 row(s), osv 1428 row(s)`.

### AU-03 — an unsupported system reported success. FIXED v0.78.0
`no advisory provider for this system yet.` was a warn with an empty summary and exit 0.
On a distro fettle has no advisory provider for, a timer would report a healthy refresh
forever. Now `!` — not a failure, since it is a fact about the platform rather than
something that went wrong.

## Note
The entry point's missing `print_summary()` and hardcoded `return 0` were fixed one
release earlier, under [advisory-check](advisory-check.md) AC-05 — `advisory-update`
shares `_run_advisory` with it, so it inherited the plumbing. This sweep is what the
plumbing then had to carry.
