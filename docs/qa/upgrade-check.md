# QA — `upgrade-check` (`-U`)

**Purpose as advertised:** *"[experimental] AI pre-upgrade safety check"*.

**Purpose as a user understands it:** *"before I run this upgrade, is anything about to
break?"*

Marked experimental, opt-in, read-only, and the only feature that costs money per run.

Status: **reviewed, not exercised.** Paul's call — *"just review the code so we don't
burn tokens testing it; I've used it 2-3 times and it works great."* Every fix below is
covered by unit tests through the injectable `runner`, so no API call was made.

---

## Cases and results

**Sweep 1 — v0.75.0 → v0.76.0, 2026-08-05.** Static review of `fettle/ai/*` plus
`_run_upgrade_check`, with one local (free) check of the redaction against real `inxi`
output.

| ID | Test | Verdict |
|---|---|---|
| QA-UC-01 | **The verdict reaches the summary** | **FAIL → fixed** (UC-01) |
| QA-UC-02 | **"Could not run" is distinguishable from "safe"** | **FAIL → fixed** (UC-01) |
| QA-UC-03 | **Model-authored commands are attributed** | **FAIL → fixed** (UC-02) |
| QA-UC-04 | Hallucinated package names are dropped | PASS *(prior work)* |
| QA-UC-05 | Off-domain sources are dropped | PASS *(prior work)* |
| QA-UC-06 | Serials / MACs / UUIDs redacted before sending | PASS — **measured** on real inxi output |
| QA-UC-07 | Failure degrades to the plain package diff | PASS |
| QA-UC-08 | The key is never printed or logged | PASS — `redact_key`, and `_diag` prints neither payload nor key |
| QA-UC-09 | Retry is bounded and only on retryable codes | PASS — 429/500/529, 3 attempts, backoff |
| QA-UC-10 | `pause_turn` continuation is bounded and says so | PASS |
| QA-UC-11 | Live run against the API | **not exercised** — by decision, see above |

## Findings

### UC-01 — the third instance of the same pair. FIXED v0.76.0
`-U` had **no summary lines at all** and returned `0` from every path: a `risky` verdict,
a clean `safe`, an absent API key and an API failure were indistinguishable to anything
downstream.

This is sys-audit's S-01/S-02 (v0.71.0) and advisory-check's AC-05 (v0.74.0) for the
third time, and it was *predicted* — the AC-05 write-up named `upgrade-check` as a likely
instance. The common factor is structural: **every subcommand with its own entry point**
(`_run_upgrade_check`, `_run_advisory`, `audit.main`) must remember to call
`print_summary()` and compute a status, and each one independently forgot. The pipeline
actions never had the bug because `actions.run()` does it once for all of them.

The split now:

- **Verdicts exit 0**, whatever they say — `safe` is `✓`, `caution`/`risky` are `!`. A
  check you asked for and got an answer from has not failed; the verdict is an opinion
  about an upgrade, not fettle being unable to do its job.
- **"Could not run" is `✗` and exit 1** — no API key, or the analysis came back
  unavailable. That is the could-not-look case, and it is the one thing a script needs
  to be able to tell apart from a clean answer.

### UC-02 — the hallucination guard protected the lower-consequence field. FIXED v0.76.0
`_validate` carefully drops any `watch_items` entry naming a package that is not actually
upgrading — a real guard, showing the author took hallucination seriously. But
`must_do_before` and `should_do_after` passed through **unvalidated**, and the system
prompt asks the model for *"concrete commands/steps, not 'be careful'"*.

So model-authored shell commands rendered under a heading styled exactly like fettle's
own `next_step` advice. You run them by hand, so this is not code execution — but the
styling invites copy-paste, and there is a path worth naming: `web_search` feeds the model
**forum posts that anyone can write**, the model is asked to emit commands, and the result
is printed as an instruction. `allowed_domains` narrows who can influence it; it does not
close it.

Attribution is the cheap half of the fix and is now in place:

```
Before upgrading (suggested by the model — verify before running):
  - …
```

Not fixed: the content itself is still unvalidated. Validating a free-form command is a
much larger problem than checking a package name against a list, and marking it honestly
is worth more than a guard that would only catch the obvious cases.

### UC-03 — the JSON schema is a prompt contract, not an API one. NOT FIXED
`_SCHEMA_HINT` asks for JSON in prose; `_extract_json` then brace-matches the reply and
tries two candidates. `output_config.format` does this at the API layer and would delete
both the parsing path and the `no JSON verdict in the reply` failure mode. Recorded as an
improvement, not a defect — the current code handles its own failure correctly.

## What held up under review

- **Redaction works.** Measured, not assumed: real `inxi -SCGaxxa` output through
  `redact()` leaves monitor serials, the root UUID and MACs all replaced. I went looking
  for a leak and did not find one.
- **Failure handling is careful everywhere.** `analyze()` returns `None` on every failure
  and the caller degrades to the plain diff; retries are limited to 429/500/529; the
  `pause_turn` loop is bounded and reports exhaustion.
- **The `ALLOWED_DOMAINS` comment earns its place** — it records that reddit and
  askubuntu block Anthropic's crawler and 400 the *whole request*, which is exactly the
  measured fact that stops someone helpfully adding them back later.
