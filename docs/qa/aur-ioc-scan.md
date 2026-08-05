> **RETIRED in v0.73.0.** `-I` / `aur-ioc-scan` no longer exists — `pkg-audit`
> (`-P`) runs every check it did, across every ecosystem. This sweep's findings
> are still live: the fixes were in `fettle/aur/ioc.py` (the shared feed layer),
> and the one that lived in the action itself — *"matched nothing, but the lists
> were never read"* — was ported into `-P`'s AUR provider as a precondition of
> retiring the flag. Without that port, folding `-I` into `-P` would have
> reintroduced the exact bug this document records.

# QA — `aur-ioc-scan` (`-I`)

**Purpose as advertised:** *"scan installed AUR pkgs vs known-compromise feeds"*.

**Purpose as a user understands it:** *"have I installed anything that is known to be
malicious?"*

**In the default action set**, so it runs on every `fettle -a`. Its entire value is the
answer, and a false "clean" here means somebody believes they were checked against malware
feeds when they were not.

Status: **swept and fixed.** Four findings fixed in v0.65.0.

---

## What it actually runs

Three independent checks against the lenucksi campaign feeds — installed package names vs
known-malicious lists, maintainer accounts vs known-malicious accounts, and JS-dependency
traces in local package-manager caches. Feeds are cached on disk with a 6-hour TTL.

### Findings, measured on the Arch guest and against the live feed

| ID | Test | Verdict |
|---|---|---|
| QA-IOC-01 | Known-malicious package installed | PASS *(unit)* |
| QA-IOC-02 | Known-malicious maintainer | PASS *(unit)* |
| QA-IOC-03 | JS cache trace | PASS *(unit)* |
| QA-IOC-04 | Clean system, feeds reachable | PASS |
| QA-IOC-05 | **Feeds unreachable, no cache** | **FAIL → fixed** (I-01) |
| QA-IOC-06 | **Feeds served from a stale cache** | **FAIL → fixed** (I-02) |
| QA-IOC-07 | **Only one of three feeds checked for failure** | **FAIL → fixed** (I-03) |
| QA-IOC-08 | Clean scan appears in the summary | **FAIL → fixed** (I-04) |
| QA-IOC-09 | A 404 feed is not a coverage gap | **FAIL → fixed** (I-05, self-inflicted) |
| QA-IOC-10 | Report written 0600 | PASS |
| QA-IOC-11 | `--dry-run` writes no report | PASS |

## Findings

### I-01 — unreachable feeds still produced a green "no indicators matched". FIXED v0.65.0
With the feeds blocked and no cache, the scan warned on stderr and then printed
`✓ scan complete: no indicators matched across N package(s)` — and added **nothing** to the
summary. In a `fettle -a` run the digest therefore showed no trace of the scan at all, while
the screen showed a green tick. A machine that was never checked looked checked.

Now a degraded scan never claims a clean bill, and the summary carries it:

```
! scan of 2 package(s) matched nothing, but coverage was INCOMPLETE — this is not a
  clean bill of health.
! IoC feeds that could not be fetched at all: aur-infected/npm-packages.txt, …
▸ Summary
  ! AUR IoC scan ran with INCOMPLETE feeds — packages compromised in campaigns
    published since then would not be seen
```

### I-02 — a stale cache was used silently. FIXED v0.65.0
`ioc.py`'s own docstring says *"stale cache rather than silently reporting clean"* — the
right instinct, and the fallback was there. But `_cached` returned the stale text with no
signal, so the caller could not tell a fresh feed from a month-old one. A laptop offline for
three weeks scanned against a three-week-old feed and announced itself exactly like a current
scan. The age is now reported and counts as degraded coverage.

### I-03 — only one of the three feeds was checked. FIXED v0.65.0
`bad_packages()` had an emptiness check; `bad_accounts()` and `bad_npm()` had none. A failure
of the accounts feed — the one that catches a *maintainer* takeover — passed without a word,
and the scan then reported confidently having consulted two lists instead of three.

### I-04 — a clean scan left no trace in the summary. FIXED v0.65.0
"Scanned and clean" and "never ran" produced identical digests. Now
`✓ AUR IoC scan: N package(s) checked, none flagged`.

### I-05 — the fix cried wolf, and this is the second time in two features
The first cut counted **every** unfetchable feed as a coverage gap, so a healthy machine with
fully working network reported `INCOMPLETE` on every run. Measured against the live feed:

| campaign | packages.txt | packages-extra.txt | npm-packages.txt | accounts.json |
|---|---|---|---|---|
| aur-infected | 200 | 200 | 200 | 200 |
| chaos-rat | 200 | **404** | **404** | 200 |
| russian-spam | 200 | **404** | **404** | 200 |

Campaigns publish different list types; a 404 is normal absence, not a failure. `_fetch` now
returns `(text, status)` distinguishing `ok` / `missing` / `unreachable`, and only
`unreachable` counts.

**This is the same mistake as the fwupd `exit 2` case one feature earlier** — treating a
routine, documented non-success as a failure. Having just written a changelog entry about
that exact confusion did not prevent repeating it, which is worth recording: the lesson
generalises better as a habit ("ask what the tool means by this code") than as a memory of
one instance.
