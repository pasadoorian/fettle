# QA — `report`

**Purpose as advertised:** *"build ~/.fettle/report.html from all stored reports/logs
(every host)"*.

**Purpose as a user understands it:** *"show me everything fettle has found, everywhere,
in one place."*

Read-only, no sudo. It is the only feature whose output is a *view* of
other features' output — so it inherits every naming decision they made, and it is where
those decisions become visible.

Status: **swept and fixed.** Four findings.

---

## Cases and results

**Sweep 1 — v0.78.0 → v0.79.0, 2026-08-05**, against the real
`~/.fettle/{reports,logs}/` on `manjaro-local`: 27 report directories, 20 log
directories, 9 report types, 2.7 MB of HTML.

| ID | Test | Verdict |
|---|---|---|
| QA-RP-01 | **Every report type has a renderer** | **FAIL → fixed** (RP-01) |
| QA-RP-02 | **One machine is one host** | **FAIL → fixed** (RP-02) |
| QA-RP-03 | **Empty host directories are not shown** | **FAIL → fixed** (RP-03) |
| QA-RP-04 | **A rejected command cannot mint a host** | **FAIL → fixed** (RP-04) |
| QA-RP-05 | Group names are not shown as hosts | PASS *(prior work — `bifrost-lab` already routed to a "group runs" section)* |
| QA-RP-06 | A bad payload cannot break the page | PASS — per-entry `try/except` falls back to a JSON dump |
| QA-RP-07 | Written 0600 and chowned back under sudo | PASS |
| QA-RP-08 | Everything is escaped; only http(s) hrefs | PASS *(prior work — `_safe_url` blocks `javascript:`)* |
| QA-RP-09 | Advisory environments show their real paths | PASS — inherited free from v0.74.0 |

**Sweep 2 — v1.12.0, 2026-08-17**, from the 2026-08-12 code review (H-12), against the
same real corpus (17 host cards).

| ID | Test | Verdict |
|---|---|---|
| QA-RP-10 | **A finding you fixed clears from the card** | **FAIL → fixed** (RP-05) |
| QA-RP-11 | A newer finding still shows over an older clean run | PASS — guard on the fix |
| QA-RP-12 | **A host with only run logs is not `OK`** | **FAIL → fixed** (RP-06) |
| QA-RP-13 | A clean audit still counts as coverage | PASS — guard on the fix |

## Findings

### RP-01 — a new feature rendered as a raw JSON dump. FIXED v0.79.0
`pkg-integrity` was split out of `sys-audit` in v0.72.0 and is built from the same
`Scan`, so its payload shape is *identical* — but it was never added to `_RENDERERS`, and
five reports fell through to `<pre>{json.dumps(...)}</pre>`. One line, and it is the
predictable cost of adding a report type: nothing fails, it just looks like debug output.

### RP-02 — one machine appeared as up to three hosts. FIXED v0.79.0
Reports were filed under the **ssh target**, so a lab guest on DHCP became a new "host"
every time its lease moved:

```
arch_192.168.1.100   arch_192.168.1.142   arch_192.168.1.211
debian_192.168.1.123 debian_192.168.1.141 debian_192.168.1.152
fedora_192.168.1.229 fedora_192.168.1.250 fedora_192.168.1.252
ubuntu_192.168.1.104 ubuntu_192.168.1.143 ubuntu_192.168.1.202
```

Twelve cards for four machines, each holding a fragment of one timeline — which defeats
the point of a dashboard whose value is *trend*. The fetch-back now asks the machine what
it calls itself (`remote_hostname()`, validated against a hostname pattern, falling back
to the sanitised target when unreachable) and files under that. Verified live:
`paulda@192.168.1.123` → `fettle-debian`, `paulda@192.168.1.192` → `fettle-rocky9`.

Existing directories are left where they are; the code stops making new ones.

### RP-03 — eight empty directories rendered as host cards. FIXED v0.79.0
Each read `no reports / latest: –`. They come from fetch-backs that found nothing and
from lab guests whose address moved. Hidden now, with the count kept in the header
(`25 host(s) · 4 empty hidden`) so they are hidden rather than disappeared.

### RP-04 — a rejected command minted a permanent host. FIXED v0.79.0
The dashboard had a host called **`clean`**. Its origin, found on disk:

```json
"argv": ["remote", "--", "-oProxyCommand=touch /tmp/pwned-by-fettle", "clean"],
"transcript": "fettle remote: ssh options go before HOST and actions after it…"
```

An injection attempt from a v0.22.0 security test. **The guard worked** — fettle refused
the command. But `runlog.log_host()` dug the "host" out of argv *before* validation,
skipping anything starting with `-`, and landed on `clean`. A refused command left a
permanent host on the dashboard.

Fixed by deleting the derivation entirely: the run-log is the record of a **local
invocation** and is now always filed under `local`. The remote machine writes and ships
back its own transcript, so the previous behaviour was also duplicating that under a
second name. Deriving nothing from argv cannot go wrong.

### Also fixed while in the file
`render()`'s per-host loop assigned `groups = []`, shadowing its own `groups` parameter.
Harmless today because both lists are computed before the loop — and exactly the kind of
thing that is not harmless the next time someone edits below it.

### RP-05 — a fixed finding never cleared. FIXED v1.12.0

`_host_problems()` chose the newest report per tool, but filtered clean reports out
**before** the choice:

```python
for e in host["reports"]:
    if _is_empty(e):
        continue                  # <-- clean reports discarded here
    if e.get("timestamp", "") >= newest.get(t, {}).get("timestamp", ""):
        newest[t] = e             # <-- newest chosen from what survived
```

So the "newest" report was the newest one that *found something*, and a resolved finding
stayed on the fleet page forever.

**Measured on the real corpus, not a fixture.** `ec1` was showing
`47 packages with a known CVE (17 High)`. Its advisory-check history:

| report | findings |
|---|---|
| 2026-07-24 (×4) | 47, 47, 61, 47 |
| **2026-07-30** | **0** |
| **2026-08-06** | **0** |

The CVEs were cleared on 30 July and the dashboard had been reporting them as current for
the thirteen days since. Selection now happens first and emptiness is interpreted after,
so a newest-and-empty report means what it says: clean.

### RP-06 — run logs alone earned an `OK` security verdict. FIXED v1.12.0

Host freshness was computed from `reports + logs`. A run-log is what `fettle -u` writes,
and `-u` audits nothing — so a host that only ever updated had a fresh timestamp, no
findings, and a green `OK` on a security dashboard for a machine where no check had ever
run. The fixture said it plainly: `OK · no reports · latest: <today>`.

Audit freshness now comes from reports alone, and a host with none says so. Empty reports
still count as coverage, because a clean audit is an audit.

The staleness chip was reworded from "has not reported in N days" to **"no audit in N
days"**, since the card's `latest:` line still counts run-log activity and the two must not
appear to contradict each other. On the real corpus this made four hosts' ages *larger*
and more honest — `fettle-fedora` and `fettle-ubuntu` went from 11 days to 16 — because a
fresh run-log had been masking a stale audit.

**Whole-corpus diff, 17 hosts, before vs after:** exactly two cards changed — `ec1` lost
the resolved CVE chip and `bifrost-lab` gained "no audit has run on this host". Nothing
else moved, which is the result that mattered: a fix that silently dropped a *current*
finding would be worse than the bug it replaced.

## Deferred by decision

Two long inline lists that want the same `[+]`/`[-]` treatment the multi-environment
expander got in v0.83.0. Parked deliberately, tracked as **D1**/**D2** in the
outstanding-issues list:

- **The uncovered-packages list** — `advisory-check` prints all 77 AUR/foreign names as
  one paragraph, under *every* retained entry, so at `keep = 10` it repeats ten times in
  one host section. Since v0.82.0 each name is a link, which makes it longer. Whatever
  replaces it must keep the *count* visible when collapsed: this is a coverage statement —
  the packages the tracker cannot see at all — not decoration.
- **`aur-audit` removal candidates** — ~50 names inline. The list length is intended
  (flag-ALL was the explicit choice in v0.16.0); only the presentation is at issue. The
  "pacman only tracks packaged dependents" caveat has to stay outside any collapse, since
  it qualifies the whole list.

## Left for the operator
The **historical** directories on disk are untouched: twelve fragments of four lab
machines, plus `clean`. Nothing merges them retroactively, and `~/.fettle/` is the user's
data.
