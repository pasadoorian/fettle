# QA — `remote`

**Purpose as advertised:** *"run maintenance on a remote host/group over ssh (safe set by
default)"*.

**Purpose as a user understands it:** *"do this on that machine, without installing
anything on it."*

The way Paul actually uses fettle, and the only feature that runs fettle **somewhere
else** — so every other feature's output has to survive a round trip before he sees it.

Status: **swept and fixed.** Four findings here, on top of three already fixed while
sweeping other features.

---

## Already fixed, before this sweep
`remote` kept surfacing in other features' sweeps, which is itself worth recording:

| | |
|---|---|
| **v0.71.0** | **Every remote run reported success**, whatever happened — `zipapp`'s generated entry point calls `main()` and discards its return. Found via sys-audit, because until then nothing could return non-zero. |
| **v0.73.1** | `--ssh-arg` reached the ssh run but **not the `scp` upload**, so a host needing an option to be reachable failed before it started. |
| **v0.79.0** | Reports filed under the ssh target, so a DHCP change forked one machine into three dashboard hosts; and a *rejected* command minted a permanent host from its argv. |

## Cases and results

**Sweep 1 — v0.85.0 → v0.86.0, 2026-08-05**, against the lab: single hosts, a
three-host group with one deliberately unreachable member, and a host that does not
resolve.

| ID | Test | Verdict |
|---|---|---|
| QA-RM-01 | **A failure says what actually went wrong** | **FAIL → fixed** (RM-01) |
| QA-RM-02 | **Errors appear next to the host they belong to** | **FAIL → fixed** (RM-02) |
| QA-RM-03 | **"No reports came back" is distinguishable from "none written"** | **FAIL → fixed** (RM-03) |
| QA-RM-04 | **The fetch-back cannot break the run it follows** | **FAIL → fixed** (RM-04) |
| QA-RM-05 | A group continues past a failing host | PASS — 3 hosts, middle one dead, both others ran |
| QA-RM-06 | Group exit status reflects any failure | PASS — exit 1 with 2 ok / 1 failed |
| QA-RM-07 | Group confirms before a destructive run | PASS — skipped under `--yes`/`--dry-run` |
| QA-RM-08 | Remote exit code reaches the caller | PASS *(v0.71.0)* |
| QA-RM-09 | No action named → the safe set | PASS — clean/update/firmware-check only |
| QA-RM-10 | `--dry-run` needs no sudo and fetches nothing back | PASS |
| QA-RM-11 | Zipapp uploaded under an unpredictable name, chmod 600, removed after | PASS *(prior work)* |
| QA-RM-12 | A host that looks like an ssh option is refused | PASS *(prior work — `_valid_host`)* |
| QA-RM-13 | Fetched archives cannot escape their directory | PASS *(prior work — basename-only, 0600)* |

## Findings

### RM-01 — `scp -q` hid the only useful line. FIXED v0.86.0
An unreachable host produced exactly this:

```
/usr/bin/scp: Connection closed
Error: scp to nosuchhost.invalid failed
```

Measured side by side:

```
scp -q  →  /usr/bin/scp: Connection closed
scp     →  ssh: Could not resolve hostname nosuchhost.invalid: Name or service not known
           /usr/bin/scp: Connection closed
```

`-q` suppresses the diagnosis. **`lab.py`'s own source documents this exact confusion** —
*"`scp -q` reports that only as 'Connection closed' — measured, and indistinguishable from
a broken guest until you run scp by hand"* — and the code it describes kept using `-q`.
Now captured rather than silenced: success stays quiet, failure is explained.

```
Error: could not copy fettle to paulda@10.255.255.1 — ssh: connect to host
10.255.255.1 port 22: Connection timed out
```

### RM-02 — every error appeared at the top, detached from its host. FIXED v0.86.0
stdout is block-buffered off a terminal; stderr never is. Captured to a file or a pipe —
which is what a group run or a CI job does — the errors floated to the top, away from the
`=== [group] host ===` header that said which machine they came from. On a four-host group
you could not tell. `Output._to_stderr` already flushes stdout first for exactly this;
these paths use bare `print` and did not.

### RM-03 — "nothing came back" was silent. FIXED v0.86.0
The fetch-back printed `Fetched N report(s)…` only when N was non-zero. So a run whose
reports failed to arrive looked identical to one that wrote none — and every audit action
writes a report, so nothing arriving is worth saying.

### RM-04 — the fetch-back could break the run it follows. FIXED v0.86.0
Introduced by me in v0.79.0: the hostname lookup was placed *outside* the `try`, so a
failure in it would propagate — in a function whose docstring promises it never breaks a
run. Caught by writing the test for RM-03 and watching it raise instead of print.

## Open
- **`fettle remote` has no `--config`**, unlike every other subcommand, so a group can only
  come from the default config file. The grammar (ssh options before HOST, everything after
  it forwarded verbatim) makes adding one a deliberate choice rather than a one-liner.
- **`fettle sys-audit remote` has no `--ssh-arg`** — recorded during the sys-audit sweep and
  still true.
