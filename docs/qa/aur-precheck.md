# QA — `aur-precheck` (`-p`)

**Purpose as advertised:** *"before installing: gate one or more named AUR packages
(RPC + IoC)"*.

**Purpose as a user understands it:** *"is this thing I'm about to build safe?"*

**The highest-consequence read-only check in the tool.** Every other audit reports on
what is already installed; this one runs *before* a package is built, once per package,
from the yay hook — so its silence is taken as permission.

Status: **swept and fixed.** Four findings, one of which meant the malware gate passed
in silence whenever its malware list could not be loaded.

---

## Cases and results

**Sweep 1 — v0.76.0 → v0.77.0, 2026-08-05**, on `manjaro-local` (77 installed AUR
packages), plus the hook contract read from `~/.config/yay/init.lua`.

| ID | Test | Verdict |
|---|---|---|
| QA-AP-01 | **Unreadable IoC feeds do not read as clean** | **FAIL → fixed** (AP-01) |
| QA-AP-02 | **The allowlist cannot be trusted blindly** | **FAIL → fixed** (AP-02) |
| QA-AP-03 | **Exit status reflects a CRITICAL** | **FAIL → fixed** (AP-03) |
| QA-AP-04 | **A disabled check says so to a human** | **FAIL → fixed** (AP-04) |
| QA-AP-05 | AUR RPC offline is distinguished from not-found | PASS *(prior work)* |
| QA-AP-06 | The `CRIT `/`WARN ` line contract is preserved | PASS — verified against the hook's parser |
| QA-AP-07 | Clean named package emits nothing | PASS — measured (`brave-bin`) |
| QA-AP-08 | Stale package warns without failing | PASS — measured (`md5`, 4055 days) |
| QA-AP-09 | Runs unprivileged, no TOML load | PASS *(by design — the hook fires per package)* |
| QA-AP-10 | Bulk fetch, not per-package | PASS — one RPC + one feed fetch per batch |

## Findings

### AP-01 — the malware gate passed in silence when its lists were blind. FIXED v0.77.0
`bad_packages()` / `bad_accounts()` were consulted; `ioc.degraded` / `unavailable` /
`stale` were not. An unreachable feed returns an **empty set**, so every package
compared clean against a list that was never loaded.

Measured, cold cache against an unreachable feed host:

```
bad_packages(): set()      degraded: True      unavailable: 2
what the yay hook would see:  (nothing about the malware lists at all)
```

Three things make this the sharpest instance of the pattern in the project:

1. **It runs before the build**, not after — its silence is consent.
2. **The same file already got it right for the other data source.** The AUR RPC half
   distinguishes offline (`could not reach the AUR RPC`) from a genuine not-found. The
   IoC half — the one that answers "is this known malware?" — did not.
3. **The IoC layer already tracked it.** `stale`/`unavailable`/`degraded` exist because
   `aur-ioc-scan`'s sweep added them, and `pkg-audit` inherited them when `-I` was
   retired. Every consumer had the guard except the one where it matters most.

`bad_npm()` carries a `DEFAULT_NPM_SEED` fallback commented *"never go blind"* — the
failure mode was understood for npm and left open for the AUR list.

Now emitted as a `WARN` line, so it reaches the hook at build time rather than only a
human at a terminal.

### AP-02 — the allowlist was an unguarded trust boundary. FIXED v0.77.0
An entry in `~/.config/yay/allowlist.txt` (or `$YAY_ALLOWLIST_FILE`) **suppresses a
CRITICAL malware warning** for the package it names. The file was read with no ownership
or permission check at all — while fettle's TOML config has refused world-writable or
foreign-owned files since day one. That made the allowlist the softer way to silence the
same alarm.

Now fails **closed**: an unsafe allowlist is announced and ignored, and every package is
checked. Checked inline rather than through `config._is_safe`, to keep this the
self-contained no-TOML helper the hook invokes once per package.

### AP-03 — always exited 0, including on KNOWN-COMPROMISED. FIXED v0.77.0
Documented as deliberate — *"advisory; never blocks an install"*. But that reasoning
comes from the hook, and **the hook does not read the exit code**: `init.lua` runs the
helper through `io.popen`, reads stdout, and discards `p:close()`. Verified in its
source before changing anything.

So the status was costing the hook nothing and misleading everyone else:
`fettle aur-precheck foo && yay -S foo` proceeded on a known-malicious package. Now 1 on
any CRITICAL, 0 otherwise. The hook is unaffected, and the line contract is byte-identical.

### AP-04 — `AUR_PRECHECK=false` disabled the check in total silence. FIXED v0.77.0
A human running `fettle -p pkg` with the toggle off got no output and exit 0 —
indistinguishable from "checked, all clear". The standalone path now says the check did
not run. The **hook** path stays silent deliberately: the env var is an explicit opt-out
and the hook fires once per package, so a line each would be noise the user asked not to
have.

## Note on scope
`precheck.scan()` — the same code path, used by `-u`'s pre-upgrade gate — inherits all
four fixes, since they live in `check()`. The gate's own behaviour was swept separately
under [advisory-check](advisory-check.md) (SG-01…04).
