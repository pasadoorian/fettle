# QA — `pkg-audit` (`-P`)

**Purpose as advertised:** *"cross-ecosystem supply-chain audit"*.

**Purpose as a user understands it:** *"where did everything on this machine come from, and
is any of it something I shouldn't trust?"*

The only audit in the default set, and the broadest thing fettle does: seven providers
covering AUR, apt/dnf, flatpak, snap, containers, GNOME extensions, VS Code/VSCodium
extensions and `gh` extensions.

Status: **swept and fixed.** One finding fixed in v0.67.0, one open by decision.

---

## What it does well, and is worth not breaking

Measured on a workstation with 46 findings across five providers:

- **Absent providers are named**: `[gh] not present on this system — nothing to audit`.
  Without that, "flatpak is clean" and "flatpak was never looked at" are the same output —
  the invariant this whole QA plan is organised around, already handled here.
- **Every provider states its own coverage limits** before its findings, including what it
  explicitly does *not* do (`Does NOT scan image contents`, `does NOT verify that a
  publisher is who they claim`, `No malware/IOC feed exists for extensions.gnome.org`).
- Findings are sorted by severity, and CRITs are counted separately.

## Cases and results

**Sweep 1 — v0.66.0 → v0.67.0, 2026-08-03**, on `manjaro-local` (46 findings) and the lab
guests.

| ID | Test | Verdict |
|---|---|---|
| QA-PA-01 | Every present provider runs and reports | PASS — 5 of 7 present, both absentees named |
| QA-PA-02 | Absent provider is reported, not skipped silently | PASS |
| QA-PA-03 | `skip_sources` silences a provider entirely | PASS *(by construction)* |
| QA-PA-04 | Coverage limits stated per provider | PASS |
| QA-PA-05 | Findings sorted by severity | PASS |
| QA-PA-06 | **Summary mark matches what was found** | **FAIL → fixed** (P-01) |
| QA-PA-07 | A CRITICAL finding fails an automated run | **FAIL → fixed** (P-01) |
| QA-PA-08 | Sideloaded `.vsix` detected | PASS — verified against the editor index |
| QA-PA-09 | **A resolved finding is distinguishable from one never checked** | **open** (P-02) |
| QA-PA-10 | Unreadable extension index is not reported as clean | PASS *(by construction)* |
| QA-PA-11 | Report written 0600 | PASS |
| QA-PA-12 | Runs unprivileged | PASS *alone* — but see P-03: inside `-a` the process is already root |
| QA-PA-13 *(new)* | **A per-user source is queried as that user, not as root** | **FAIL → fixed for GNOME** (P-03); podman still open |

## Open

- **The podman half of the container source is dark under a root run — silently.** Same
  root cause as P-03 (per-user state queried as root), worse failure mode: rootless
  podman's store is `~/.local/share/containers/storage`, so as root it reads root's
  store, finds nothing, and reports **no findings at all** rather than `UNVERIFIABLE`.
  Measured on the QA workstation: unprivileged the provider yields **docker 16 + podman
  5**; every stored root-run report has **docker 16 + podman 0**, and no report has ever
  mentioned podman.

  **Not fixed with the same one-liner, deliberately.** `docker` and `podman` need
  opposite treatment: podman's store follows the *user*, while docker is a system daemon
  reached through a `root:docker` socket — so dropping privileges for docker would make
  *it* dark on any host where the invoking user is not in the `docker` group. The fix has
  to be per-runtime, and it wants verifying under real elevation.

- **`flatpak list` is unscoped, and is the same shape.** `flatpak_source` passes no
  `as_user` and no scope flag, so under a root run it sees system installs plus *root's*
  per-user ones — the invoking user's `~/.local/share/flatpak` apps are invisible.
  **Unverified end to end:** the QA workstation has zero flatpaks installed (user and
  system both), so there is nothing here to observe the discrepancy against.

## Findings

### P-01 — 46 open items under a green tick. FIXED v0.67.0
The summary read `✓ 46 supply-chain finding(s)`. Findings are a to-do list, not an
accomplishment, and a green mark over them reads as "all good" at a glance — the opposite of
the point. It now uses the three-state vocabulary:

```
✓ no supply-chain findings              nothing to do
! N supply-chain finding(s)             open items, exit 0
✗ N supply-chain finding(s), M CRITICAL — INVESTIGATE     exit 1
```

The CRIT case now fails the run. This is the one read-only audit where that is right: a
package on a known-malicious list is not a to-do item, and a scripted run should stop.

### P-03 — the GNOME channel was dark for a week. FIXED v1.13.0

Raised by Paul from his own run logs: the same line in the 21, 24, 25 and 26 August runs —

```
! [gnome] gnome-extensions: could not list extensions (exit 2) — extensions were NOT audited
```

— on a workstation with 24 extensions installed and working.

**Why it was root's fault.** `pkg-audit` is in the no-root set and QA-PA-12 passes when it
runs *alone*. But `-a` / `--everything` re-execs the whole process under `sudo` for the
mutating actions, and after that every action in the run is root, including the ones that
never asked to be. **An action being in the no-root set does not mean it executes
unprivileged — only that it does not elevate on its own.**

GNOME extensions belong to a *login session*, not to the machine: `gnome-extensions` asks
the session bus, and sudo's `env_reset` had already discarded `DBUS_SESSION_BUS_ADDRESS`
and `XDG_RUNTIME_DIR` from the run. Measured:

| invocation | exit |
|---|---|
| `gnome-extensions list` | 0 (24 extensions) |
| `env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR ... list` | **2** |
| `env -u DBUS_SESSION_BUS_ADDRESS ... list` | 0 |
| `env -u XDG_RUNTIME_DIR ... list` | 0 |

**The fix has a trap, and `as_user` alone does not clear it.** `sudo -u` resets the
environment a *second* time, so dropping privileges still hands the child no bus address.
`command.run` gained `session=True`, which re-supplies `XDG_RUNTIME_DIR=/run/user/<uid>`
across the drop — either variable is enough, and that is the one reconstructable from the
uid alone.

**A second way the same channel went dark, found while verifying the first:** unprivileged
but with no session in fettle's *own* environment — a plain crontab entry sets no
`XDG_RUNTIME_DIR` — failed identically. Same symptom, different branch; both closed.

Credit where due: fettle reported this honestly as `UNVERIFIABLE` rather than as a clean
result the whole time, which is the governing invariant working. The invariant is what
made a week-long outage *visible* instead of silent — but visible is not fixed.

### P-02 — you can only tell you fixed something by noticing an absence. OPEN
Raised from real use: two VSCodium extensions were flagged as sideloaded `.vsix`,
`codium --update-extensions` re-fetched them from Open VSX, and the findings simply stopped
appearing. Verified that this is **correct** — the index entries genuinely changed from
`source: vsix` to `source: gallery`, so the provenance concern no longer applies.

But nothing said so. A finding vanishing could equally mean the check broke, the detection
is flaky, or the extension was uninstalled. The audit has no notion of *resolved*.

`pkg-audit` already writes a full JSON report of every finding on each run, so diffing
against the previous one is feasible — but a findings-diff is a feature with its own design
questions (which report is the baseline, how to handle a first run, whether to report
resolutions on every run or only when asked) and does not belong in a QA sweep. Recorded for
a decision.

**Documented in the meantime**: the sideload finding describes *the copy currently
installed*, not the extension's history, and the finding now tells you how to clear it —
`re-install it from the registry to clear this (codium --update-extensions, …)`.
