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
| QA-PA-14 *(new)* | **Every provider says what it examined** | **FAIL → fixed** (P-04) |
| QA-PA-15 *(new)* | "nothing installed" and "examined N, all clean" read differently | **FAIL → fixed** (P-04) |
| QA-PA-16 *(new)* | "could not look" is not recorded as "examined zero" | PASS — guard on the fix |
| QA-PA-17 *(new)* | The enabled GNOME extensions are named | **FAIL → fixed** (P-04) |
| QA-PA-18 *(new)* | The enabled list does not inflate the finding count | PASS — guard on the fix |
| QA-PA-19 *(new)* | **podman's per-user image store is audited** | **FAIL → fixed** (P-05) |
| QA-PA-20 *(new)* | podman's root store is audited too, and the two are told apart | **FAIL → fixed** (P-05) |
| QA-PA-21 *(new)* | docker is never asked as the user | PASS — guard on the fix |
| QA-PA-22 *(new)* | **flatpak is asked as the invoking user** | **FAIL → fixed** (P-05) |
| QA-PA-23 *(new)* | A store that cannot be read is blindness, not an empty store | **FAIL → fixed** (P-05) |

## Open

- ~~**The podman half of the container source is dark under a root run**~~ — **FIXED
  v1.15.0** (P-05).
- ~~**`flatpak list` is unscoped**~~ — **FIXED v1.15.0** (P-05). Same
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

## Open

- **A stopped `snapd` used to hang this action outright** — fixed v1.16.0, written up as
  **F-13** in [clean.md](clean.md) because it hung `clean` too, `--dry-run` included.

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

### P-05 — two more per-user stores audited as the wrong identity. FIXED v1.15.0

The third and fourth instances of the shape behind P-03: **software that belongs to a
person, checked as if it belonged to the machine.**

**podman — 11 images never audited.** Rootless podman gives each user a private image
store in their home directory. fettle asks as root, so podman answers from
`/var/lib/containers/storage` — empty on the QA host — instead of
`~/.local/share/containers/storage`, which holds 11.

| how the audit ran | docker | podman |
|---|---|---|
| as the invoking user | 16 findings | **5** |
| as root (every stored report) | 16 findings | **0** |

No report fettle had ever written mentioned podman. **Worse than P-03 in one specific
way:** GNOME *failed* and said so daily for a week; podman *succeeds* and returns an empty
list, so there was no error to notice at all.

Confirmed under a real `sudo` once the fix had landed: `sudo podman images` → **0**,
`sudo -u paulda podman images` → **11**, and then the whole action: `sudo fettle -P`
reported *22 container images examined — across docker, podman, podman(paulda)* with five
`podman(paulda):` findings, where every previous elevated report had none. **The elevated
run and the unprivileged run now return the same 51 findings** — the audit describes the
machine, not the way it was launched. The second proves the mechanism works under
genuine elevation rather than only under the development proxy; the first proves root's
store is empty *here*, which is why the double-ask below earns its keep somewhere else
rather than on this machine.

**The obvious fix would have broken docker.** docker is the opposite shape — one
system-wide daemon behind a `root:docker` socket that root can always reach and an
ordinary user can reach only if they are in that group. A blanket "ask as the user" fixes
podman here and breaks docker on any host where the invoking user is not in that group.

**And asking *only* as the user would just move the blind spot,** since running containers
as root is ordinary on a server. So podman is now asked **twice** when the two identities
differ, each finding naming its store (`podman:` vs `podman(paulda):`), and the examined
line says where it looked: *33 container images examined — across docker, podman,
podman(paulda)*. `SUDO_USER=root` (a `sudo fettle` from a root shell) is not a second
store, or one store would be read twice and every finding in it doubled.

**flatpak — the same shape.** A `--user` install lives under `~/.local/share/flatpak`, so
as root fettle saw the system apps plus *root's own*. Asked as the invoking user now, which
needs no second query: a normal user's `flatpak list` covers both scopes. Its exit status
was also being discarded, so a flatpak that could not run read as a host with no flatpaks —
that is now `UNVERIFIABLE`. **Honestly unverified end to end:** the QA host has zero flatpak
apps installed, system or user, so there is nothing here to observe the difference against.
The code path is identical to podman's, and identical-looking is not the same as verified.

Both now route through one helper, `util.invoking_user_for`, whose docstring carries the
list of what is per-user and what is machine-wide — so the next provider asks the question
deliberately instead of rediscovering it.

### P-04 — a provider that found nothing said nothing. FIXED v1.14.0

Raised by Paul immediately after P-03: with the session bug fixed, `pkg-audit` reported
*nothing at all* about his 24 GNOME extensions except the coverage sentence.

**The check was right; the reporting was not.** All 24 are distro-packaged, so all 24 are
deliberately skipped — the provider only reports unattributed extensions. But the audit
then printed no line of its own, and because other providers *did* find things, even the
`no supply-chain findings` fallback never fired.

Not a GNOME bug. Measured across the six providers present on the QA workstation:

| provider | findings | actually examined |
|---|---|---|
| aur | 30 | 76 packages |
| container | 21 | 22 images |
| **gnome** | **0** | **24 extensions, 5 enabled** |
| **vscode** | **0** | **11 extensions** |
| **snap** | **0** | **0 — nothing installed** |
| **flatpak** | **0** | **0 — nothing installed** |

**Four of six were silent, hiding two different facts.** gnome and vscode examined 35
objects and cleared every one; snap and flatpak examined nothing because nothing is
installed. Those are different statements about a machine and they rendered identically.

`fettle` had already fixed this one layer up — the action loop in `actions.py` carries the
comment *"no way to tell 'twelve checks were clean' from 'twelve never ran'"* with the fix
directly under it. It was never carried down to the providers inside this audit: the
recurring shape where **a fix applied to one layer is not a fix applied to the pattern.**

Providers now record an `Examined(count, unit, detail)` as they work, and every one prints
its outcome. Four states stay distinct: *not installed* (already handled) · *installed,
nothing to examine* · *examined N, all clean* · *could not look* (the existing
`UNVERIFIABLE`). It is opt-in per provider — `examined = None` renders exactly as before —
and it is recorded in the stored JSON, because a report saying "no findings" is worth
nothing unless it also says what was looked at.

**And the enabled extensions are now named.** The provider's own trust model is that
extension code runs *inside the gnome-shell process* with full session privileges; on a
machine where everything is packaged, the audit had that list in hand and discarded it.
Listed as body detail through `out.detail` (so `--quiet` suppresses it), deliberately
**not** as a `Finding` — findings drive the count and the summary mark, so an informational
one would turn every GNOME desktop into "N supply-chain finding(s)" with a warn beside it.

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
