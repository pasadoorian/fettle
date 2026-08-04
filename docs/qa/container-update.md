# QA — `container-update` (`-C`)

**Purpose as advertised:** *"pull container images (asks per image; see [containers] config)"*.

**Purpose as a user understands it:** *"my images are stale — refresh them, but don't
change anything behind my back."*

The only state-changing part of the container work; the audit half lives in
`pkg-audit`'s container provider. Opt-in (never in the default set) and rootless — it
talks to the docker/podman socket, not to the package manager.

Status: **swept and fixed.** Five findings fixed in v0.69.0, two of which also applied to
the audit half and were fixed there.

---

## What it actually runs

```
<runtime> images  --format …          # inventory
<runtime> image inspect --format …    # NEW: which of these came from a registry
<runtime> pull <ref>                  # per image, only when policy or a human says so
```

Decision order per image, first match wins:
`auto_update = never` → `auto_update = always` → `never_update` → `always_update` → **ask**.

## Cases and results

**Sweep 1 — v0.68.0 → v0.69.0, 2026-08-04**, on `manjaro-local`, which turned out to be
the ideal target: **both docker and podman installed, with different image sets** (11 and
4), and 6 of the docker images locally built.

| ID | Test | Verdict |
|---|---|---|
| QA-CU-01 | Inventory is complete | **FAIL → fixed** (C-01) — 11 of 14 images reported as the total |
| QA-CU-02 | Decision table honoured | PASS — override beats lists, `never` beats `always` |
| QA-CU-03 | Globs match bare repo and `repo:tag` | PASS — `never_update = ["cvetool", "pyemba-*"]` skipped 5 |
| QA-CU-04 | Unrecognised `auto_update` value | **FAIL → fixed** (C-02) — silently meant "ask" |
| QA-CU-05 | `--yes` never pulls an unlisted image | PASS — the documented contract holds |
| QA-CU-06 | `--yes` says what it left undone | PASS — `next_step` names both remedies |
| QA-CU-07 | Locally-built images | **FAIL → fixed** (C-03) — offered for pulling |
| QA-CU-08 | Daemon unreachable | **FAIL → fixed** (C-04) — inline warning, empty summary |
| QA-CU-09 | Failed pull | **FAIL → fixed** (C-05) — landed under a green tick |
| QA-CU-10 | `--dry-run` pulls nothing | PASS — and now reaches the summary |
| QA-CU-11 | Runs unprivileged | PASS |
| QA-CU-12 | Error text is readable | **FAIL → fixed** — truncated mid-word at 120 chars |

**Not exercised live:** a *failing* pull (QA-CU-09) — every pullable image on the QA host
resolves upstream, so forcing a failure would have meant mutating a read-only host. Covered
by a regression test proved failing without its fix, and recorded here rather than implied.

## Findings

### C-01 — half the machine was invisible, in both halves of the feature. FIXED v0.69.0
`next((r for r in RUNTIMES if command.which(r)), None)` — **the first installed runtime
wins**. The QA host has docker *and* podman with different image sets, so `-C` reported
`11 image(s) considered` on a host with 14, and podman's `alpine`, `fedora` and `ubuntu`
were never considered at all. Nothing said so.

The same line, with the same effect, was in the **audit** provider: `pkg-audit` audited
docker and produced a report that read as though it covered the machine.

Both now iterate every installed runtime, and label each image with the runtime it came
from when more than one is present — which matters immediately, since this host has
`almalinux:10` in *both* stores.

This is the K-01 lesson arriving on schedule: *a fix applied to one action is not a fix
applied to the pattern.* Here the two copies were in the same feature, so the second one
was found by looking rather than by waiting for its own sweep.

### C-02 — `auto_update = false` silently meant "ask". FIXED v0.69.0
`[containers]` is a passthrough dict, so the config loader — which warns about unknown
*keys* — never inspects the *value*. `auto_update = false` is a natural thing to write in
TOML and reads as "never"; it matched none of the three modes and fell through to "ask".
Both spellings measured: `false` and the typo `"nevr"` behaved identically to no config at
all, with no warning. Now reported, still defaulting to the safe mode.

### C-03 — it offered to pull images that were built here. FIXED v0.69.0
6 of this host's 11 docker images are local builds (`cvetool`, `pyemba-*`,
`docker-jetkvm-jetkvm`). `-C` offered to pull every one, and `<runtime> pull cvetool:latest`
resolves to **Docker Hub** — a registry that never served that image.

Measured today: the pull fails (*denied / unauthorized*), so the cost is guaranteed
failures, not danger. **Stated precisely because the stronger version is tempting and
wrong**: those names are *unclaimed*, not reserved, so were one published, a "yes" would
replace a local build with a stranger's image. That is a hazard the design created, not
something that is happening — the same distinction the `kernel` sweep got wrong once and
had to withdraw.

The discriminator is local and exact: **a pulled image has a `RepoDigest`, a built one has
none** — verified on both runtimes, including for bare-name library images like
`python:3.12-slim` and `almalinux:10`, which are pulled and correctly stay eligible. Local
builds are now reported as `built here, not from a registry — nothing to pull`.

### C-04 — a dead daemon produced an empty summary. FIXED v0.69.0
Measured with `DOCKER_HOST=unix:///nonexistent`:

```
! could not list images (exit 1: failed to connect to the docker API …)
▸ Summary
  nothing to report                      ← and exit 0
```

The inline warning was already right; the digest — the part people read after `fettle -a`
— said nothing at all. **This is F-01 (the dead fwupd daemon) in a different action**, and
the reason it survived is that the inline half was correct, so it did not look like the
bug it was. Now:

```
! containers: 0 image(s) pulled, 4 left for a human — but docker could NOT be read;
  those images were not assessed
```

Note what that line does: it reports podman's 4 images *and* refuses to let them stand for
the machine.

### C-05 — failures and outstanding decisions wore a green tick. FIXED v0.69.0
`out.summary_add(...)` unconditionally, so `✓ containers: 0 image(s) pulled, 3 failed` and
`✓ containers: 0 image(s) pulled, 11 left for a human` were both ticks. Now: a failed pull
is `✗` (it is a command fettle ran that did not work), outstanding decisions are `!`, and
`✓` means asked and answered.

### Also fixed
The listing error was cut at 120 characters, which landed mid-word (`…if the daemon is
running: d`) — exactly where the useful part starts. Now shown whole.

### A wording bug the multi-runtime work exposed
With local builds labelled, the audit's `:latest` finding was visibly wrong on them:
*"**pulled by** the mutable tag ':latest'"* on images that were never pulled. The tag is
mutable either way — a re-pull and a rebuild both move it — so it now says
*"':latest' is a mutable tag"*, which is true of both.
