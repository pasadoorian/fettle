# QA — privilege escalation (cross-cutting)

Root when the work needs it; never when it does not.

Status: **swept — 3 findings fixed, incl. the open H-06.** Minimal, with the stable
release close.

---

## The distinction the whole row rests on

*"Does this change the system?"* and *"does this need root?"* look like one question and
are not. They come apart in **both** directions, which is why the exceptions are written
out rather than derived:

- **mutates, needs no root** — `container-update` talks to the docker/podman socket as
  you; elevating would only add a password prompt.
- **read-only, needs root** — `pkg-integrity` must hash every installed file and cannot
  read ~65 of them unprivileged; `sys-audit` reads firmware and the boot chain through
  root-only interfaces. Reading can need privilege too.

## Findings

### P-01 — `fettle -D` asked for a sudo password to read a CVE cache. FIXED
`advisory-check` reads the package database and a SQLite cache under `~/.cache`. It needs
no root, and as a subcommand it never took any. Giving it a flag in v0.104.0 moved it into
the pipeline's elevation path without adding it to the read-only set, so the flag form
started prompting where the command form did not. **A regression introduced four releases
ago by this same QA pass.**

### P-02 — `sys-audit` was classified as not-read-only. FIXED
It elevated correctly, so nothing misbehaved, but it sat outside `READ_ONLY_ACTIONS` while
being read-only — which left the set meaning "read-only *and* rootless" in practice and
would have misled the next person to read it. Now listed as read-only **and** as a
declared needs-root exception, alongside `pkg-integrity`.

### P-03 — `fettle remote` elevated for everything. FIXED (this was H-06)
`sudo = not dry_run`. So a read-only audit ran as root on the far host and asked for a
password to do it, while the local path had always resolved the request against
`NO_ROOT_ACTIONS` properly.

Recorded as **H-06** during the hardening row, where it was what exposed checksec's
sleep-as-root behaviour. The remote path now asks the same question of the tokens it is
forwarding.

**Unknown tokens count as needing root.** A run holding privilege it did not need works;
one lacking privilege it did need fails partway with a permissions error. Wrong in the
safe direction.

Measured against a live guest:

| | |
|---|---|
| `fettle remote host -P` | `sudo=off` |
| `fettle remote host -D` | `sudo=off` |
| `fettle remote host -V` | `sudo=on` |
| `fettle remote host -c` | `sudo=on` |
| `--full-preview` under `--dry-run` | `sudo=on` — the documented exception |

## Checked and sound

- The sudo re-exec carries `--config` and `PYTHONPATH`, so an elevated child reads the
  same config and can still import fettle from a venv.
- `DEFAULT_CONFIG` resolves from `invoking_user_home()` (SUDO_USER-aware), not
  `Path.home()`. This was Phase 9's highest-impact bug and it returned once; the fix now
  lives at the constant, so all consumers get it.
- Reports and logs are chowned back to the invoking user after an elevated run.
- `--dry-run` never elevates, except `--full-preview`, which exists to say so out loud.
