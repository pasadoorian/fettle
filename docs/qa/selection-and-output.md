# QA — default action set · `--only`/`--skip` · output framing

The last three cross-cutting rows, swept together. None of them can damage a machine,
which is why they were left until last — but two decide what actually runs, and a
selection that silently resolves to nothing is a run reporting success for work it never
did.

Status: **swept — 2 findings fixed, 1 recorded and deliberately not changed.**

---

## Default action set

### S-01 — `-a` inspected the machine before it updated it. FIXED
The default set ran `clean, orphans, update, rebuild-check, …` — so `orphans` reported the
system you **booted**, not the one the upgrade just produced. `--everything` had been given
the right order two releases earlier and the two disagreed on nine shared actions.

Now the same order in both: clean (frees space before the upgrade needs it), update, the
rebuild checks (they catch what the update made stale), then orphans and config-drift —
both of which are things an upgrade *creates*.

A test asserts the two orders agree where they overlap, because two different orders for
the same work is exactly the kind of thing nobody notices until the output disagrees.

## `--only` / `--skip`

### S-02 — an unknown name was silently ignored. FIXED
`fettle --only hardening-audi` selected nothing, ran nothing, and **exited 0**. A typo in
a cron line reported success for work that never happened.

Bare action words have always been validated (`fettle hardening-audi` → *unknown action*);
these two flags were not. They are now, and they accept the same spellings as everywhere
else — `upgrade` for `update`, hyphens or underscores.

## Output framing

Checked: `--no-color` produces no escape sequences, colour switches itself off when output
is not a terminal, and exit codes are unaffected by `--quiet`.

### S-03 — `--quiet` is inverted, and is being left alone. RECORDED

`--quiet` suppresses section headers and the end-of-run summary, but **not** the body
detail. So a quiet run drops the two things that organise the output and keeps the raw
file lists:

```
$ fettle -d --dry-run --quiet
    /etc/default/useradd.pacnew
    /etc/gdm/custom.conf.pacnew
    /etc/hosts.pacnew
```

That is backwards for the obvious use — a cron job wants the digest and not the listing.

**Not fixed, because it cannot be done cheaply.** The detail comes from **17 bare
`print()` calls** across the three backends that bypass `Output` entirely, so nothing can
suppress them without touching every one. That is a refactor, and this is the wrong side
of a stable release to do it on.

The help text describes the current behaviour accurately, so nobody is misled — they are
just not well served. Worth doing properly once 1.0 is out.
