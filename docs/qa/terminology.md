# QA — terminology consistency (cross-cutting)

**The stated top priority of this pass**, and the row most likely to drift: nothing breaks
when a new summary line invents its own vocabulary, so nothing catches it.

Status: **swept — 4 findings fixed, 1 open question for Paul.**

---

## The evidence that started it

A real multi-action summary from the Debian guest, annotated with what each line came from:

```
✓ packages updated (apt)                          ← update
✓ reboot required (kernel)                        ← rebuild-check
✓ 3 service(s) need restarting                    ← rebuild-check
✓ caches cleaned — 68.8 MiB reclaimed             ← clean
✓ auto-updates: ON (unattended-upgrades)          ← auto-updates
! pkg-integrity: debsums: Not installed           ← pkg-integrity
! 3 High, 32 Medium, 13 Low (218 deviations…)     ← hardening-audit
! sys-audit: 6 warning(s) — …                     ← sys-audit
! advisories: 361 pending, 0 fix-available        ← advisory-check
```

Nothing on the page says which action produced most of those lines. *"218 deviations across
48 packages"* — deviations of **what**? With `--everything` now running fourteen actions,
that is unreadable.

## Findings

### T-01 — most summary lines did not say which action produced them. FIXED
Five of nine lines above carried no attribution. The four that did were hand-written at the
call site, which is why the other ~35 call sites simply never did it.

The pipeline knows which action is running, so it now tags every line itself. The prefix is
**the command name** — `hardening-audit:` — so the summary tells you what to type to look
into the thing it just mentioned.

### T-02 — the hand-written prefixes disagreed with the command names. FIXED
`advisory-check` announced itself as `advisories:` and `container-update` as `containers:`.
Two names for one thing, and neither is what you would type. All hand-written prefixes were
removed in favour of the automatic one, and a test now rejects any new line that starts
with an action name.

### T-03 — green ticks on things that need you to act. FIXED
`✓ reboot required`, `✓ 3 service(s) need restarting`, `✓ 12 config file(s) to review`,
`✓ dpkg --audit found package problems`, `✓ security update(s) need Ubuntu Pro`.

A green tick now means **done, nothing needed from you**. Anything requiring action moved to
the warning mark, so an all-green run genuinely means an idle machine. One of the tests
pinning the old behaviour was already called `test_auto_updates_warns_when_…` while
asserting the green channel — the name knew before the code did.

### T-04 — one flag spelled its action differently. FIXED
The action is `firmware_check` everywhere — including the prefix its summary lines now
carry — but the flag was `--firmware`. `--firmware-check` is now the canonical spelling,
with `--firmware` kept as an alias, because it is what has been documented and typed since
the beginning and breaking it buys nothing.

## The naming rule, written down

Derived from the names that already existed, and it fits all of them. It exists so the
*next* action does not have to be guessed at:

| form | means | examples |
|---|---|---|
| `<thing>-audit` | judges what you **already have** and grades it | pkg-audit, aur-audit, sys-audit, hardening-audit |
| `<thing>-check` | asks whether something is **pending or needed** | rebuild-check, advisory-check, firmware-check |
| bare noun | names the thing it manages or reports | clean, orphans, update, kernel, config-drift, pkg-integrity |

Per Paul's decision the rule is applied to descriptions and documentation; the existing
command names are left alone. A test enforces that no action ends in `-audit` or `-check`
without being classified, and that no third verb (`scan`, `verify`, `inspect`, `analyse`)
creeps in — a third vocabulary is how a CLI stops being learnable.

## Open question for Paul

**An action that ran and found nothing produces no summary line at all.** Six actions ran
against the Debian guest just now and two appeared in the summary. The section headers show
all six ran, but the summary — the part people read — is silent about four of them.

With `--everything` running fourteen actions this matters: a summary of two lines gives no
way to tell "twelve checks were clean" from "twelve checks never ran". The counter-argument
is real too — fourteen lines of `✓ nothing to report` is its own kind of noise.

Options are a line per action, a single closing "N actions ran, M had nothing to report", or
leaving it. Not picked blind: it changes what every run looks like.
