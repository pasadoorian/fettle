# Changelog

> **1.0.0 is the first official release.** Every action was specified, run against seven
> live systems, and fixed where it misbehaved or explained itself badly — the pass is
> recorded in `docs/qa/`. `fettle web` is the one feature it did not reach, and stays
> marked experimental.
>
> Entries below 1.0.0 are the history of getting there, kept as written.

All notable changes to fettle are recorded here. Newest first.

## [Unreleased]

## [1.9.0] — extras no longer run on top of a failed system upgrade

Second fix from the 2026-08-12 code review (H-06).

`actions._update` evaluated both halves of the upgrade in one list literal:

```python
results = [backend.update_system(ctx), backend.update_extras(ctx)]
```

so `update_extras` ran before anything had looked at whether `update_system` worked. A
failed pacman transaction was followed straight away by `yay -Sua`, rebuilding AUR
packages against a half-upgraded system; Debian and RHEL went on to flatpak and snap the
same way. Extras are the step most likely to compile against whatever the system upgrade
just left behind, which makes them the worst thing to run next.

The two calls are now sequenced, and extras run only if the system upgrade recorded no
failed command **and** the backend did not report failure. When they are skipped the run
says so rather than going quiet.

**A declined upgrade stops it too.** Without `--yes` a non-zero exit means the user
answered "no" at the package manager's prompt — and someone who declined the system
upgrade did not ask for their flatpaks to be updated regardless. That path stays a
warning, not a failure, as before.

Verified live in a Debian container with a package manager rigged to fail and a fake
`flatpak` on `PATH` that logs every invocation: the log stayed empty, the skip was
reported, exit 1.

### The live check found something else first

The obvious way to make an upgrade fail is to point the repositories at nothing. Doing
that produced **`✓ packages updated (apt, flatpak)` and exit 0** — because `apt-get
update` exits 0 with every repository unreachable and `full-upgrade` then has nothing to
do. The guard was right and simply never fired, because apt never admitted to failing.

That is **H-05**, the next fix in this series, now demonstrated end to end rather than
inferred: on a host that cannot reach a single repository, `fettle -u --yes` currently
reports a successful update.

## [1.8.0] — fettle no longer deletes pacman's database lock

First fix from the 2026-08-12 code review (H-02), and it closes a finding the `clean` QA
sweep had already raised and left open as **F-05 / QA-CLEAN-16 — UNTESTED**.

`clean_caches()` opened with an unconditional `rm -f /var/lib/pacman/db.lck`, announced
as *"removed stale pacman db lock"* — while nothing had established that it was stale.
libalpm takes that lock to stop two package transactions running at once, so deleting one
that pacman, pamac or an AUR helper is holding lets a second transaction start against the
same database.

### What it does now

**It never removes the lock.** Three outcomes:

- **Held by a live process** — refuses the clean and names the holder (`pid 4242
  (pacman)`), exit **1**. Refusing is right for the cache as well as the database: a live
  transaction is reading the very files `paccache` would delete.
- **Present, unheld** — names the file, gives the removal command, and gets on with the
  clean. A genuinely stale lock is rare and removing it is the user's call.
- **Present, but `/proc` was unreadable** — refuses, and says it could not tell. "I could
  not determine it" is not "it is safe", which is the invariant this project already
  applies to reports, applied here to a destructive action.

### Two implementation choices worth keeping

**Holders are matched by inode, not by path.** A path comparison would miss a lock deleted
and recreated under the same name — precisely the window this check exists to notice.

**`/proc` is read directly rather than shelling out to `fuser` or `lsof`.** Neither is
installed on a minimal Arch system, and a missing tool would have silently downgraded a
safety check into "no holders found".

`actions._clean` now respects a backend that *declines* rather than fails. Without that,
a refused clean fell through to *"caches already clean — nothing to reclaim"* — a
description of a clean that did not happen.

### Verified

Four new tests, each proved to fail against the previous code, and each covering a
distinct behaviour (restoring the old `rm` fails all four; making "cannot tell" mean
"unheld" fails exactly one). Live in an `archlinux:latest` container against a process
genuinely holding the lock open: holder identified, nothing ran, exit 1, lock intact.

The Arch test harness now defaults `ctx.root` to a path that cannot exist. Without it,
every clean test would have passed or failed according to whether a pacman transaction
happened to be running when `pytest` was invoked — the "tests that assert on the host"
trap this suite has hit before.

## [1.7.4] — "re-run with sudo" was advice for a problem you do not have

Testing `-M` on a machine that now has `bpftool` turned up a wording bug rather than a
code one.

**`compromise-check` elevates itself.** It is classified read-only *and* needs-root, so a
plain `fettle -M` re-execs under sudo once, up front — exactly as `sys-audit` does. The
only invocation that stays unprivileged is `--dry-run`. Yet every blind entry ended in
*"re-run with sudo to include it"*, which tells the reader to do something they never
needed to do, about a line they could only be reading under `--dry-run` in the first
place. All five now say *"run it without `--dry-run` and fettle elevates for you"*.

### Requirements, rewritten

- **The install commands are spelled out for all three families** rather than left to a
  table cell, and now cover `bpftool` alongside `checksec`.
- **`bpftool` needs root to list anything** — it exits **255** for an ordinary user with
  the error on stderr and nothing on stdout. Installing it is therefore only half the
  job: it helps a run that elevates, which a plain `fettle -M` does and a `--dry-run`
  does not. That is the fact a prerequisite list is actually for, and it was missing.
- The Arch/Manjaro package remains `bpf`; verified installed and working here
  (`bpftool v7.8.0`, from `bpf 7.1.7-1`).

## [1.7.3] — the `bpftool` install hint named a package that does not exist on Arch

`compromise-check` reports a missing `bpftool` as blindness and offers the command that
would fix it. On Arch and Manjaro that command was **`sudo pacman -S bpftool`**, and
there is no such package — not in the repos, not in the AUR. Reported by Paul, on the
machine the feature was developed on.

Measured rather than guessed this time: `pacman -Fx 'bin/bpftool$'` gives **`extra/bpf`**
(part of the `linux-tools` group), while Debian 13 and Rocky 9 each carry a `bpftool`
package of their own. The hint is now per-backend, the same way the `checksec` hint
already was — and for the same stated reason, which this change is the counter-example
to: *a confidently wrong install command is worse than none, because it sends someone to
a shell prompt to be told the tool does not exist, and they conclude fettle is broken
rather than that the hint was.*

The README's Requirements table said `bpftool` in the Arch column too; both it and the
wiki now name `bpf` and say outright that the package is not named after the binary
everywhere. A parametrised test pins all three distro names.

## [1.7.2] — docs catch up with the layout, and the QA matrix gains a row

Documentation only.

- **`docs/qa/README.md`** lists `compromise-check` in the coverage matrix (swept at
  v1.6.1, five findings, all fixed) and the headline count moves to **24 of 25 features
  swept** — `web` remains the one on hold.
- **The wiki's hardening page** still described the table-per-axis layout that v1.7.0
  replaced. It now describes one ranked table with a GROUP column, and records the two
  behaviours a reader is most likely to be surprised by: subjects truncate in the
  **middle** rather than at the end, and width follows the terminal to a cap of 120 but
  is fixed at 80 when piped.
- **The wiki's compromise page** gains a *How to read the output* section with a worked
  example, which it had been missing entirely.

## [1.7.1] — the smoke tests were asserting on a label that moved

v1.7.0 keyed the audit's coverage lines by the short axis **name** (`filesystem:`)
instead of the prose title (`Filesystem hygiene`). **Nine packaging smoke assertions
were grepping for the title** — three in `ci.yml`, five in `release.yml` and two in
`packaging/binary/smoke.sh` — and every one of them silently stopped matching.

CI caught it on the `packages` job; the unit suite could not, because the assertions live
in the workflows rather than in pytest. The one in `smoke.sh` mattered most: it is the
guard that proves the axes were **compiled into the binary**, whose whole design point is
that a build missing them looks cautious rather than broken. It would have failed the
next release tag.

All nine now match on the axis **names**, which are also the `[hardening] disable_axes`
keys, the JSON keys and the table's GROUP column — the most stable token fettle has for
this. Verified by building the `.deb` and running the exact CI command against it in a
Debian 12 container locally, rather than by pushing and watching.

## [1.7.0] — the QA sweep for `compromise-check`, and one table instead of four

The sweep every other feature had. Five defects, all fixed; the write-up is in
`docs/qa/compromise-check.md`.

### Clear — the output

**One table across every check group, ranked worst first**, replacing four separate
tables with four repeated `SEVERITY / SUBJECT / FINDING` headers. The worst thing on the
machine was previously somewhere in the middle. The per-group coverage lines stay above
it — they carry the `(487 checked)` number, which a findings table cannot — and the GROUP
column drops itself when every finding came from one group.

**The table broke on the subjects it actually has.** A 56-character unit name against a
30-character column took a row of its own and left the finding indented into the middle
of the screen with nothing to its left; two of four findings on the reference machine
looked like that. Now:

- **Width follows the terminal**, capped at 120, and fixed at 80 when output is not a TTY
  so a run-log does not change shape with the window that produced it.
- **Middle-truncation keeping both ends.** Head-truncation renders
  `rumble-agent-4b7a89f3-…` and `rumble-agent-e87f42e9-…` identically, turning two
  findings into one indistinguishable pair.
- **Column widths from the data**, never narrower than the header — with subjects like
  `/tmp` and `/var` the computed width was 6 and the header read `SUBJECTFINDING`.

`hardening-audit` shares the renderer and gets all of it.

### Fixed — truthfulness

- **`--only <non-default action>` blamed the backend and exited 0.**
  `fettle -a --only compromise-check` said *"none of the default actions are implemented
  by the arch backend"*, which is false twice over: the backend implements it, and the
  real cause is that `--only` narrows the default set and this action is not in it. **Not
  specific to this action** — `--only hardening-audit`, `--only kernel` and
  `--only only-update` produced the same false sentence. Now says what was asked for,
  that `--only` narrows rather than adds, the command that does work, and exits 1.
- **`--quiet` was inverted.** `-M -q` suppressed the headers and the summary and printed
  the entire findings table, because the body went through a bare `print()` that never
  consulted `Output`. Fixed with a new `Output.detail()` channel, and applied to the
  binary axis too so both halves of `-H` obey the flag rather than one of them. This is
  one instance of the repo-wide `--quiet` defect on the outstanding list; the other call
  sites are untouched.

## [1.6.1] — the README banner stops going stale

It read **"This is 1.0.0 — the first official and tested release of fettle"** for six
releases, so anyone landing on the front page was told the current version was 1.0.0
while the repo was at 1.6.0. Point-in-time wording in a place nobody re-reads.

It now says fettle is stable and released, and points at the Releases page and the
changelog for the current number — true at every version, and nothing to remember to
edit. The topgrade comparison's maturity row loses its pinned version for the same
reason.

## [1.6.0] — `compromise-check` lands: dashboard, exit status, documentation

Phase 4, and the feature is finished. The detection work shipped in 1.1.0-1.5.0; this is
everything that makes it usable by someone who did not write it.

### The exit status now turns on severity

`fettle -M` exits **1** on a **High or Critical** finding, or on a run that examined
nothing at all. It exits **0** otherwise, including with Medium and Low findings
present.

That distinction is the whole design. Every real machine has findings — the reference
desktop has four, and all four are explicable in a sentence: two vendor agent services,
a cron entry `timeshift` writes itself, and a self-updating AppImage. Exiting non-zero on
any of them would make `-M` red forever and teach people to ignore it, which is the trap
`-H` deliberately avoids. High and Critical are the two bands that already print the
preservation banner, so the status and the banner now agree about what "stop and look at
this" means.

Partial blindness — `bpftool` absent, `/sys/fs/bpf` unreadable — is reported loudly and
does **not** set the status, matching how every other action treats a missing tool. Only
a run that examined *nothing* fails on blindness, and it is recorded as `BLIND` rather
than `FOUND`, so automation that needs to tell "could not read `/sys/fs/bpf`" from
"found a rootkit" can, even though fettle's documented convention exits 1 for both.

### The dashboard

- `compromise-check` reports render in `fettle report`, reusing the hardening-axes
  renderer because the payload is the same shape.
- **A compromise finding is not capped in the host verdict.** The hardening bands are
  capped at Medium there, because every desktop has Critical-band packages and letting
  them drive a fleet page trains you to ignore the colour. This is the opposite kind of
  thing: a host running something nobody installed must not sit on that page looking
  like a host with a stale package.
- **A blind compromise run reaches the card too.** A host whose rootkit checks could not
  run is not a host with nothing to report, and at fleet scale that is exactly the
  difference nobody notices.
- The dashboard reads both `axes` and `groups` keys. `hardening-audit` writes the first
  and `compromise-check` the second; renaming either would make reports already on disk
  unreadable, and stored reports are forever.

### Documentation

- **README**: a sixth feature family, a `-M` row in the what-works-where matrix with a
  footnote on why it is not in the default set, a quick-start line, and `bpftool` as an
  optional tool.
- **Wiki**: a new [Compromise indicators](https://github.com/pasadoorian/fettle/wiki/Compromise-check)
  page — what each group checks, what needs root and what does not, the exit status, and
  a *"if you got a finding"* section that leads with **do not clean up yet**. Plus the
  edits that situate it: Home and the sidebar (five security audits, not four),
  Maintenance-actions (the `-M` row and the `--everything` ordering), Reference (the exit
  row), and two cross-links that are the point rather than decoration — `pkg-audit` tells
  you a package you installed was in the June 2026 AUR wave, `compromise-check` tells you
  whether the implant is still here; and `sys-audit` *judges* Secure Boot posture while
  `compromise-check` only *states* it.
- `fettle -h` gains `-M` in the which-check-is-which block, where it says outright that
  it reports anomalies to investigate and never a fix.

## [1.5.0] — running-process provenance

Phase 3 of `compromise-check`, and the last of its detection work. One question asked
five ways: **is anything executing that the package manager never put here?**

### Added — `processes` group

- **Executed from memory.** A process whose binary came from `memfd_create` was never a
  file: nothing to hash, no package that could own it, nothing for `pkg-integrity` to
  verify. It is the technique modern Linux malware converged on precisely because it
  defeats every check that starts by looking at a file. Reported **Critical**, with the
  command line and the two commands that capture it before it exits.
- **Deleted but running**, graded by provenance rather than by the deletion. A binary
  that ran from `/tmp` and then unlinked itself is **High**; an unowned one in an
  ordinary location is **Low**; a package-owned one is not a finding at all — it is an
  upgrade that replaced a running process, and the useful advice is "restart it to pick
  up the fix".
- **Listening sockets with no package behind them.** The modern replacement for
  rkhunter's `backdoorports.dat`: a port number means nothing — 4444 is as legitimate as
  443 if something you installed is behind it — while a listener nobody can account for
  means something whatever port it is on. Parsed from `/proc/net/*` and mapped to
  processes through `/proc/<pid>/fd`, no external tools.
- **Promiscuous interfaces**, and **regular files under `/dev`** — two ideas taken from
  rkhunter and chkrootkit that are still true and still cheap.

### chkrootkit's best idea, implemented so that it can fire

Version 0.59 added a "process executed from memory" test, and it **cannot match**:

```sh
ls -alR /proc/*/exe | grep "^\/memfd:.*?\(deleted\)"
```

`^` anchors to a line that begins `lrwxrwxrwx 1 root root 0 …`, not `/memfd:`, and
`.*?` is a PCRE lazy quantifier that `grep` without `-P` reads as `.*` followed by a
literal `?`. Verified against a synthetic line of exactly the right shape: it matches
neither the original pattern nor the anchor-stripped one. The threat is the right one
to pick, so it is implemented here properly — and verified against a **real** fileless
process (a memfd holding an interpreter, `execve`'d), not a mock.

### Two calibrations that came from being wrong first

- **Bridge ports are excluded from the promiscuous check.** The first run reported two
  findings on the reference machine — the physical NIC and a docker `veth`. Both are
  bridge ports, and a bridge member *has* to accept frames not addressed to it; that is
  what bridging is. Without the exclusion this fires on every VM host and every
  container host in existence. `/sys/class/net/<if>/brport` exists for exactly the
  bridge ports, so it is a clean discriminator, and the excluded ones are still counted
  in a note — silent filtering is indistinguishable from having found nothing.
- **`ip link` and sysfs disagree about promiscuity, and the fix line says so.** On the
  reference machine `ip link` prints `<BROADCAST,MULTICAST,UP,LOWER_UP>` with no
  `PROMISC` while `/sys/class/net/<if>/flags` has the bit set; `ip -d` reports the truth
  as a separate `promiscuity` counter. Anyone cross-checking a finding with `ip link`
  and seeing no PROMISC would reasonably conclude fettle was wrong.

### Coverage

**Unprivileged, 9 of 26 listening sockets resolved** on the reference machine: mapping a
socket to its process means reading `/proc/<pid>/fd`, which an ordinary user cannot do
for anyone else's processes — 760 were denied. Reporting "no unowned listeners" from a
third of the data would be a clean result over an unasked question, so the unresolved
count is reported as blindness. As root the same run resolves everything.

### Fixed

- A pre-existing test time-bomb, in its own commit: a dashboard fixture pinned to a
  wall-clock date asserted a host card reads OK, and the staleness threshold is 7 days,
  so it passed for exactly a week and then failed forever.

## [1.4.0] — kernel, loader and boot chain

Phase 2 of `compromise-check`: two new groups covering the layer below userspace. Five
checks, and **two of them exist in their present form only because the obvious
implementation was measured and thrown away.**

### Added — `kernel` group

- **`/etc/ld.so.preload`** — the cheapest high-value check here. A stock Arch, Debian or
  RHEL system does not have this file, and every LD_PRELOAD rootkit family creates it.
  Its existence is the finding; each library it names is reported with its owning
  package, so a legitimate `libeatmydata` is recognisable at a glance.
- **Loaded modules and kernel taint, reconciled against each other**, because neither
  alone says anything. The reference machine reads taint **12288** — out-of-tree and
  unsigned — while all 155 loaded modules are signed and none reports taint of its own.
  Taint is sticky and never names its cause, so this records that something was loaded
  and unloaded: a DKMS rebuild nearly always, a self-removing LKM rootkit occasionally.
  Reported at **Low**, with the ordinary explanation first and `journalctl -k` to settle
  it. Unsigned modules are reported alongside the enforcement state, since "none loaded"
  means nothing when `sig_enforce` is off and Secure Boot is disabled — which is the
  reference machine's actual configuration.
- **Hidden processes**, by comparing `/proc`'s directory listing against the PIDs the
  **cgroup hierarchy** accounts for. Two independent kernel interfaces: `ps`, `top` and
  `pgrep` all read `/proc`, so a `getdents64` hook — the technique the June 2026 AUR
  wave used — blinds all of them at once, and cgroup membership is not read that way.
- **The eBPF surface** — pinned objects in `/sys/fs/bpf`, plus loaded programs via
  `bpftool` when present. The wave's three fixed pin names (`hidden_pids`,
  `hidden_names`, `hidden_inodes`) are named IoCs, so "was I hit by that campaign" is a
  string comparison rather than an inference.

### Added — `boot` group

- **Bootloader configuration**, for the loader actually in use — grub, systemd-boot or
  rEFInd. chkrootkit 0.59's Bootkitty check is the right threat and one grub-only line;
  this reads whichever loader is present and looks for injected `LD_PRELOAD`, an `init=`
  pointing into a world-writable directory, and blacklisting of an integrity subsystem.
- **Secure Boot state accompanies every boot result, always.** The reference machine's
  grub configuration is clean *and* Secure Boot is disabled with the platform in setup
  mode, so nothing verifies the bootloader, kernel or initramfs. Printing the first
  without the second is the half-truth that makes a report feel reassuring and be
  worthless.

### Measured, then rejected

- **The classic hidden-process sweep is unusable.** Walking every PID to `pid_max` and
  stat-ing `/proc/<pid>` — what `chkproc` does — produced **6,272 false positives** on
  the reference desktop: every non-leader *thread* answers a direct stat, while `readdir`
  correctly lists only thread-group leaders. Filtering on `Tgid == Pid` fixes the
  correctness and leaves the cost, **7.8 seconds** for 2.5 million stat calls. The cgroup
  census gives the same answer — an exact 1046-against-1046 match — in **0.01 s**, needs
  no privilege, and holds inside a PID namespace.
- **Ownership is the wrong test for a generated boot config.** `/boot/grub/grub.cfg` is
  written by `grub-mkconfig` and `/boot/loader/entries/*.conf` by `kernel-install`;
  neither is package-owned on any machine. Judged on content only. `/etc/default/grub`
  and `/etc/grub.d/*` *are* package-owned, so those keep the provenance test. This is
  the third time the same asymmetry has come up — after user crontabs and user units —
  and it is now stated as a rule in each module that has to make the distinction.

### Fixed

- **A sub-check could mark its whole group "not applicable".** `na` is a property of the
  entire group, so the hidden-process check setting it on a host without cgroups would
  have rendered the kernel group as one "not applicable" line — hiding an
  `/etc/ld.so.preload` finding sitting right next to it. Sub-checks now report their own
  blindness and `na` stays a whole-group verdict.
- **The summary now carries coverage.** A run where most checks were blind and one
  trivial one succeeded summarised as "nothing to report", because `actions.run` fills
  an empty summary with exactly that. The screen said "plus N not checked"; the summary
  did not, and the summary is the line a fifteen-action sweep is read from. It now says
  `2 Medium, 2 Low; 3 check(s) could not look`.

Verified live on two families, each check with a planted positive control: the reference
desktop reports the taint discrepancy and nothing else new; a Debian container with a
planted `/etc/ld.so.preload` and an injected `LD_PRELOAD` in `grub.cfg` reports both at
High with the preservation banner.

## [1.3.1] — a permission error that only happened on other people's Pythons

CI failed on 1.3.0 after a green local run, and the cause was neither the code nor the
test being wrong on its own terms.

**`Path.is_dir()` handles a permission error differently depending on the Python
version.** On 3.11-3.13 it calls `self.stat()` and re-raises anything
`pathlib._ignore_error` does not cover — ENOENT, ENOTDIR, EBADF and ELOOP, but **not
EACCES**. On 3.14 it is `os.path.isdir()`, which swallows everything and returns False.
The development machine runs 3.14; CI runs the other three.

**The user-visible bug this hid.** Probing `/var/spool/cron/crontabs` requires searching
`/var/spool/cron`, and **Debian ships that directory `0730 root:crontab`**. So on a
Debian host running python 3.11, an unprivileged `compromise-check` raised out of the
persistence group entirely; `run_all` caught it and reported the whole group blind. That
user got **no** persistence findings at all — not the unowned units, not the unowned
cron entries — instead of the ones the check can see perfectly well without root. The
failure was quiet, correct-looking, and exactly the shape this action exists to prevent.

### Fixed

- Every filesystem predicate in `fettle/compromise/` now goes through `is_directory()`
  or `is_regular_file()`, which cannot raise. "Cannot tell" is answered by the caller
  asking explicitly, rather than by whichever interpreter is installed.
- Nested unreadable directories are reported once. On Debian both `/var/spool/cron` and
  `/var/spool/cron/crontabs` are searched; naming the second when the first is already
  unreadable says the same thing twice and implies we know the second exists.

### Testing

- **The CI-only failure is now reproducible on the development machine.** A test
  simulates 3.11-3.13's `Path.is_dir()` by mirroring `_ignore_error`'s errno list
  exactly, so the scenario is pinned on every interpreter rather than only where the
  filesystem happens to behave that way. Reverting the fix fails it here.
- The permission-denial tests now skip as root, where `chmod 000` denies nothing and
  they would assert blindness on a run that could see everything. That is the same trap
  the QA pass hit when five tests passed only on the developer's machine.
- Verified on python 3.11 in a container both as root (5 skipped, correctly) and as an
  ordinary user (all 68 exercised) — the combination CI actually runs.

## [1.3.0] — the rest of persistence: cron, `at`, and every user's own units

Phase 1 of `compromise-check` is complete. M1.2 covered system unit files; this adds the
four remaining places something can arrange to run — and the reason it is not simply
"the same check pointed at more directories" is that **half of them cannot be judged the
same way**.

### The asymmetry, which is the whole design

`/etc/cron.d` and the `cron.{hourly,daily,…}` directories are **package-managed**, so
"no package owns this file" means something there. `/var/spool/cron/**` and
`~/.config/systemd/user/` are **never** package-managed — `crontab -e` and a user's own
config create them by definition — so the same test applied there would report every
user crontab and every user unit on every machine as a finding. That is the
"unnecessary homework" failure in its purest form.

So user-scope persistence is **reported as review material** — here is what is
scheduled, and for whom, in the saved report — and becomes a *finding* only when the
command runs from somewhere a scheduled binary does not belong.

### Added

- **System cron**: `/etc/cron.d`, `/etc/cron.{hourly,daily,weekly,monthly}`,
  `/etc/crontab`, `/etc/anacrontab`, judged on ownership like the system units. On the
  reference machine this finds exactly one thing —
  **`/etc/cron.d/timeshift-hourly`**, which timeshift writes at runtime when you enable
  scheduled snapshots rather than shipping in its package. Root, hourly, and owned by
  nobody.
- **Per-user crontabs**, both spool layouts (`/var/spool/cron/<user>` on Arch and RHEL,
  `/var/spool/cron/crontabs/<user>` on Debian and Ubuntu).
- **Queued `at` jobs**, reported by existing rather than parsed: a one-shot job on a
  machine that does not otherwise use `at` is worth a human look on its own.
- **`~/.config/systemd/user/` for every real user**, not just the caller — the non-root
  branch of the June 2026 AUR wave, which dropped its unit there when it lacked root.

### Truthfulness

- **An unreadable spool is blindness, not emptiness.** `/var/spool/cron` *absent* means
  there are no user crontabs; *present and mode 0700* means there may be any number and
  we cannot see them. Debian ships it `0730 root:crontab`, so an unprivileged run there
  hits the second case every time — and silently reporting zero scheduled jobs on a host
  that has them is the failure this project is named for. Same treatment for the `at`
  spools and for home directories that cannot be opened.
- **The blanket privilege notice is gone.** Every unprivileged run used to print
  "user-scope persistence, at jobs and the eBPF surface need root". That was true while
  nothing was implemented and became false the moment a real check landed — those checks
  now run, and mostly succeed, without root. Each check names the directory *it* could
  not open, which is more useful and cannot end up disagreeing with what the run
  actually did.

### Parsing, and where it deliberately gives up

- A system crontab has a user column (`m h dom mon dow USER command`) and a user crontab
  does not. Getting that backwards reports the *user name* as the command on one and
  swallows the first word of the command on the other — and both still look like
  plausible output, which is why it is a named parameter rather than a guess.
- `argv0` steps over `sudo`/`nice`/`env` and their own options, then **stops at the first
  real token** and returns it only if absolute. It does not keep hunting for something
  path-shaped: `timeshift --check /tmp/report` would otherwise resolve to `/tmp/report`
  and be reported as a job running out of `/tmp`. Missing a finding is recoverable; an
  alarm over an argument teaches people to stop reading the alarms.
- `run-parts` ignores files with a dot in the name, so `.pacsave`/`.dpkg-dist` leftovers
  in the cron directories are skipped here too. They are not scheduled, so reporting
  them as scheduled jobs would be wrong.

Verified live on two families: the reference desktop reports 3 findings from 487
subjects, all explicable; a Debian container with a planted `@reboot root
/var/lib/x/agent` reports it as High with the preservation banner, while the root
crontab sitting beside it is reported as review material and not flagged.

## [1.2.0] — boot persistence: what starts at boot that no package installed

`compromise-check`'s first real check group, and the one that closes the gap the whole
feature was proposed for. The June 2026 AUR wave persisted with a systemd unit —
`Restart=always`, dropped in `/etc/systemd/system`, payload under `/var/lib`.
`pkg-audit` could tell you a package you installed was in that wave. Nothing could tell
you whether the unit it dropped is still on the machine.

### Added

- **`persistence` check group.** Every real `.service` and `.timer` under
  `/etc/systemd/system`, `/usr/local/lib/systemd/system` and `/usr/lib/systemd/system`,
  matched against the package database. Each unowned unit reports the binary it runs and
  whether anything vouches for *that*, because a unit nobody owns pointing at a binary
  nobody owns is a different claim from a hand-written unit starting `/usr/bin/rsync`.
- **`/usr/lib/systemd/system` is scanned**, despite being the distribution's own
  directory and costing 480 stats. All 480 of its units are package-owned on the
  reference machine, which makes an unowned one there a file in the distro's unit
  directory that the distro did not put there — the place an implant would most want to
  be.
- **`[compromise] disable_checks`** now has a group name to take, and is documented in
  `fettle.toml.example`.

### The gap this closes, proved rather than asserted

`hardening-audit`'s services axis already reports unpackaged units — but only above an
exposure score of 7.0, because there unpackaged-ness is one input into a judgement about
*reach*. The AUR wave's unit runs one binary and opens no sockets, so it scores low and
that check skips it. A test builds that exact unit, runs it past the services axis, and
asserts the axis finds nothing; feeding the same unit through at exposure 8.5 produces a
finding, so the threshold is demonstrably the reason and not something incidental.

### Calibration — three rules that sounded right and were wrong

Measured on the reference desktop before shipping, because the difference between an
actionable check and homework is entirely how often it fires on a healthy machine.

- **Symlinks and `.wants/` are excluded: 41 findings become 2.** Both are what
  `systemctl enable` creates. They carry no content and each points at a unit examined
  here on its own merits.
- **`Restart=always` is not a signal.** It is in **27 of the 480** distro units and in
  *both* legitimate unowned agents on the reference machine. Escalating on it would have
  produced two High findings and a preservation banner on a clean box. It is now printed
  as context and never scored.
- **An unowned binary is not a signal either.** Every vendor install is unowned by
  definition. What survived is the target's *location*: `/opt` and `/usr/local` are
  where the FHS puts software the package manager did not install, while `/tmp`,
  `/dev/shm` and the `/var` state directories are not places a service binary belongs.

### Fixed

- **A fully blind run summarised itself as clean.** With every group unable to look, the
  action added no summary line, so `actions.run`'s "an action that said nothing gets
  *nothing to report*" fallback filled it in — while the screen directly above said "not
  checked". The exact inversion this action exists to avoid, found by the M1.1 invariant
  test the moment a real group landed. A blind run now says so in the summary too.
- **A dead unit was graded `High` and given the preservation banner.** Found on the
  first live run, on a healthy machine: a unit pointing at a binary that no longer
  exists (a vendor had renamed it). A unit whose target is missing cannot execute
  anything, which makes it the *least* dangerous state here rather than the most. Now
  `Low`, and worded as the hygiene finding it is.

## [1.1.0] — `compromise-check`: the action, not yet its checks

The first milestone of a new feature family. fettle could tell you a package you
installed was in the June 2026 AUR wave; it could not tell you whether the implant that
wave dropped is still on the machine. That is a different question from every other one
fettle asks — *is this configured safely* has a fix command, *is something already here*
has an investigation — so it is a different action.

**This release ships the action and its plumbing. It ships no checks.** `fettle -M`
runs, and says exactly that. The first real checks (unowned systemd units, user-scope
persistence, timers and cron) land in the next milestone.

### Added

- **`compromise-check` / `-M`**, read-only, opt-in, and **included in `--everything`
  where it runs last** — after `advisory-check`, because an update removes a vulnerable
  package and does not remove an implant. Available as a flag, a long flag and a bare
  word, on every distro family.
- **`[compromise] disable_checks`** in the config, deliberately separate from
  `[hardening] disable_axes`. Someone silencing a chatty hardening axis must not silence
  a rootkit check as a side effect. A name that matches no group is reported, not
  ignored — believing a rootkit check is off when it is running, and believing it is on
  when it is not, are equally bad and equally silent.
- **A real-user filter** for the user-scope checks to come. wopr has **32 `nixbld*`
  accounts pointing at `/var/empty`**; sweeping every UID ≥ 1000 would walk 34 home
  directories to examine one and then report "34 users checked", which is true and
  useless. Accounts with no home or a `nologin` shell are skipped, counted, and the
  count is printed.

### The invariant, in the place it matters most

An action that examined nothing **must not render like one that examined everything and
found nothing wrong**. With no check groups built, every run is currently that case,
which made this the right milestone to pin it: the run says "nothing was examined" in
the summary *and* in the not-checked block, and a test asserts the output contains none
of the wording fettle uses elsewhere for a genuine all-clear. Reverting either line
fails two tests.

The same rule covers the privilege split. Most of what this action will read is
root-only — other users' homes, the at-job spool, `/sys/fs/bpf` — but the system-scope
half needs nothing special, so it degrades rather than refusing, and names the half it
could not reach. `compromise-check` is classified read-only **and** needs-root, the same
pair as `sys-audit` and `pkg-integrity`; the remote path resolves it the same way, which
is asserted rather than assumed after that classification went wrong once in each
direction during the QA pass.

### Changed

- **The action-naming rule got wider, rather than the name getting worse.** The
  terminology guard rejected `compromise-check`: `-check` meant "asks whether something
  is PENDING or NEEDED", and nothing about a compromise is pending. `compromise-audit`
  was the alternative and is worse — every `-audit` is `<the thing being graded>-audit`,
  and a compromise is the *finding*, not the subject. The rule now distinguishes a
  **yes/no question about current state** (`-check`) from a **graded inventory**
  (`-audit`), which was checked against all eleven existing action names and fits every
  one.

## [1.0.2]

Follow-through on 1.0.1: the manual moved to the wiki, and the things that pointed at
the manual still pointed at the README.

### Added

- **`fettle -h` names the documentation.** The help was the only place a user could
  reasonably expect to find out where the manual is, and it did not say. One line at the
  end of the epilog.
- **`[project.urls]` in `pyproject.toml`** — Homepage, Documentation, Changelog,
  Releases. A package is often where someone first meets fettle, and package metadata
  was carrying the repo URL only.

### Changed

- The `RUNNING.md` bundled in the zipapp and binary archives now points at the wiki as
  well as the README. Those two archives are the artifacts for people with no package,
  which is exactly the audience least likely to find the wiki on their own.
- Two QA records (`docs/qa/exit-codes.md`, `docs/qa/pkg-integrity.md`) said "the README"
  about content that is now on the wiki. The record of what was done stays as written;
  each now names where that content went.

## [1.0.1]

### Changed

- **The README is now a front page, not a manual.** It had grown to 2200 lines, which
  is a length nobody reads and a length that hides the three things a new reader
  actually needs: what fettle is, whether it runs on their machine, and how to install
  it. It keeps exactly those — plus the per-action support matrix, the topgrade
  comparison and a quick start — and is 464 lines. Everything else moved verbatim to
  the [wiki](https://github.com/pasadoorian/fettle/wiki), split into nine pages that
  follow the sections it already had. No documentation was dropped; every heading and
  every line of the old README is either still on the front page or on a wiki page.
- **`hardening-audit` is now a feature family in its own right.** "What it does" listed
  four families and left `-H` out of all of them — it is not a supply-chain question and
  it is not maintenance, so it had nowhere to be described and simply wasn't. It is now
  family four of five: *is this machine configured safely?*, across seven axes. The
  three families whose names are easy to confuse (Package supply chain, System supply
  chain, System hardening) are disambiguated in one sentence rather than two.
- The opening section also now names the three things that cut across every family —
  running over SSH with nothing installed on the far side, the saved reports and the
  `fettle report` dashboard, and the experimental AI upgrade check. All three existed
  and none was mentioned before the reader was 1500 lines in.

### Added

- **An install section for the zipapp.** The Installation section pointed at it twice —
  "use the zipapp" is the advice for every system the prebuilt binary's glibc floor
  excludes — but never said how to install one. It now does, including the detail that
  makes the difference between working and not: the `fettle` launcher resolves
  `fettle.pyz` *beside itself*, so the two files install into the same directory.

### Fixed

- Four stale claims in the topgrade comparison, each contradicted by the README section
  above it: platforms said Arch and Debian only (RHEL has been supported since v0.46.0),
  integrations omitted dnf and containers, maturity claimed four distro families
  including Fedora while Supported distributions explicitly declines to claim Fedora as
  one, and the hardening row still described `-H` as a binary-only checksec wrapper,
  which it stopped being when the six non-binary axes landed in v0.111.0-v0.116.0.
- The action table (now on the wiki) called `-H` *six* axes and then listed six,
  counting the binary axis among them. It is seven; the certificates axis was missing.

## [1.0.0] — the first official release

fettle keeps a Linux machine updated and clean, audits where its software came from and
whether it has been tampered with, and scans the firmware and boot chain — from one
command surface, on four distro families.

**Supported:** Arch and Manjaro, Debian and Ubuntu, RHEL / Rocky / AlmaLinux, and
Fedora. Pure standard library: it needs **python 3.11 or newer** and nothing else, which
is what lets it ship itself to a remote host as a single file and run there under
whatever interpreter it finds.

**What 1.0.0 rests on.** Every action was specified, run against seven live systems, and
fixed where it misbehaved or explained itself badly. That pass is written down, feature
by feature, in [`docs/qa/`](docs/qa/) — roughly ninety findings, including actions that
reported success while doing nothing at all, a preview that deleted run history, and an
unattended flag that would have purged a list fettle had guessed at.

One rule came out of it and now governs the output everywhere: **a check that could not
look must never render identically to a clean result.** "Not installed", "could not
read", "does not apply" and "nothing found" are four different answers, and fettle says
which one it means.

**Installing.** Attached to this release: `.deb`, `.rpm`, `.pkg.tar.zst`, a zipapp that
runs anywhere there is a python 3.11+, and a prebuilt x86_64 binary that needs no python
at all. Every package is built and then *installed and run* in a clean container of its
own distro before it is published. `SHA256SUMS` covers everything.

**Still experimental:** `fettle web`, the browser UI. It is the one feature the QA pass
did not reach — it both serves a page and runs privileged actions from a password typed
into a browser, and it has not been swept. Localhost-only by default; keep it that way.
`fettle report`, the static HTML dashboard, is not experimental and is included.

**Known limit:** the prebuilt binary needs glibc 2.38 or newer, so it does not run on
Ubuntu 22.04, Debian 12 or RHEL 9. Those have their own packages here, and the zipapp
works everywhere.

## [0.122.2] — the test suite stops testing the developer's laptop

Also found by the dress rehearsal, and worse than the lint problem: **CI had been failing
on every push since at least 2026-08-06** and nobody looked, because the suite was being
run locally and called green. Five tests passed on the Arch development box and failed
everywhere else — they were asserting on the *host*, not on fettle:

- **`test_dry_run_lists_actions_without_elevating`** and **`test_bare_action_words_work`**
  asserted `rc == 0`. With `--distro arch` forced on a machine with no pacman, `update`
  correctly reports "could not determine what is pending" and the run exits 1 — fettle
  being truthful, which the tests read as fettle being broken. They now assert what they
  are actually about: that both actions dispatched, in order.
- **`test_config_drift_lists_pacnew`** mocked `pacdiff -o`, a command
  `check_config_drift` stopped calling when it changed to walking `/etc` (pacdiff cannot
  see a `.pacsave`). With `ctx.root` left at `/` it was reading the developer's own
  `/etc` and passing because there happened to be `.pacnew` files in it. It now builds a
  tree under `tmp_path`, and a second test covers the clean case.
- **Two secureboot tests** asserted a message that branches on `is_root()`, so they
  passed for a normal user and failed under `sudo pytest` or in any container. The
  helper now pins the uid rather than inheriting whoever ran the suite.
- **`test_a_tag_that_is_not_a_version_tag_is_rejected`** pinned exit code 1, but
  `${1:?…}` exits 1 under bash and **2 under dash** — and `/bin/sh` is dash on Debian and
  Ubuntu, including the runner. It now asserts non-zero.

Verified on Manjaro as a user and on Ubuntu 24.04 as root, since between them those two
cover every difference above.

## [0.122.1] — the lint rules are now stated, not inherited

Found by the release pipeline's first real run, which is what a dress rehearsal is for.

CI installs `ruff>=0.6`, so it takes the newest — and **ruff 0.16 changed its default
rule selection**. A tree that was clean under 0.15 produced **267 errors** under 0.16
with no code change, and the failure landed on a tag rather than on a commit anyone
could blame. `pyproject.toml` now names the rule set explicitly (`E4`, `E7`, `E9`, `F`
— ruff's classic default, what this codebase was written and reviewed against), so an
upgrade cannot silently change what is checked. Verified clean under both 0.15.20 and
the 0.16.2 that CI installed.

The newer rules — import sorting, pyupgrade, bandit, blind-except — are worth adopting
deliberately, as their own change, with the findings read rather than bulk-fixed on the
way out of the door.

## [0.122.0] — the binary ships, and a bug only a bare container could find

`packaging/binary/archive.sh` packs the compiled binary as
`fettle-<version>-linux-x86_64.tar.gz` / `.zip` with the example config, the completion
script and a `RUNNING.md`. The release workflow builds it, smoke-tests it, and installs
it from the archive in a container with nothing else in it.

**A real bug, found by testing the archive rather than the build.** In a bare
`debian:13` container fettle died on its very first section header:

```
UnicodeEncodeError: 'ascii' codec can't encode character '\u25b8'
```

`\u25b8` is `▸`. A normal CPython coerces the C locale to UTF-8 (PEP 538/540), so with
no `LANG` set — a container, a cron job, a minimal server — output still works. **The
interpreter Nuitka bundles does not.** In the same container the zipapp printed fine
under the system python while the binary crashed, which is what identified it as
Nuitka's behaviour rather than fettle's. The entry point now forces UTF-8 on both
streams, and the smoke test runs a check under `env -i` so it cannot return unseen.

**The glibc floor is measured, and it is not the build host's glibc.** The outer binary
needs only `GLIBC_2.34`; the *libpython Nuitka bundles* needs `2.38`, and that is the
real limit. Verified by running it on eight distros: it works on Ubuntu 24.04, Debian
13, Fedora 40+ and Arch, and does not on Ubuntu 22.04, Debian 12 or RHEL/Rocky/Alma 9.
Those three are covered by their own distro package and by the zipapp, both on the same
release page — and worth noting that building in an older container would remove the
limitation entirely, since the floor follows the bundled python.

**The stale-flag sweep now knows an artifact filename is not a flag.** It read
`fettle-1.0.0-linux-x86_64.tar.gz` as advising a `-linux-x86_64` option, having already
done the same with `-zipapp`. A flag is never followed by a dot and more word
characters; every archive suffix is. Its canary covers both directions, including that a
flag ending a sentence is still caught.

## [0.121.0] — fettle can be compiled, and still knows how to become root and travel

Groundwork for the prebuilt binary. `packaging/binary/build.sh` compiles fettle with
Nuitka into a single ~12 MB x86_64 executable — but building it was the easy half.

fettle **re-executes itself** twice: to elevate via `sudo`, and to relaunch under a pty
so it can transcribe a run. Both built `[sys.executable, "-m", "fettle", …]`, which is
meaningless in a compiled build — no interpreter to point at, no `fettle` package on
disk. `sudo fettle -u` would have failed, and that is the single most important thing
the tool does. Both now re-exec the binary itself with the original arguments.

Three facts were measured against a real build rather than assumed, and the first would
have shipped a bug nobody could diagnose:

- **`sys.executable` is not the binary.** It is `/tmp/onefile_…/python`, a scratch
  directory Nuitka unpacks into and deletes on exit — so re-exec'ing it works while the
  parent lives and fails afterwards. `sys.argv[0]` is the binary, absolute even when
  invoked by bare name from PATH.
- **Nuitka does not set `sys.frozen`**; it adds `__compiled__` to every compiled module.
- **`fettle/__main__.py` cannot be the entry point** — its relative import needs package
  context, so the binary compiles and then dies at startup. The build generates a
  two-line absolute-import entry, the same shape `remote.build_zipapp` already uses.

**Every build now smoke-tests its own output** (`packaging/binary/smoke.sh`) and fails
if the binary is wrong, because the failures that matter here are silent. fettle loads
its six hardening axes by a computed module name; if one is lost the binary does not
crash — the framework reports it as *blind*, so the audit looks careful and examines
nothing. Demonstrated by compiling one with two axes excluded: exit 0, no error, and
`Filesystem: not checked`. The smoke test asserts positive results — six axes, none
blind, real subjects examined, `fettle remote` able to build its zipapp — rather than a
zero exit.

The axes also get an explicit `--include-module` each, derived from `AXIS_NAMES` so a
seventh cannot be forgotten. Worth recording that these turned out to be *redundant*:
`--include-package=fettle` already includes them, verified by building without them.
They stay as belt-and-braces for a silent failure, not because they are load-bearing.

**`fettle remote` works from the binary too.** It ships fettle to a host by building a
zipapp from fettle's own `.py` files, which a compiled build does not have — it failed
with a bare `FileNotFoundError` traceback naming Nuitka's scratch directory. The build
now embeds a prebuilt zipapp and `remote.build_zipapp` copies that out instead. Verified
by intercepting the upload and running the captured file: it is a complete, working
fettle, axes and all. A build made without the data file raises an error naming the
missing flag rather than failing inside `shutil.copytree`, where the exception says
nothing about the cause.

**`fettle --version` now reports the build kind** (`fettle 0.121.0 (binary)`), so a bug
report says which artifact it came from.

Verified in a container as an unprivileged user with passwordless sudo: the binary
elevates, records run-logs (and still writes none under `--dry-run`), and all six axes
produce real findings. The non-compiled path is byte-identical to before.

## [0.120.0] — the hardening axes reach the dashboard, and read as a table

The axes shipped in 0.111.0–0.116.1 and then sat in two places that had not been
taught about them: the terminal printed them as prose, and the HTML dashboard did not
print them at all.

**On screen: a table per axis** — severity, subject, what is wrong — ranked worst
first. The previous layout gave each finding a wrapped sentence with its remedy
underneath, so five findings filled the terminal and none of them could be scanned.
The table drops the *why* and the fix; both are kept in full in the saved report, the
same split the binary axis already makes between its on-screen ranking and its full
matrix. A subject too wide for its column (a 56-character systemd unit name) takes a
row of its own rather than being truncated mid-hash or shunting the finding off the
margin.

**One severity scale.** The axes said `high`/`medium`/`low` while the binary axis said
`Critical`/`High`/`Medium`/`Low`, so a single screen carried two vocabularies for the
same idea and nothing could rank across them. Now one scale everywhere. `Critical` is
defined for the shared ordering; no axis emits it today, which is worth saying rather
than pretending the scale is shorter than it is.

**The dashboard had four separate gaps, not one.** The card rendered only binary
packages; the severity filter ranked only binary bands; the host verdict counted only
binary bands; and `_is_empty` tested `packages` alone, so a run whose findings all came
from the filesystem, kernel or ssh axes **vanished from the dashboard entirely**. A
machine whose one finding was a world-writable `/tmp` read as clean — the same
silence-reads-as-a-pass failure the audit exists to prevent, in a different surface.
All four are fixed, and blindness now shows on the card too.

Unlike the binary bands, an axis finding is **not** capped at Medium in the host
verdict. That cap exists because every real desktop has Critical-band packages, so
uncapped they would make every host red forever; an axis finding is the opposite kind
of thing — specific, rare and actionable.

The section is also no longer labelled "Binary Hardening Audit", which it stopped being
in 0.111.0. Reports written before the axes existed, and those written with the
lower-case scale, both still render.

## [0.119.0] — bash completion, and now you can actually use it

Third and last completion milestone. `contrib/fettle.bash` ships the script; the two
previous releases built the machinery behind it.

```sh
source ~/src/fettle/contrib/fettle.bash                        # or, system-wide:
sudo ln -s ~/src/fettle/contrib/fettle.bash /usr/share/bash-completion/completions/fettle
```

Completes every flag and action at the top level, and each subcommand's own options
inside it. `fettle sys-audit <TAB>` also offers the nine check categories, minus any
already typed; `fettle -S <TAB>` completes as sys-audit, since that is what it runs.

The script is **about six lines and knows nothing about fettle's options** — it asks
fettle itself, so it cannot fall out of step with the CLI. Roughly 70 ms per tab press.

**Verified in a real bash process**, driving the actual completion function rather than
only the helper behind it — a completion that passes its unit tests and does nothing
when you press tab is the obvious failure mode here. Eleven cases, all correct: prefix
matching (`fettle hard` → `hardening-audit`), subcommand contexts (`fettle report --`
offers only report's flags), category filtering (`sys-audit tp` → `tpm`), and
`aur-precheck` correctly offering nothing.

**And the data-loss guard checked against reality**: 395 real run-logs in `~/.fettle`
before eight tab presses, 395 after. Without the guard added in 0.117.0 each of those
would have written a log and rotated the directory.

Two deliberate limits, documented rather than left to be discovered: it completes
**names, not values** (no paths for `--config`, hosts for `remote`, or package names for
`aur-precheck` — sys-audit's categories being the fixed-set exception), and it binds to
the `fettle` command, so `python -m fettle` gets nothing.

## [0.118.0] — completion knows every subcommand (still no shell script)

Second of three milestones. Still internal — the bash script is M3 — but the helper now
answers for the whole CLI rather than only the top level.

**Every subcommand parser moved to module level** (`report_parser()`, `web_parser()`,
`advisory_parser()`, `upgrade_check_parser()`, and sys-audit's `parser()` /
`remote_parser()`). They were built inside their runner functions, so nothing could ask
what options a subcommand takes without running it. Pure refactor, no behaviour change —
and it is what lets the anti-drift test cover the whole surface instead of a third of it.

Each context now offers its own flags and nothing else: `fettle report <TAB>` does not
suggest `--dry-run` or `clean`, because `fettle report --dry-run` is not a thing and
suggesting it teaches a CLI that does not exist.

- **sys-audit** adds its nine categories and its `remote` sub-subcommand, and drops
  categories already typed — they are repeatable positionals, so this is the one place
  it matters. `sys-audit remote` switches to that parser's own flag set.
- **A dispatch shortcut completes as its subcommand**: `fettle -S <TAB>` is inside
  sys-audit, because that is what it will run.
- **remote** offers ssh options before HOST and forwarded actions after it. A
  `--ssh-arg` value is not mistaken for the host, which would flip the context a word
  early. HOST itself is deliberately not completed.
- **aur-precheck** offers nothing: it takes package names and no flags of its own, and
  an empty list is honest where offering flags it ignores would not be.

**Options hidden from `--help` are never offered.** `upgrade-check --collect` is the
remote transport asking for a JSON snapshot; suggesting it invites someone to type it
and get output they cannot use.

**Repeatable options keep being offered** — `--only` twice names two actions, `--ssh-arg`
twice passes two ssh options. Derived from every parser rather than listed, so an
`append` option added anywhere keeps working.

Two constants now have source-scanning guards, because both are second copies of
something: `SUBCOMMANDS` (checked in 0.117.0) and `REMOTE_FLAGS`. The latter is the
weakest link by design — `fettle remote` is hand-parsed, so unlike every other context
the constant is not read by the code it describes, and the test scans the runner's own
source instead.

## [0.117.0] — groundwork for shell completion (not usable yet)

First of three milestones adding bash completion. This one is **internal**: it adds the
machinery and its guards, but ships no shell script, so nothing changes for a user yet.

**`fettle --complete <cword> -- <words...>`** — a hidden helper that prints the
candidates valid at a given word position, one per line. Routed before argparse (the
words are arbitrary half-typed input, which the pipeline parser would reject with a
usage error), and it never raises, never exits non-zero, and prints nothing rather than
an error: a broken completion must not break the user's shell.

Candidates are **derived from the real parser** rather than listed by hand — 90 of them
at the top level, covering every option string, every action in all three of its
interchangeable spellings, the word aliases, the subcommands and the dispatch shortcuts.
That derivation is the anti-drift mechanism; encoding fettle's CLI a second time in bash
is how the two would come apart, and this project has already spent a QA pass on bugs of
exactly that class.

**A data-loss guard, which is the reason this needed care.** Writing a run-log rotates
the directory to `keep` entries, and completion shells out to fettle on *every tab
press* — so without a guard, tab-completing would quietly evict real run history a few
keystrokes at a time. That is the identical bug measured and fixed for `--dry-run`
(eleven real logs down to nine after one preview). `--complete` is now in the no-record
set, verified end to end: two tab presses write zero logs, a real run still writes one.

Two new constants keep the second copies honest: `SUBCOMMANDS` (the routing table's
names) and `HIDDEN_FLAGS` (real flags absent from `--help`). Tests read `cli.py`'s own
source and fail if either drifts from what is actually routed. `HIDDEN_FLAGS` also
teaches the stale-flag sweep that `--complete` is a real spelling — without it, that
sweep reported the new module's own documentation as advising a flag fettle does not
accept.

## [0.116.1] — a template unit could have blanked every service's owner

Two fixes in the `services` axis, both found by profiling the finished feature rather
than by reading it.

**A single template unit blanked the entire owner lookup.** `systemctl show` aborts the
*whole batch* on a name like `getty@.service` — exit 1, no output — and
`list-unit-files --state=enabled` returns exactly that on an ordinary desktop. With no
owners, every service at high exposure is reported as **unpackaged**: eighteen false
findings on the reference machine, from the one axis specifically built not to do that.
Template names are now filtered out, and a batch that comes back empty is retried one
unit at a time, so no single bad name can blank the map.

**A speed change was tried and reverted, which is the more useful note.**
`list-unit-files --state=enabled` costs ~1.4 s because it stats every unit file on
disk; `systemctl show '*.service'` answers the same question in 149 ms. But its glob
only matches units systemd has **loaded**, so a service that is enabled and has never
started is absent from it — and that dropped one of the two real findings here. The
slow call is kept. A second of wall clock does not buy silently losing a class of
result.

## [0.116.0] — certificate expiry, ignoring the 121 certificates that don't matter

The sixth and last `hardening-audit` axis: **`certs`**, and the design question was
*which* certificates rather than how to read a date.

**The CA trust store is deliberately excluded.** `/etc/ssl/certs` on the reference
machine is 121 root CAs symlinked out of the `ca-certificates` bundle. Some expire;
that is normal, no local action fixes it, and `update-ca-certificates` already handles
it. Walking that directory would bury the certificates that matter under dozens of
findings nobody can act on. A trust-store path added by hand is **refused, and the run
says so** — never silently, or the user is left believing a directory is watched when
it is not.

What is scanned is what this host *presents*: `/etc/letsencrypt/live`, `/etc/nginx`,
`/etc/httpd`, `/etc/apache2`, `/etc/pki/tls/{certs,private}`, `/etc/ssl/private`,
`/etc/dovecot`, `/etc/postfix`, `/etc/openvpn` — three levels deep, capped at 200
files, and only files that look like certificates so `openssl` never runs on
`httpd.conf`. Expired is high; expiring within `certificate_warn_days` (default 30) is
medium. Verified in a container against real certificates: an expired one, one due in
eight days, and one valid for 800 days — the third stays silent.

A file that is not a certificate is skipped silently; one that cannot be **read** —
private-key directories need root — is blindness, because "could not open" must never
become "fine". No `openssl` is blindness with an install hint. No service certificates
at all is *not applicable*, which is a different statement from "they are all fine".

New config: `[hardening] certificate_paths` (additive) and `certificate_warn_days`.

## [0.115.0] — ask the SSH server, not its config file

A fifth `hardening-audit` axis: **`ssh`**, and the clearest case in this whole
comparison for asking the right question.

On the reference machine Lynis prints **twenty-two** lines of
`OpenSSH option: X [ NOT FOUND ]` — on a host whose `sshd_config` is three non-comment
lines, so every one of them is at an OpenSSH default, and modern OpenSSH defaults are
fine. Twenty-two finding-shaped lines saying nothing about actual exposure, because the
question was asked of the file rather than of the server.

fettle parses **`sshd -T`** — the effective configuration with defaults filled in — and
reports only what is genuinely weak. On a stock Debian 13 that is two low notes and
nothing else (verified live in a container). The worst case is a combination rather than
two separate lines: `PermitRootLogin yes` *with* password authentication is one **high**
finding, because the account that matters most becomes reachable by guessing.

The weak-algorithm lists are deliberately not a modern-crypto wishlist. `hmac-sha1` and
`aes256-ctr` are shipped defaults — checked against a real `sshd -T` rather than assumed
— so listing them would fire on every unmodified host. Only non-default algorithms
(`3des-cbc`, `arcfour`, `ssh-dss`, `diffie-hellman-group1-sha1`) are reported, because
their presence means someone re-enabled them deliberately.

`sshd -T` needs root. Unprivileged it reports blindness with the reason, and
deliberately does **not** fall back to parsing the config file against a built-in table
of defaults — that table drifts with every OpenSSH release, and being confidently wrong
about `PermitRootLogin` is worse than saying nothing. No SSH server is **not
applicable**; an installed-but-stopped one is audited with a note that it is not live.

Also fixes an alignment bug: a subject of exactly the column width rendered as
`PasswordAuthenticationpassword authentication is enabled…`.

## [0.114.0] — a firewall that is "active" and filters nothing

A fourth `hardening-audit` axis: **`firewall`**, which asks the half that usually goes
unasked. "A firewall is active" is close to content-free — a service running with an
empty ruleset filters nothing and reads as protection on every dashboard it reaches.
Lynis reports `[ ACTIVE ]` and stops.

Two questions, answered separately because they need different privileges: which
management service is running (`systemctl is-active`, rootless), and whether the kernel
actually holds packet-filter rules (`nft list ruleset`, falling back to `iptables -S`,
**needs root**). Measured on the reference machine: nothing here is readable
unprivileged — nft, iptables, ufw and `firewall-cmd` all refuse. So an unprivileged run
names the active service and says plainly that the rules are unverified.

**Permission-denied is never read as an empty ruleset.** Both produce no output, and
one of the two answers is a serious finding.

**Rules outrank the absence of a service.** Docker and libvirt program netfilter
directly and many hosts load rules from a script, so a populated ruleset with no
managing service is reported as filtering rather than as "no firewall". `-P INPUT
ACCEPT` counts as the *absence* of filtering — it is what "allow everything" looks like
written down — while `-P INPUT DROP` counts as filtering.

**Fixed a truthfulness bug in the axis renderer** that this axis exposed: an axis that
examined some of its subjects but was blind to others signed off with a bare "nothing
to report". Unprivileged, the firewall axis can see that ufw is active and cannot read
a single rule, and "nothing to report" there is close to the opposite of the truth. The
tally line now says how many things went unchecked. The filesystem axis had the same
gap when `/proc/mounts` was unreadable.

## [0.113.0] — kernel posture, judging fewer things and getting them right

A third `hardening-audit` axis: **`kernel`**, read straight out of `/proc/sys` with no
`sysctl` binary, so it works inside the remote zipapp on a host with nothing installed.

**The key list is deliberately short.** Lynis compares 38 sysctls against a fixed
profile; on the reference machine two of its deviations were *requirements* —
`net.ipv4.conf.all.forwarding` must be 1 on a host running libvirt and Docker, and
`kernel.modules_disabled=1` would leave a workstation unable to load a module for newly
attached hardware. This axis judges only keys whose right value does not depend on what
the machine is for, and the saved report **names the ones it declines to judge, with
the reason** — an explicit scope beats a hidden weighting.

It also permits more than one right answer where there is one: `fs.suid_dumpable` is
safe at `0` and at `2` (dumps written root-readable only), and only `1` exposes them.
Lynis wants `0` and calls `2` a deviation, which is a preference reported as a defect.

**ICMP redirects are computed rather than read**, because the single `conf/all` value
everyone reads is wrong in both directions, and the two address families do not follow
the same rule. Per the kernel's own `ip-sysctl` documentation, IPv4 accepts a redirect
if *both* `all` and the interface are set when that interface forwards, or if *either*
is set when it does not; IPv6 accepts one only when local forwarding is disabled. So
fettle walks the interfaces and applies the real rule. That changed the answer both
ways here: **no** IPv4 interface was accepting redirects (Lynis flagged `conf.default`,
which only templates interfaces created later), while **ten** IPv6 interfaces were — a
live exposure it reported as one generic "differs from profile".

Settings the kernel does not have — `yama.ptrace_scope` without the Yama LSM, or a
container's masked `/proc/sys` — collapse into one line instead of a dozen findings
about knobs that were never offered. An unreadable `/proc/sys` is blindness, not a pass.

## [0.112.0] — service exposure, without the wall of text

A second `hardening-audit` axis: **`services`**, reading `systemd-analyze security`.

**A high exposure score is not a defect, and the design turns on that.** `sshd` scores
9.6 "UNSAFE" on a perfectly healthy machine because it runs as root and opens a
listening socket — as do `docker`, `libvirtd` and `gdm`. Reporting eighteen unsafe
services on a working desktop tells the reader nothing to act on and teaches them to
skip the section. So the axis splits its output:

- **Findings** are services at high exposure whose unit file is owned by **no package**
  — a fact rather than an opinion: something outside the package manager installed a
  service, no packaging review looked at it, and it runs with wide access. Each finding
  names the directives it leaves unset ("has access to the host's network; runs as root
  user") instead of quoting a score. Found two real ones here: unpackaged agent units
  under `/etc/systemd/system`, running as root with host networking.
- **Review material** — the worst running-or-enabled units with their owning package —
  goes to the saved report, not the screen. Same split the binary axis already makes.

Only **running or enabled** units count; one that exists but never starts is not
exposure. On the reference machine that is 37 units rather than 67, and 18 unsafe
rather than 42.

No systemd reports **not applicable** rather than blindness — there are no unit files
to be exposed, and sending the reader to install something they do not want is its own
kind of wrong answer. systemd installed but not the running init (the container case)
reports that it could not look, with the reason.

Also fixes a rendering bug the axis exposed: a 56-character unit name overflowed the
subject column and wrapped the detail one word per line. Long subjects now take their
own line.

## [0.111.0] — `hardening-audit` grows axes, and finds a real `/tmp` bug

Prompted by reading a Lynis run against the same machine and asking which of its 454
tests fettle should actually have. Most of the answer was "none — fettle already answers
that, or it is advice rather than state". This is the first of the few that survived.

**`hardening-audit` is no longer only a binary scan.** It now asks *is this system
hardened?* along independent **axes** — `binary` (checksec, as before) and `filesystem`
(new) — each reporting on its own. Every axis is on by default; `[hardening]
disable_axes` switches one off, and a name that is not an axis is reported rather than
quietly ignored.

**A missing tool no longer ends the whole action.** `hardening-audit` used to
`return Result(ok=False)` the moment checksec was absent, so a host without checksec got
*no* hardening answer at all rather than the part needing no external tool. One missing
tool now costs one axis. An axis that raises is recorded as **blind**, never as clean,
and cannot take the others down with it.

**New filesystem axis.** Sticky bits on world-writable directories, and
`nosuid`/`noexec`/`nodev` on the filesystems that hold them — from `stat` and
`/proc/mounts`, with no directory walk. It found a real defect on the development
machine: `/tmp` was a separate tmpfs at mode `0777` with **no sticky bit and no
nosuid/nodev/noexec**, so any local user could delete another user's files there and drop
a setuid binary. Mount options are only reported where the path is *its own mount* — on a
single-filesystem host the four paths that inherit from `/` collapse into one note
instead of four phantom findings, because asking for mount options on a directory that is
not a filesystem is advice to repartition, not a defect.

Configurable via `[hardening] filesystem_paths` (**added** to the built-in list, never
replacing it — asking fettle to also watch `/srv` must not silently stop it watching
`/tmp`) and prunable via the existing `exclude_paths` / `exclude_checks`.

Findings **warn**; nothing here changes the exit status. Same reasoning as the binary
scoring bands: every real machine has some, and an action that is red forever gets
ignored.

## [0.110.0] — the default set updates before it inspects; `--only` rejects a typo

The last three cross-cutting rows, swept together.

**`-a` inspected the machine before it updated it.** The default set ran `clean, orphans,
update, …`, so `orphans` described the system you *booted* rather than the one the upgrade
had just produced. `--everything` was given the right order two releases ago and the two
disagreed on nine shared actions. Both now run clean → update → rebuild checks → orphans →
config-drift, and a test asserts they agree where they overlap.

**`fettle --only hardening-audi` ran nothing and exited 0.** An unknown name was silently
ignored, so a typo in a cron line reported success for work that never happened. Bare
action words have always been validated; these two flags now are too, accepting the same
spellings as everywhere else.

### Recorded, not changed: `--quiet` is inverted

It suppresses section headers and the summary but **not** the body detail, so a quiet run
drops the two things that organise the output and keeps the raw file lists — backwards for
the obvious use. It is not fixed because the detail comes from **17 bare `print()` calls**
across the backends that bypass the output layer entirely; suppressing them is a refactor,
and this is the wrong side of a stable release for one. The help text describes the
current behaviour accurately, so nobody is misled. Worth doing properly after 1.0.

**All ten cross-cutting rows are now swept**, alongside 23 of 24 features — `web` remains
on hold.

## [0.109.0] — root only when the work needs it

The privilege-escalation row. Three fixes, one of them a regression this QA pass
introduced itself.

**`fettle -D` asked for a sudo password to read a CVE cache.** `advisory-check` reads the
package database and a cache under `~/.cache`; it needs no root, and as a subcommand it
never took any. Giving it a flag in v0.104.0 moved it into the pipeline's elevation path
without adding it to the read-only set, so the flag form started prompting where the
command form did not.

**`fettle remote` elevated for everything except `--dry-run`** — recorded as H-06 during
the hardening row, where it was what exposed checksec's sleep-as-root behaviour. A
read-only audit ran as root on the far host and asked for a password to do it, while the
local path had always resolved the request against the no-root set properly. The remote
path now asks the same question of the tokens it forwards. Measured against a live guest:
`-P` and `-D` go `sudo=off`, `-V` and `-c` `sudo=on`, and `--full-preview` still elevates
under `--dry-run` as documented.

An unrecognised token counts as needing root. A run holding privilege it did not need
works; one lacking privilege it did need fails partway with a permissions error.

**`sys-audit` was classified as not-read-only.** It elevated correctly so nothing
misbehaved, but it sat outside the read-only set while being read-only, which left that
set meaning "read-only *and* rootless" in practice. Now listed as read-only **and** as a
declared needs-root exception, next to `pkg-integrity`.

The row rests on one distinction worth restating: *"does this change the system?"* and
*"does this need root?"* look like one question and are not. `container-update` mutates
and needs no root; `pkg-integrity` and `sys-audit` change nothing and do.

## [0.108.0] — `--yes` no longer auto-purges a list fettle guessed at

The `--yes` row. One finding, one fix.

`deborphan` no longer exists in Debian 13 or Ubuntu 26.04, so v0.94.0 added a fallback
that answers the same question from dpkg's own data — **fettle's own reverse-dependency
scan**. Under `--yes`, the per-package chooser selects everything and the purge runs with
`apt-get purge -y`, so `fettle -o --yes` on a modern Debian would remove every package a
*heuristic* guessed at, with apt's confirmation suppressed too. No human anywhere in the
loop, on the output this project's own notes call the most dangerous it produces.

**Fixed by applying a rule fettle already follows elsewhere:** `--yes` answers questions,
it does not override a safety judgement. A CRITICAL AUR pre-check finding already needs
`--force-aur` on top of `--yes`; container images awaiting confirmation are already
skipped rather than auto-approved. So an unattended run now reports an inferred orphan
list and removes nothing. `deborphan`'s verdict is a tool's and keeps its behaviour, and
interactive runs are untouched — a human is there to review per package.

### Checked and left alone

Kernels exclude running ∪ newest before `--yes` sees the list. Arch orphans come from
`pacman -Qtdq`, the package manager's verdict rather than fettle's inference. Containers
skip deferred images and point at `[containers] always_update`. `confirm()` and `select()`
keep answering yes and selecting all, because that is the point of the flag — the guard
belongs at the call site that knows whether the list can be trusted, not in the primitive.

## [0.107.0] — run-logs are owner-only from creation; `report` counts hosts, not directories

The reports-and-run-logs row. Two fixes, deliberately small with the stable release
approaching.

**A run-log was world-readable while it was being written.** It was created with the
default mode and only tightened to `0600` when the run *finished* — so it was exposed for
the whole run, and permanently if the run was killed. There was a 0-byte `0644` log in the
author's own tree from an interrupted run.

Stated honestly: this was defence in depth rather than an open door, because every
directory in the tree is `0700` and another user cannot traverse in to read the file. It
matters for the cases where that is not true — a tree predating the `0700` behaviour, a
restored backup, a `[reports] dir` pointed somewhere unusual — where the file mode is all
that is left. Both the transcript and its JSON sibling are now created `0600`.

**`fettle report` said 19 hosts on a tree with 17.** It counted host *directories*, two of
which were empty: `fleet` — a **group** name left behind by a remote run that never
resolved — and an empty `wopr`.

### A fix that went in the wrong layer first

The dashboard already hides empty hosts and prints `N empty hidden`, deliberately, so they
do not silently disappear. The first attempt at this filtered them inside `collect()`,
which fixed the count and broke that message — the hidden-host number became uncomputable.
The test suite caught it. The bug was in the summary line added in v0.100.0, the only
thing reading the raw directory list, and that is where it is fixed.

### Checked and left alone

Rotation removes each `.txt` with its `.json` sibling, keeps at least one entry whatever
the config says, and sorts on a fixed-width timestamp. Ownership is handed back to the
invoking user after an elevated run. Directory modes are `0700` at every level.

One thing recorded rather than changed: the local machine writes to a host directory named
`local` while remote runs use real hostnames, so this workstation appears twice. Renaming
needs a migration for every existing tree — not a fix, and not minimal.

## [0.106.0] — `--dry-run` was deleting your run history

The `--dry-run` row. Its promise is *change nothing*, and it was breaking that in the worst
possible direction: not by creating something, but by **deleting** something.

### A dry run removed real run-logs

Writing a run-log rotates the directory to `keep` entries, so a dry run evicted older
**real** logs. Measured on a seeded tree: **eleven real run-logs before a single
`fettle -d --dry-run`, nine after.**

Quiet, too — rotation prints nothing and the evicted logs are the oldest ones nobody is
watching. The one command you type *because* it is safe was destroying history.

Dry runs are no longer recorded. That is right on a second ground as well: a dry run
showing up in `fettle report` as a run is misleading by itself, since the dashboard would
report maintenance on a host where nothing was touched. A preview belongs on your terminal.

### Two audits wrote reports under `--dry-run`

`-V` wrote two files; `-P` and `-A` wrote none — so `pkg-integrity` was the outlier rather
than the convention. And `sys-audit`, which has no `--dry-run` flag of its own, became
reachable through `--everything --dry-run` when it turned into a pipeline action, where it
would have written a report inside a command that promised no changes.

Both now announce *"report would be saved to ~/.fettle/reports/"*, matching what
`--dry-run` does everywhere else and what `orphans` was fixed to do last release.

### What held up

The execution gate itself is sound. Every mutating verb across pacman, apt, dnf, yay,
flatpak, snap, docker and podman goes through it; the only direct calls outside are
read-only. Prompts do not appear, privilege-dropped commands are gated too, and the
failed-command list stays empty so the exit code cannot key off work that never happened.

**The shape worth noting:** every finding was state fettle keeps about *itself* — reports,
logs, rotation. The gate around the dangerous operations has been solid since it was
written. What leaked was the bookkeeping nobody thinks of as "changing the system".

## [0.105.0] — the summary is a checklist: one line per action

Six actions ran against a test host and **two** appeared in the summary, because an action
that finds nothing said nothing at all. The section headers showed all six ran, but the
summary — the part people read — was silent about four of them. With `--everything`
running fourteen actions, that leaves no way to tell "twelve checks were clean" from
"twelve never ran".

Every action now gets exactly one line:

```
✓ orphans: nothing to report
✓ rebuild-check: nothing to report
✓ config-drift: nothing to report
✓ auto-updates: ON (unattended-upgrades)
✓ firmware-check: nothing to report
! pkg-integrity: debsums: Not installed (apt install debsums)
```

An action that reports something of its own keeps its own line — it does not also get a
"nothing to report" — and one that could not run says `did NOT run` rather than
disappearing from the list entirely.

This is the same question the `Not checked` block answers about coverage, asked about the
actions themselves: *how much of what you asked for actually happened?* Closes the
terminology row.

## [0.104.0] — `--help` sweep: the CVE check was invisible in it

Reported by Paul: `advisory-check` does not appear under "audit & security actions".

It was worse than a missing line. **`advisory-check` became a real action in v0.95.0** —
it runs under `--everything`, `--only` and by name — but it had no flag, and the audit
section lists flags. So the one place a user scans for security checks did not mention
the CVE check at all; you had to already know the subcommand existed to find it.

It now has `-D` (aDvisory), sits with the other audits, and works in all three forms
(`-D`, `--advisory-check`, `advisory-check`).

### The rest of the sweep

- **The subcommand block moved above positional arguments**, directly under the audits
  where you are already reading. It used to be in the epilog, below ~25 lines of options,
  so the two commands most people want next were the last thing on the page.
- **Its title was untrue.** "subcommands, for the ones that take options" listed
  `advisory-check` and `advisory-update`, neither of which takes any. Now: *"the same
  audits as commands, where some take further arguments"*, and `advisory-update` is
  marked as the only entry there that is not read-only.
- **Four options shipped with no help text at all** — `-v`, `-q`, `--no-color`,
  `--config`. A user reading `--help` learned nothing about them.
- **`--everything` was missing from the examples** despite being a headline feature, as
  were `-D` and a remote example.

### A doubled prefix the previous release created

`advisory-check: advisories: 34 pending, 142 fix-available`. The automatic prefixes added
in 0.103.0 removed the hand-written ones, but the guard only caught lines starting with an
exact action name — and this one said `advisories:`, a near-miss. The guard now catches
stems and plurals too, which is the shape it should have had.

### Kept honest by test

Four new checks: every option has help text; no action flag falls back to printing its own
name as its description; every runnable action appears somewhere in `--help`; and the
long-form block cannot claim its entries take options. `--help` is the only documentation
most people read, and nothing breaks when it drifts — which is exactly why it had.

## [0.103.0] — every summary line says which check produced it

The terminology row, and the stated top priority of this QA pass.

### The problem, from a real run

```
✓ packages updated (apt)
✓ reboot required (kernel)
✓ caches cleaned — 68.8 MiB reclaimed
✓ auto-updates: ON (unattended-upgrades)
! 3 High, 32 Medium, 13 Low (218 deviations across 48 packages, worst first)
! advisories: 361 pending, 0 fix-available
```

Nothing says which check produced most of those. *"218 deviations across 48 packages"* —
deviations of **what**? With `--everything` running fourteen actions, that is unreadable.

### Every line is now attributed, automatically

The pipeline knows which action is running, so it tags every summary line itself rather
than relying on ~40 call sites to remember — which is exactly why four of them did and the
rest did not. The prefix is **the command name**, so the summary tells you what to type to
look into whatever it just mentioned:

```
✓ auto-updates: ON (unattended-upgrades)
! pkg-integrity: debsums: Not installed (apt install debsums)
! hardening-audit: 3 High, 32 Medium, 13 Low (218 deviations across 48 packages)
```

The hand-written prefixes are gone, and with them a quiet inconsistency: `advisory-check`
had been announcing itself as `advisories:` and `container-update` as `containers:` —
neither of which is a command you can run. A test now rejects any new line that writes its
own prefix.

### A green tick means "nothing needed from you"

`✓ reboot required`, `✓ 3 service(s) need restarting`, `✓ 12 config file(s) to review`,
`✓ dpkg --audit found package problems` — all green ticks on things that need you to act.
They now carry the warning mark, so an all-green run genuinely means an idle machine.

One of the tests pinning the old behaviour was already named
`test_auto_updates_warns_when_security_updates_need_pro` while asserting the green channel.
The name knew before the code did.

### The naming rule, written down and enforced

- `<thing>-audit` judges what you **already have** — pkg-audit, aur-audit, sys-audit,
  hardening-audit
- `<thing>-check` asks whether something is **pending or needed** — rebuild-check,
  advisory-check, firmware-check
- a bare noun names the thing it manages — clean, orphans, update, kernel, config-drift,
  pkg-integrity

Derived from the names that already existed and it fits all of them, so it exists to stop
the *next* action being guessed at. Command names are unchanged; a test enforces that
nothing ends in `-audit` or `-check` unclassified, and that no third verb (`scan`,
`verify`, `inspect`) creeps in.

The one exception found: the action is `firmware_check` everywhere, including the prefix
its lines now carry, but the flag was `--firmware`. `--firmware-check` is now canonical,
with `--firmware` kept working.

## [0.102.0] — exit codes are documented, and the row is closed

X5, the last milestone of the exit-code sweep — and the **first cross-cutting row in the
QA matrix to get a status at all**.

The README gained an **Exit codes** section: what `0`, `1`, `2` and `255` mean per
invocation, and the advice that actually matters — *gate automation on a single action,
not on `--everything`*. `fettle -V` is a tripwire and goes red when a packaged file's
contents changed, when the integrity database could not be opened, or when the tool is
missing. `--everything` answers "did the run complete", because fourteen checks on a real
machine always find something and a status that is red every time is one nobody reads.

Every row of that table was **run** rather than transcribed from the source.

### Writing it down found one more defect

Which is the argument for documenting rather than treating it as paperwork.
`aur-precheck`'s module docstring still said *"Always exits 0 (advisory; never blocks an
install)"* — the exact contract disproved and fixed in v0.77.0, when QA found that the yay
hook does not read the exit code and `fettle aur-precheck foo && yay -S foo` was
proceeding on a known-compromised package. The code was corrected then. The sentence at
the top of the file outlived the fix by six months, so anyone reading the file to learn
the contract learned the wrong one.

### The row, closed

Four findings across five milestones. Three of them were **not** in the code that
computes exit codes — they were in what the code *claimed*: a summary that never printed,
a status that was a constant, a docstring that outlived its fix. The exit status is
downstream of whether an action is honest about what happened, which is why this row kept
turning into the same lesson as the rest of the pass.

## [0.101.0] — "nothing happened" stops reporting success

X4: the cross-cutting exit-code cases that had been sitting on the tracker.

### An action you named that cannot run is a failure

F-11 was filed against two paths and both were already fixed — an unknown `--distro` and
a machine fettle cannot identify each exit non-zero. The same shape survived by a third
road:

    $ fettle -A --distro debian
      skipping 'aur_audit' — not supported by the debian backend
      ! nothing to do (no supported actions selected).
    $ echo $?
    0

You named an action, fettle declined, nothing happened, and the status said success — so
`fettle -A && echo audited` printed a lie. Now a failure.

The **default** set finding nothing applicable is deliberately *not* a failure. That is a
different statement: you asked for "whatever applies here" and the honest answer was
"nothing does". Failing it would put a bare `fettle` permanently in the red on a minimal
backend.

### A host you could not reach is not a host that failed

In a group run both were exit `1`, so the summary read the same for a machine that was
audited and came back bad and one that was never contacted at all. Unreachable is now its
own verdict, using ssh's own convention for a connection failure:

    [OK]          bifrost
    [FAIL]        ec1  (exit 2)
    [UNREACHABLE] gibson
    1 ok, 1 failed, 1 unreachable (nothing is known about those)

It still fails the group — the work did not happen — but you can now tell which is which,
and the phrasing says plainly that the rest of the summary does not speak for that host.

### B8, settled by precedent rather than taste

Under `--dry-run`, Debian and RHEL both announced *"would be saved for review"* while
Arch said nothing, so an Arch user had no idea a review report was even part of the
action. Announcing is what `--dry-run` does everywhere else in fettle — *"would run: …"*
— which made Arch the outlier rather than a coin-flip. It now matches, with a test on
both halves so the announcement cannot quietly replace the thing it announces.

### Re-proved rather than assumed

Remote exit propagation: a guest returning non-zero reaches the local shell, and a clean
run returns 0. Worth re-checking because the zipapp wrapper discarded a return value once
before.

## [0.100.0] — `fettle report` answers for itself, and a guard so the next one has to

X3, and the end of a defect this QA pass found six times: *a subcommand with its own
entry point independently forgets both to print a summary and to compute an exit code.*

`report` was the last one standing. It printed one line and returned success whatever
happened, so nothing scripting it could tell a rebuilt dashboard from a failed one.
Now it:

- **fails** when the dashboard could not be written, instead of raising a traceback or
  claiming success
- **says so when the dashboard contains no hosts** — a page built from nothing is a valid
  HTML file and a useless answer, and reporting only "written to <path>" invites the
  reader to believe their fleet is represented in it
- reports how many hosts it actually covered (19 here)

### The guard matters more than the fix

This was never a bug in one place; it is what happens by default every time someone adds
a subcommand. So there is now a permanent test, split by what an entry point actually is:

- **work runners** — `report`, `advisory-check`, `upgrade-check` — must print a summary
  and must not end in a hardcoded `return 0`
- **orchestrators** — `remote`, the group runner — print no digest of their own, since
  the group runner prints a per-host table and the remote path forwards the remote's own
  summary, but their status must still be computed rather than assumed

`fettle web` is in neither: it hands control to a server that runs until interrupted, so
"what happened" is not a question it can answer at the end.

The guard was checked against the reverted fix rather than assumed to work.

## [0.99.0] — exit codes mean something, and a "Not checked" list says what was missed

X2 of the exit-code sweep.

### The status

A **single check** stays strict: `fettle -V` goes red when a packaged file's contents
changed, `fettle -S` when a check could not run. That is the precise thing to gate a
script on.

**`--everything` fails only when an action could not do its job.** Findings do not fail
it — fourteen checks on a real host essentially always find something, and a status that
is red every time is one nobody reads. Nor does blindness, which is the deliberate part:
on the development workstation chipsec cannot run at all, so two checks report "could not
run" on every single run, and failing on that would put the sweep permanently red for a
condition nobody can fix.

The `ctx.failed_commands` stopgap from v0.95.0 is gone, and the "known limit" comment
with it.

### `Not checked`

The invariant this whole pass is built on is that *a check which cannot look must never
render identically to a clean result*. A summary of what was **found** cannot satisfy
that — a short list of ticks reads the same whether nine checks passed or one passed and
eight never ran.

So every run now ends with what it could not examine, and how to fix it:

```
▸ Not checked
  these were not examined, so nothing above speaks for them
  ? hardware inventory detail — inxi is not installed
      install: sudo apt install inxi
  ? SPI/BIOS write protection, SMM, Secure Boot variables (chipsec) — chipsec is not
    configured — set [secure] chipsec_cmd in your config
  ? storage device firmware — smartctl is not installed
      install: sudo apt install smartmontools
```

The install command is worked out from the package manager actually present, so it is
right on the machine where it will be typed rather than on the one that asked. Where no
known package manager is found, no command is offered at all: a confidently wrong install
line sends someone to a shell to be told the tool does not exist, and they conclude fettle
is broken rather than that the hint was.

chipsec's unsupported-platform case is named specifically, using detection that already
existed — *"this platform is not supported by chipsec — it has no register definitions
for this CPU"* — rather than leaving a bare exit code the reader has to interpret.

## [0.98.0] — a check that could not run is no longer reported as a finding

X1a of the exit-code sweep, and the reason X1 was done as a separate, inert step: the
labelling exposed that two summary lines were lying about what they contained.

`pkg-integrity` and `sys-audit` each built **one** summary line by rolling up every
record they had marked as an error. That bucket is not homogeneous:

    UNKNOWN — the rpm database could not be queried; packages were NOT verified
    UNKNOWN — chipsec failed (exit 128)
    UNKNOWN — mokutil failed (exit 2)
    rpm: Not installed

None of those are findings. They are the check saying it could not look — and rolled in
with genuine findings, they were about to be counted as "the audit worked and found
something", which would have let a sweep report success on a machine that was never
actually audited.

Now reported separately:

    ✗ sys-audit: 2 check(s) could NOT run — ME Manufacturing Mode, BIOS Write Protection
    ✗ sys-audit: 3 finding(s) needing attention — …

Real data from the QA fleet, which is what confirmed the split matters: this workstation
reports two chipsec checks that could not run, while another host reports three genuinely
expired certificates. Before this they were the same sentence.

**Marked at the source, not inferred from the wording.** Every one of these happens to
say "UNKNOWN" or "NOT verified" somewhere, and matching on that would work right until
someone rephrased a message — a trap this project has walked into more than once. Scan
records now carry the distinction explicitly.

A wholly blind scan also no longer reports "nothing flagged", which was a clean bill of
health from an audit that never happened.

### Recorded, not decided

There turn out to be **two tiers** of "could not look": a check that tried and failed
(chipsec exited 128) is a failure line, while a check that never started because its tool
is absent (smartctl, dmidecode, inxi) is a warning and does not affect the exit status at
all. Both are blindness. Making every missing optional tool fail the run would put
`fettle -S` in the red on most machines, which is the same cry-wolf problem from the
other direction — so where that line sits is a deliberate per-tool judgement, noted in
`docs/qa/exit-codes.md` for a decision before X2.

## [0.97.0] — every `✗` now says which kind of bad news it is

Groundwork for the exit-code sweep, and **deliberately inert**: nothing about what fettle
prints or what it returns changes in this release. The full test suite passes untouched,
which is the point.

fettle has had one way of saying "that didn't go well", and it covers three situations
that call for opposite responses:

- **the action could not do its job** — the update failed, a rebuild did not finish
- **the check could not look** — the tool was missing, a feed would not refresh, no
  API key. *The all-clear you just got is not an all-clear.*
- **the check looked and found something** — an altered file, an unpatched CVE. The tool
  worked perfectly; go fix what it found.

All fifteen places that report bad news now say which one they mean. On screen they are
identical — same `✗`, same wording, same order. What it buys is that the pass/fail status
can later answer the right question: a single check should fail on any of the three,
while a fourteen-action sweep that fails on every *finding* is red on every real machine
and stops being read. What such a sweep must never do is treat "could not look" as
success — which is exactly what `--everything` does today, documented as a known limit
when it shipped.

The split is six *failed*, five *could not look*, four *found*. A permanent test requires
every future one to declare which it is, because an omission would silently default to
the strictest reading and be wrong for a finding.

**And labelling them found a real problem, which was the point of doing it separately.**
`pkg-integrity` and `sys-audit` each roll up every record they marked as an error into a
single summary line — and that bucket mixes genuine findings with checks that could not
run (`the rpm database could not be queried`, `mokutil failed`, `rpm: Not installed`).
Both are labelled *found* today and both are wrong whenever the cause was blindness,
which is the unsafe direction. Specified as X1a in the plan and fixed before the labels
start affecting behaviour.

## [0.96.0] — group runs label every section with the host

Running a group puts six machines' output into one terminal, one after another. The
per-host banner is printed once and then scrolls off long before the actions do, so by
the third host you are reading a summary with no idea whose it is.

Every section header and the summary now carry the host:

    ▸ [1/12] Cleaning caches (bifrost)
    ▸ [2/12] Updating packages (bifrost)
    …
    ▸ Summary (bifrost)

Only for group runs. A single remote host does not get it — its banner is right there,
and the parentheses would be noise.

The label is carried by a `--host-label` flag that `fettle remote <group>` sets per host,
because the headers are printed by the fettle running **on the remote**, which otherwise
has no idea it is one of six. It is appended to the argument list **after** the
action-detection step, deliberately: `--host-label bifrost` puts a bare word in the
arguments, and a bare word is how fettle recognises "the user named an action", so adding
it any earlier would have silently suppressed the default action set on every group run.

## [0.95.2] — `fettle remote` says so when it could not read your config

A stray line in `config.toml` made the whole file invalid, so `[remote.groups.fleet]`
was never seen and `fettle remote fleet` treated the group name as a hostname:

    Error: could not copy fettle to fleet — ssh: Could not resolve hostname fleet

A true statement about the wrong thing. The real cause — *invalid TOML at line 80* — was
known at the time and thrown away: the remote path called `load()` and discarded both its
warnings and any exception, so **a config that could not be read looked exactly like a
config with no groups**. That is this project's governing invariant, in the one place a
user is most likely to hit it, since a group name that silently degrades to a hostname
produces a confident error about DNS.

The local path has always printed these warnings. The remote path now does too.

## [0.95.1] — `--everything` cleans before it updates

Corrects the action order shipped in 0.95.0. `clean` now runs **first**, not last:

    clean, update, rebuild-check, python-rebuild-check, orphans, config-drift, …

The reason 0.95.0 gave for putting it last — that cleaning first "forces a re-download" —
was simply wrong. `clean` removes cached packages that are **no longer installed** and
trims the rest to `keep_versions`; the upgrade downloads **new** versions that were never
in the cache. Nothing clean removes is anything the upgrade was about to reuse, so there
is no cost to going first, and there is a real benefit: it frees space *before* the
upgrade needs it, which is the difference between a successful run and a failed one on a
box with a small `/var`.

`orphans` and `config-drift` also move to just after the rebuild checks, since an upgrade
is what creates both.

Checked while reordering, since the remaining audits were described as order-independent:
they are. The only relationship worth preserving is `pkg-audit` and `aur-audit` staying
adjacent — both query the AUR RPC, and the second benefits from the first's TTL-cached
fetch. They keep *separate* maintainer snapshots on purpose (sharing one meant a takeover
was reported by whichever ran first and was invisible to the other), so their order
between themselves does not matter.

**One caveat now documented:** with `keep_versions = 0`, cleaning first removes every
cached version including the running one, so an upgrade that goes wrong leaves no offline
rollback. The default of 2 keeps it.

## [0.95.0] — `--everything`, and two subcommands become real actions

`fettle --everything` runs every action that is safe to leave running unattended, in a
deliberate order, locally or over `fettle remote`. It adds what `-a` leaves out —
`pkg-integrity`, `hardening-audit`, `aur-audit`, plus **`sys-audit`** and
**`advisory-check`**, which until now were reachable only as their own subcommands.

### The part that was actually work

Making those two into pipeline actions, rather than shelling out to them in sequence.
That is the difference between one summary and one exit code, and three digests in a row
with a status that reflects only whichever ran last — and it also chips away at the
structural defect this QA pass has now found five times: *every subcommand with its own
entry point independently forgot to print a summary and compute a real exit code.*

Both are distro-neutral by construction, so `supports()` treats them as universal rather
than requiring every backend to remember to list them — the one that forgot would have
silently dropped the action.

Two integration defects surfaced on the first live run and are pinned as tests:

- `sys-audit` sets `step_total` to its own category count and numbers each one, so
  nesting it inside a counting pipeline produced `[3/9] … [10/9]` — a running number
  against someone else's total, ending past it.
- `sys-audit` also called `print_summary()` itself, so the run ended with two digests.
  It now takes `summarize=False` when it runs as one action among many; `_summarize`
  still runs either way, since that is what turns its records into summary entries.

### Order

`update` first, so everything downstream describes the system you will be running rather
than the one you booted. `rebuild-check` after it, because it exists to catch what the
update just made stale. `clean` after — cleaning first only forces a re-download.
`pkg-integrity` after, or it verifies packages about to be replaced. `advisory-check`
last, where it reports what is **still** unfixed.

### What it excludes, and why

`kernel` can remove your ability to boot, which is why it is not in the default set
either; `container-update` pulls images over the network. Both are one flag away.
`only-update` is redundant once `update` runs. And `aur-precheck` is not included because
it is not an audit at all — it is an install-time gate that takes package names as
arguments and is invoked per-package by the yay hook, so with no arguments there is
nothing for it to check.

### Exit status

`--everything` answers **did the run complete**, not **is the machine clean** —
deliberately different from a single action. Fourteen checks on a real host will
essentially always find something (advisory-check alone reported 142 fix-available on the
development machine), and a status that is red every time is one nobody reads.

**Known limit, recorded rather than hidden:** `had_failures` currently conflates a failed
command, a finding, and a check that could not look. Only the first is separable today, so
a check that could not run reports itself in the summary but does not colour
`--everything`'s exit status. That is the wrong way round for this project's own
invariant and wants the summary channels split. Until then, single actions keep the
stricter rule — `fettle -V` still exits non-zero on a content change — and that is what
automation should gate on.

## [0.94.0] — the rest of the matrix follow-up: orphans, Arch kernels, and an honest grid

Closes items C through F of the matrix follow-up plan. A, B and G shipped in 0.89–0.93.

### Orphaned libraries work again on Debian 13 and Ubuntu 26.04 (item D)

`deborphan` no longer exists in either release, so this check had become a **permanent
skip on the two most widely deployed server distros in the lab** — honest, but the
capability was missing exactly where it matters most.

**`apt-get autoremove` is not the answer**, though it looks like it. This action already
previews autoremove separately, and autoremove only ever considers packages apt marked
*auto-installed* — a library you installed by hand and no longer need is invisible to it
forever. That case is deborphan's whole purpose, and it is what actually went missing.

So the fallback answers deborphan's question directly from dpkg's own status file:
**which installed library packages does nothing installed depend on?** One file read, no
new dependency, no per-package `apt-cache rdepends` storm. Every dependency-ish field
counts as a reference — Depends, Pre-Depends, Recommends, Suggests, Enhances — and
alternatives (`a | b`) protect both sides. Suggests is included deliberately: it costs a
few false negatives and buys the opposite of a false positive, and **this list feeds a
removal prompt**, so an over-eager entry is far worse than a missing one. Essential and
Required packages are never listed.

Whichever source answers, it is used **only as a list**; the removal stays the existing
explicit per-package purge, so no blanket `-y`, apt's own transaction shown, and the
installed set diffed around the command. The output names which source produced the list,
because the two do not answer quite the same question.

Validated against a real Debian 13 dpkg status file, which is how a genuine bug was
caught: a package that **Provides** a virtual name was being offered for removal, because
the virtual name was marked as referenced rather than the package supplying it. Virtual
names are not packages. Fixed, with a test.

### Kernel management does something on Arch now (item E)

`mhwd-kernel` is Manjaro-only, so on Arch this action printed "skipping" and did nothing —
an action that appears to exist and then declines at runtime, which is worse than one
that is honestly absent.

Arch now gets an inventory: which kernels are installed, which package owns each, which
one is running, and any module tree no package owns (an upgrade leftover). It **reports
rather than removes**, the same choice the RHEL backend makes and for the same reason —
kernel removal is the most consequential thing this tool can do, and Arch kernels are
ordinary packages with no series concept, so removal is a deliberate `pacman -R` the user
is better placed to decide on.

Which package owns the running kernel is asked of pacman, never built by pasting
`uname -r` into a package name — that shortcut is the Debian bug this project already
recorded once, where a kernel named anything unexpected stops matching and the *running*
kernel then looks like just another removable entry.

### The matrix grid distinguishes "not applicable" from "could not check" (item F)

`aur-audit` on Debian is the tool correctly declining, not a gap — but it scored the same
as a check that could not run, so the grid read as eight gaps when five were nothing of
the kind. **N/A** is now its own verdict, counted separately, and only `skip` means
something could not be checked.

### Fedora's signature failure was transient (item C)

Diagnosed, not fixed, because there was nothing to fix. `Signature verification failed`
on a kernel rpm reproduced clean once the dnf cache was cleared — a corrupt cached
package, not the stale keyring it might have been. fettle reported it correctly at the
time (*"update did NOT complete — dnf failed. Some packages may be upgraded and others
not; re-run to finish"*).

## [0.93.0] — the last three install channels notice when something is pulled

`withdrawn upstream` now covers **all eight** of fettle's install channels. VS Code /
VSCodium extensions, GNOME Shell extensions and GitHub CLI extensions were the three that
had never been asked.

They matter for the same reason the others do — removal is what a registry *does* to
malware — and arguably more, because of where the code runs. A VS Code extension is
unsandboxed Node with your full user privileges. A GNOME extension runs **inside the
gnome-shell process**, so an enabled one sees the whole session. A `gh` extension runs
with your authenticated CLI session and can act as you anywhere your token reaches.

| channel | asked | absent looks like |
|---|---|---|
| VS Code / VSCodium | the gallery the editor is **actually wired to** | 404 from Open VSX or the marketplace item page |
| GNOME Shell | extensions.gnome.org, **hand-installed only** | 404 from its extension-info endpoint |
| GitHub CLI | the GitHub API | 404 for the origin repository |

**The bug this shipped with, caught on a real machine before release.** The first
implementation inferred the registry from the profile directory — `.vscode-oss` meaning
VSCodium meaning Open VSX. That is wrong: measured on an Arch box, `Code - OSS` keeps its
profile in `.vscode-oss` and is patched to use *Microsoft's marketplace*. Asking Open VSX
about its extensions reported `ms-vscode.cpptools` and `platformio.platformio-ide` as
withdrawn when both are present in the gallery their editor actually uses — they had
simply never been published to the other one.

fettle now reads `extensionsGallery.serviceUrl` from the editor's `product.json` (user
override first, then the system install), and when it cannot determine the gallery it
**skips the check and says so**. Asking the wrong registry does not produce a weaker
answer; it produces a confident wrong one.

Three more things the shape of this demanded:

- **A canary for the marketplace.** Its "absent" signal is the store page's own 404, not
  an API contract — the *documented* gallery endpoint answers 404 for present and absent
  alike, so building on that would have called every extension withdrawn. Because a page
  could start serving 200 with a "not found" body and the check would go quietly blind,
  each run first asks about an id that cannot exist; if that looks present, the answers
  are discarded as unknown rather than trusted.
- **Only ask where the question makes sense.** Packaged GNOME extensions are skipped —
  plenty ship in a distro package and were never on e.g.o. Sideloaded `.vsix` installs are
  skipped. A `gh` extension with no determinable origin is skipped.
- **`gh` is honest about its limit.** Deleted, renamed and made-private are the same 404
  to an unauthenticated request, and a rename is routine — so the finding says to check
  rather than to act.

The HTTP three-state helper is shared with the CLI-based one from v0.91.0: only a definite
404 reads as withdrawn, and a rate limit, timeout or captive portal reads as *not checked*.

## [0.92.0] — "not in the AUR" becomes "vanished since the last run"

The previous release stopped a green tick appearing over removed packages. This one makes
the finding worth acting on.

"Absent from the AUR" was two very different situations under one label. On a real
79-package host it stood at **9 every single run** — most of them work packages built
in-house that were never in the AUR at all — and a warning that is permanently on is one
nobody reads.

The event worth alarming on is **disappearance**: it was there when fettle last looked,
and now it is not. That is what deletion for malware looks like. fettle already keeps a
per-package snapshot to detect maintainer takeovers, and that same file answers "was this
ever in the AUR". Now:

- **VANISHED from the AUR since the last run** — warns, and is named in the summary.
- **Not in the AUR, and never seen there** — listed quietly, still counted in the summary
  line and still in the JSON report. "Installed from somewhere else" and "deleted before
  fettle first ran" are genuinely indistinguishable, so it does not pretend otherwise.

The vanished entry is **retained for as long as the package is installed**. Writing only
what is currently in the AUR would forget it immediately, so the alarm would fire once —
on a run the user may never read — and then silently downgrade to "never seen there"
forever after. Entries for uninstalled packages drop out, so the file cannot grow without
bound.

**The honest cost of this change:** on an existing host the first run goes quiet. The
snapshot only ever recorded packages that *were* in the AUR at the time, so anything that
disappeared before this release is in the never-seen bucket and cannot be recovered —
including the `claude-desktop-bin` case that prompted the work. There is no other record
on the system to reconstruct it from: the AUR helper's build cache was checked and holds
one entry. The alarm is prospective by nature.

## [0.91.0] — Flatpak and Snap now notice when an app is pulled upstream

fettle asked the AUR whether your installed packages still exist there, and asked no
other ecosystem at all. So a Flatpak or Snap that had been **withdrawn from its store**
was invisible — which matters, because removal is what a registry *does to malware*.

Both providers now check, against the remote the app actually came from (not flathub by
assumption, or a third-party app would report as withdrawn on every run):

- Flatpak — `flatpak remote-info <origin> <appid>`
- Snap — `snap info <name>`, skipping sideloaded snaps, which were never in the Store
  and would otherwise be flagged forever

**The failure mode this was written around:** the question is answered over the network,
and a store that is merely unreachable would make every installed app look withdrawn at
once — "could not look" rendering as "found a problem", which cries wolf exactly as badly
as the reverse. A non-zero exit is not enough. The tool has to say, in as many words,
that it looked and the thing was not there; anything else is reported as `UNVERIFIABLE`,
**once for the run rather than once per app**.

Measured against the real tools before it was written — `flatpak remote-info` exits 1
with `Can't find ref`, `snap info` exits 1 with `no snap found for` — and verified live
through the shared helper afterwards, including that an unreachable remote returns
"don't know" rather than "withdrawn".

## [0.90.0] — a vanished AUR package no longer gets a green tick

`fettle -A` on a real 79-package host summarised as::

    ✓ AUR audit of 79 package(s) — 9 no longer in the AUR, 7 flagged out-of-date
    EXIT=0

A green tick whose own words report nine findings. The body carried a `!` warning, but
the summary — the part people read, and the part the dashboard and exit code key off —
was green. An earlier fix had corrected the summary *text* to say what was found and left
the *mark* alone, which is how it survived.

It sat on the highest-signal supply-chain indicator fettle has. A package that disappears
from the AUR is exactly what a package **deleted for malware** looks like from here: it is
what Arch staff did to `firefox-patch-bin` and friends, and to 1,579 packages in June 2026.

Now warns (still exit 0 — this is advisory) when either **event-shaped** signal is present:
a package that vanished upstream, or one that changed maintainer since the last run. Both
are things that *happened*. Out-of-date and orphaned stay counted in the text without
raising the mark — on that same host 7 are flagged out-of-date more or less permanently,
and a warning that fires every single run is how a warning stops being read.

## [0.89.0] — package integrity stops crying wolf on a clean machine

The full lab matrix (64 pass · 6 issue · 0 FAIL · 8 skip) showed `pkg-integrity`
reporting a **red integrity error on three freshly built cloud images**. Across all 13
findings there was **not one content change** — only file mtimes and directory modes:

| guest | reported | what actually differed |
|---|---|---|
| Rocky 9 | `✗ 10 packaged file(s) differ` | mtime on 7 EFI/shim binaries and a grub font; mode on `/` and `/boot` |
| AlmaLinux 9 | `✗ 1 packaged file(s) differ` | mtime on `/boot/grub2/fonts/unicode.pf2` |
| Fedora 44 | `✗ 2 packaged file(s) differ` | mode on `/` and on **`/run/cloud-init`** |

`rpm -Va` flags a content mismatch with `5`. None of these had one.

This is the one check whose entire job is detecting tampering, so a red mark on an
untouched machine is worse than useless: it teaches you that red means nothing, and the
day a real digest mismatch appears it scrolls past with the rest. It is the mirror of the
invariant this QA pass exists to enforce — *"could not look" must not render as "found a
problem"* — here, "nothing meaningful changed" rendered as "found a problem".

**Fixed by classifying on what differs, not how many files differ.** `rpm -Va` compares
all nine attributes, where `debsums` and `paccheck --sha256sum` compare content alone, so
this split is specific to the RPM path:

- **content** (digest, size, symlink target, or a missing file) → the finding, `error`
- **permission** (mode, owner, group, capabilities, device) → `warn`. True and worth
  seeing — a world-writable binary matters — but not the same event as bytes changing.
- **timestamp only** → expected. `cp`, `rsync` and every image builder rewrite an mtime
  without touching a byte; rpm reports it because rpm reports everything.

`/run` joins the regenerated-paths list: it is a tmpfs rebuilt every boot, so nothing
there survives from a package install.

Measured after the fix — **AlmaLinux 9 is now completely clean**, and the other two report
zero content findings with their metadata drift shown as a warning:

| guest | before | after |
|---|---|---|
| Rocky 9 | `✗ 10 differ` (exit 1) | `✓ no contents changed` · `! 2 permission drift` (exit 0) |
| AlmaLinux 9 | `✗ 1 differs` (exit 1) | `✓ installed files match their packages` |
| Fedora 44 | `✗ 2 differ` (exit 1) | `✓ no contents changed` · `! 1 permission drift` (exit 0) |

A regression test plants a real digest mismatch on an unmarked packaged file and asserts
it still alarms — the guard that proves this quieted the noise without muting the check.

### Not changed

Debian reports the same finding at `warn` where RHEL uses `error`. Inconsistent, noted,
and left alone rather than widened into this fix.

## [0.88.0] — the hardening audit was asleep, not working

`fettle -H` against a Rocky 9 or AlmaLinux 9 host took **over 30 minutes** and was killed
by the lab harness before it reported anything. Both EL targets have been recorded as
permanent SKIPs for the hardening audit since v0.48.0, for a reason that turns out to be
wrong twice over.

The cause is not fettle and not the volume of work — checksec examines ~900 binaries on
these hosts in about a minute. It is checksec 2.x itself, at its own line 6:

```sh
[ "$(env | sed -r -e '/^(PWD|SHLVL|_)=/d')" ] && exec -c "$0" "$@"
```

It sanitizes its environment by re-execing with an **empty** one, which wipes `PATH` — and
then restores `/sbin`:`/usr/sbin` **only when not root**. So as root it cannot find
`sysctl`, prints "Not all necessary commands found", and calls `sleep 2`. Every
invocation. Measured on Rocky 9: **61 ms as a user, 2063 ms as root**. `fettle remote`
elevates, so ~900 binaries × 2 s ≈ 30 minutes, spent entirely asleep.

**Fixed** by invoking checksec unprivileged when fettle is root, which puts it on the
branch that repairs `PATH`. Nothing else works: the environment we would fix is discarded
by that re-exec, and `--listfile` does not help because checksec implements it by
invoking itself once per file anyway (measured — an earlier attempt at batching this
changed nothing and was withdrawn).

Coverage does not shrink, because dropping privileges wholesale would have been its own
bug: 12 of 2318 entries in the bin directories on Rocky 9 are root-only readable. Anything
the unprivileged pass could not open is retried as root — detected by its **absence**,
since checksec answers an unreadable file with coloured text on stdout and exit 0 rather
than an error entry. The elevated run reports 149 deviations where the unprivileged one
reports 147; those 2 are exactly what the retry recovers.

Measured end to end via `fettle remote`, elevated: **1800 s (timed out) → 81 s.**

- **Rocky 9** — 885 binaries, 149 deviations across 35 packages: 1 Critical
  (`grub2-tools-minimal`), 1 High (`kernel-tools`), 24 Medium, 9 Low.
- **AlmaLinux 9** — 877 binaries, 147 deviations across 33 packages, in 76 s.

The unprivileged pass sees 885/872 binaries and 147/145 deviations respectively; the
difference in both cases is the handful of root-only files the retry recovers.

Also in this release: `util.invoking_user()`, the companion to `invoking_user_home()`, for
the cases that need to hand privileges *back* rather than resolve a path.

### Still open, deliberately not fixed here

`fettle remote` elevates **everything except `--dry-run`** (`sudo=not dry_run`), ignoring
the read-only/needs-root knowledge the CLI already keeps in `_MUTATES_BUT_NO_ROOT` and
`_READ_ONLY_BUT_NEEDS_ROOT`. That blanket elevation is what exposed this, and it is a
larger change than one QA fix should carry.

## [0.87.0] — `fettle web` is marked EXPERIMENTAL and put on hold

Every other feature has now been swept feature-by-feature against real hosts and the VM
lab — 23 of 24, recorded in [`docs/qa/`](docs/qa/README.md). The web UI has not, and it is
the one surface that both serves a page **and** runs privileged actions from a password
typed into a browser. Labelling it accurately is the honest thing to do while its sweep
waits.

Marked in the README, in `fettle -h`, in `fettle web --help`, in the module docstring,
and — because documentation is not what someone reads at 2am — **at run time**:

```
fettle web is EXPERIMENTAL — unlike the rest of fettle it has not been through the
QA sweep in docs/qa/.
  It serves reports AND runs actions (some under sudo). Localhost-only by default;
  keep it that way.
```

The CLI it drives is the tested part; what has not been examined is the layer between a
browser and that CLI.

## [0.86.0] — remote failures now say what went wrong, and where

QA pass on `fettle remote`, against the lab: single hosts, a three-host group with one
deliberately unreachable member, and a host that does not resolve.

**`scp -q` hid the only useful line.** An unreachable host produced
`/usr/bin/scp: Connection closed` and nothing else. Measured side by side, dropping `-q`
yields `ssh: Could not resolve hostname …: Name or service not known` first — and
**`lab.py`'s own source documents this exact confusion**, describing the code that kept
doing it. Now captured rather than silenced: success stays quiet, failure is explained.

**Every error appeared at the top, detached from its host.** stdout is block-buffered off
a terminal, stderr never is — so captured to a file or a pipe, which is what a group run
or a CI job does, the errors floated above the `=== [group] host ===` header that said
which machine they came from. `Output._to_stderr` already flushes stdout first for exactly
this reason; these paths used bare `print`.

**"Nothing came back" was silent.** The fetch-back reported only when it collected
something, so reports that failed to arrive looked identical to none being written — and
every audit action writes a report.

**And the fetch-back could break the run it follows** — a bug I introduced in v0.79.0 by
putting the hostname lookup outside the `try`, in a function whose docstring promises it
never does that. Caught by writing the test for the finding above and watching it raise
instead of print.

Verified working as designed: a group continues past a dead host, exits 1 when any host
failed, confirms before a destructive run, and falls back to the safe action set when none
is named.

## [0.85.0] — chipsec's whole default set, and "not applicable" told apart from "fine"

`sys-audit`'s `firmware` category ran exactly two modules — `common.me_mfg_mode` and
`common.bios_wp` — chosen when the only target was Intel. Measured on an AMD Ryzen
workstation **both are NOT APPLICABLE** (no Intel ME, no SPI HAL), so the category
produced nothing at all. chipsec's default set, on the same machine in **5.0 seconds**,
found an unprotected flash (`rom_armor` FAILED) and Secure Boot disabled with no PK, KEK
or db (`secureboot.variables`). chipsec already knows which of its modules apply to a
platform, and it decides that better than a hardcoded list can.

**Read from chipsec's JSON, not its prose.** `-j` yields a documented, ordered summary of
`passed` / `failed` / `warnings` / `failed to run` / `information` / `not applicable`.
Matching `"PASSED"` in output text is the same trap already fixed in `-f` (v0.61.0) and in
sys-audit's own fwupd copy (v0.71.0).

**The header mattered more than any single verdict.** chipsec said three times that it did
not recognise the platform — `Unknown Platform: VID=0x1022, DID=0x1480, CPUID=0x830F10`,
*"Results from this system may be incorrect"*, *"Platform dependent functionality is likely
to be incorrect"*. So its **26 NOT APPLICABLE results are 26 checks it had no register
definitions to perform**, not 26 things being fine. fettle now leads with that and marks
the remaining verdicts provisional:

```
! Platform: chipsec does NOT recognise this platform — every verdict below is
  provisional, and the checks it skipped were skipped for want of register
  definitions, not because they passed
✗ common.rom_armor: FAILED
! common.secureboot.variables: warning
! common.cpu.cpu_info: could not run
  Chipsec modules: 33 run — 2 passed, 26 not applicable
```

Reporting the seven that ran without that caveat would have been a blind scan presented as
a scan — the governing invariant of this whole QA pass, arriving at hardware level.

A chipsec run that leaves no readable results is an error, not a quiet pass. Unprivileged,
the category says it did not audit rather than skipping in silence.

## [0.84.2] — `fettle -S` read root's config, not yours

Reported from a real run: `fettle -S firmware` said *"chipsec: not configured"* on a
machine whose config had just been given `[secure] chipsec_cmd`.

`-S` **elevates itself**, sudo sets `HOME=/root`, and `DEFAULT_CONFIG` was
`Path.home() / ".config/fettle/config.toml"` — so the elevated process read
`/root/.config/fettle/config.toml`, found nothing, and silently used built-in defaults.

**This is Phase 9's highest-impact bug, back in a new place.** It was fixed then by
teaching the maintenance sudo re-exec to carry `--config <resolved path>`, and the
project's notes describe it in exactly those terms. v0.84.0 gave `sys-audit` its first
reason to read config — and `sys-audit` elevates by a different route, so it walked
straight into it. The correct pattern was already in the same file: `_write_report` does
the `SUDO_USER` → home lookup, and the new code did not use it.

Fixed at the constant rather than at the call site: `DEFAULT_CONFIG` now resolves from
the **invoking** user's home. That covers all eight consumers in one move, including
`sudo fettle advisory-check` / `report` / `upgrade-check`, which had the same bug and
nobody had hit yet. The four hand-rolled `SUDO_USER` lookups now have one shared
implementation in `util.invoking_user_home()`.

## [0.84.1] — a top-level key documented below a table header lands in that table

`fettle.toml.example` documented `ai_model` / `ai_effort` / `ai_max_web_searches` /
`ai_api_key` **after** `#[hardening]`. In TOML a bare key belongs to whatever table
precedes it, so uncommenting `ai_model` as shipped nested it inside `[hardening]` — where
it is accepted without complaint, because that section is a passthrough dict, and simply
never takes effect. Moved above the first table header.

Found by diffing the *loaded* config of a proposed merge against the live one, rather
than reading the file. Eyeballing it would not have shown this: the text looks right, and
only the parse is wrong.

## [0.84.0] — chipsec is configured, and the stale-flag sweep grew teeth

**`[secure] chipsec_cmd`.** chipsec ships in at least three layouts — a git checkout run
as `python3 /opt/chipsec/chipsec_main.py`, a distro package at `/usr/bin/chipsec_main`,
and a pip entry point wherever that interpreter keeps scripts — and their *invocations*
differ, so a path alone is not enough. fettle searched only for the checkout, so on the
QA host (chipsec 2.0.7, packaged) it reported *"Not found — install from github"*: advice
for a problem the user did not have. It is configured now, and unset it says plainly that
it did not run, naming the setting. `sys-audit` reads config at all for the first time.

**The example config was as stale as anyone's.** `fettle.toml.example` is dated the same
day as the QA host's live config and was missing `[clean]`, `[containers]`,
`[advisories]`, `[supplychain]`, `[updaters.rhel]`, `refresh_mirrors` and `stale_days` —
and its `default_actions` example still listed the retired `aur-ioc-scan`. Now complete,
with each block verified to parse.

## The sweep, widened — and three live bugs it found

v0.82.1's sweep only looked near the word "fettle". Widening it to retired *names*
anywhere found three references that had survived every previous pass:

- `out.next_step("check AUR packages before the next build: fettle -A -I")` — printed
  after **every AUR upgrade**.
- `"foreign (AUR/manual) packages saved to … (vet with -A/-I)"`.
- `fettle/aur/audit.py`'s docstring pointing at the removed `aur-ioc-scan` module.

And the reason the first one survived: **a test asserted it.**
`test_update_extras_hint_uses_current_aur_flags` pinned `"fettle -A -I"`, so correcting
the message would have failed a test, and the obvious response to that is to put the
message back. That test had already been wrong once before, for the v0.4.0 rename. It now
asserts the current spelling and rejects both historical ones.

Legitimate mentions — the routing table that catches the retired flag, the message
explaining where it went, report types still on disk under the old name, and the
regression tests whose subject is the rename — carry an explicit `stale-flag-ok` marker
rather than being matched by a heuristic. Twenty of them, each one a deliberate act.

Also: the sweep was scanning `venv-fettle-web/`, where pip's own source uses `-I`. It
skips any virtualenv now, not just the one that existed when it was written.

## [0.83.0] — multi-environment findings expand to their paths

An advisory affecting several Python environments rendered as `44 environments` with the
paths in a `title` tooltip. A tooltip cannot be copied, cannot be reached on a touch
device, and would not have held 44 paths anyway.

They expand now, with the same `[+]`/`[-]` affordance the report entries use:

```
[-] 44 environments
    23.2.1       /home/paulda/src/ALEAPP/venv
    24.0         /home/paulda/src/CVE-2022-31814/venv
    26.1.1       /home/paulda/src/bifrost/.venv
```

**Oldest version first**, because within one finding the installed versions differ a lot —
`pip` sat at **11 distinct versions across its 44 venvs** — and which ones are furthest
behind is what turns a count into a work queue. The fix target is the same for all of them.

Sorted numerically, not lexically: string order ranks `10.0` below `9.0`, and `6.8.0-99`
above `6.8.0-124` — the trap the kernel code already documents. Rendered as plain lines
rather than a list, so a drag-select copies clean paths.

One implementation note worth recording: these are `<details>` nested inside the entry
`<details>`, and the severity filter walked *every* `details` under a group. It now
selects entry-level ones only, or filtering would have collapsed and revealed the
expanders as a side effect.

## [0.82.1] — the stale-flag bug becomes a test instead of a habit

`-I` was retired in v0.73.0. Grepping for `aur_ioc_scan` found none of the four places
that outlived it, because all four spell it **`-I`**: the advisory footer's
`vet via fettle -A/-P/-I`, the **web UI still offering it as a runnable action**, the lab
matrix's label map, and a fourth in an f-string found two releases later. The project's
own notes already called this "the post-v0.4.0 stale-flag class of bug" and said to grep
the flag *letters* — advice that existed and was not followed, twice.

So it is a test now (`tests/test_stale_flags.py`). It reads the valid set from the
parsers themselves — the main parser plus every subcommand's `--help` — so it cannot
drift from what fettle actually accepts, and it checks both spellings: `fettle -X` and
a backticked `` `fettle some-action` ``.

The full sweep over the repo is **clean**. Two things about that result are worth stating,
because "found nothing" is the same shape as "could not look":

- The sweep is proved against a **canary**: a second test plants `fettle -I`,
  `fettle aur-ioc-scan` and `fettle --totally-made-up` in the tree and asserts all three
  are caught, while `fettle -p pkg` (valid) and `pacman -Qtdq` (not ours) are not.
- Getting to zero took three rounds of narrowing. Matching `fettle` anywhere on a line
  flagged `pacman -Qtdq` next to a `~/.fettle/` path; treating any line starting with
  "fettle" as a command flagged a hundred sentences ("fettle refuses to…"). Both
  false-positive classes are documented in the test so nobody widens it back.

## [0.82.0] — every name and identifier in the report is a link

Package names link to wherever that package actually lives, and every advisory
identifier to the authority that holds it. Applied to `advisory-check`, `pkg-audit`,
`hardening-audit`, and the `alien-pkgs` / `obsolete-pkgs` lists.

**Arch repo packages and AUR packages go to different places, on purpose.**
`advisory-check`'s `arch` findings come from security.archlinux.org, which tracks
**core/extra** — so `arch/apr` links to `archlinux.org/packages/?name=apr`, and an AUR
link there would 404. The AUR packages are the ones in the tracker's own *"not covered"*
list, which now link to `aur.archlinux.org`.

**Advisory identifiers each go to their own authority**: `CVE-` to NVD, `GHSA-` to GitHub
Advisories (many never reach NVD at all, so an NVD link would dead-end), `UBUNTU-CVE-` to
Ubuntu's page (which carries the per-release fix status NVD cannot show), `AVG-`/`DSA-`/
`USN-` to that distro's tracker. An identifier fettle does not recognise stays plain text
rather than being guessed at.

**Language findings now record their ecosystem**, so `osv/certifi` links to PyPI rather
than nowhere. It was already being captured — and stored in the `distro_class` slot, which
is what `[advisories] exclude_classes` filters on, so `exclude_classes = ["PyPI"]` would
have silently dropped every Python finding. It has its own column now (cache schema 5;
rows refresh on the next run, and older reports simply carry no link).

Also: an `advisory-check` report with no findings but a non-empty *uncovered* list was
treated as empty and hidden entirely — a host with no tracked CVEs and 77 packages the
tracker cannot see rendered as nothing to report. And the uncovered footer still advised
`fettle -A/-P/-I`, three releases after `-I` was retired.

## [0.81.1] — advisory tables were losing every column but the first

Reported from a real run: the dashboard's **Fix available** section showed only the
severity badge and a CVSS vector — package, versions, CVEs and links were missing.

The data was never missing. It was all in the HTML and unreachable: `section.host` clips
its content and no table could scroll, so anything wider than the pane simply had no way
to be seen. The **44-character CVSS vector** was what forced the first column that wide.

- The vector moves into the badge's tooltip. It is reference detail, not something read
  at a glance, and it was the single widest thing in the row.
- Report bodies scroll horizontally (`overflow-x:auto`), so no future wide content can
  hide data again. That is the general fix; the CVSS change just makes the common case
  fit without scrolling at all.

Content that exists but cannot be reached is the layout form of the bug this whole QA
pass is about.

## [0.81.0] — what changed since you last looked, and a severity filter

**The delta.** Each host card now carries `+11 new, -47 resolved since 2026-07-24`, and
the newest report of each type gets a `+4 / -2` badge whose tooltip names the packages
that appeared or went away.

The baseline is the newest report from an **earlier calendar day**, deliberately not the
previous report: three runs in an hour would reset it and show an empty delta right after
you fixed something. Measured during the QA pass that prompted this — the whole of
`local`'s advisory history had been pushed into a single afternoon.

Resolved findings are as prominent as new ones, because *"you fixed it"* must not render
the same as *"it was never there"* — this project's own invariant, applied to its own
dashboard. `sys-audit` and `pkg-integrity` store no per-finding identity, so those report
a count change and say so rather than inventing an identity that would mismatch every run.

**A severity filter** beside the existing host/type/grep controls: *Critical*, *High and
above*, and so on. It hides host cards below the threshold and report entries whose worst
finding is below it. Entries with no findings at all — run-logs, package lists — are hidden
by it too: asking for "High and above" and getting a run-log back is not an answer.

**`[reports] keep` now defaults to 10**, up from 5. Retention is also the depth of the
change history, and five rotated out of one busy afternoon. These are small text/JSON
pairs — a 14-host tree was 690 KB at the old default.

Two rendering bugs caught by building against the real tree rather than a fixture: the
card printed a raw `20260730` instead of a date, and a count-only delta rendered an empty
tooltip reading `" (since 2026-08-04)"`.

## [0.80.0] — the dashboard card now says what is actually wrong

UX pass on `fettle report` (and therefore on `fettle web`, which serves the same page).

**The card led with the least actionable number.** It showed `hardening-audit` bands and
nothing else — an opt-in audit that every real desktop has bands in — so a host with files
failing integrity, unpatched Critical CVEs or Secure Boot disabled displayed **no chip at
all**, while one with a routine hardening tally looked alarming. Underneath it counted
*reports* per type, answering "how much data do I have" rather than "what is wrong".

Each card is now a **verdict across every audit**: the worst severity in the newest report
of each type, then the two or three findings that drove it. Hardening is capped at Medium,
for the same reason `-H` does not fail a run — its "Critical" is a scoring band, not a
compromised machine, and letting it dominate teaches you to ignore the colour.

**One severity scale.** Supply-chain findings used `INFO/LOW/WARN/CRIT` while advisories
used `Critical/High/Medium/Low`, and the dashboard showed both — `LOW: 38` and `Low: 510`
side by side meaning different things, so nothing could sort or filter across them.
Unified to `Critical / High / Medium / Low / Info` in the terminal and in the JSON
(`CRIT`→Critical, `WARN`→Medium). Reports written before this release are normalised on
read, since they are on disk forever.

**A host that stopped reporting is now a finding** — `has not reported in 13 days`,
threshold `[reports] stale_days` (default 7). It is the fleet-level form of the invariant
this whole QA pass is about: a silent host looked exactly like one that reported clean
this morning.

Also fixed while measuring the new card against real data: five retained advisory-check
reports put the same 770 CVEs on one card five times, and `770 package with a known CVEs`
did not agree with itself about plurals.

## [0.79.0] — one machine was showing up as three hosts

QA pass on `fettle report`, against a real tree: 27 report directories, 20 log
directories, 9 report types. It is the only feature whose output is a *view* of other
features' output, so it inherits their naming decisions and is where those become visible.

**One machine appeared as up to three hosts.** Reports were filed under the **ssh
target**, so a lab guest on DHCP became a new "host" every time its lease moved — twelve
dashboard cards for four machines, each holding a fragment of one timeline, which defeats
the point of a view whose value is trend. The fetch-back now asks the machine what it
calls itself (validated against a hostname pattern, falling back to the sanitised target
when unreachable) and files under that.

**A rejected command had minted a permanent host.** The dashboard had one called `clean`,
traced to an injection test from v0.22.0:
`fettle remote -- -oProxyCommand=touch /tmp/pwned-by-fettle clean`. **The guard worked** —
fettle refused it — but the run-log took its host name from argv *before* validation,
skipping anything starting with `-`, and landed on `clean`. The derivation is deleted: a
run-log records a **local invocation** and is filed under `local`, full stop. The remote
writes and ships back its own transcript, so the old behaviour was duplicating that under
a second name anyway.

**`pkg-integrity` rendered as a raw JSON dump** — split out of `sys-audit` in v0.72.0,
built from the same `Scan` so its shape is identical, and never registered in the renderer
table. Five reports affected.

**Eight empty host directories rendered cards** reading "no reports / latest: –". Hidden
now, with the count kept in the header so they are hidden rather than disappeared.

Also: `render()`'s per-host loop shadowed its own `groups` parameter — harmless today
because both lists are computed before the loop, and exactly the kind of thing that stops
being harmless the next time someone edits below it.

Historical directories are left alone; this stops new ones being created.

## [0.78.0] — a failing advisory refresh looked exactly like a healthy one

QA pass on `advisory-update` — one function, no findings to render, and the feature most
likely to be run by a timer. That last part is the whole story.

**The failure printed and the process exited 0.** `out.err()` writes a line to stderr;
`summary_fail()` is what sets the exit status. Only the first was called, so a run where
every feed failed printed `✗` per provider and still exited **0** with `nothing to
report`. A systemd timer never reads stdout — so a permanently-failing refresh was
indistinguishable from a healthy one for as long as nobody ran it by hand, while
`advisory-check` quietly answered from ageing data. Partial failure now names both what
failed and what refreshed, since a half-stale cache is invisible to the next check.

**A successful refresh said nothing either** — measured, it cached 3951 rows across two
providers and the digest read `nothing to report`. Now
`✓ advisory cache refreshed: arch 2523 row(s), osv 1428 row(s)`.

**An unsupported system reported success**: `no advisory provider for this system yet.`
was a warn with an empty summary and exit 0, so a timer on such a host would report a
healthy refresh forever. Now a warning — a fact about the platform, not a failure.

## [0.77.0] — the install-time malware gate passed in silence when its lists were blind

QA pass on `aur-precheck` — the highest-consequence read-only check in the tool. Every
other audit reports on what is already installed; this one runs *before* a package is
built, once per package, from the yay hook, so its silence is taken as permission.

**It never checked whether the IoC feeds loaded.** `bad_packages()` and `bad_accounts()`
were consulted; `degraded` / `unavailable` / `stale` were not. An unreachable feed returns
an **empty set**, so every package compared clean against a list that was never read.
Measured with a cold cache against an unreachable feed host: `bad_packages()` → `set()`,
`degraded` → True, and nothing was emitted at all.

Three things make this the sharpest instance of the pattern this QA pass keeps finding:
it runs *before* the build rather than after; **the same file already got it right for
the other data source** (the AUR RPC half distinguishes offline from not-found); and the
IoC layer already tracked coverage — `aur-ioc-scan`'s sweep added it and `pkg-audit`
inherited it when `-I` was retired, so every consumer had the guard except the one where
it matters most. `bad_npm()` even carries a seed fallback commented *"never go blind"*.

**The allowlist was an unguarded trust boundary.** An entry in
`~/.config/yay/allowlist.txt` suppresses a CRITICAL malware warning for the package it
names, and the file was read with no ownership or permission check — while fettle's TOML
config has refused world-writable or foreign-owned files since day one. It now fails
**closed**: an unsafe allowlist is announced and ignored, and every package is checked.

**It always exited 0, including on KNOWN-COMPROMISED.** Documented as deliberate —
"advisory; never blocks an install" — but that reasoning comes from the hook, and the
hook does not read the exit code (`io.popen`, reads stdout, discards `p:close()`;
verified in its source before changing anything). So the status cost the hook nothing and
misled everyone else: `fettle aur-precheck foo && yay -S foo` proceeded on a known-
malicious package. Now 1 on any CRITICAL. The `CRIT `/`WARN ` line contract is unchanged.

**`AUR_PRECHECK=false` disabled the check in total silence** — no output, exit 0,
indistinguishable from "checked, all clear". The standalone path says so now; the hook
path stays quiet, because the env var is an explicit opt-out and the hook fires per
package.

`precheck.scan()` — the same code path, used by `-u`'s pre-upgrade gate — inherits all
four fixes.

## [0.76.0] — upgrade-check: a verdict you can act on, and commands attributed to their author

Code review of `upgrade-check` (no live run — it costs money per invocation, and it is
known to work; every fix here is covered by unit tests through the injectable runner).

**The third instance of the same pair.** `-U` had no summary lines at all and returned `0`
from every path, so a `risky` verdict, a clean `safe`, an absent API key and an API failure
were indistinguishable to anything downstream. sys-audit had this in v0.71.0 and
advisory-check in v0.74.0 — and the v0.74.0 write-up *predicted* this one. The common
factor is structural: every subcommand with its own entry point has to remember to call
`print_summary()` and compute a status, while pipeline actions get it once from
`actions.run()`.

Now: verdicts reach the digest and **exit 0** whatever they say (`safe` is `✓`,
`caution`/`risky` are `!`), while **"could not run" is `✗` and exit 1** — no API key, or
the analysis unavailable. A check you asked for and got an answer from has not failed; one
that never ran is the thing a script needs to tell apart.

**The hallucination guard protected the lower-consequence field.** `watch_items` entries
naming a package that is not actually upgrading are dropped — a real guard. But
`must_do_before` / `should_do_after` passed through unvalidated, and the system prompt
asks the model for *"concrete commands/steps, not 'be careful'"*. Those rendered under a
heading styled exactly like fettle's own advice, which invites copy-paste — and web search
feeds the model forum posts anyone can write. They are now labelled *"suggested by the
model — verify before running"*. The content is still unvalidated: validating a free-form
command is a much larger problem than checking a name against a list, and saying so
honestly beats a guard that only catches the obvious cases.

Recorded, not changed: the JSON schema is a prompt-level contract parsed by brace-matching,
where `output_config.format` would enforce it at the API layer.

## [0.75.0] — the pre-update security gate argued for the harmful answer

`fettle -u` / `-a` ran a `security_gate` before a real upgrade, and on an unpatched
Critical CVE it asked:

> `Continue with the update despite unpatched Critical CVEs?`

Measured on the QA host: **732 of 770 findings had a fix already released.** The update
it offered to abort was precisely what installs those fixes — answering "no" left the
machine unpatched *and* still vulnerable. For a Critical with no fix released, aborting
does not help either, since the update is unrelated to it. There is no state of the world
where the abort is the better answer.

The reasoning was already in the codebase, as a *contrast*: RHEL's `_signature_gate`
docstring notes that "an unpatched CVE is a pre-existing condition that blocking does not
fix — refusing to upgrade leaves you unpatched, which is worse", while the advisory side
did the opposite. The two agree now.

`security_gate` is now **`security_note`** — it informs and gets out of the way:

- Criticals **with a fix released**: a note naming them, since this upgrade should
  install them and you will want to check afterwards.
- Criticals with **no fix released**: a warning — the one thing an upgrade cannot fix.
- Never blocks, never prompts, still never fetches and never raises.

`[advisories] warn_gate` is retired; a config that still sets it is told so, instead of
leaving someone believing their updates are guarded.

**Two more from the same sweep.** The note said `770 advisory finding(s) … see
`fettle advisory-check``, and that report showed **176** — it counted raw findings while
the report groups by package+CVE, so the note contradicted the document it cited. And
aborting an upgrade was reported as `✓ update SKIPPED at the security gate`.

## [0.74.0] — advisory-check says what it looked at, and where

QA pass on `advisory-check`, prompted by two observations on sight: you could not tell
which findings came from the package database and which from a scan of the filesystem,
and the filesystem ones named `jetkvm` without ever saying where `jetkvm` was.

**What was checked, stated up front.** Rows from the distro's package database and rows
from a recursive walk of your home directory were interleaved, distinguished only by an
`arch/` vs `osv/` prefix you had to already know how to read. Each provider now answers
for itself, naming the roots and depth it walked.

**Environments are identified by absolute path.** The short label used to be the
*identity*, which had two costs: two environments that shrank to the same label could
collapse into one finding (hence the collision-widening logic), and a finding could not
be acted on without running `find` first. Labels are now display-only, resolved in a key
at the end of the report and in the JSON. The cache's row format changed with it, so
`SCHEMA_VERSION` is bumped — otherwise an existing cache renders `ALEAPP  ALEAPP` until
its TTL expires.

**The summary was written to a channel nobody rendered.** `_run_advisory` called
`check.run()` and returned a hardcoded `0`, never calling `print_summary()`. Every
summary line this feature produced went nowhere, and a Critical-with-a-fix could not be
reported to a script. **The same pair sys-audit had in v0.71.0** — both are subcommands
with their own entry point rather than pipeline actions.

Now: `✗` and exit 1 for Critical with a fix available (consistent with the gate that
already blocks `-u`/`-a` on it), `!` for anything else outstanding, `✓ nothing
known-vulnerable` when clean — and a feed that could not be refreshed says so instead of
passing as clean.

**And a retired flag in three places.** The uncovered-packages footer advised
`fettle -A`/`-P`/`-I`; the **web UI still offered `-I` as a runnable action**; the lab
matrix still labelled it. `-I` was retired the day before. Grepping for `aur_ioc_scan`
missed all three, because all three spell it `-I` — which is precisely what this
project's own notes call the "stale-flag class of bug" and say to grep for.

## [0.73.1] — `--ssh-arg` now reaches the upload, not just the run

`fettle remote --ssh-arg=…` configured the ssh command and **not** the `scp` that uploads
the zipapp — `_upload_zipapp` never took the argument. So any host that needs an option
to be reachable *at all* (a jump host, a non-default port, a specific `known_hosts`)
failed before it started, reported as scp's uninformative `Connection closed`. Found
while pointing the VM lab at its own `known_hosts` file, which is exactly that case.

The lab tooling (`tests/lab/lab.py`, not shipped) now keeps guest host keys in
`~/.ssh/known_hosts.fettle-lab` instead of the real one: those VMs are rebuilt constantly
and their keys change every time, and training yourself to click past REMOTE HOST
IDENTIFICATION HAS CHANGED is a bad trade for the convenience. Each guest is recorded
under both `fettle-<target>` and its address, because ssh keys `known_hosts` by whatever
it actually connects to — the lab connects by address while a human types the name.

## [0.73.0] — four AUR views become three, and each one says when to use it

Four commands looked at AUR packages and printed overlapping answers. Reading the code
rather than the docstrings: **`pkg-audit` already reported everything `aur-ioc-scan` did,
and everything bare `aur-precheck` did** except the JS-cache trace.

**`-I` / `aur-ioc-scan` is retired.** It had already been dropped from the default set
(running both fetched the AUR RPC and the IoC feeds twice and reported each finding twice);
this finishes the thought. `fettle -I` now explains where the capability went instead of
argparse's "unrecognized arguments".

**A precondition, not a detail: `-P` had to inherit `-I`'s coverage reporting first.**
`-I`'s QA sweep fixed a malware check that said *"nothing matched"* while the lists it
matches against were never fetched. `-P`'s AUR provider never had that guard — it called
the feed and used the results without asking whether they loaded. Retiring `-I` as-is would
have deleted the fix and left it missing from the one action that runs on every `fettle -a`.
`-P` now reports feeds that could not be fetched, and feeds served from a stale cache.

**The remaining three are distinguished by *when*, not by what they query** — the help and
README now lead with that:

- **`-P` pkg-audit** — routine, after the fact, every ecosystem. **Where it came from.**
- **`-A` aur-audit** — after the fact, AUR only. The census: age, votes, maintainer, and
  what nothing depends on any more. The only one that tells you what is safe to remove.
- **`-p` aur-precheck** — **before an install**, on package names you give it, emitting
  `CRIT`/`WARN` lines for a hook to parse. This is what the yay hook and `-u`'s pre-upgrade
  gate call.

Bare `fettle -p` points the install-time gate at what is already installed — a different
job from the one it was built for. It still works, and now says so, naming `-P` and `-A`.

Also: the README claimed `pkg-integrity` "runs unprivileged and never prompts", left over
from before v0.72.1 made it elevate. Corrected, with the read-only-but-needs-root
distinction stated where the elevation rules are documented.

## [0.72.1] — `fettle -V` now actually elevates

**Correction to 0.72.0.** Its notes said pkg-integrity "elevates, because unprivileged it
cannot read a large share of the files it must hash". That described the intent; the code
did the opposite. Reported on first use: `fettle -V` never asked for sudo and reported 65
files it could not read.

`NO_ROOT_ACTIONS` was derived as `READ_ONLY_ACTIONS | {"container_update"}` — encoding
**read-only ⟹ needs no root**, with a test asserting it. But the two questions come apart
in *both* directions, and pkg-integrity is the second direction: it changes nothing and
still needs root. Adding it to the read-only set (true) silently added it to the no-root
set (false).

The set is now built from two explicitly-listed exception sets instead of derived, and the
test asserts every difference between them is one of those exceptions:

- `container-update` — **mutates, needs no root** (docker socket, as the invoking user).
- `pkg-integrity` — **read-only, needs root**. Reading can need privilege too.

`--dry-run` still stays passwordless, and the report still lands in your home rather than
root's.

## [0.72.0] — package integrity is its own action: `pkg-integrity` (`-V`)

Installed-file verification lived inside `sys-audit` as its `packages` category. That put
a **package** question inside the **firmware and boot chain** scanner, and made every `-S`
run pay for a 35-second content-hashing pass. It is now its own audit action:

```
fettle -V            # or --pkg-integrity, or `fettle pkg-integrity`
```

Read-only, in the *audit & security* group of `fettle -h`, and **not** in the default set:
it is a check you run for a reason, not on a timer. It elevates, because unprivileged it
cannot read a large share of the files it must hash.

**What it compares against is now documented per distro** — pacman's MTREE, dpkg's
`.md5sums`, the rpmdb's file digests — along with what that is actually worth: the
manifest came from the same package and root can rewrite both, so this is a **tripwire,
not proof of authenticity**. It catches what does not think to cover its tracks, which is
most intruders and every interrupted upgrade.

**The signal was 3 files in 82 lines.** On the QA workstation `paccheck --sha256sum`
reports 17 differences, of which **14 are rewritten after install by a tool rather than a
person**: depmod's `modules.*` index for each of three kernels, VLC's plugin cache,
`pacman-mirrors`' `mirrors.json`. They differ on every machine that has those packages, so
they carry no information — and a check that is red everywhere is a check nobody reads.
Counted separately now, listed under `-v`, leaving three files that are genuinely worth a
look. The list is short and every entry names the tool that regenerates the file; the
three survivors were deliberately *not* added to it, because inventing a justification to
quiet an unexplained difference is the exact failure this check exists to prevent.

RHEL already triaged via rpm's `c`/`g`/`d` markers and now consults the same list, so all
three backends behave alike.

`sys-audit` loses the `packages` category, and every check it has left is distro-neutral.

## [0.71.0] — the security scan had no verdict, and neither did any remote run

QA pass on `sys-audit`, on a workstation and all six lab guests.

**The scan produced no verdict and always exited 0.** Every check reported through
`scan.status(...)`; nothing in `fettle/secure/` ever reached the summary channels. Measured
on a machine with Secure Boot disabled, 17 files failing integrity verification and a
firmware check reading as dead: 8 warnings and 2 errors in the body, and `nothing to
report` underneath. `error` now sets the exit status; `warn` does not, because a missing
TPM is a fact about the machine its operator may have chosen.

**Every `fettle remote` run reported success, whatever happened** — not just sys-audit.
`zipapp`'s generated entry point is `import fettle.cli; fettle.cli.main()`: it *calls* the
entry point and discards what it returns, so the interpreter always exits 0. A failed
remote upgrade, an unsupported distro, an audit full of findings — all arrived back as
success. Found only because the fix above finally gave the remote something non-zero to
return: the bug had been hiding behind another bug.

**fwupd: the v0.61.0 fix never reached this copy.** sys-audit has its own fwupd check,
still matching the English string `"no updates"` — fwupd prints *"Devices with no available
firmware updates:"* and exits 2, so a fully patched machine was reported as
`✗ UNKNOWN — fwupdmgr failed`.

**"Could not look" rendered as "found a problem", at scale.** 65 of the 82 lines under
`Package Integrity: Issues found` were paccheck saying *permission denied*. Now 17 differ
and 65 could not be read. Debian had its own version, counting packages that ship no
checksums as integrity failures. The RHEL implementation already did all of this
correctly — the pattern was learned in one backend and never carried back.

**A disk that could not be read printed nothing at all.** smartctl merges its error onto
stdout, so the emptiness guard passed, no field matched, and the device rendered exactly
like a healthy one — every disk on the machine, unprivileged.

**And two things that would have made the new exit code noise**: `mokutil` exiting 255 with
*"This system doesn't support Secure Boot"* is a definite negative, not a failure; and a
missing optional tool (`smartctl`, `dmidecode`, `fwupd`) is a coverage gap, not a finding —
otherwise every minimal server would exit 1 for lacking smartmontools.

Also: the certificate check told **root** to "try as root", and the TPM DMI subsection
printed nothing at all beneath its own header when unprivileged.

## [0.70.0] — the help now groups by what things are for

`sys-audit` — the deepest security scan in the tool — appeared only in a block titled
*"shortcut flags & their fuller subcommand forms"*, so the one action that looks at
firmware, boot and hardware read as a footnote. The cause was grouping by **mechanism**
(flags in one list, subcommands in the epilog) when people read by **purpose**.

- **Two action groups.** *maintenance actions* (`-c -o -u -O -r -y -d -x -f -k -C`) and
  *audit & security actions* (`-S -P -A -I -H -p -U`). `-S`, `-p` and `-U` are flags whose
  fuller forms are subcommands; they are now listed with the other audits and their
  subcommand forms noted below, rather than being findable only as subcommands.
- **`·` marks the default set.** The help said `-a  run the default action set` and never
  said what was in it — 9 of the 15 actions, and you had to read the README to learn
  which. Now visible per action, in `fettle -h` and in the README table.
- **Actions come before global options.** ~25 lines of `--no-color` / `--config` /
  `--distro` stood between the description and the first thing fettle can do.
- `container-update` and `sys-audit` were missing from the README action table entirely;
  the table also mixed audits into a section titled "Maintenance actions" and is now
  split the same way as the help.

Behaviour is unchanged: `-S`/`-p`/`-U` are still routed before argparse sees them, so
`fettle -S --list` and the "can't be combined with other action flags" error work exactly
as before. Five tests cover the layout, including that a new action must land in one of
the two groups rather than silently in neither.

## [0.69.0] — half the machine was invisible

QA pass on `container-update`, on a host that turned out to be the ideal target: **docker
and podman both installed, with different image sets**, and 6 of 11 docker images built
locally.

**Only the first runtime was ever read.** `-C` reported `11 image(s) considered` on a host
with 14; podman's `alpine`, `fedora` and `ubuntu` were never considered, and nothing said
so. The same line, with the same effect, was in the **audit** provider — `pkg-audit`
audited docker and produced a report that read as though it covered the machine. Both now
use every installed runtime and label each image with where it came from, which matters
immediately: this host has `almalinux:10` in both stores.

**It offered to pull images that were built here.** `docker pull cvetool:latest` resolves
to Docker Hub, a registry that never served it. Today that fails (*denied /
unauthorized*), so the cost is guaranteed failures rather than danger — but the names are
unclaimed rather than reserved, so the design was one publication away from replacing a
local build with a stranger's image. The discriminator is exact and local: a pulled image
has a `RepoDigest`, a built one has none. Bare-name library images (`python:3.12-slim`,
`almalinux:10`) are pulled, and correctly stay eligible.

**A dead daemon produced an empty summary** — the inline warning was right, the digest said
`nothing to report`, exit 0. This is the dead-fwupd bug (v0.61.0) in a different action; it
survived because the half that was correct made it look unlike the bug it was.

**Failures and outstanding decisions wore a green tick.** A failed pull is now `✗`,
outstanding decisions `!`, and `✓` means asked and answered.

**`auto_update = false` silently meant "ask".** `[containers]` is a passthrough dict, so
the loader that warns about unknown *keys* never inspected the *value*. Now reported.

Also: the listing error was truncated mid-word at 120 characters, exactly where the useful
part starts; and the audit's `:latest` finding said *"pulled by the mutable tag"* on images
that were never pulled — the tag is mutable either way, so it now says so plainly.

## [0.68.0] — a green tick over a Critical band, and a gap that was not there

QA pass on `hardening-audit` — the action the VM lab caught first, when it reported "no
deviations" after analysing **zero** binaries on three distros. That fix (v0.48.0/0.48.1)
is verified intact here.

**A green tick over a Critical band.** Measured on a real workstation:
`✓ 1 Critical, 7 High, 130 Medium, 95 Low (816 deviations across 233 packages)`. Deviations
are open items, so the mark is now `!`.

Deliberately **not** a failure, unlike `pkg-audit`'s CRITICAL. There, critical means a
known-malicious package is installed — rare and actionable. Here "Critical" is the worst band
of a scoring scheme and every real desktop has some; failing the run would make `-H` exit
non-zero forever and teach people to ignore it.

**"Not audited" looked like "nothing wrong", twice.** A missing `checksec`, and finding no
ELF binaries at all, were each a quiet note with an **empty summary** — the exact confusion
the analysed-zero guard exists to prevent, left unhandled in the two easier cases.

**The install advice was wrong on the RHEL family**: `dnf install checksec` fails there,
because the package is in EPEL rather than the base repositories. The hint is now chosen from
the backend.

## A gap that was recorded twice and does not exist

The lab notes and the QA plan both said *"`checksec` is not packaged for EL at all, EPEL
included — Fedora is the only dnf target that can run it"*, and two lab targets were marked
permanently blocked on the strength of it.

**False for EL9.** `dnf install epel-release && dnf install checksec` installs checksec 2.5.0
on Rocky 9, and `fettle -H` then reports **147 deviations across 35 packages**, including a
Critical on `grub2-tools-minimal`.

The original measurement was taken on the **EL10** box, where checksec genuinely is absent
from every repository, and generalised to "EL" without retesting on EL9 — which is 53% of the
EL fleet. `rocky9` and `alma9` now install it, turning two permanent SKIPs into real coverage.

**A measurement is true of the thing measured.** EL10 is not EL.

## [0.67.0] — findings are a to-do list, not an accomplishment

QA pass on `pkg-audit`, the only audit in the default set and the broadest thing fettle
does — seven providers across AUR, apt/dnf, flatpak, snap, containers, GNOME, VS Code and
`gh` extensions.

**46 open items under a green tick.** On a real workstation the summary read
`✓ 46 supply-chain finding(s)`. A green mark over a to-do list reads as "all good" at a
glance. The three-state vocabulary now applies:

```
✓ no supply-chain findings
! N supply-chain finding(s)                              open items, exit 0
✗ N supply-chain finding(s), M CRITICAL — INVESTIGATE    exit 1
```

**A CRITICAL finding now fails the run.** This is the one read-only audit where that is
right: a package on a known-malicious list is not a to-do item, and a scripted run should
stop rather than continue with a warning in the log.

**What was already right and is worth recording**: absent providers are named rather than
skipped silently (`[gh] not present on this system — nothing to audit`), and every provider
states its own coverage limits before its findings, including what it explicitly does not do.
That is the invariant this whole QA plan chases, already handled here.

### The VSCodium case, and a gap it exposed

Two extensions flagged as sideloaded `.vsix` stopped being reported after
`codium --update-extensions`. Verified **correct**: their index entries genuinely changed
from `source: vsix` to `source: gallery`, so the provenance concern no longer applied. The
finding describes the copy currently installed, not the extension's history.

But nothing said so — a finding vanishing could equally mean the check broke or the
extension was uninstalled. **The audits have no notion of *resolved***, which is the mirror
of the invariant they are built on. Recorded as an open question rather than fixed in a
sweep, since a findings-diff has real design questions and the same gap exists in
`advisory-check` and `hardening-audit`.

In the meantime the finding now says how to clear it: *"re-install it from the registry to
clear this (codium --update-extensions, …)"*.


## [0.66.0] — three AUR checks, told apart

Prompted by running `pkg-audit` on a real box and finding two AUR sections whose
relationship to `-A` and `-I` was undocumented. Measured, the overlap is near-total:
**`-P` performs every check `-I` does**, and everything `-A` does except votes and the
reverse-dependency analysis.

Two concrete consequences, both fixed; the overlap itself is deliberate and now documented
rather than restructured.

**`fettle -a` did the AUR work twice.** `-P` and `-I` were both in the default set, so every
routine run fetched the AUR RPC and the IoC feeds twice and reported each finding twice.
`-I` is **no longer in the default set** — `-P` covers it — and remains available on its own
as the fast AUR-only threat scan.

**A maintainer takeover was reported once and then invisible.** `-P` and `-A` shared
`~/.cache/fettle/aur-maintainers.json` and both *read and rewrote* it, so whichever ran first
consumed the difference and reset the baseline: run `fettle -P` then `fettle -A` and the
second said "none". That is precisely the signal all three actions exist to catch. They now
keep separate baselines, with the old shared file still read once as a fallback so nothing
already pending is lost on upgrade.

**New README section, "Three AUR checks, and which to reach for"**, with a per-check table
and plain guidance: `-P` is the routine one and the only default; `-A` is the census and the
only one that tells you what is safe to *remove*; `-I` is the threat scan alone, for when
news of a campaign breaks. `fettle -h` carries the short version.


## [0.65.0] — the malware scan could report "clean" without having checked

QA pass on `aur-ioc-scan`. It is **in the default action set**, so it runs on every
`fettle -a`, and its entire value is the answer to "have I installed anything known to be
malicious?"

**With the feeds unreachable it printed a green `✓ scan complete: no indicators matched`**
and added nothing at all to the summary. A machine that had never been checked was
indistinguishable — on screen and in the digest — from one that had been checked and was
clean.

**A stale cache was used silently.** The fallback was deliberate and `ioc.py` says so —
*"stale cache rather than silently reporting clean"* — but the caller got no signal, so a
laptop three weeks offline scanned against a three-week-old feed and announced itself exactly
like a current scan. The age is now reported.

**Only one of the three feeds was ever checked for failure.** `bad_packages()` had an
emptiness test; the accounts feed — the one that catches a *maintainer takeover* — and the
npm feed had none.

A degraded scan now refuses to claim a clean bill, names the feeds it could not read, and
says so in the summary. A genuinely clean scan now leaves a trace too, since "scanned and
clean" and "never ran" previously produced identical digests.

**And the first cut of this fix cried wolf**, which is recorded rather than quietly
corrected. It counted every unfetchable feed as a coverage gap, so a healthy machine reported
`INCOMPLETE` on every run — because campaigns publish different list types and a 404 is
normal absence, not failure. Measured: `aur-infected` has all four lists, `chaos-rat` and
`russian-spam` have no `packages-extra.txt` or `npm-packages.txt` at all. `_fetch` now
distinguishes `ok` / `missing` / `unreachable`.

That is the **same mistake as the fwupd `exit 2` case one release earlier** — treating a
routine, documented non-success as a failure — made immediately after writing a changelog
entry about it.


## [0.64.1] — say the removal command once, not 59 times

`aur-audit`'s "Candidates for removal" section repeated
`review, then: sudo pacman -Rns <name>` beneath **every** candidate. On a real 77-package
host that is 59 candidates and 118 lines, half of them the same sentence with a different
name in it — so the list was twice as long as the information in it, and the actual package
names were harder to scan.

The instruction is now given once, at the top of the section:

```
=== Candidates for removal (no packaged dependents) ===
  Review these packages and decide if you need to keep them;
  remove with: sudo pacman -Rns <package name>

  krdc-xfreerdp  [shared library]
  reiserfsprogs  [shared library]
  …
```

The "pacman only tracks PACKAGED dependents" caveat stays where it was, at the end, since it
is a warning about the whole list rather than an instruction.


## [0.64.0] — the AUR audit reported that it ran, not what it found

QA pass on `aur-audit`, run against a workstation carrying 77 real AUR packages.

| What the audit found | |
|---|---|
| **not in the AUR any more** | **9** — `claude-desktop-bin`, `littlesnitch`, `vanta`, … |
| flagged out-of-date | 4 |
| removal candidates | 59 |

What the summary said:

```
✓ AUR audit of 77 package(s)
```

Those nine are the most alarming thing this action can produce — its own report labels them
*"deleted/renamed - investigate"* — and they appeared only in body text. **A package removed
from the AUR for malware looks exactly like a package that was renamed**, which is why the
case is worth surfacing rather than burying. Now:

```
! 9 installed AUR package(s) are NOT in the AUR any more (deleted or renamed upstream)
  — a package removed for malware looks exactly like this: claude-desktop-bin, …
▸ Summary
  ✓ AUR audit of 77 package(s) — 9 no longer in the AUR, 4 flagged out-of-date
```

Maintainer changes are warned about for the same reason, and a failed RPC no longer leaves
the summary silent — an audit that could not run was indistinguishable from one that found
nothing.

**Second finding: "none (or first run - baseline saved)".** One sentence for two different
facts, on the run where it matters most. A first run now says the baseline was saved and
changes will be reported from now on; a later run with nothing moved says `none`. An
*unreadable* baseline counts as a first run rather than as "nothing changed" — that path is
reached when a prior elevated run left the snapshot root-owned.


## [0.63.0] — fix the pattern, not the instance

QA pass on `python-rebuild-check`, which found the same *shape* of bug the `kernel` sweep had
just found: **a fix applied to one action, never carried to its sibling.**

`check_rebuilds` gained a guard in v0.57.0 so a failed rebuild is reported as a failure.
`check_python_rebuilds` — the adjacent method in the same file — still ran
`summary_add("rebuilt packages for Python …")` unconditionally. Two sweeps in a row finding
that shape was enough, so this time the codebase was searched for the whole pattern rather
than the instance:

```
summary_add claiming an outcome, with no failure check in the preceding lines
  fettle/backends/arch.py:722  rebuilt packages for Python {current}
```

One hit, now fixed, and the pattern is otherwise clear across every backend. That result is
worth more than the fix.

**Two more from the same pass.** Stranded packages never reached the summary, so a
`fettle -a` run with packages broken by a Python upgrade produced a digest identical to one
with none — in the action whose only job is surfacing them. And when the running Python
version could not be determined, `current` fell back to the string `"unknown"`, so every
`python3.*` directory was compared against `"pythonunknown"`, matched nothing, and counted as
old — every package owning one would have been reported as stranded. It now says the check
did not run.

## Elevation is now per-backend

`-y` demanded a sudo password for `python3 -c`, a glob and `pacman -Qoq` — all rootless.
That was the **third** instance after `-O` and `-r`, which is what justified fixing the cause.

`cli.NO_ROOT_ACTIONS` was one global set where the right answer is per-family: on Arch those
three actions genuinely need nothing (its `refresh_metadata` runs no command at all, and
`checkrebuild` exits 0 as an ordinary user — both measured), while on apt and dnf the same
three really do write under `/var`. Backends now declare `extra_no_root`; only Arch declares
anything.

The tracker entry for this had assumed it was awkward because elevation is decided before the
backend is chosen. It is not — the backend is already detected first. Verified on the
workstation: `-y`, `-r` and `-O` all run unprivileged now, and Debian/RHEL still elevate.


## [0.62.0] — the safety change `orphans` got, applied to the action that needs it more

QA pass on `kernel`, the highest-stakes action in the tool: every other mistake can be undone
from a shell, this one can remove the shell.

**`orphans` was fixed in v0.56.0 to drop the blanket `-y`**, so the package manager shows its
own transaction and a cascade cannot happen unseen. `kernel` still ran
`apt-get purge -y <chosen>` — the user saw nothing and could refuse nothing — and still
reported `len(chosen)` rather than what actually went. Both are now fixed the same way.

That two sibling actions with the same hazard were fixed a release apart, and only because
one happened to be swept first, is the lesson worth keeping: **a fix applied to one action is
not a fix applied to the pattern.**

Measured on Debian 13 after the fix — the guest was rebooted mid-sweep so an older kernel
became genuinely removable:

- declining apt's transaction left all 438 packages and reported `no kernels were removed`
- `--yes` removed exactly 1, reported `1 package(s) purged`, and left the running kernel
  and the `linux-image-cloud-amd64` meta-package intact

**The prior hardening is intact.** Before the reboot the guest ran `6.12.96` with `6.12.100`
installed and **neither** was offered — the newer one labelled "boots next", with a reboot
advised. That is exactly the rollback the v0.4.3 bug would have proposed.

**A claim made during this sweep is corrected in `docs/qa/kernel.md`.** `apt-get purge
--dry-run` on a kernel image also purged the meta-package that pulls in future kernel
upgrades, and that was described as what fettle was about to do. It was not: the meta depends
on the *newest* image, which fettle protects and never offers. The cascade is real and the
consent problem was real; that particular consequence was not. The guard that warns when a
meta-package does go stays in as defence, labelled as defence.

**Left open:** Arch's `mhwd-kernel -r` produces no summary line at all, so the most
consequential thing fettle can do leaves an empty digest. Not fixed because it cannot be
exercised — `mhwd-kernel` is Manjaro-only, the lab has no Manjaro guest, and the workstation
is read-only. Tracked with the Manjaro-VM item.


## [0.61.0] — a dead fwupd daemon no longer reads as "up to date"

QA pass on `firmware`, which closes **B1** — the highest-priority item in the
outstanding-issues list, carried since the RHEL work and left open because it needed a live
daemon to stop. The lab provides one now.

`fwupdmgr` documents its exit codes and uses them correctly. Measured on Debian 13 with
fwupd 2.0.20:

| State | stdout | exit |
|---|---|---|
| healthy, nothing to update | *(empty)* | **2** — "no actions but successfully executed" |
| **daemon masked, cannot answer at all** | *(empty)* | **1** |

fettle discarded the exit code and decided from stdout, so both produced
`✓ no firmware updates available.` A machine whose firmware service was dead reported as
current. The verdict now comes from the code:

```
! could not determine firmware status (fwupdmgr exited 1) — firmware was NOT assessed.
▸ Summary
  ! firmware status UNKNOWN — the check could not run
```

**And the same action made the opposite mistake.** `fwupdmgr refresh` also returns **2**
when the metadata is already current — the normal state on any machine that ran recently —
and `run_quiet` treated every non-zero code as failure, so a routine condition printed
`✗ firmware metadata refreshed failed (exit 2)` on every healthy host.

"Non-zero" and "failed" are not synonyms. `Context.execute` and `Output.run_quiet` now
accept **`ok_codes`**, and firmware declares `(0, 2)`. The pair is worth naming: one was
false calm, the other crying wolf, and both came from not reading what the tool actually
said.

**The verdict also depended on matching English prose** — `"no updates"` / `"No updatable"`
against the tool's own output. On a localised system neither matches, so a clean result would
have been announced as updates being available, with the translated "nothing to update"
message printed beneath it as if it were the list. Deciding by exit code makes the language
irrelevant.

**Still blocked, and stated rather than papered over:** no VM has updatable firmware, so the
updates-available branch continues to rest on unit tests, exactly as recorded for v0.43.3.
What changed is that the other three branches are now measured.


## [0.60.0] — "automatic updates are on" did not mean they were working

QA pass on `auto-updates`. This is the action whose *entire output* is a single verdict,
read by somebody deciding whether they still need to check a machine themselves — so a wrong
answer here is not a cosmetic problem.

**Every backend stopped at "is the timer enabled".** Measured on Rocky 9 with
`dnf-automatic.timer` enabled, `apply_updates=yes`, and its service failing on every run
against a dead repository:

```
  systemctl: timer enabled, service Result=exit-code, exit 1
  fettle:    ✓ auto-updates: ON (dnf-automatic)
```

A host that had not been patched for months looked exactly like one patching itself nightly.

New shared `PackageBackend.timer_health()`, wired into all three backends. The timer names
its own service in `Unit=`, so no basename guessing is involved. `Result` is empty until the
service has ever run, which is why **"has not run yet" is a separate answer rather than a
failure** — a freshly enabled timer is not broken, and calling it broken would cry wolf on
every machine that just switched automatic updates on.

```
! but automatic updates are NOT working: dnf-automatic.service last finished with
  exit-code (exit 1). This host is not being patched — check the unit's logs
  (journalctl -u dnf-automatic).
▸ Summary
  ✓ auto-updates: ON (dnf-automatic)
  ! auto-updates: enabled but the last run FAILED — this host is NOT being patched
```

Verified in both directions on the same guest: it warns while the service is failing, and
the warning disappears once it succeeds.

**Two findings left open**, both recorded in `docs/qa/auto-updates.md` rather than fixed in
passing: Arch reports `OFF` as a fact when its curated name-list means *no timer I
recognise*, and an absent `systemctl`/`apt-config` still leaves an empty summary. Fixing the
first properly means deciding whether to scan every enabled timer's `ExecStart` — a design
the existing docstring weighed and rejected — and the two want deciding together.


## [0.59.1] — document the output contract the QA pass changed

Documentation only, filling two gaps found by auditing the docs against the behaviour.

**Exit status is now part of the contract and was documented in one place only.** Since
0.52.0 fettle exits `1` whenever an action reports a failure, and `0` otherwise — including
for a run you *declined*, because you got what you asked for. That was mentioned inside the
`only-update` section and nowhere else, though it changed for every action and matters most
to the cron and CI callers least likely to read a feature section.

**The summary vocabulary was never documented.** `✓ / ! / ✗` now have a table, and the
reason the middle state exists: `pacman`, `apt` and `dnf` all exit non-zero **both** when you
answer "no" and when they genuinely break, so an interactive run that stops early is
ambiguous and fettle says only what it knows.

New **"Reading the output"** section covers both, plus the invariant the whole QA plan is
organised around — *"could not look" is never reported as "clean"*.

Also: the support matrix row for `-r` said "Rebuilds & service restarts", which
undersells it since 0.57.0/0.58.0 — it reports a pending reboot on all three families now.


## [0.59.0] — `config-drift` says whether your settings still apply

QA pass on `config-drift`. The action lists files an upgrade left behind — and **which**
file it left tells you two very different things, which only one of the three backends was
saying.

| What happened | Arch | Debian | RHEL |
|---|---|---|---|
| New default shipped, **your file still in effect** | `.pacnew` | `.dpkg-dist`, `.ucf-dist` | `.rpmnew` |
| **Your file moved aside — the package's version is in effect now** | `.pacorig` | `.dpkg-old`, `.ucf-old` | `.rpmsave`, `.rpmorig` |

The second row means a setting somebody deliberately made has silently stopped applying. The
RHEL backend has always warned about it separately, and its docstring names the offender:
*"Lumping them together (as the Debian backend does for its own three suffixes) would hide
the case where a machine quietly stopped honouring settings someone deliberately made."*

**It was worse than that comment claims. Debian was not lumping them together — it was never
looking for them.** `.dpkg-old` and `.ucf-old` appeared in no pattern list, so a config an
upgrade had replaced was simply invisible to `-d`. Arch received all four of pacman's kinds
from `pacdiff` and labelled the lot *"pacnew files needing attention"*.

**And `pacdiff` cannot see the files that matter most.** It is a *merge* tool: measured, it
lists only leftovers whose base file still exists, because with nothing to merge against it
has nothing to do. Three files seeded into `/etc` — `.pacnew`, `.pacorig`, `.pacsave` — and
`pacdiff -o` returned **none of them**. A `.pacsave` is created when a package is *removed*,
so its base is gone by definition and every one was invisible on Arch.

Arch now walks `/etc` like the other two backends, which also retires the "absent or failing
`pacdiff` reads as clean" problem rather than patching it — there is no longer an external
tool that can be absent. `pacdiff` and `rpmconf` are still suggested for the merging.

All three now classify, warn on the displaced ones, and carry the count that matters:

```
✓ 4 config file(s) to review — 1 where YOUR version is no longer in effect
```

Verified on Arch, Debian and Rocky with both kinds seeded. README gains a section and the
`-d` help line now describes the outcome rather than listing suffixes.


## [0.58.2] — document what `orphans` and `rebuild-check` now do

Documentation only, and overdue: the `clean` and `only-update` sweeps updated the README and
the help text as part of the pass, the `orphans` and `rebuild-check` sweeps did not. The
action table was still describing behaviour that changed several releases ago.

- **`-r` now has its own section.** What it actually answers — *is the patch in effect?* —
  and the three ways a pending reboot is detected, including the Arch case where the running
  kernel can no longer load modules. Also that a check which could not run says so, since
  "nothing to do" is precisely what a broken check looks like.
- **`-o` now has its own section.** That the real transaction can exceed your selection and
  the package manager gets to confirm it; that the reported count is measured rather than
  assumed; that `keep_orphans` holds packages back by name; and a warning that `--yes` means
  "delete them" in this one action.
- **Help lines rewritten for both**, from mechanism to outcome. `-r` was "find
  packages/services needing a rebuild or restart"; it is now "is the patch in effect?
  reports a pending reboot and services still running old libraries".


## [0.58.1] — audit of the QA findings so far

Documentation only. An end-to-end check that every finding from the five completed sweeps
is either fixed in the code or deliberately parked, rather than assumed to be.

**All 29 findings accounted for.** 21 fixed and each verified present in the source, 1
withdrawn as never real, 7 open by decision (three deferred pending Paul's research, three
awaiting a direction, one cosmetic).

**One finding was never written down.** `fettle -r` demands a sudo password on Arch, while
`checkrebuild` run directly as an unprivileged user exits 0 and gives the same answer. It was
observed during the `rebuild-check` pass, mentioned in passing, and never reached a case ID
or a findings section — so the audit found it, not the sweep. Now recorded as **R-06** and
folded into the existing question about elevation, which turns out to have two instances:

* `-O` on Arch — `refresh_metadata` runs no command and the preview is rootless by design
* `-r` on Arch — `checkrebuild` needs no privileges

Both stem from `cli.NO_ROOT_ACTIONS` being one global set where the right answer is
per-backend: RHEL genuinely needs root for its service list, Debian's `needrestart` likewise,
Arch's tools do not. On Arch this makes two read-mostly actions unusable anywhere a password
cannot be typed.

**Stale statuses corrected in `docs/qa/clean.md`** — five findings still read as merely
"CONFIRMED" although the retest table directly above them recorded the fixes. A findings list
that does not carry its own status invites exactly the misreading this audit was checking for.


## [0.58.0] — two more ways a pending reboot went unmentioned

The `rebuild-check` sweep across all six guests, after 0.57.0 fixed the Debian half.

**Arch had the same gap, with a sharper edge.** A guest running kernel `7.1.3-arch1-3` with
`7.1.5-arch1-2` installed reported `✓ no packages need rebuilding` and nothing else —
`checkrebuild` only looks at libraries. But the `linux` package *owns*
`/usr/lib/modules/<release>`, and an upgrade replaces that directory: the running kernel
could no longer load any module it had not already loaded. Plugging in a USB device or
mounting an unusual filesystem would simply fail.

Detected now by comparing `uname -r` against the module directories on disk, rather than
parsing version strings — the package version (`7.1.5.arch1-2`) and the kernel release
(`7.1.5-arch1-2`) are punctuated differently and matching them textually is a trap.
Verified in both directions: the guest warns, and a workstation with **13** module
directories whose running kernel is among them stays quiet.

**A dnf4 host without `yum-utils` was given a false all-clear.** The RHEL backend chose its
reboot-hint command by asking whether the standalone `needs-restarting` binary existed,
treating absence as "this must be dnf5". It is not: a dnf4 host simply without `yum-utils`
also lacks it, and there `dnf needs-restarting` is a **process list that exits 0** whether or
not a reboot is owed.

Measured, and the contrast is the proof — same dnf 4.14.0, same lab, opposite outcomes:

| | standalone tool | fettle said | truth |
|---|---|---|---|
| **AlmaLinux 9** | absent | *(nothing about a reboot)* | running 687.5.3, **687.31.1 installed** |
| **Rocky 9** | present | `reboot required` | running 687.10.1, 687.33.1 installed |

The generation now comes from `dnf --version`, and a dnf4 host with no standalone tool is
told the check could not run — and pointed at `yum-utils` — rather than given silence that
reads as a pass. This is the failure the backend's own docstring set out to prevent ("only
exit 0 is allowed to mean 'no reboot'"); the guard was right, the command being guarded was
wrong.

`docs/qa/rebuild-check.md` carries the full sweep.


## [0.57.0] — Debian never told you to reboot

QA pass on `rebuild-check`. The question this action exists to answer is *"I just patched
this box — is the patch actually in effect?"*, and on the Debian family it was answering a
different one.

**`needrestart` reports the kernel state and fettle read only the service lines.** Measured
on a guest that had just upgraded its own kernel:

```
NEEDRESTART-KCUR: 6.12.96+deb13-cloud-amd64     <- running
NEEDRESTART-KEXP: 6.12.100+deb13-cloud-amd64    <- installed
NEEDRESTART-KSTA: 3                             <- needrestart: reboot required
```

fettle's answer on that machine:

```
✓ 3 service(s) need restarting
→ restart them: sudo needrestart
```

The advice was not merely incomplete, it was wrong: restarting those services cannot help
while the running kernel is the old one. And **`kernel` (`-k`) is not in the default action
set**, so a routine `fettle -a` that upgraded the kernel told nobody to reboot — while the
identical run on Rocky said "reboot required", because the RHEL backend has a whole
docstring about this exact asymmetry.

`NEEDRESTART-KSTA` is now read, with its own documented meanings (0 unknown, 1 current,
2 ABI-compatible newer kernel, 3 newer kernel — reboot). Same box, now:

```
✓ reboot required (kernel)
✓ 3 service(s) need restarting
→ reboot to start running the kernel you have installed
```

**Two more "could not look" holes closed while here.** Empty `needrestart` output — it
always prints a header, so nothing at all means it did not run — reported *"no services need
restarting"*. On Arch, a missing `checkrebuild` was a quiet note with an empty summary, and a
*failing* `checkrebuild` produced *"no packages need rebuilding"*. Both now say the check
did not run.

**A failed rebuild is now a failure** rather than `✓ rebuilt packages with outdated deps`.

> **Correction (added after this entry first shipped).** It also claimed `-r -R` "could
> rebuild nothing while offering to", because the package list took field 2 of each
> `checkrebuild` line and dropped shorter ones. **That does not happen.** `checkrebuild`
> emits `repo<TAB>pkgname` — always two fields; its source ends with
> `awk '{ print $2 "\t" $1 }'`, and a live run prints `foreign⇥zoom`. The original parse
> was correct. The code change (fall back to field 1 when a line has only one) is harmless
> and stays as a guard, but it fixed a defect that was never there, and the claim was
> written from reading rather than from measurement. Left visible rather than deleted,
> for the same reason 0.43.2 is.


## [0.56.1] — count only what is actually installed on Debian

Follow-up to 0.56.0, found by chasing a number that did not add up.

The `orphans` sweep showed Ubuntu claiming 10 packages autoremoved while the installed count
dropped by 8. **fettle was right and the measurement was wrong:** `dpkg-query -W` also lists
**`rc`** packages — removed, but with their config files kept — and two of the ten had left
config behind. All ten really went.

But the same mistake was inside the fix shipped in 0.56.0. `installed_packages()` used the
unfiltered `dpkg-query -W`, and a plain `apt-get remove` leaves a package in exactly that
`rc` state — so it would appear in **both** the before and after snapshot and the diff would
score it as still installed, under-reporting every removal on the Debian family. It now
filters to status `ii`.

The Debian autoremove path also reports the measured set rather than the preview count, so
every removal path on every family now answers the same question: what actually went?

`docs/qa/orphans.md` carries the full sweep — six guests, candidate lists cross-checked
against each distro's own tool, `keep_orphans` honoured and named, `--dry-run` and
no-stdin removing nothing anywhere.


## [0.56.0] — `orphans` asks about everything it removes, and counts it honestly

QA pass on `orphans`, the one action that deletes installed software.

**Removing an orphan can remove more than the orphan.** `pacman -Rs` also drops
dependencies the chosen package was the last thing needing. Measured on a lab guest:
`pacman -Qtdq` offers `nmap`; removing it also takes `lua54`. fettle ran
`pacman -Rsn --noconfirm`, so pacman printed that two-package transaction and then answered
its own confirmation — the user watched an extra package go by with no way to refuse it —
and the summary said:

```
✓ 1 orphan(s) removed          # two packages were removed
```

The RHEL backend already documents avoiding exactly this: *"Without `--yes` dnf then shows
its own transaction and confirms, so a removal that cascades into dependents cannot happen
unseen."* The Arch path did the thing that comment describes avoiding, and Debian's
`apt-get purge -y` had the same shape.

Both now drop the blanket confirmation-suppressing flag unless `--yes` was given, so the
package manager's own transaction is a real decision point. Declining it removes nothing and
reports nothing.

**Counts are now measured, not assumed.** New `PackageBackend.installed_packages()` on all
three backends; the removal paths diff the installed set around the command and report what
actually went, naming anything beyond the selection:

```
✓ 2 package(s) removed (including 1 unused dependency(ies): lua54)
```

Verified on Arch: declining pacman's prompt leaves 273 packages and says "nothing was
removed"; `-o --yes` removes 2, reports 2, and names `lua54`.

**Note for scripted use:** a run with two interactive prompts (fettle's per-package chooser,
then the package manager's) cannot be driven by piping stdin — Python's `input()` buffers,
and swallows the line the package manager was waiting for. Use `--yes` for automation, which
is unattended by design and keeps the suppressing flag.


## [0.55.2] — say what you are about to do, in the right order

The last two findings from the `update` sweep. `docs/qa/update.md` now carries the full
results: 340 packages installed across six guests, six findings, all fixed.

**The mirror step announced only after it had finished.** Reported from a live `fettle -a`.
It runs `quiet=True`, so it printed its tick on completion while every other step of the
upgrade announces beforehand — and with a bare `-f` it probes *every* known mirror, so the
user watches a silent terminal for however long that takes and reasonably reads it as a
hang. It now says `regenerating the mirror list (probing mirrors — this can take a
while)...` first. Under `--dry-run` the existing `would run:` line already is the
announcement, so nothing extra is printed and nothing false is claimed.

**Diagnostics jumped ahead of the output they belonged to.** stderr is unbuffered while
stdout is *block*-buffered whenever it is not a terminal, so over ssh, in a run-log, or
through a pipe, every warning appeared **before** its own section header. Measured with a
signature warning printed above the `▸ Updating packages` line it was warning about:

```
  ! 1 enabled repository install packages WITHOUT verifying their signature
  ▸ [1/1] Updating packages          <- the header arrived second
```

`Output` now flushes stdout before writing any diagnostic. This is not specific to
`update` — it has silently scrambled the ordering of every warning fettle has ever written
into a log or an ssh session.


## [0.55.1] — installing unverified packages is not an achievement

The RHEL-family half of the `update` sweep. With a `gpgcheck=0` repository enabled and
`--yes`, the run ended:

```
▸ Summary
  ✓ upgraded from 1 unsigned repo(s)
  ✓ packages updated (dnf)          <- dnf had just failed
```

The signature gate does its job — it warns twice before proceeding — and then records the
outcome in the summary **with a green tick**, as though installing code whose signature was
never checked were something the run had accomplished. It is now a warning:

```
  ! installed packages from 1 repo(s) WITHOUT signature verification (gpgcheck=0)
  ✗ update did NOT complete — dnf failed. …
  EXIT=1
```

Verified on Rocky 9 with an unsigned, unreachable repo.


## [0.55.0] — `update` stops claiming upgrades that never happened

QA pass on `update`/`upgrade`, the one action that installs software.

**The summary claimed success unconditionally.** `update_extras` ended with
`summary_add("packages updated (…)")` outside any check, so three runs that installed
nothing all signed off green — measured on live guests:

| Run | Installed | Reported |
|---|---|---|
| `-u --dry-run` | nothing | `✓ packages updated (repos: pacman, AUR: yay)` |
| `-u` **declined at the prompt** | nothing | `✓ packages updated` |
| `-u --yes` with nothing to do | nothing | `✓ packages updated` |

On an up-to-date Manjaro box the dry-run printed `✓ no updates pending` and
`✓ packages updated` in the same summary, contradicting itself.

The backends now describe *what they did* via `Result.summary` ("repos: pacman, AUR: yay")
and `actions._update` decides whether that description has been earned — the same split
already used by `clean`. It also consults `ctx.failed_commands`, so a failed upgrade is
reported as one and **exits non-zero**.

**New `Output.summary_warn()`, and the reason it had to exist.** The first cut of this fix
reported a *declined* upgrade as a failure, because pacman, apt and dnf all exit non-zero
both when the user answers "no" and when they genuinely break — an ambiguity this codebase
already documented for dnf and then walked into anyway. Trading a false "success" for a
false "failure" is not progress. `--yes` is the one reliable discriminator: with it there
was no prompt to decline, so non-zero is a real failure (`✗`, exit 1). Without it the run is
ambiguous and says so (`!`, exit 0) rather than picking a side it cannot know.

Live-verified on Arch with 27 updates pending: dry-run leaves them pending and says
`would update packages`; a declined run reports `!` and exits 0; an unreachable mirror under
`--yes` reports `✗` and exits 1. Four tests, three confirmed to fail without the fix.


## [0.54.1] — say plainly that 0.5.x is under test, and document the mirror change

Documentation only.

- **Release-status notice**, at the top of both the README and this file: the 0.5.x line is
  undergoing a feature-by-feature QA pass, behaviour can change between releases, and the
  next stable release is **0.6.0**. The sweep has already found actions reporting success
  while doing nothing at all, so the notice says `--dry-run` first if the machine matters.
- **New README section on the Arch-family mirror refresh**, because `fettle -u` rewriting
  `/etc/pacman.d/mirrorlist` is a change to system configuration and users should not have
  to read the changelog to discover it. Covers why it defaults on, why setting a number is
  worth it (bare `-f` has no limit and probes every known mirror), that vanilla Arch and
  EndeavourOS have nothing wired up, and why no other distribution needs the concept —
  Fedora uses metalink, the RHEL family a mirrorlist service, Debian/Ubuntu a CDN.
- Table of contents now lists the per-action sections added during the QA pass.


## [0.54.0] — the Manjaro mirror refresh is now yours to configure

`update` on Manjaro has always run `pacman-mirrors -f` first, unconditionally and
unannounced beyond a terse "mirrors refreshed". It rewrites `/etc/pacman.d/mirrorlist`,
which is system configuration, so it should be the user's call.

New **`[updaters.arch] refresh_mirrors`**, which takes three shapes:

| Value | Behaviour |
|---|---|
| `true` *(default)* | `pacman-mirrors -f` — regenerate the mirrorlist before upgrading |
| `false` | leave the mirrorlist alone |
| integer `N` | `pacman-mirrors -f N` — rank the fastest N mirrors |

**Default is ON, from experience rather than theory:** a mirror that has fallen behind
serves an old database, and pacman then resolves the upgrade against package versions that
mirror no longer holds. Reasoning alone suggested defaulting it off, since the historical
case for local mirror ranking has weakened — modern Arch ships CDN endpoints
(`geo.mirror.pkgbuild.com`, `fastly.mirror.pkgbuild.com`) and every other family fettle
supports has moved mirror selection server-side (Fedora metalink, Rocky's mirrorlist
service, Debian/Ubuntu CDNs). Measured breakage beats that argument.

**Why the integer form exists.** Bare `-f` is not a moderate default but the heaviest
variant: its argument is `nargs="?", const=-1`, and pacman-mirrors reads anything `<= 0` as
"test the entire pool". So every upgrade speed-tests every known mirror. `refresh_mirrors =
5` bounds that.

Two smaller things while here: the status line now says **`mirror list regenerated
(/etc/pacman.d/mirrorlist)`** rather than "mirrors refreshed", because the old wording did
not reveal that a system file was being rewritten; and when the setting is on but
`pacman-mirrors` is absent — vanilla Arch, EndeavourOS — fettle now says so and points at
`reflector`, instead of skipping in silence while the user believes it ran.

Verified on Manjaro under `--dry-run` for all three shapes; the mirrorlist was not touched.
Seven tests.


## [0.53.0] — `-O` no longer answers with stale data as though it were current

QA pass on `only-update`, swept across all seven targets.

**A failed metadata refresh produced a confident answer.** With the network broken, every
non-Arch family printed a full list of pending packages, no caveat, exit 0. The two package
managers fail differently and both were mishandled:

* **apt exits 0 when it could not reach a single repository** — measured on Ubuntu 26.04
  with DNS broken. fettle therefore printed `✓ apt package lists refreshed` for a refresh
  that never happened. `apt-get update --error-on=any` exits **100** instead (measured), so
  that is now used — probed via `apt-get --version` for apt ≥ 2.1, since an older apt
  rejects the option with the same exit code the flag exists to detect.
* **dnf exits 1 correctly**, and fettle recorded it in `ctx.failed_commands` — but
  `_only_update` never looked. It does now.

A refresh failure is reported, the preview is labelled `(from stale metadata)`, and the run
exits non-zero. The list is still printed: last-known data is useful, presenting it as
current is not. Arch was already the one family that got this right.

**The summary omitted the one number the action exists to produce.** A run with 179 packages
waiting signed off `nothing to report`. Now `✓ 179 package(s) pending`, or `no updates
pending`, and `(from stale metadata)` when that applies.

**The Arch staleness note named a cause it had never checked.** `_temp_synced_db` can fail
three unrelated ways and the caller reported the first one regardless — telling users to
install `fakeroot` and `pacman-contrib` when both were present and the mirror was simply
unreachable. It now returns the real reason and quotes pacman.

**`--dry-run` claimed a refresh was happening.** The "refreshing package metadata" line sat
outside the dry-run gate, the same shape fixed for `clean` in 0.51.0.

Live-verified on Ubuntu 26.04 and Rocky 9, healthy and with DNS broken. Seven tests, three
confirmed to fail without their fix.


## [0.52.0] — a blocked action can no longer sign off green

QA finding **F-12**, found by a `clean` case that had never been run: make one cached
package undeletable and the clean fails, says so at the step level — and then reports
success anyway.

```
✗ dnf package cache cleared failed (exit 1):
[Errno 1] Operation not permitted: '.../bash-5.1.8-9.el9.x86_64.rpm'
▸ Summary
  ✓ caches already clean — nothing to reclaim      <- three rpms still on disk
EXIT=0
```

Two causes, both now fixed.

**The summary had no way to report a failure.** `print_summary` rendered every line with a
green tick, so an action that failed could either claim success or say nothing. New
`Output.summary_fail()` renders with a red `✗`, and `Output.had_failures` drives the exit
status.

**Nothing above the individual command knew it had failed.** `Context.execute` now records
non-zero exits in `ctx.failed_commands`. Tracked centrally rather than at each call site so
a backend cannot forget — this bug existed precisely because no layer above the command was
watching. `actions._clean` compares the list before and after its own work, which separates
*there was nothing to free* from *it could not be freed*; both free zero bytes, and the byte
delta alone cannot tell them apart.

**`fettle` now exits non-zero when an action reports a failure.** The maintenance pipeline
returned 0 unconditionally, so a cron job could not distinguish a completed run from one
whose work was blocked — the run log said so, the exit status did not. Only actions that
call `summary_fail` affect it, so today that means `clean`; the channel is there for the
rest as their QA passes land.

Live-verified on Rocky 9 — blocked: `✗ clean did NOT complete — dnf failed (nothing was
reclaimed)`, `EXIT=1`, three rpms still present; unblocked on the same host: `✓ caches
cleaned — 3.0 MiB reclaimed`, `EXIT=0`. Three tests, two confirmed to fail without the fix.


## [0.51.1] — document `clean`: every platform, every invocation form, the config

Documentation only; no behaviour change. Prompted by a plain question — *"do we ever say
that clean can be run as `-c`, `--clean`, or just `clean`?"*

- **The action table described behaviour that changed an hour earlier.** It still said Arch
  clean does "pacman + pamac/yay caches", which stopped being true in 0.50.0. Now describes
  the retention policy and links to its config key. Exactly the drift the QA plan exists to
  catch, caught late.
- **All three invocation forms are now stated outright**, in the README and in `fettle -h`.
  Both already said actions work "as a flag or a bare word", but neither spelled out that
  the long flag exists too. The help group header now reads `fettle -c` == `fettle --clean`
  == `fettle clean`.
- **New README section: Cache cleaning (`-c`)** — what it reclaims on each family and why
  they differ. The Arch rollback rationale (the cache *is* the downgrade path, which is why
  retention exists and why `-Scc` is not used), Debian's untouched package lists, and the
  measured RHEL figures behind `clean packages` over `clean all`. Documents
  `[clean] keep_versions`, and says plainly that it is Arch-only because apt and dnf keep no
  version history to trim.
- **`-c`'s one-line help** was "clean package-manager caches" — jargon that described the
  mechanism rather than the outcome. Now "reclaim disk from downloaded package files; keeps
  rollback versions on Arch".


## [0.51.0] — `clean` tells the truth on every family, not just Arch

The rest of the QA sweep's `clean` findings. v0.50.0 fixed the Arch no-op; these are the
four that affected Debian, Ubuntu, Rocky, Alma and Fedora, where cleaning had always
*worked* but described itself badly.

**The summary moved out of the backends into `actions._clean`**, which now sizes the cache
directories around the call. One truthful account for every family instead of three
copies of `summary_add("caches cleaned")` — a line that used to print in three situations
that are not the same thing:

```
✓ caches cleaned — 39.2 MiB reclaimed     (a run that freed something)
✓ caches already clean — nothing to reclaim
✓ would clean caches                      (--dry-run, which deleted nothing)
```

Backends now declare `cache_paths()` — what their clean reclaims — and the action measures
it. Sizing the directory rather than parsing tool output is deliberate: parsing is exactly
what would not have caught the Arch bug. `RhelBackend` lists **both** `/var/cache/dnf` and
`/var/cache/libdnf5`, because dnf5 uses the latter and leaves the former present but empty
— measuring only the traditional path reports a clean cache that was never looked at.

**The confirmation prompt no longer asks about "build dirs" on families that have none.**
It was `remove package-manager caches and build dirs?` everywhere; only the Arch family
removes build directories, so Debian and RHEL users were consenting to something that
could not happen, on a prompt whose safe default is No. Now `remove downloaded package
caches?`, with the Arch backend overriding to name its AUR build directories.

**`apt-get autoclean` no longer runs after `apt-get clean`.** `clean` empties the archive
directory outright; `autoclean` removes only packages that can no longer be downloaded, so
it had nothing left to consider. It printed its own success line regardless, so a user
counted two operations where one had happened.

Live-verified on Debian 13 and Rocky 9: 39.2 MiB and 3.0 MiB reclaimed respectively, a
second run reporting `already clean`, and `--dry-run` reporting `would clean caches`.
Seven new tests.


## [0.50.0] — `clean` has never cleaned anything on Arch. It does now.

Found by the new manual QA plan (`docs/qa/`), first feature swept: `clean` across seven
targets — six lab VMs and a live Manjaro workstation.

**`pacman -Scc --noconfirm` removes nothing.** `--noconfirm` makes pacman take the
*default* answer to its own prompts, and `-Scc` defaults to **No** because the operation is
destructive:

```
:: Do you want to remove ALL files from cache? [y/N]     <- --noconfirm answers N
```

It exits 0 and prints nothing to say otherwise, so fettle reported `✓ pacman cache cleared`
and the caller could not tell. Measured on a lab guest: **194 cached packages before, 194
after**. On the workstation that surfaced it, the cache had reached **59 GB / 15,673 files**
— it had only ever grown, across every `fettle -c` ever run on it.

Debian, Ubuntu, Rocky, Alma and Fedora were all measured clean-correct in the same sweep
(41 MB of `.deb` files to zero; rpms removed with repo metadata preserved). **The defect was
Arch-family only.**

**Answering "yes" would have been the wrong repair.** `-Scc` also deletes the cached copy of
every *currently installed* package, and on Arch that cache is the primary way to roll back
a bad upgrade without a network. Fixing the no-op naively would have converted a harmless
lie into a destructive default. The replacement splits the work by rollback value:

1. `paccache -r -u -k0` — cached packages **no longer installed at all**. No rollback
   value; always removed. On the 59 GB cache that is 1,389 packages holding **31.1 GiB**.
2. `paccache -r -k<n>` — superseded versions of installed packages, keeping `n`
   (**new `[clean] keep_versions`, default 2**). Keeping two is 18.3 GiB on that same cache
   and still leaves a working rollback target plus a spare.

Without `pacman-contrib` it falls back to `pacman -Sc --noconfirm`, whose prompt defaults to
**Yes** and which keeps installed versions — less thorough, correct, no new dependency.

**The summary now tells the truth in three distinguishable ways**, where all three used to
read `✓ caches cleaned`:

```
✓ caches cleaned — 353 KiB reclaimed      (a real run that freed something)
✓ caches already clean — nothing to reclaim
✓ would clean caches                      (--dry-run, which deleted nothing)
```

Space freed is measured from the cache directory itself, not parsed from the tools' own
summaries — parsing would not have caught this bug, and measuring does.

Live-verified on the Arch guest: 10 cached files for uninstalled packages removed, `bash`'s
two cached versions preserved, `353 KiB reclaimed` reported. Five regression tests, each
confirmed to fail against the old command.

## [0.49.1] — lab: one login name across every guest

Test tooling. Setting **`ADMIN_USER`** in `lab.conf` creates an extra account on every
guest, with the configured key and passwordless sudo. Each cloud image otherwise has its
own default user — `arch`, `debian`, `ubuntu`, `rocky`, `almalinux`, `fedora` — so anything
driving the lab had to know six names. Configured rather than hardcoded, since this repo is
public.

Two things worth recording from applying it to the existing guests:

- **Revert before re-snapshotting.** The matrix sweep ends on `update --yes`, so every VM
  was sitting fully patched. Re-baselining in that state would have quietly destroyed the
  out-of-date baseline the whole lab depends on. Reverted first, then verified the
  restored state still had pending updates (Debian 3, Rocky 63) *before* taking the new
  snapshot.
- **A NetworkManager guest registers the wrong DHCP hostname on first boot**, because it
  takes its lease before cloud-init sets the hostname — so `fettle-fedora` did not resolve
  while the other five did. One `systemctl restart NetworkManager` fixes it for good.

## [0.49.0] — lab: the matrix sweep

Test tooling. `lab.py matrix` runs every action against every built target through
**`fettle remote`**, and prints a PASS/FAIL/SKIP grid with a reason on every non-PASS cell.

**Three states, never two.** An action that could not run must not look like one that ran
and found nothing — that is the failure mode this entire lab was built to catch, and a
runner that scored it as a blank or a pass would reproduce it at scale. So a missing
`checksec`, an unsupported action, and "the hardening audit did NOT run" are all SKIPs
carrying their reason, distinct from both PASS and FAIL.

Isolation is the other half:

- **Read-only actions share one revert; every mutating action gets its own.** `-u` consumes
  the pending upgrades `-O` exists to report, and an `-o` that removed something changes
  what `-P` sees. Without that, the sweep measures whatever the previous action left behind.
- **`--yes` on mutating actions**, because without a tty `ctx.confirm` returns its safe
  default — the action would decline and "pass" having changed nothing.

One classifier subtlety, found by reading a failure rather than trusting the verdict: **`✗`
is not a failure signal.** A real `-u` on Arch upgraded all 17 pending packages and *then*
printed `✗ yay not found` for the AUR half. Scoring that FAIL condemns a working action;
scoring it PASS hides that half of it never happened. It is a SKIP.

Per-cell output is kept under `tests/lab/matrix-logs/` so any verdict can be re-examined.

## [0.48.2] — lab: both checksec generations now covered

Test tooling. `checksec` is declared on the `arch` target too (it is in `extra`, so
cloud-init can install it), which closes the gap left by 0.48.1: **3.x had no lab coverage**
after the parsing was refactored around 2.x.

Verified live on Arch — checksec **3.2.0**, 830 binaries, 143 deviations across 9 packages —
so the refactor did not break the generation it was originally written for.

Both paths are now exercised by real hosts rather than unit tests alone: **3.x on Arch, 2.x
on Fedora, Debian and Ubuntu**. Since the two share no command line and getting it wrong
produces a *clean-looking* result rather than an error, neither can rot unnoticed.

## [0.48.1] — the checksec blast radius was wider than 0.48.0 said

0.48.0 described the false-clean `hardening-audit` bug as affecting "every host with
checksec 2.x" without knowing which distros those were. Now measured — **it was every
supported distro except Arch**:

| | checksec | binaries | before 0.48.0 | after |
|---|---|---|---|---|
| Arch / Manjaro | **3.x** | — | worked | worked |
| Fedora | 2.7.1 | 725 | "no deviations" | 158 deviations, 43 packages |
| **Debian 13** | 2.6.0 | 531 | "no deviations" | **204 deviations, 40 packages** |
| **Ubuntu 26.04** | 2.6.0 | 507 | "no deviations" | **81 deviations, 25 packages, incl. 1 Critical** |

The audit was developed on a Manjaro host, which is where 3.x ships — so it worked
throughout development and was silently useless everywhere else. That is the whole argument
for testing against real distros rather than the one under the developer's hands.

### Lab: per-target packages

Targets can now declare prerequisites, installed by cloud-init at build time so they are
**baked into the `pristine` snapshot**. Installing a prerequisite by hand after the snapshot
means the next `reset` silently loses it — which is exactly what happened when `checksec`
was first installed on the Fedora guest to reproduce the bug above.

`checksec` is now declared on `fedora`, `debian` and `ubuntu`, deliberately covering both
generations: 2.x on those three, 3.x on Arch. Verified surviving a revert.

## [0.48.0] — hardening-audit reported a clean system after examining nothing

**`hardening-audit` has been silently useless on every host with checksec 2.x.** It printed
"no hardening deviations from the distro baseline" while analysing **zero** binaries. On the
first Fedora host it ran against, the fix turns that same clean bill of health into **158
deviations across 43 packages**.

Two checksec generations are in the wild and they share no command line:

| | checksec 3.x (what this was written against) | checksec 2.7.1 (what **Fedora ships**, dated 2015) |
|---|---|---|
| invocation | `checksec listfile <f> -o json --no-banner` | `checksec --format=json --file=<f>`, one file per call |
| JSON | list of `{name, checks:{relro:{value:…}}}` | map of `{"/path": {"relro":"full",…}}` |
| wording | `Canary Found`, `PIE Enabled` | `canary:yes`, `pie:yes` |

The 3.x invocation against a 2.x binary produces nothing parseable, so every binary dropped
out and the audit concluded there was nothing wrong.

- **2.x is now supported**, normalised at the edge into the 3.x shape so exactly one
  comparison vocabulary exists downstream rather than teaching every baseline two.
- **And the guard that should have caught it in the first place:** analysing 0 of N binaries
  is now reported as *"the hardening audit did NOT run"*, never as a clean result. This is
  the same invariant applied throughout 0.37–0.47 — a check that cannot look must not render
  identically to one that looked and found nothing — and it was missing from precisely the
  action whose whole job is to find weaknesses.
- The success line now states how many binaries were analysed, so "no deviations" is
  auditable rather than asserted.

Found by the VM lab: `checksec` is not packaged for EL at all, so a Fedora guest was the
first dnf host ever to run this action. It also gave `rpm -qf` binary attribution (0.46.0)
its first end-to-end exercise — the 43 package names in that report are it working.

Lab: `alma9` and `fedora` join the working targets; all six now build, snapshot and revert.

## [0.47.5] — README: how this gets tested against real distros

Documentation only. The Development section explained the unit suite but said nothing about
the two harnesses that actually catch things, which is a gap for anyone wanting to
contribute — and understates why the tests are trustworthy.

Unit tests mock the package managers, which proves the parsing but not the assumptions
behind it. A large share of the bugs fixed in 0.37–0.47 were formats and exit codes that
documentation described incorrectly: `dnf check-update` exiting 100 on success, dnf5
repeating each upgrade as a `replacing` sub-row, `dnf-automatic`'s timers overriding its own
config, Ubuntu Pro hiding security updates from apt. None of those are reachable with mocks
alone.

- **Containers** for most things — reproducible in a way a borrowed host is not, since "no
  findings" on a real box might mean clean, unentitled, or simply empty.
- **`tests/lab/`** for what containers cannot reach: systemd timers firing, snapd, fwupd,
  real reboots, the privilege model, and `fettle remote` over ssh.

Both are stdlib/shell only, because `dependencies = []` is load-bearing for the remote
zipapp.

## [0.47.4] — lab: Rocky 9 lands, and the RHEL backend meets EL9 at last

Test tooling. Phase 2 of the lab is complete: `arch`, `ubuntu`, `debian` and `rocky9` all
build, snapshot and revert.

**Rocky 9 also needs UEFI**, and failed more obscurely than Debian did — under BIOS its
serial log was *entirely empty*, never reaching a bootloader. All four base images are
BIOS+UEFI hybrids by partition layout, so the layout does not predict which will boot; half
of them simply will not, and only a console log distinguishes the failures.

### The RHEL backend has now run on EL9 — 53% of the enterprise fleet, previously untested

Everything was built and verified against EL10 (~1% of the fleet). EL9 differs concretely,
and the differences are exactly the ones that could have broken it:

- **dnf 4.14** on EL9 against 4.20 on EL10.
- **`rpm -E %{_dbpath}` is `/var/lib/rpm`**, not EL10's `/usr/lib/sysimage/rpm`. That path
  difference was flagged as a risk when the integrity check was written; it survives because
  the check probes with `rpm -q rpm` rather than assuming a path.

`-O`, `-d`, `-x`, `-k` and `-r` all behave. Two things worth noting from the run:

- `-O` correctly classified the kernel packages as **new dependencies** rather than
  upgrades, which is right for installonly packages.
- `-x` exercised a branch that had only ever been unit-tested: Rocky's cloud image **ships
  `dnf-automatic` with no timer enabled**, so "installed but disabled" — distinct from the
  "not installed" state on the RHEL test boxes — was confirmed against a real host.

## [0.47.3] — lab: Debian unblocked; three distros, three boot recipes

Test tooling. `debian` joins `arch` and `ubuntu`; per-target firmware is now supported.

Debian's genericcloud image does not boot under BIOS here — it printed ``Booting `Debian
GNU/Linux'`` and reset ~1400 times with no kernel output at all. **UEFI fixes it**, but
needs two things beyond `--boot uefi`, each discovered by hitting it:

- libvirt refuses an internal snapshot of a pflash VM unless the NVRAM is **qcow2**, and
  virt-install 5.1 has no `nvram.format`. It does have `nvram.templateFormat`, so the
  firmware VARS template is converted once and libvirt inherits the format.
- Handing a qcow2 template to `--boot uefi` then defeats libvirt's firmware
  auto-selection entirely ("Unable to find 'efi' firmware that is compatible with the
  current configuration"), so the loader is named explicitly.

Conventions adopted from the `labctl` lab manager in `~/src/bifrost`, which drives the same
hypervisor: `--boot uefi` is the modern flag, BIOS must emit **nothing** (current
virt-install rejects `--boot bios`), and `--virt-type kvm` is explicit. Its documented
reboot-loop investigation — bootloader message repeating ~1/s, no kernel output, root cause
machine type — is the same symptom shape Debian showed, and is what pointed at firmware.

Arch (BIOS + cdrom seed), Ubuntu (BIOS + virtio-disk seed) and Debian (UEFI) each need a
different combination. Every one was forced by a failure that produced no error message.

## [0.47.2] — lab: Ubuntu builds, and four fixes the VMs forced

Test tooling. `ubuntu` joins `arch` as a working target; `debian` is blocked and documented
rather than left looking unattempted.

Everything here was found by building real VMs, and every one of them failed *silently* in
its own way — which is the argument for the lab existing at all.

- **cloud-init needs `package_update: true`.** It was set false to keep the guest behind,
  but that also stops the apt-list refresh, so installing the guest agent fails on a
  minimal image and the build hangs forever with no agent. The pair that actually matters
  is `package_update: true` (refresh lists — nothing changes version) with
  `package_upgrade: false` (which is what would consume the pending updates).
- **The serial console is now logged to a file.** Without it a guest that never brings up
  networking is undiagnosable: nothing to read, and `virsh console` needs an interactive
  tty. Every diagnosis below came from this.
- **Ubuntu 26.04 needs the seed as a virtio disk, not a cdrom.** Its early `ds-identify`
  pass did not recognise an emulated SCSI cdrom, and when ds-identify finds no datasource
  it disables cloud-init for the entire boot **silently** — no console output, no
  `/var/log/cloud-init.log`, a guest that reaches a login prompt with none of the requested
  config applied. Seed attachment is now per-target, because forcing virtio on everything
  breaks Debian instead.
- **`osinfo` ids are pinned properly** — `debian13` was being hinted as `debian12`, and
  `--osinfo` needs `name=` when combined with `require=off` or the bare id parses as an
  unknown key.

### Debian is blocked, and that is recorded

It boots to GRUB, prints ``Booting `Debian GNU/Linux'`` and resets, forever, with no kernel
output. Ruled out: the seed as cdrom *and* as virtio disk, explicit `boot.order`, and the
osinfo id. The disk chain is intact — a `qemu-img info` failure during investigation turned
out to be only the running-VM lock. Untried: UEFI firmware, another machine type, and the
`generic` image in place of `genericcloud`.

## [0.47.1] — a VM test lab, and the first Arch coverage

Test tooling; no change to fettle itself. `tests/lab/` builds small disposable distro VMs on
a KVM/libvirt host for the things containers cannot reach — systemd timers actually firing,
snapd, fwupd, real reboots, the privilege model — and, most importantly, **`fettle remote`,
which is how fettle is normally used and which nothing tested before**.

Stdlib only; it shells out to ssh/virsh/qemu-img so `dependencies = []` is untouched. Host
specifics live in a gitignored `lab.conf` (see `lab.conf.example`) because this repo is
public.

- **Cloud images, not installers**: Debian's genericcloud qcow2 is 328 MiB and boots in
  seconds against 755 MiB for its netinst ISO. Every family publishes one, Arch included.
- **Snapshot-pinned**: a cloud image is dated the day it was built, so a VM reverted to its
  `pristine` snapshot always presents the *same* pending updates — and that set grows as the
  archive moves on. cloud-init is told **not** to update on first boot for the same reason:
  it would consume the very updates the tests need. Revert-to-usable measured at 17 seconds.
- First target built and verified: **Arch**, which had no disposable coverage of any kind
  despite being the most featured backend. `fettle remote` against it found real pending
  upgrades including a kernel and systemd.

### Three things the first VM taught, all now handled

1. **An address is not readiness.** Arch's cloud image ships `qemu-guest-agent`
   *preinstalled*, so the agent answered within seconds — long before cloud-init had
   finished. Waiting on the address snapshotted a half-built machine. The gate is now a
   successful ssh.
2. **A bridged guest is unreachable until it speaks first.** Nothing upstream has learned
   its MAC, so inbound ARP goes unanswered while the guest itself is perfectly healthy —
   it had already taken a DHCP lease. The build now has the guest ping its gateway to prime
   the path.
3. **Recycled DHCP addresses break ssh two different ways.** A stale `known_hosts` entry
   makes ssh refuse the new host; removing it leaves the host *unknown*, which is equally
   fatal to anything non-interactive. `scp -q` reports either only as "Connection closed",
   which reads like a broken guest. The harness now forgets the old key **and** records the
   new one.

## [0.47.0] — Ubuntu: stop under-reporting security updates

On an Ubuntu host **not attached to Ubuntu Pro**, `apt` cannot see the `esm-infra` and
`esm-apps` pockets — so the count of available security updates it reports is smaller than
the truth, and fettle repeated that smaller number without qualification. Same failure shape
as the RHEL bugs fixed through v0.37–v0.46: *a check that cannot see everything rendering as
though it can.*

- **The upgrade preview now names what apt cannot see** — "N further security update(s) are
  NOT shown above", with the esm-infra and esm-apps split. Only when the host is unattached
  *and* updates are actually being withheld; an attached host already has those pockets as
  real apt sources, so adding a note there would double-count.
- **`-x` reports the coverage gap even when nothing is outstanding.** Measured on a live
  Ubuntu 24.04 host: automatic updates enabled, zero packages pending — and **18 installed
  packages that receive no security updates at all** without a subscription. "Up to date"
  alone hides that entirely.
- Data comes from `pro security-status --format json`, which is the interface `pro` itself
  asks scripts to use: its human output opens with a warning that the text is "subject to
  change". Gated on the **binary**, not the distro ID, so Debian and Mint skip it untouched.
- Best-effort throughout: a missing, failing, or unparseable `pro` yields no claim rather
  than a clean report.

### Two sibling issues investigated and NOT fixed — deliberately

**Linux Mint's `apt` wrapper: not a bug.** A research pass claimed Mint's
`/usr/local/bin/apt` shim auto-prepends `sudo`, which would have made our read-only upgrade
query block on a password prompt. Reading `mintsystem`'s source settled it: `list` dispatches
to `/usr/bin/apt` unchanged, and is **not** in the tuple of subcommands that receive `sudo`.
The claim's own quoted code contradicted its conclusion. No change made, and none needed.
(Two real wrapper behaviours that do not affect us: `apt search` routes to aptitude, and
`apt clean`/`autoclean` route to `apt-get` and do take sudo — we already call `apt-get`
directly through the elevated path.)

**Ubuntu phased updates: real, but unverifiable today, so untouched.** Ubuntu withholds a
percentage of updates per machine, and `apt list --upgradable` may list packages that will
not install yet. No package was mid-phase on any host or container available while this was
written — `apt-get -s upgrade` with `Always-Include-Phased-Updates` both true and false gave
identical results — so neither the bug nor a fix could be demonstrated. Shipping an
unverified fix for an unreproduced bug is how the wrong thing gets locked in; it waits for
the Ubuntu VM in the test lab.

## [0.46.1] — README: a support matrix you can read at a glance

Documentation only. "Supported distributions" listed the three families and described RHEL
in prose, but there was no way to answer *"will `-k` run on my box?"* without reading the
whole maintenance-actions table, whose cells describe behaviour rather than support.

- New **What works where** table: every action against every family, with the actions that
  run by default marked, and the totals (Arch 15/15, Debian 12/15, RHEL 12/15) alongside a
  note that the three gaps are Arch-only by nature — so Debian and RHEL are *complete*,
  not partial.
- Footnotes for the two RHEL differences that a tick would otherwise overstate: kernels are
  reported but never removed (dnf prunes them itself), and the hardening audit needs
  `checksec`, which is not packaged for RHEL 10 even in EPEL.
- States plainly which features are distro-independent, which distros have native CVE feeds,
  and that `pkg-audit` covers the same seven ecosystems everywhere.

## [0.46.0] — RHEL: kernels and binary attribution — the family is complete

The last two gaps close, bringing the RHEL backend to **parity with Debian**: every action
except the three that are Arch-only by nature (`aur-audit`, `aur-ioc-scan`, and
`python-rebuild-check`, which dnf handles itself).

**`fettle -k` — kernels, informational by design.** Unlike apt, dnf enforces
`installonly_limit` (3 by default) and removes the oldest kernel itself when a fourth is
installed. So there is no routine cleanup to offer, and the most dangerous operation in the
tool is simply not performed on this backend. It reports what is installed, which is
running, whether a newer one is waiting for a reboot, and how many slots are used.

- **`kernel-core` is queried, not `kernel`.** On the RHEL 10.1 VM `rpm -q kernel` reported
  **one** version while `kernel-core` reported **two** — including the running one. On
  RHEL 8+ `kernel-core` carries the actual kernel, so querying `kernel` can hide the kernel
  you booted.
- Versions are sorted **numerically**. A string sort ranks `6.12.0-99` above
  `6.12.0-124` because `'9' > '1'`, which would name the wrong kernel as next-to-boot and
  miss a pending reboot entirely.
- `rpm` writes *"package kernel-core is not installed"* to **stdout**, so it is filtered
  rather than parsed as a version.
- A running kernel that no installed `kernel-core` owns — a hand-built one, or the package
  removed underneath it — is flagged rather than ignored.

**`rpm -qf` binary attribution**, so `hardening-audit` can name the package behind a
weakly-built binary instead of just a path.

- **Only paths that exist are queried**, because rpm's two failure modes are not equally
  safe: a **missing** file errors on *stderr* and the line is **skipped**, shifting every
  later result up one so it is blamed on the wrong file; a file that exists but is
  **unowned** gets *"file X is not owned by any package"* inline on *stdout*, preserving
  the 1:1 mapping. Filtering to existing paths turns the dangerous case into the safe one.
- If alignment is somehow still lost, an empty map is returned rather than a shifted one —
  "no package named" degrades the report, a wrong package name corrupts it.

Verified live on the RHEL 10.1 VM, read-only: `-k` reports both kernels with the running
one tagged and 2 of 3 slots used, and the attribution maps `bash`, `coreutils`,
`openssh-server` and `rpm` correctly while dropping an unowned file and a missing one with
no shifting. `checksec` is not packaged for el10 even in EPEL, so the attribution was
exercised directly rather than through `-H`.

## [0.45.0] — RHEL: is a reboot or a service restart owed?

`fettle -r` now works on the RHEL family, via `needs-restarting`.

- **Two invocations, one meaning.** dnf4 ships a standalone `needs-restarting` (from
  `yum-utils`) where `-r` is the reboot hint. **dnf5 ships no such binary** — the hint is
  bare `dnf needs-restarting`, and its own `-r` is documented as *"Has no effect, kept for
  compatibility with DNF 4"*. Keyed on which of the two exists, not on a version string.
- **Only exit 0 is allowed to mean "no reboot required."** Exit 1 means a reboot is owed,
  but it is also dnf's generic error code — `dnf -C` with no metadata cache exits 1 with
  empty stdout. The asymmetry decides the tie: a needless reboot is cheap, while wrongly
  reporting "no reboot" leaves a host running the very libraries it just patched. So exit
  1 is either the hint or an explicit "could not determine", never a clean result.
- **The hint body is printed verbatim rather than matched against an English phrase**, so
  a localised host still gets the warning instead of a shrug.
- **The service list needs root and returns nothing without it** — measured on the VM,
  where rootless `-s` printed no services at all while root printed the real (empty)
  answer. An unprivileged run now says it could not look. This matters under `--dry-run`,
  which deliberately does not elevate.
- On an unregistered RHEL box the *entire* `-s` output is dnf's subscription notices on
  stdout; without stripping them, three notices read as three services needing a restart.

Verified live on both generations by actually causing the condition: upgrading `glibc` and
`systemd-libs` in an AlmaLinux container flipped it from "no reboot required" to naming
both, and the same in a Fedora container through the subcommand path. The RHEL 10.1 VM
read-only reports no reboot and no services, which matches `needs-restarting` run by hand.

## [0.44.0] — RHEL: does this host patch itself?

`fettle -x` now works on the RHEL family, reporting whether `dnf-automatic` installs
updates unattended.

- **The timer overrides the config, so all four timers are checked.** `dnf-automatic`
  ships `dnf-automatic.timer` plus `-install`, `-download` and `-notifyonly` variants,
  and the `ExecStart` lines differ: `-install` passes `--installupdates` and therefore
  applies updates **even when `automatic.conf` says `apply_updates = no`**, while
  `-download`/`-notifyonly` pass `--no-installupdates` and never apply them however the
  file is set. Reading the config alone — or only the plain timer — gets both cases
  backwards. Verified live in a container: with `apply_updates = no` on disk and
  `dnf-automatic-install.timer` enabled, fettle reports ENABLED and says why.
- **dnf5 differs in unit name and config location.** The package is
  `dnf5-plugin-automatic`, the unit is `dnf5-automatic.timer`, and both `/etc` config
  paths are rpm **ghost** entries that are never written to disk — so the effective
  config is the shipped copy under `/usr/share`. Verified by flipping that file and
  watching the verdict change.
- **"Not installed" and "installed but no timer enabled" are different answers**, and so
  is "systemctl is missing", which reports that it cannot tell rather than "off".
- **A host configured to reboot itself after patching is warned about** — a bigger
  operational fact than the patching. Only when updates are actually applied.
- **A container cannot report a false ON.** `systemctl is-enabled` reads unit *files*, so
  it answers happily with no systemd — which also means the whole matrix is testable in a
  container, contrary to an earlier note here. `systemctl is-system-running` returns
  `offline` there, and that caveat is printed. Exit codes are not a usable discriminator:
  `not-found` came back rc=1 on the VM and rc=4 in a container, so the text is matched.
- Also notes when repo metadata refreshes on `dnf-makecache.timer`.

Verified on AlmaLinux (dnf4) across all four states, Fedora (dnf5) including the ghost
config, and the live RHEL 10.1 VM read-only, where `dnf-automatic` is not installed.

## [0.43.4] — reconcile three sessions that shared one checkout

Cleanup and documentation. **If the 0.43.0–0.43.3 entries are confusing, this is why:**
three sessions had `~/src/fettle` open at once — RHEL maintenance (waves W2–W4), the snap
lift, and the RHEL firmware-check claim. Their edits interleaved, so the commits do not
line up with the work.

**What actually shipped in 0.43.0–0.43.3, by subject rather than by commit:**

| Real change | Where it landed | Verified |
|---|---|---|
| snap pruning moved to `PackageBackend` (Arch + RHEL gained it) | `6b9015f` | removal path **not** live-verified — wopr has snapd but zero snaps |
| `firmware_check` added to `RhelBackend.supported` | `6b9015f` — *not* its subject | live on both RHEL 10.1 hosts, fwupd 1.9.31 |
| two unused `dnf-automatic` constants | `6b9015f` — accidental | dead code; **removed here** |
| one README line about firmware-check | `9895867`, `bb995f3`, `543dd42` | — |

So `6b9015f` ("snap pruning is not a Debian feature") carried three sessions' code, and
three of the four commits were docs churn over a single README line — including a
retraction of a *true* claim (`bb995f3`) that `543dd42` then had to withdraw.

- **Removed the dead code.** `_AUTO_TIMERS` and `_AUTO_CONF_PATHS` were research constants
  for an unstarted wave, swept in mid-edit. Nothing referenced them, and ruff does not flag
  unused module-level constants. The findings they encoded are kept in
  `~/src/claude-scratchpad/fettle-w5-auto-updates-findings-2026-07-29.md`.
- **The firmware verification is settled, from two independent directions.** `543dd42`
  cited fettle's own remote run-logs; this session separately re-ran `fettle remote rhel -f`
  and `fettle remote rhel-vuln -f` and saw `no firmware updates available.` on both, with
  `get-updates` exiting 2, stdout empty and `No updatable devices` on stderr. Still only
  the no-updatable-devices path — neither host has updatable firmware.
- **Docs:** the maintenance-actions table had **no RHEL column at all** despite RHEL
  supporting nine actions; it has one now, including the deliberate `clean packages`
  (not `clean all`), the kernel exclusion in `orphans`, and `check-update`'s exit 100.
  Snap-revision pruning moved out of the Debian-only cell, since it is now every distro's.
  The RHEL notes list said "Two" over three bullets.

### Known risk carried forward, not fixed

`PackageBackend.firmware_updates` infers "no updates" from **empty stdout alone**, ignoring
the exit code. Correct on these hosts — but a host whose fwupd *daemon* is down also emits
empty stdout, and would be reported as "no firmware updates available": a clean answer from
a check that could not look. Measuring that case means stopping a service on a live box, so
nothing was changed on a guess. It affects every backend.

## [0.43.3] — the 0.43.2 retraction was itself wrong; the RHEL runs did happen

Documentation only; no behaviour change. Third entry about one README line, which is two
more than it should have taken — recorded in full because the failure mode is interesting.

**0.43.2 retracted a true claim.** It asserted that 0.43.1's "live-verified on both RHEL
10.1 test hosts" described a run that never happened and that no RHEL host was contacted.
Both hosts were contacted, and `fettle -f` ran on both. The 0.43.1 bullet is restored.

**The evidence is fettle's own remote run-logs**, which `fettle remote` writes *on the
remote host* and then tar-streams back into `~/.fettle/logs/<host>/` (`remote.fetch_logs`).
They cannot exist unless the host ran fettle, and the four of them record the whole arc:

| log | `argv` | version | transcript |
|---|---|---|---|
| `rhel/run-20260730-001254` | `-f --dry-run` | 0.42.0 | `skipping 'firmware_check' — not supported by the rhel backend` |
| `rhel/run-20260730-001540` | `-f --dry-run` | 0.42.0 | `would run: fwupdmgr refresh` + `get-updates` |
| `rhel/run-20260730-001908` | `-f` | 0.43.0 | `✓ firmware metadata refreshed` / `✓ no firmware updates available.` |
| `rhel-vuln/run-20260730-001926` | `-f` | 0.43.0 | same |

Both hosts: RHEL 10.1 (Coughlan), `fwupd-1.9.31-1.el10.x86_64`, daemon `active`,
`fwupdmgr get-devices` exit 0 enumerating the QEMU display controller and swtpm TPM — so
the "nothing to update" result is a real one, not a broken install.

- **How a correct entry got retracted.** The verification and the retraction were written
  by two different sessions working the same checkout at the same time. The second could
  read the repository but not the first's run-logs, so a claim it had no record of
  producing looked unsupported. A reasonable inference from incomplete information, and
  wrong. The lesson is about *checking before retracting*, not about the inference:
  `~/.fettle/logs/` is the artefact that settles it, and it was never consulted.
- **What is still genuinely unverified**, stated so this doesn't overshoot in the other
  direction: only the **no-updatable-devices** path ran live, because neither host has
  updatable firmware. The updates-available branch rests on unit tests. The container
  fleet cannot close that gap — those images have neither fwupd nor dbus.
- 0.43.2's own text is corrected in place below and marked withdrawn, by the same
  reasoning it used: a retraction that quietly disappears repeats the failure.

## [0.43.2] — retract an unverified "live-verified" claim *(WITHDRAWN — see 0.43.3)*

Documentation only; no behaviour change.

**This entry was wrong and is withdrawn.** It said the 0.43.1 "live-verified" bullet
described a run that "did not happen — no RHEL host was contacted". Both RHEL hosts were
contacted and `fettle -f` ran on both; see 0.43.3 for the run-log evidence. What follows is
the original reasoning, kept visible rather than deleted.

- It held that the claim rested only on the unit tests in `tests/test_rhel_maintenance.py`,
  and that "unchanged and unit-tested" is not "verified on the distro". That principle is
  sound — it was simply applied to a claim that *had* been verified on the distro.
- Rewrapped the paragraph the 0.43.1 README edit left with a 100-column line. (This part
  stands; the rewrap is still in place.)

## [0.43.1] — docs: the RHEL support list was missing `firmware-check`

Documentation only; no behaviour change. `firmware_check` started working on the RHEL
family in 0.43.0, but "Supported distributions" still omitted it, so the README said
`fettle -f` was unavailable there while the code ran it fine.

- README now lists `firmware-check` among the working RHEL actions, and names *why* it
  needed no RPM-specific code: the `fwupdmgr` path is shared with the other backends
  because fwupd is distro-neutral.
- **Live-verified on both RHEL 10.1 test hosts** (fwupd 1.9.31, daemon active,
  `fwupdmgr get-devices` exits 0 — a real "nothing to update", not a broken install).
  `fettle -f` reports "✓ no firmware updates available." on each, and `-f --dry-run`
  previews `fwupdmgr refresh` + `get-updates` instead of the old "not supported by the
  rhel backend". Only that path ran live: neither host has updatable firmware, so the
  updates-available branch rests on the unit tests in `tests/test_rhel_maintenance.py`,
  which also pin the case where `fwupdmgr get-updates` exits **2** and writes "No updatable
  devices" to *stderr* with stdout empty. The container fleet cannot cover any of this —
  those images have neither fwupd nor dbus.
  *(This bullet was retracted as fabricated in 0.43.2 and restored in 0.43.3, where the
  run-log evidence is laid out.)*

## [0.43.0] — snap pruning is not a Debian feature

`fettle -c` offers to reclaim superseded ("disabled") snap revisions on **every** distro,
not just Debian and Ubuntu.

- **`_prune_disabled_snaps` moved from `DebianBackend` to `PackageBackend`**, and Arch and
  RHEL now call it too. snapd installs and refreshes identically everywhere — an Arch box
  with the AUR `snapd` package accumulates exactly the same reclaimable revisions a Debian
  one does, and fettle never offered them. This is the same asymmetry already fixed for
  the supply-chain providers, which used to hang off the Debian backend alone and so
  audited an Arch box with flatpaks as though it had none.
- **Behaviour is unchanged, deliberately.** Each revision is still confirmed
  *individually* — removing an installed snap revision must never happen without asking,
  and only `--yes` opts into all. Parsing still keys on the `Notes` column of
  `snap list --all` containing "disabled".
- Self-gated on `snap` being on PATH, so a machine without snapd pays one `which` call.
  `[updaters.debian]` / `[updaters.rhel]` `snap_updater = "none"` still opts out; there is
  no `[updaters.arch] snap_updater` key to consult, and none was invented — every revision
  is confirmed individually regardless.
- Two dry-run tests that asserted `clean` runs *no* command at all now allow the read-only
  `snap list --all`, which is what previews the revisions a real run would offer. Nothing
  that changes the system runs under `--dry-run` (`ctx.select` declines everything).

Not live-verified end to end: wopr has snapd active but no snaps installed, so the live
run exercised the gate and the nothing-to-do path only. The removal path rests on the unit
tests, which drive all three backends against one real `snap list --all` fixture.

### Also in this release, from in-flight RHEL work committed alongside

- `RhelBackend` now claims `firmware_check`. The base-class `firmware_updates` was always
  inherited and always worked; the missing *claim* made `fettle -f` on a RHEL box report
  "not supported by the rhel backend", and `fettle remote <rhel-host>` skip it silently.
  Covered by two new tests, including the measured case where `fwupdmgr get-updates` exits
  **2** and writes "No updatable devices" to *stderr* with stdout empty.
- `_AUTO_TIMERS` / `_AUTO_CONF_PATHS` groundwork for RHEL `check_auto_updates`, not yet
  wired to an action.

## [0.42.0] — RHEL: config drift, and `.rpmsave` is not the same as `.rpmnew`

`fettle -d` now works on the RHEL family: pending config merges under `/etc`, plus
`dnf check` as the analogue of Debian's `dpkg --audit`.

- **The three rpm suffixes are reported differently, because they mean opposite things.**
  With a `.rpmnew`, *your* file is still in effect and a new default sits unmerged beside
  it — informational. With a `.rpmsave` or `.rpmorig`, rpm moved your file aside and the
  **package's** version is now live, so settings someone deliberately made silently
  stopped applying. Those warn. Lumping them together (as the Debian backend does for its
  own suffixes) would hide the case that actually costs you something.
- `rpmconf -a` is suggested for reconciling them, and named as something to install when
  it is absent rather than suggested blindly.
- **`dnf check` exits 1 for merely finding problems** — the same trap as `rpm -Va` and
  `dnf check-update`. A genuinely broken dnf also exits 1 (measured: removing libxml2
  breaks its own Python bindings), so the exit code cannot separate the two and the
  presence of real output is the discriminator. A non-zero exit with no output is
  reported as "NOT assessed", never as a clean bill of health.
- The problem list is shown verbatim rather than parsed, because the generations disagree
  on its shape: dnf4 writes one line per problem, dnf5 writes the package with an indented
  `missing require` beneath. Only the count is taken, from the summary line both write to
  *stderr* in different wording.

### Fixed — a false positive found by running it, not by testing it

**dnf writes several informational lines to `stdout`, not stderr**, and an unregistered
RHEL box emits three of them from `dnf check` while exiting 0. The "was there output?"
test therefore reported package problems on a completely clean machine — with no count,
because there were no problems. Those notices are now stripped before the emptiness test,
via a shared helper. The other parsers in this backend were already immune by
construction: they require a specific row shape (three fields, or a whitespace-free
`name.arch`) that no notice matches.

Verified live on both generations: AlmaLinux and Fedora with real leftovers and a
genuinely broken dependency, and the RHEL 10.1 VM read-only — which is where the false
positive surfaced and where the fix was confirmed.

## [0.41.0] — RHEL: `orphans`, with kernels off the table

`fettle -o` now works on the RHEL family: it reports installed packages that no enabled
repository offers, and offers unused dependencies for removal one at a time.

- **A kernel is never offered for removal.** This is the hazard the action is shaped
  around, and it is not theoretical — it was reproduced live. After `dnf mark remove
  kernel-core`, dnf genuinely lists `kernel-core` and `kernel-modules-core` among its
  `--unneeded` packages; under `-o --yes` fettle held both back, removed the other 32,
  and the kernel was still installed afterwards.
  - The protected set comes from `dnf repoquery --installonly`, **plus** a name-prefix
    net as defence in depth if `installonlypkgs` is misconfigured. Over-protecting
    (sparing something like `kernelshark` needlessly) is the right way to err.
  - The query matters beyond the prefix net: dnf's `installonlypkgs` includes
    `installonlypkg(kernel-module)`, so a DKMS package such as `kmod-nvidia` is
    installonly while matching no `kernel` name.
  - **If that query fails, nothing is offered at all.** An empty result and a failed
    query are byte-identical, and this is not a mistake recoverable from a shell that no
    longer boots.
- **`--installonly --installed` is a hard error on dnf5** (dnf4 accepts the pair), and
  the complaint goes to *stderr* — so with stderr discarded it read as a clean "no
  kernels installed". `--installonly` alone means "installed installonly packages" on
  both generations and is what is used.
- **Removal uses `dnf remove <chosen>`, not `dnf autoremove`.** The selection is
  per-package and autoremove is all-or-nothing by construction. Without `--yes`, dnf then
  shows its own transaction and confirms, so a removal cascading into dependents cannot
  happen unseen.
- **`dnf repoquery --queryformat` output needed two fixes**, both measured: dnf4 already
  terminates each record, so the `\n` that dnf5 *requires* (without it dnf5 runs every
  record onto one line) makes dnf4 emit a blank line between entries; and dnf writes its
  rootless "Not root, Subscription Management repositories not updated" notice to
  **stdout**, mixed in with results. Both would have become entries in the removal offer.
- Packages from no enabled repository go to the same `obsolete-pkgs` report Debian uses,
  so `fettle report` picks them up either way. On the RHEL box that finds the Eclypsium
  sensor packages. `keep_orphans` is honoured, and held-back packages are always named
  rather than silently dropped.

Verified live on both generations: AlmaLinux (dnf4) with the kernel hazard reproduced,
Fedora (dnf5) removing 14 real orphans, and the RHEL 10.1 VM read-only.

## [0.40.0] — RHEL: `clean` reclaims the package cache

`fettle -c` now works on the RHEL family: `dnf clean packages` plus unused flatpaks.

- **`clean packages`, deliberately not `clean all`.** The two are priced very
  differently. Measured on the RHEL 10.1 box, `/var/cache/dnf` held **796M — 736M of
  `.rpm` files and 60M of metadata**. `clean packages` frees the 736M; `clean all` would
  also discard the metadata, so the next dnf command re-downloads it — a slow,
  network-dependent surprise traded for a rounding error of disk.
- Worth knowing: RHEL ships `keepcache=0`, so packages are normally removed after a
  successful install. A large `.rpm` cache usually means an **interrupted** transaction,
  which is precisely when reclaiming it helps.
- Verified in an AlmaLinux container with a deliberately-populated cache: 17 rpms → 0,
  metadata 32M before and after.
- Snap revision pruning is **not** included. Debian has it as a private helper, and
  snapd on RHEL needs EPEL; duplicating the helper for a rare case is worse than lifting
  it to the base class for all three backends, which is a separate change.
- Test fix: `test_default_run_says_which_actions_the_backend_cannot_do` pinned literal
  action names and so asserted that `update` and `clean` were *unsupported* on RHEL — it
  went stale the moment they landed. It now asserts the property (the line names the
  skipped actions, and never names a supported one).

## [0.39.0] — `fettle -u` upgrades a RHEL box

The headline action finally works on the RHEL family: `update` runs
`dnf upgrade --refresh`, which expires the metadata cache first and so is the
equivalent of Debian's `apt-get update && apt-get full-upgrade` in one command. Without
`--yes`, dnf shows its own transaction table and prompts — the same deal apt gets.
flatpak and snap are updated too when present, gated on `command.which` exactly as on
Debian.

- **An upgrade from a `gpgcheck=0` repository asks one extra time**, naming the
  repositories. This is not hypothetical: all three enabled CentOS Stream repos on the
  test box ship `gpgcheck=0`, so a bare `fettle -u` there would install ~340 packages
  without verifying a single signature.
  - The gate **reuses the pkg-audit provider** rather than re-parsing
    `/etc/yum.repos.d`, so the gate and the audit cannot disagree — and an *absent*
    `gpgcheck` correctly inherits `[main]` from `dnf.conf` instead of being read as
    disabled, which would fire on essentially every RHEL box.
  - Disabled repositories do not trip it; they install nothing today.
  - It **fails safe**, unlike the advisory gate which deliberately fails open. An
    unpatched CVE is a pre-existing condition that blocking does not fix — refusing to
    upgrade leaves you unpatched. `gpgcheck=0` is the reverse: the upgrade itself is the
    delivery mechanism, so no readable stdin means "do not install unverified packages".
  - `--yes` proceeds, loudly, and records it in the summary. Automation is never
    silently blocked, nor silently allowed.
  - Under `--dry-run` it warns without blocking, since blocking there would only hide
    the command the user asked to preview.
- `update` also refuses on an image-based host, for the reason in 0.38.1.
- README: RHEL is no longer described as audit-only, and `--full-preview` is documented.

Verified live: a real `-u --yes` upgrade in both an AlmaLinux (dnf4) and a Fedora (dnf5)
container through the same code path; the gate blocking and then proceeding under
`--yes` in a container with `gpgcheck` flipped; and the gate firing for real on the RHEL
10.1 VM under `--dry-run`, which changed nothing.

## [0.38.1] — refuse to preview a dnf upgrade on an image-based host

On an ostree-based system (rpm-ostree, Fedora Silverblue, RHEL Image Mode / bootc) dnf
will happily *list* pending upgrades, and that list is a lie: applying it writes into a
deployment the next boot discards. `-O` and `-u --dry-run` now report that the host
cannot be upgraded this way and name `bootc upgrade` / `rpm-ostree upgrade` instead.

- **The marker is `/run/ostree-booted`, not the presence of a binary.** `rpm-ostree` and
  `bootc` can both be installed on an ordinary RHEL box, and refusing to upgrade a
  perfectly normal machine would be a worse failure than the one being guarded against.
  The file exists only when the running system actually booted from an ostree deployment,
  which covers bootc too since bootc images are ostree-based.
- The suggested command comes from what is installed, and **`rpm-ostree` is suggested
  without `sudo`** — it authenticates through polkit over D-Bus, unlike `bootc`.
- Verified on the same AlmaLinux container image with and without the marker: 17 pending
  upgrades in one case, the refusal in the other.

## [0.38.0] — RHEL: `--full-preview` resolves the real transaction

`-u --dry-run` on the RHEL family could only list upgrades, because dnf has no
rootless equivalent of `apt-get -s`. The new `--full-preview` flag elevates so the
preview can resolve the *whole* transaction — measured on a live RHEL 10.1 box, that
is 345 packages against the 337 the rootless query can see, the extra 16 being new
dependencies (kernels among them) and an obsoletes replacement, offset by 8 entries
the resolver classifies differently.

- **The resolver branches on privilege, not on the flag.** `-O` already elevates, so
  it gets the complete transaction at no extra cost; `--full-preview` exists purely to
  opt a `--dry-run` into the sudo prompt it otherwise avoids. `--dry-run` alone stays
  passwordless.
- `--assumeno` answers dnf's own prompt with "no", so nothing is installed and the
  command is safe under `--dry-run`; `--no-sync` adds `-C` for a purely cached answer.
- **`dnf` exits 1 both when `--assumeno` declines and on a genuine error** ("Error: No
  packages marked for upgrade."), so the exit code cannot tell them apart — the
  resolved table is the discriminator instead of a localisable message. Nothing to
  upgrade exits 0 with "Nothing to do."
- **dnf5 follows every upgrade with a `replacing <pkg>` sub-row** carrying the version
  being *removed*, indented three spaces instead of one. Accepting those would double
  every upgrade and list the outgoing version as the incoming one — verified live on
  Fedora, where the count is 35 and not 70.
- **A zero epoch is dropped.** dnf5's table writes `0:9.10-4.fc44` where rpm and
  `check-update` write `9.10-4.fc44`, so left alone every package on a dnf5 host
  appeared to be gaining an epoch.
- Sections the preview cannot express — `Downgrading:`, `Reinstalling:` — are
  *reported* rather than dropped, since a preview the user is about to act on must not
  quietly omit part of the transaction. Parsing stops at "Transaction Summary", which
  dnf5 writes with a trailing colon that would otherwise read as a section header.
- A partial preview that stayed partial *despite* `--full-preview` now says elevation
  did not happen, rather than advising a flag that was already passed.
- `fettle remote HOST -O --dry-run --full-preview` elevates on the far end too; a
  dry run otherwise deliberately runs without sudo.

## [0.37.0] — RHEL: metadata refresh and an honest upgrade preview

First slice of dnf **maintenance** support (the backend was audit-only until now):
`fettle -O` refreshes repo metadata and reports what is upgradable. `update` itself
is deliberately not claimed yet.

- **One code path for dnf4 and dnf5.** The advisory provider needed a version gate
  because `updateinfo` and `advisory` emit unrelated formats. The maintenance verbs
  do not — `upgrade`, `check-update`, `makecache`, `clean` and `autoremove` were
  measured to behave identically on dnf 4.20 (RHEL 10) and dnf5 5.4.2 (Fedora) — so
  nothing here branches on the dnf version.
- **`dnf check-update` exits 100 when upgrades exist.** 100 is success; 0 means
  nothing to do. Reading it as a failure yields a silent "up to date" on a box with
  337 pending upgrades.
- **The preview says what it cannot see.** dnf has no rootless equivalent of
  `apt-get -s`: `dnf upgrade --assumeno` resolves the full transaction but refuses to
  run without root. The preview therefore lists upgrades only and states that new
  dependencies and removals are missing, rather than letting a partial answer render
  identically to a complete one. It also reports how many packages replace *obsoleted*
  packages (they have no `old -> new` to show), and warns when a rootless query
  skipped subscription-manager repositories.
- **Parsing hazards, all measured rather than assumed:** dnf lists an obsoleting
  package a *second* time under its obsoletes header, so `fwupd` was double-counted
  until the parser stopped there — dnf4 spells it `Obsoleting Packages` and dnf5
  `Obsoleting packages` (both read out of the shipped binaries). dnf5 also prefixes
  the list with a bare `Upgrades` header that dnf4 omits, and dnf writes its "Not
  root" notice to *stdout*, not stderr.
- **Epochs are rendered as dnf renders them.** A bare `%{EVR}` omits the epoch, so
  every epoch-bearing package would appear to be changing epoch (`1.54.0-1.el10` vs
  dnf's `1:1.58~rc1-1.el10`); the rpm queryformat restores it conditionally.
- Multilib arches stay separate: `glibc.i686` and `glibc.x86_64` are two independent
  upgrades, and keying on the bare name reported one while dropping the other.
- `[updaters.rhel]` accepts `system_updater` (dnf | none), `flatpak_updater` and
  `snap_updater`, matching `[updaters.debian]`.
- A backend claiming an action it never implemented is now caught for **every**
  backend, replacing a hardcoded pin on RHEL's exact `supported` set that would have
  needed editing on each wave.

## [0.36.0] — hardening-audit: a real baseline for the RHEL family

`hardening-audit` ran on RHEL but scored binaries against the **generic** baseline,
so its expectations were not the distribution's. It now derives them from rpm's own
build macros, alongside the existing Arch (`makepkg.conf`) and Debian
(`dpkg-buildflags`) sources.

- The hardening flags live in **redhat-rpm-config**, a *build-time* package that is
  normally absent from a running system — a stock RHEL 10.1 box and a stock AlmaLinux
  container both lack it. Without it `%{build_cflags}` degrades to a bare `-O2 -g`,
  which carries no hardening at all, so Red Hat's documented defaults are used
  instead and the report says so. This mirrors how the Debian baseline falls back
  when `dpkg-buildflags` is unavailable.
- **An undefined rpm macro evaluates to its own literal text** (`%{build_ldflags}`),
  not to an error or an empty string, so that is what distinguishes "no value" from a
  real one.

Verified live on RHEL 10.1: the baseline is now `rhel (rpm build macros)` with a
`fortify_source` criterion the generic baseline never had.

## [0.35.0] — pkg-audit: DNF/YUM repository provenance

New `dnf` provider for the RHEL family, the RPM analogue of the existing APT one.
Every package on the system comes from a repository in `/etc/yum.repos.d`, and three
properties of that list decide whether "installed from the distro" means anything.

- **`gpgcheck=0` → `INSECURE_TRANSPORT` (WARN)** — packages installed without
  verifying their signature. Matches how the APT provider treats `[trusted=yes]`, so
  the same weakness reads the same on either family.
- Plain-`http` URLs → `INSECURE_TRANSPORT`; repositories outside the distro vendors →
  `UNOFFICIAL_SOURCE` (EPEL counts, exactly as a Launchpad PPA does on Ubuntu).
- A `.repo` file that cannot be parsed is reported as `UNVERIFIABLE`, not skipped.
- Disabled repositories are reported at a lower severity rather than hidden — inert
  today, a landmine if switched on — and are not counted as package *sources*.

Two things measured on real systems rather than assumed:

- **`gpgcheck` is resolved, not read.** An absent key inherits `[main]` from
  `/etc/dnf/dnf.conf`, which ships as `gpgcheck=1`. Treating absence as "disabled"
  would have flagged nearly every repo on every box. A missing dnf.conf also assumes
  checking is *on*, since that is dnf's own default — never assume a system is less
  safe than it is.
- **`repo_gpgcheck=0` is deliberately not reported.** Metadata signing is rarely
  deployed on RPM systems — EPEL itself ships `repo_gpgcheck=0` — so it would be a
  finding that is true, universal and useless. `coverage` states that only package
  signing is assessed.

Reads `/etc/yum.repos.d` through `ctx.root` rather than shelling out to `dnf
repolist`, matching `apt_source`: testable under a fake root, needs no dnf, and
reports what is *configured* rather than what dnf could reach today. `configparser`
runs with interpolation disabled, since real files carry `$releasever`/`$basearch`.

Verified live: a RHEL 10.1 box reports **3 enabled repositories with `gpgcheck=0`**
plus EPEL as third-party; a stock AlmaLinux 10 reports **zero**.

## [0.34.1] — say which actions a backend cannot run

`fettle -a` silently dropped actions the detected backend doesn't implement. That was
deliberate and defensible while every backend covered nearly the whole default set —
a Debian run drops only a couple of Arch-only actions, and a note per action would be
noise. It stops being defensible once a backend implements a small subset: on RHEL,
`-a` ran **1 of 10** actions and said nothing, so a nearly-empty run was
indistinguishable from a complete one.

Default runs now emit **one summary line** naming what was skipped
(`9 of 10 action(s) not implemented by the rhel backend: clean, orphans, …`) rather
than a line per action. Explicitly-named actions still get an individual note each,
and a backend that supports everything requested stays silent.

## [0.34.0] — sys-audit package integrity on RHEL (`rpm -Va`)

`sys-audit`'s `packages` category reported "not implemented for the rhel backend".
`RhelBackend.verify_integrity` now fills it — the RPM analogue of debsums/paccheck.

- **Separates the signal from the noise.** Config files you edited, ghost files created
  at runtime and documentation all legitimately differ from their package, and on a
  stock system they are most of `rpm -Va`'s output. Rows with **no file-type marker**
  are packaged files — binaries and libraries — and only those are reported as altered;
  the rest are summarised as expected differences (full list under `-v`).
- **`rpm -Va`'s exit code cannot detect failure, in both directions.** It exits **1
  merely for finding discrepancies**, so treating non-zero as failure would mark every
  real system unverifiable; and it exits **0 with no output when the database is
  unreadable**, which is byte-identical to a clean system. The rpm database is
  therefore proven queryable first, and only that stands between "could not look" and
  "all verified".
- Paths are matched by anchoring on the leading `/` rather than splitting on
  whitespace, so a path containing spaces is not truncated and the optional file-type
  marker stays unambiguous.

Verified live on AlmaLinux 10: tampering with `/usr/bin/gzip` moved the altered count
3→4 and listed it as `S.5....T.`; removing the rpm database (which on RHEL 10 lives at
`/usr/lib/sysimage/rpm`, not `/var/lib/rpm`) produced `UNKNOWN … NOT verified` where
raw `rpm -Va` returned exit 0 and no output.

## [0.33.0] — advisory-check: dnf5 support

The RHEL provider parsed **dnf4 output only**, and dnf5's is a completely different
shape. Worse, dnf5 keeps `updateinfo` as an alias for `advisory`, so the dnf4 command
*succeeds* there and simply returns something the regex cannot match: 19 real
advisories read as **zero, silently** — and the blind-spot check would then announce
that the repositories publish no security errata, which on a dnf5 system is flatly
wrong. Latent on RHEL 10.1 (dnf 4.20) but waiting for RHEL 11 / Rocky 11.

- Version-gated on `dnf --version` containing the literal `dnf5`, **not** a path
  check: on a dnf5 system dnf5 *is* `/usr/bin/dnf`, while on RHEL 10.1 that path is a
  symlink to `dnf-3`.
- dnf5 uses `advisory list --json` and `advisory info --json` — structured output, no
  text parsing at all.
- **`--with-cve` is not used on either version, for opposite reasons.** On dnf4 it
  emits three rows per advisory (upstream RHSA, the CVE, the distro's own id); on dnf5
  it is a *filter* that drops every advisory without a `cve` reference — which on
  Fedora is all of them.
- CVEs come from structured `references` of type `cve`, falling back to scanning
  reference titles and the description. That fallback carries real weight: on Fedora
  **0 of 20** references were type `cve` (all bugzilla), yet 7 of 8 advisories named
  their CVE in a title or description.

Verified against both real systems: Fedora 44 / dnf5 5.4.2.1 → 19 findings with CVEs
and versions (0 before); AlmaLinux 10 / dnf 4.20 → 19 findings, unchanged.

## [0.32.2] — fix: the container audit found nothing on podman

**0.32.1 claimed podman compatibility and was wrong.** That claim rested on podman's
manual, which lists `.Repository`/`.Tag`/`.ID`/`.CreatedAt` as `--format` placeholders.
Those are the accessors you may *write*; they are not the JSON tags the struct
serialises to. `podman images --format "{{json .}}"` actually emits lowercase
`repository`/`tag` plus `Id` and `Created`, so the docker-shaped parsing matched
nothing and every podman host reported **zero container findings, silently** — the
exact failure mode the provider was built to prevent. Verified against a real podman:
1 image in, 0 findings out. RHEL ships podman, so this affected the whole new platform.

- `images_argv()` now picks the right flag per runtime: docker keeps
  `--format '{{json .}}'`; podman uses plain `--format json`, which *does* carry the
  capitalised keys.
- `parse_images()` accepts podman's single JSON array as well as docker's
  newline-delimited objects, and normalises the differences: `Id` → `ID`, lowercase
  `repository`/`tag`, and `Size` as an integer byte count rather than a human string.
- `_created()` parses podman's ISO 8601 (`2026-06-16T00:01:29Z`) alongside docker's
  `2026-06-15 10:30:30 -0400 EDT`.
- Both call sites — the audit provider and `container-update` — go through
  `images_argv()`, so the update action had the same bug and is fixed too.

After: the same real podman image yields 2 findings (mutable `:latest` and image age).
Tests are built from captured podman output rather than from the manual.

## [0.32.1] — pin podman format compatibility

RHEL ships podman rather than docker, so podman-only hosts are now the main new
platform — and a format mismatch there would report zero container findings forever
rather than failing visibly. Two differences are now pinned by tests:

- `podman images --format "{{json .}}"` serialises podman's reporter struct, whose
  fields are `Repository`/`Tag`/`ID`/`CreatedAt`/`Size` — the same names docker uses.
  Podman's *other* JSON form, `--format json`, emits lowercase `id`/`names`/`created`
  and would not parse; the provider uses the template form, and a test says why.
- Podman's `.CreatedAt` is `YYYY-MM-DD HH:MM:SS +nnnn` with **no trailing zone
  abbreviation**, where docker appends one (`… -0400 EDT`). The parser takes the first
  three whitespace fields so both work; only docker's shape had been covered.

## [0.32.0] — advisory-check on the RHEL family

New `rhel` advisory provider reading errata from the repositories' own `updateinfo`
metadata via dnf — local, authoritative for the repos you actually use, and needing no
network beyond what dnf already has.

- Reports `RHSA`/`ALSA`/`RLSA` advisories with severity, affected package and CVEs.
  RHEL's `Important` maps to fettle's **High** (RHEL has no "High"); `Moderate` → Medium.
- **Names the blind spot rather than implying safety.** `updateinfo` only knows what a
  repository publishes, and CentOS Stream publishes no security errata. A real RHEL
  10.1 box was observed with **341 pending updates and zero security advisories** —
  reporting that as "no findings" would be a clean bill of health for a system a year
  behind. When there are no advisories *and* packages are upgradable, it now says so.
- Everything is `FIXED_AVAILABLE`: `updateinfo` describes advisories that *have* a fix.
  "Vulnerable, no fix yet" isn't knowable this way and would need Red Hat's CSAF/VEX
  feed — stated in the report rather than left to silence.

Two things the research got wrong and the live box corrected:

- **RHEL 10.1 ships dnf 4.20 with no dnf5 at all** (`dnf` → `/usr/bin/dnf-3`), so the
  planned dnf5 `advisory list --json` path is unreachable there and is deliberately not
  written. A note records that `dnf --version` containing `dnf5` is the discriminator
  when such a system appears.
- **Red Hat publishes no OVAL for RHEL 10+**, so the approach used for Ubuntu does not
  transfer. OSV was also rejected: it carries a `Red Hat` ecosystem, but a probe
  returned 550 records for one kernel version because it includes RHBA/RHEA bug and
  enhancement advisories.

Parsing notes, since `dnf updateinfo` output has three traps: the block *title*
(`  Important: acl security update`) looks like a `Key: value` field; `Bugs:` and
`CVEs:` both use `<pad>: value` continuation lines, so keying only on `Key: value`
drops every CVE after the first; and `Description:` continuations contain colons of
their own. Restricting the parser to a known key set handles all three. The
`--with-cve` variant is deliberately unused — it emits three rows per advisory (the
upstream RHSA, the CVE, and the distro's own id).

## [0.31.0] — RHEL family: detection and package audit

fettle raised `UnknownDistro` on RHEL, so nothing ran there. New `rhel` backend covering
**RHEL, CentOS Stream, Rocky, AlmaLinux and Oracle Linux**.

- Registering the backend is what unlocks the work: `PackageBackend` already returns the
  six distro-agnostic supply-chain providers, so `pkg-audit` covers flatpak, snap,
  containers, GNOME/VS Code/gh extensions on RHEL with **no RPM-specific code**. podman
  is RHEL's default runtime and the container provider already prefers docker then it.
- **Audit only, deliberately.** `supported` claims `pkg_audit`, `hardening_audit` and
  `container_update` and nothing else, so the maintenance actions report as unsupported
  rather than half-working. `PackageBackend` has no abstract methods, so this is the
  intended way to advertise partial capability.
- **Every ID is registered explicitly** rather than relying on `ID_LIKE`: RHEL 9/10
  carry only `ID_LIKE="fedora"`, and the clones spell theirs differently between
  releases. Fedora is *not* claimed — its advisories are Bodhi `FEDORA-*`, not `RHSA-*`.
- **The action-registry cross-check now derives its backend list from the registry.** It
  hardcoded Arch and Debian, so it silently stopped covering the new backend the moment
  it was added — a typo in `RhelBackend.supported` would not have been caught. A fourth
  backend is now covered automatically.
- Help text: `--help` distro tags are auto-derived, so actions RHEL cannot do now
  correctly read `[arch/debian]`. `.rpmnew` added to the config-drift description, and
  `dnf install checksec` to the hardening hint.

## [0.30.0] — advisory-check: Rust crates (crates.io)

`cargo install`ed crates are compiled from source into `~/.cargo/bin`: unsigned, never
updated unless you do it by hand, and invisible to every OS package manager. They now
join Python and Node as a third ecosystem in the existing OSV path — the client,
SQLite cache, classifier, grouping and reporting all already existed.

- Read from **cargo's own install index** (`~/.cargo/.crates2.json`) rather than the
  binary names in `~/.cargo/bin`, which need not match their crate
  (`flutter_rust_bridge_codegen` is a binary of a differently-named crate).
- **The install source is carried into the environment label.** A crate built from a
  `path`/`git` checkout appears as `cargo(path)` / `cargo(git)` rather than plain
  `cargo`, because its version is whatever the checkout declared and need not be the
  published release of that name — a finding against it should be read with that in
  mind, not presented as a registry match.
- A missing, malformed or unexpectedly-shaped index yields no crates instead of
  raising.

## [0.29.0] — pkg-audit: GitHub CLI extension provenance

New `gh` provider, completing the extension family. `gh` extensions install straight
from an arbitrary GitHub repository with no registry, review or signing — and `gh` runs
them with your **authenticated session available**, so an extension can act as you
against everything your token reaches. A one-line extension is a credential-
exfiltration primitive.

- Reports the origin repository of each installed extension →
  `UNVERIFIED_PUBLISHER` (WARN), naming `github.com/<owner>/<repo>` and the token
  exposure. Extensions owned by `cli`/`github` are first-party and not flagged; an
  extension whose origin can't be determined is LOW rather than silence.
- Provenance comes from the extension directory's own records — a binary extension's
  `manifest.yml`, or a source extension's git `origin` remote (https and ssh forms) —
  **not** from parsing `gh extension list`, whose output is unstructured text with no
  stable contract. The manifest is read with a line scan rather than a YAML parse,
  since the file has a fixed flat shape and fettle ships no YAML parser.

## [0.28.0] — pkg-audit: VS Code / VSCodium extension provenance

New `vscode` provider. Editor extensions are unsandboxed Node with your full user
privileges — filesystem, shell, SSH keys — and they auto-update, which makes them one
of the most actively exploited desktop supply-chain surfaces.

- Reads the editor's own extension index (`<profile>/extensions/extensions.json`), the
  only local record of *where* each extension came from. Covers VSCodium, VS Code and
  VS Code Insiders as separate profiles.
- **Sideloaded `.vsix` installs → `UNOFFICIAL_SOURCE` (WARN)**: they bypassed the
  registry entirely, so no namespace or publisher check ever applied. The claimed
  publisher is named in the finding, since a hand-installed extension asserting a major
  vendor's name is exactly the interesting case.
- An extension whose index entry records no install source → LOW rather than silence.
- An index that can't be read or isn't in the expected shape → `UNVERIFIABLE`. Note
  `json.dumps([])` is the non-empty string `"[]"`, so "no extensions installed" and
  "unreadable index" cannot be told apart from the raw text — the parser returns
  `None` vs `[]` to keep them distinct.
- Deliberately does **not** verify publisher identity or scan extension code: doing
  that reliably needs a curated known-good publisher list per registry. `coverage`
  states this, and notes that VSCodium's registry is Open VSX, whose namespace vetting
  is lighter than Microsoft's marketplace.

## [0.27.0] — pkg-audit: distro-agnostic providers + GNOME Shell extensions

- **Supply-chain providers now run on every distribution.** Flatpak, snap, containers
  and GNOME extensions install the same way anywhere, but flatpak/snap had been
  registered on the Debian backend only — so an Arch box with flatpaks installed was
  audited as though it had none. They move to a shared base
  (`PackageBackend.supply_chain_sources`); each backend adds only its native provider
  (AUR, APT). Each still self-gates with `is_present`.
- **A provider whose tool is absent is reported, not silently skipped** — "flatpak is
  clean" and "flatpak was never looked at" must not read the same.
- **New `[supplychain] skip_sources`** (list of provider names): an ecosystem you
  knowingly don't use is neither run nor mentioned. Deliberately stronger than hiding
  the absence notice — a tool can be installed but empty, so silencing only the notice
  wouldn't help. `[supplychain.hosts.<hostname>]` overrides it per machine for a
  shared config (`fettle remote` reads the *remote's* config, so host tables only
  matter for configs you sync).
- **New `gnome` provider** — GNOME Shell extension **attribution**. Extension JS runs
  inside the `gnome-shell` process with full session access, and e.g.o. review is
  light, so the useful question is provenance: extensions under `/usr/share` trace to
  a package (`pacman -Qo` / `dpkg -S`); ones under
  `~/.local/share/gnome-shell/extensions`, or system-path ones no package owns, were
  placed by hand. Enabled-and-unattributed → WARN, disabled → LOW. Parses
  `gnome-extensions list --details` off the known-uuid set, since a wrapped
  `Description:` continues on unindented lines. Reports `UNVERIFIABLE` when the tool
  fails; states in `coverage` that it does not judge extension *code* (no IOC feed).

## [0.26.0] — `container-update` (`-C`): refresh images, one decision at a time

The audit added in 0.25.0 reports that an image is stale; this refreshes it. Opt-in
(never in the default set) and **needs no root** — docker/podman talk to their socket
as the invoking user.

- Per-image decisions from `[containers]`: `auto_update` (`"ask"` default / `"always"` /
  `"never"` — **overrides both lists**), `never_update` and `always_update` name globs,
  matched against both `repo:tag` and the bare repository so `["cvetool"]` works without
  writing `["cvetool:*"]`. First match wins: override → never → always → **ask**.
- **Unattended runs honour config only.** Under `--yes` the "ask" case is *skipped*, not
  auto-approved: an image never explicitly opted into is never pulled without a human
  seeing the question. This deliberately short-circuits before `Context.confirm()`,
  which returns True under `--yes`.
- `--dry-run` prints the resolved decision for every image and pulls nothing.
- A daemon that can't be listed updates nothing and says so, rather than reporting
  "nothing to do".
- **Elevation now keys off a new `NO_ROOT_ACTIONS` set** rather than
  `READ_ONLY_ACTIONS`. Those are different questions, and conflating them made `-C`
  demand a sudo password it has no use for: `container-update` changes the system but
  needs no root. `READ_ONLY_ACTIONS` keeps its literal meaning and remains a subset.

## [0.25.0] — pkg-audit: container images

Container images were a blind spot: `pkg-audit` covered apt/aur/flatpak/snap while
whole security toolchains ran from images nothing on the system tracked. New
`container` provider (docker, falling back to podman), inventory only — pure stdlib
JSON from `<runtime> images --format '{{json .}}'`.

- **`:latest` → `MUTABLE_REFERENCE`** (a new question in the supply-chain vocabulary):
  the bits behind the name change without the name changing, so nothing records what
  actually ran. Deliberately *only* `:latest` — flagging every non-digest-pinned tag
  would light up essentially every image on every machine.
- **Image age → `STALE_OR_ABANDONED`**, default over 90 days
  (`[containers] max_age_days`). Rated more harshly than the AUR staleness reading on
  purpose: an AUR package still receives distro updates, whereas an image is frozen at
  build time and carries every CVE published since.
- **Registry provenance → `UNOFFICIAL_SOURCE`** for registries outside a known-operator
  set. A bare name (`cvetool`, `python`) is *not* claimed either way — `docker images`
  cannot distinguish a local build from a Docker Hub library image.
- **Dangling images** reported as INFO hygiene with the `prune` command.
- **A daemon that cannot be queried is reported, never silently skipped** —
  `UNVERIFIABLE`, the second new question, which exists so a failed check can never
  render identically to a clean one. Covers a stopped daemon and the common "not in
  the `docker` group" case.
- Explicit non-goal, stated in the provider's `coverage` line: scanning image
  *contents* for vulnerable packages. That is trivy/grype's job.
- New `[containers]` config: `max_age_days` (default 90), `ignore` (name globs).

## [0.24.1] — advisory-check: reach nested virtualenvs, and stop losing colliding ones

- **`venv_depth` default 3 → 5.** Project virtualenvs are routinely nested a few
  levels down (a cloned repo inside a topic directory). On a real tree depth 3 found
  41 of 50 in 0.11s while depth 5 finds 49 in 0.52s — the ones it had been missing
  were all security-research code.
- **Fix silently dropped findings from environments whose labels collided.** The
  label is part of a finding's identity — rows are cached as `env:package` and
  deduplicated on that name — so two environments sharing a label collapsed into one
  and a real finding disappeared. Both shapes occur in practice: different projects
  with the same directory name (`src/cisa-kev/venv` vs `src/cvetool/cisa-kev/venv`),
  and two environments in one project (`venv-fettle-dev` vs `venv-fettle-web`, both
  labelled by their parent). Colliding labels are now widened with path context until
  distinct — on a real tree, 49 environments that produced 46 labels now produce 49,
  with only the 6 ambiguous ones widened.

## [0.24.0] — advisory-check: group findings by the fix, not by the environment

Scanning unmanaged environments (0.23.0) meant one vulnerable package copied into
many virtualenvs arrived as many findings — 591 occurrences across 35 environments on
a real box. That noise is **replication, not severity**: a severity floor would have
removed almost none of it (209 of 212 findings were rated High, which spot-checks
against the OSV records confirmed is correct data, not a banding bug). So reporting
groups instead of filtering, and nothing is hidden.

- Findings are grouped by the **remediation** — package + fix version + CVEs — and
  deliberately *not* by the installed version: "upgrade pip to 26.1.2" is one action
  whether a given virtualenv sits on 24.0 or 25.2. Measured: keying on the installed
  version gave 323 groups, keying on the fix gives 132.
- Each group lists its environments with their own versions
  (`in 3 environments: cve-maker (3.4.0), dfir (4.0.0), …`), and the installed side
  shows a span when they differ (`42.0.7…48.0.0 (6 versions) -> 48.0.1`). Ten are
  named before the rest are summarised; the JSON sibling always keeps every
  occurrence.
- Section headers report the pre-grouping totals — `(591 occurrences across 35
  environment(s), grouped by package+CVE)` — so a smaller count than the previous
  release cannot be mistaken for findings having gone missing.
- `AdvisoryFinding` gains an `environment` field (empty for the OS providers, whose
  packages are installed once), carried into the JSON. `counts` gains
  `pending_occurrences` / `fixed_available_occurrences` alongside the grouped totals.
- The HTML report groups identically and gains a **where** column.

## [0.23.0] — advisory-check: scan the language packages your distro does NOT manage

The OSV language provider enumerated `importlib.metadata.distributions()` — the
*running interpreter's* packages. On a distro machine that is the system
site-packages, which the package manager owns, so the "language ecosystem" scan was
in fact scanning distro packages. Two consequences, both wrong:

- It re-reported packages the arch/debian providers already cover, judged by **PyPI
  version semantics** instead of the distro's own verdict (a backported fix or an
  explicit "not affected"), and under a second name — `osv/ecdsa` alongside
  `arch/python-ecdsa` — so one package looked like two problems.
- It missed **every virtualenv on the machine**. Measured on a real box: 264 packages
  scanned, 100% package-manager-owned, while 36 virtualenvs were invisible.

Now scans only environments that are unmanaged *by construction* — virtualenvs, `uv`
tools, `pipx` apps, per-user (`pip install --user`) installs, and `bun`/`nvm` Node
trees — so there is no overlap to dedupe and no ownership query to run. Node reads
`node_modules/*/package.json` directly (works for bun/nvm trees `npm ls -g` won't
report) and skips a global root under a system prefix. Same real box after: **736
packages across 38 unmanaged environments**, 0 distro-owned.

- Findings are environment-qualified (`SploitScan:requests`) — the same vulnerable
  package in three virtualenvs is three things to fix, and dedup keys on that name.
- New `[advisories] venv_roots` (default `["~/src"]`) and `venv_depth` (default `3`)
  bound virtualenv discovery; an unbounded `$HOME` walk measured over two minutes.

## [0.22.2] — docs

- **README table of contents rebuilt.** It was missing the whole `advisory-check`
  section, and three subcommands were invisible in it because they are documented as
  subsections: `hardening-audit`, `fettle report`, and `fettle web` (the last two
  filed under *Configuration*). The ToC is now two levels deep and every anchor is
  verified to resolve.
- **README overview covered three feature families; there are four.** Security
  advisories / CVE tracking was absent from *What it does* and from the topgrade
  comparison table despite being a headline feature.
- Document the v0.22.0 sys-audit behaviour in the sys-audit section: a check that
  could not run reports `UNKNOWN` (an un-run security check is a finding), a check
  that ran but reported no verdict is a neutral `Unknown`, and the Secure Boot
  certificate matrix skips rather than claiming "Not present" when a UEFI variable
  can't be read.
- Drop a stale `v0.13.0` version reference from the comparison table (it now says
  "beta" rather than pinning a number that goes stale every release).

## [0.22.1] — argument-parsing hardening (defence in depth)

Neither of these has a known attack path — both values come from your own config
or CLI — but both are one-line guards.

- `fettle remote` refuses a host that ssh/scp would parse as an option rather than
  a destination (e.g. `-oProxyCommand=...`, which would run a command locally)
  instead of passing it through. Applies to the run and report/log-fetch paths.
- `flatpak info --show-permissions` now passes `--` before the app id, matching the
  end-of-options guard `aur/audit.py` already uses.

## [0.22.0] — sys-audit: a check that could not run now says so

`Scan.run_text()` discarded the exit code, so checks that derive a verdict by
substring-matching a tool's output could not tell "no problem found" from "never
ran". Minor bump: sys-audit output changes on affected systems.

- **Secure Boot cert expiry no longer reports a failed read as a healthy state.**
  stderr is merged into the command output, so a failed `efi-readvar` returned its
  own error message — a non-empty string containing no certificate names. That
  slipped past the emptiness guard and rendered every certificate "Not present",
  which for the 2011 certs prints green/ok. A failed UEFI variable read was
  displayed as a fully-migrated Secure Boot posture. Failed reads now return empty,
  and a *partial* read (one store readable, the other not) skips instead of
  half-reporting.
- **chipsec failures are now visible.** ME Manufacturing Mode and BIOS Write
  Protection matched neither "passed" nor "failed" when chipsec crashed, so they
  printed nothing at all — and a missing line reads as "no problem here". A failed
  tool is now a loud `UNKNOWN`, while a clean run that reports no verdict (module
  not applicable to the hardware) is a neutral `Unknown` rather than an error.
- **`fwupdmgr` failures are no longer reported as "Updates available".** Note that
  fwupdmgr also exits non-zero when there is nothing to do, so "no updates" is
  still matched first and an up-to-date system stays `ok`.
- `mokutil --sb-state` failure is reported instead of printing a blank status.
- New `Scan.run_text_rc()` returns `(text, returncode)`; `run_text()` is unchanged,
  so the verbose-dump call sites are untouched.

## [0.21.3] — fix: `-A --dry-run` crashed

- Fix an `UnboundLocalError` that crashed `fettle -A --dry-run`: the aur-audit summary
  line read the report path outside the `if not ctx.dry_run:` block that binds it. The
  same line also crashed the `except OSError` path (unwritable/full `~/.fettle`), so a
  failed report write took the whole run down instead of warning. Present since
  2026-07-07; the summary now names the report only when one was actually written.
- Add a regression guard over the whole class: every `READ_ONLY_ACTIONS` member is now
  exercised under `--dry-run`, since `--dry-run` is supported for all of them and only
  aur-audit happened to be broken.

## [0.21.2] — Phase 19 complete: docs sync

- Mark the security-advisory / CVE-tracking feature (Phase 19) complete: Arch, Debian,
  and Ubuntu native feeds (fix-available + pending, Ubuntu pending opt-in via OSV) plus
  Python/Node language deps via OSV — all live-verified end-to-end.
- Fix two stale notes that claimed Ubuntu "no fix yet" data "isn't shown yet" — it *is*,
  opt-in via `[advisories] ubuntu_pending` + `ubuntu_pending_severity` (the
  `advisory-check` report footer and the README both said otherwise).
- README: document `ubuntu_pending` / `ubuntu_pending_severity` and the OSV language-dep
  coverage under `[advisories]`.

## [0.21.1] — fix: advisory-check crash on Ubuntu

- Fix an `IndexError` that crashed `advisory-check` on Ubuntu (introduced in 0.21.0):
  the OSV dedup accessed a `cvss` column on the bulk providers' shorter rows (padded
  only later), tripping on a duplicate-CVE severity tie in real OVAL data — which the
  unit test's collision-free fixture missed. `dedup_rows` now tolerates short rows.

## [0.21.0] — advisory-check: Ubuntu "no fix yet" via OSV, opt-in (Phase 19 M4b)

- Ubuntu's **"vulnerable, no fix yet"** (pending) findings — which the OVAL feed can't
  provide — are now available via the shared OSV client, keyed on your installed
  source packages. It's **opt-in and floored** because a real box returns ~1300
  pending Ubuntu CVEs, the vast majority negligible/won't-fix:
  - `[advisories] ubuntu_pending = true|false` (default **false**)
  - `[advisories] ubuntu_pending_severity = low|medium|high|critical` (default
    **high**) — only pending at/above this floor is kept, so it's the actionable few.
  OVAL remains the default Ubuntu source for fix-available; enabling `ubuntu_pending`
  adds the pending layer on top (records cached + synced incrementally; the first
  refresh is heavier).
- Ubuntu OSV findings carry Canonical's native `priority` (from the OSV `severity`
  list) as the band plus the CVSS vector — both perspectives.

## [0.20.0] — advisory-check: vulnerable language deps via OSV (Phase 19 M4a)

- `fettle advisory-check` now flags vulnerable **Python (PyPI)** and **Node (npm)**
  packages installed system-wide — CVEs the OS trackers can't see. It enumerates
  installed language packages and queries **OSV.dev** (`querybatch`), caching each
  vuln record in the SQLite DB and syncing **incrementally** off its `modified` time
  (first run heavier, then only-changed). A missing `fixed` event = pending; a
  `fixed` event above your version = fix-available. Cross-platform (any distro).
- **Severity shows both perspectives:** the native GHSA/OSV rating *and* the CVSS
  vector side by side (they carry different biases). Duplicate advisories for the
  same CVE across databases (GHSA + PYSEC …) are collapsed to the best-rated one.
- This is the shared OSV client that will also fill Ubuntu "no fix yet" (M4b).

## [0.19.0] — advisory-check: Ubuntu provider (Phase 19 M3)

- `fettle advisory-check` now covers **Ubuntu** too (Arch/Manjaro + Debian + Ubuntu).
  It bulk-fetches Ubuntu's per-release **OVAL** feed
  (`security-metadata.canonical.com`, `bz2` + `xml`, both stdlib), which carries
  fix-available data with Canonical's `priority` (**including `critical`**, so the
  `-u`/`-a` warn-gate works on Ubuntu), and classifies installed source packages via
  `dpkg` (shared with the Debian provider). Ubuntu-proper only — it tracks its fix
  state independently of Debian.
- **Known gap (transparent in the report):** the OVAL feed contains only *fixed*
  CVEs, so Ubuntu's "vulnerable, no fix yet" (pending) findings aren't surfaced yet —
  that data lives in Canonical's CVE JSON API, which was returning HTTP 503 when M3
  landed. Pending will appear when that endpoint is reachable.
- Refactor: Debian and Ubuntu share an `AptAdvisorySource` base (dpkg-based
  classification, source mapping); only each tracker's fetch/parse differs.

## [0.18.0] — advisory-check: Debian provider (Phase 19 M2)

- `fettle advisory-check` now covers **Debian** (in addition to Arch/Manjaro). It
  bulk-fetches `security-tracker.debian.org`, filters to the **running release**
  (`VERSION_CODENAME`), and classifies installed **source** packages — pending
  (`status: open`, or a `no-dsa` won't-fix), or fix-available (compared via
  `dpkg --compare-versions`; source mapping via `dpkg-query`), into the same shared
  SQLite cache and report. Each finding carries its Debian **class tag** (`nodsa`,
  `unimportant`, `end-of-life`, urgency), so `[advisories] exclude_classes =
  ["nodsa","unimportant","end-of-life"]` cuts the long tail of won't-fix CVEs to the
  actionable set. Debian assigns no "critical" urgency, so the `-u`/`-a` Critical
  warn-gate won't fire on Debian-only findings. Ubuntu tracks independently and lands
  in M3.

- `fettle -u` / `-a` now runs a **best-effort security gate** before a real upgrade:
  it reads the **cached** advisory data (never fetches, never blocks/fails a routine
  update on missing/stale/offline data), prints a one-line security summary, and — if
  `[advisories] warn_gate` is on (default) and **Critical** CVEs are currently
  unpatched — asks one extra confirmation before proceeding. Skipped under `--yes`
  (unattended never stalls) and on `--dry-run`.

## [0.17.0] — security-advisory / CVE tracking, Arch/Manjaro (Phase 19 M1)

- New opt-in **`fettle advisory-check`** (Arch/Manjaro; Debian/Ubuntu planned) — for
  each installed package it reports known CVEs with **a fix you haven't applied yet**,
  and — the distinctive part — CVEs it's **currently vulnerable to with no fix released
  yet** (a heads-up *before* an advisory/patch exists). The AUR RPC / package manager
  can't surface either.
- Bulk-fetches `security.archlinux.org` into a **rebuildable SQLite cache**
  (`~/.cache/fettle/advisories.db`; `sqlite3` is stdlib, so the zero-dependency core
  holds), refreshed on-run when stale, or on demand via **`fettle advisory-update`**.
  Version comparison is delegated to `vercmp` (never hand-rolled).
- Report: a **"Pending fixes"** callout (vulnerable, no fix yet) above a
  severity-banded **"Fix available"** table, plus the packages the tracker **doesn't
  cover** (AUR/manual/foreign) so a clean result never over-reassures. Rendered in the
  HTML dashboard too. On Manjaro, "fix available" is phrased as possible sync-lag, not
  alarm. New `[advisories]` config (`cache_ttl`, `severity_threshold`,
  `exclude_packages`, `exclude_classes`, `warn_gate`), all quiet defaults.
- Read-only, opt-in (never in the default `-a` set).

## [0.16.0] — aur-audit: reverse-dependents ("nothing uses this") check

- `-A` (`aur-audit`) now flags foreign packages that **nothing on the system depends
  on** — the AUR RPC can't surface this, so a healthy-but-leftover clone (e.g. an old
  `webkit2gtk` that nothing links) previously looked perfectly fine. For every foreign
  package it reads `pacman -Qi` reverse-deps and adds a graded flag: **`NO-DEPENDENTS`**
  (nothing requires *or* optionally-needs it), **`NO-HARD-DEPS`** (only an optdep of
  something), and **`LIB`** when it ships a public `/usr/lib/*.so` — so an unused
  *library* (the actionable case) reads `NO-DEPENDENTS LIB`. A **"Candidates for
  removal"** section (text + HTML, libraries first) lists the strong ones with a
  `sudo pacman -Rns <pkg>` hint and the caveat that **pacman only tracks packaged
  dependents** (unpackaged software / `dlopen` could still use them — verify first).
  The JSON gains `required_by`/`optional_for`/`is_library` per package and a
  `removal_candidates` list. `-A` stays read-only — it advises, never removes.

## [0.15.2] — web UI: controls on top

- The `/run` and `/remote` pages now put the **action controls at the top** of the
  page with the live **output log below** them (they were under the log before, so
  the options were pushed off-screen).

## [0.15.1] — web UI: run history

- **Run history (`/history`):** a new page (linked from the toolbar) listing every
  stored run across all hosts, newest first — `when · host · fettle <argv> · ok/exit`
  — each expandable to its full transcript. Reads the `fettle.log/1` run-logs the CLI
  already writes, including web-triggered runs.

## [0.15.0] — web UI (`fettle web`, beta)

An optional NiceGUI web interface over the fettle CLI. Strictly opt-in and
localhost-only; the CLI core stays pure-stdlib.

- New optional **`fettle web`** command serves a NiceGUI web UI (localhost-only by
  default). It's strictly opt-in: `pip install 'fettle[web]'`. The CLI core stays
  **pure-stdlib** (`dependencies = []`) — only `fettle/web/` imports nicegui, and a
  test enforces that importing the core never pulls it in, so the stdlib-only remote
  zipapp is unaffected. Without the extra, `fettle web` prints a friendly install
  hint instead of a traceback.
- **Live dashboard (Phase 1):** the web UI mirrors `fettle report` exactly — it
  serves the *same* HTML, generated live from the current `~/.fettle` on each load
  (no disk write), for all hosts at once, via the real report renderers. Served as a
  plain page with a small injected toolbar (**run** + **refresh**), so the report's
  own terminal CSS/JS (filter, collapse) work untouched.
- **Run read-only audits (Phase 2):** a `/run` page (linked from the dashboard) with
  a button per read-only audit (`pkg-audit`, `aur-audit`, `aur-ioc-scan`,
  `hardening-audit`, `config-drift`, `auto-updates`, `only-update`). Clicking one
  runs it as an unprivileged `python -m fettle <action>` subprocess and **streams the
  output live**; when it finishes, reload the dashboard to see the new report.
- **Run system-modifying actions (Phase 3):** the `/run` page also drives the
  privileged actions (`update`, `clean`, `orphans`, `kernel`, `rebuild-check`,
  `python-rebuild-check`, `firmware`, and the full `-a` set). Each has a **Preview**
  (a no-sudo `--dry-run`) and a **Run (sudo)** that first shows a **confirmation**
  and then runs `sudo -S fettle <action> --yes` with a sudo password you type on the
  page (held in memory only, never stored or logged, never on the command line),
  streaming the output live. The web server itself stays unprivileged. Note: some
  flows (AUR helpers / pamac) may prompt for a password separately.
- **Remote hosts & groups (Phase 4):** a `/remote` page lists the configured
  `[remote.groups.<name>]` (with their hosts) and takes an ad-hoc host, with an
  actions field (default `-a`). **Preview** runs `fettle remote <target> … --dry-run`
  (safe); **Run** confirms, then `fettle remote <target> … --yes` over SSH, streaming
  the per-host output. Remote hosts elevate themselves over SSH (no local sudo);
  `--yes` uses non-tty SSH, so it needs passwordless sudo on the targets. Fetched-back
  per-host reports then appear under each host on the dashboard.
- **Hardening (Phase 5):** binds `127.0.0.1` by default and rejects any request whose
  `Host` header isn't localhost (defends a privileged local tool against
  DNS-rebinding / cross-origin drive-by). Every web-triggered action is recorded in
  `~/.fettle/web-actions.log` (`0600`; the command line only, never the password).
  Networked/multi-user access with authentication is intentionally out of scope for
  now — run it behind your own auth if you expose it.

## [0.14.0] — AUR reports link packages + say what they are

- **In the HTML report, AUR package names are now links to their AUR page**
  (`aur.archlinux.org/packages/<name>`) — in the AUR Package Health report *and* in
  the supply-chain (`pkg-audit`) and IOC-scan (`aur-ioc-scan`) findings. Only AUR
  packages are linked; `apt`/`flatpak`/`snap` names (no AUR page) stay plain text.
- **The AUR Package Health table gains a "software" column** — the AUR one-line
  description (truncated, full text on hover) plus a `↗ homepage` link to the
  upstream project. Both come from data fettle already fetches (the AUR RPC
  response), so there are **no new network calls**. Upstream URLs are gated to
  `http(s)` before becoming a link (a malicious `javascript:` URL is never emitted).
  The plain-text `.txt` report is unchanged.

## [0.13.3] — `fettle remote -h` docs refresh

- `fettle remote -h` now documents **host groups** (`HOST|GROUP` grammar + how a
  `[remote.groups.<name>]` runs each host in order) — the help predated the groups
  feature — and points at the **current** report location
  (`~/.fettle/{reports,logs}/<host>/`, with the run-log now fetched back too) instead
  of the stale pre-0.11 `~/upgrade-check-<host>.txt` path. Main `--help` and an
  internal docstring got the same path correction. No behavior change.

## [0.13.2] — no ncurses over SSH; show each report's command

- **Debian/Ubuntu upgrades no longer pop a full-screen ncurses dialog.** `apt`'s
  `needrestart` service-restart menu and any `debconf` config screen used to take
  over the terminal (and corrupt it — wrapped, single-line output — especially over
  `ssh -t` under the run-log recorder). fettle now runs the upgrade with
  `NEEDRESTART_MODE=l` (needrestart *lists* what needs restarting instead of
  prompting; fettle already surfaces `sudo needrestart` as a next step) and a
  plain-text `debconf` frontend (`DEBIAN_FRONTEND=readline` interactively,
  `noninteractive` under `--yes`). `apt` still asks its own `[Y/n]` in the default
  (non-`--yes`) mode.
- **The HTML report shows the exact command that produced each report.** Every
  report records the `fettle …` invocation that created it (e.g. `fettle -H`), shown
  as a `$ fettle -H` chip on the entry. Recorded per host, so a fetched remote
  report shows how it was produced *there*. Pre-0.13.2 reports simply omit the chip.

## [0.13.1] — group runs show under each target host

- **A group run's per-host result now shows under that host in the HTML report.**
  After a remote (or group) run, fettle fetches back not just the host's reports but
  also its **own run-log** (its session transcript, including the package-update
  output) into `~/.fettle/logs/<host>/`. So `fettle remote bifrost-lab -a` produces
  a "Session Transcripts (run logs)" entry under **each** of bifrost/ec1/ec2/ec3 —
  the actual `fettle -a` run that happened on that host.
- **The "group runs" area is now a tiny pass/fail summary**, not a transcript dump:
  one line per `fettle remote <group>` session (when · command · ok/exit badge).
  The detail lives under each host, where the previous bullet now puts it.

## [0.13.0] — remote host groups

- **`fettle remote <group>` runs on a whole group of hosts, one by one.** Define a
  group in the config and update the entire lab with one command:
  ```toml
  [remote.groups.bifrost-lab]
  hosts = ["bifrost", "ec1", "ec2", "ec3"]   # + optional actions / ssh_args / yes
  ```
  `fettle remote bifrost-lab -a` runs `fettle -a` on each host **in order** (same
  per-host flow, including the report fetch-back), **confirms the host list** first
  (skipped under `--yes` / `--dry-run`), **continues past a failing host**, and
  prints a **pass/fail summary** (non-zero exit if any host failed). A group can set
  per-group default `actions`, `ssh_args`, and `yes`; a bare host list is shorthand.
  A group name wins over a same-named single host. For a walk-away run, use `--yes`
  with passwordless (`NOPASSWD`) sudo on the hosts.
- In the HTML report, a group is **not** shown as a host asset: each host in the
  group keeps its own dashboard card/section (results are fetched back per host),
  and the group's orchestration transcript appears in a separate "group runs" area.

## [0.12.0] — machine-readable JSON output; HTML report (beta)

- **Every report and run-log now has a structured `.json` sibling.** Alongside the
  `.txt`, fettle writes `<name>-<ts>.json` under `~/.fettle/{reports,logs}/<host>/`
  — a `{schema, tool, host, timestamp, fettle_version, data}` envelope whose `data`
  is the real structure the report was built from (scored hardening packages,
  supply-chain findings with severity, the upgrade-check result, package lists, log
  transcript + argv/exit). Same `0600`, same rotation (txt+json rotate as a unit).
  Toggle with `[reports] json = false`.
- **`fettle report` — an HTML dashboard (BETA, initial revision).** Regenerates a
  single self-contained `~/.fettle/report.html` (`0600`) from all stored JSON,
  across every host: a per-host summary card row (latest hardening band tally,
  per-type counts, latest run), collapsible sections (with a `[+]`/`[-]` expand
  affordance) grouped by report type with native rendering (scored hardening
  tables, severity-coloured findings, upgrade verdicts, package lists, log
  transcripts), and a host/type/text filter. **Empty reports** (a clean
  `obsolete-pkgs`, an `aur-ioc-scan` with no indicators, …) are hidden, with a
  per-host "N hidden" note. Styled as a **dark Linux terminal** (monospace, phosphor
  palette, shell-prompt header). Pure stdlib, no external assets. `fettle report
  --open` opens it in a browser.
  *This is a first cut — the layout and contents will evolve; feedback welcome.*
- **`fettle report --backfill-json`** — one-off converter that gives pre-0.12
  `.txt` reports/logs a JSON sibling (idempotent, non-destructive) so the dashboard
  is populated without re-scanning.
- Remote report fetch-back now pulls the `.json` siblings too.
- **`sys-audit` now writes a report** (`~/.fettle/reports/<host>/sys-audit-<ts>.{txt,json}`),
  so the firmware/boot/hardware scan shows up in the HTML dashboard alongside the
  other reports — previously it only printed to the terminal. Every scanned
  category is captured (even ones whose detail comes from raw command output, not
  status lines), with per-item status levels **and a full raw-output section**.
  `fettle sys-audit remote <host>` fetches its report back to the controller.

## [0.11.0] — reports moved to ~/.fettle, timestamped & rotated; run logs

- **Reports no longer clutter `$HOME`.** Every report (`aur-audit`, `pkg-audit`,
  `aur-ioc-scan`, `hardening-audit`, `upgrade-check`, the orphans list) now lands
  under **`~/.fettle/reports/<host>/`**, **timestamped** (so runs don't clobber
  each other), **`chmod 0600`** (they name your packages and can hold system
  detail), and **rotated** to the newest `keep` (default 5) *per host, per report
  type*. `<host>` is `local` locally, or the target hostname for `fettle remote
  <host> …`, so each machine keeps its own history. Pre-0.11 `~/*.txt` reports are
  left untouched; fettle notes the move once.
- **Every run is recorded to a transcript** under `~/.fettle/logs/<host>/run-<ts>.txt`
  (same `0600` + rotation). On an interactive terminal fettle captures the whole
  session — its own output **and** every tool it runs — `script(1)`-style, by
  re-execing once under a pseudo-terminal so the run happens on a real tty and
  colours / `sudo` / PKGBUILD prompts are unaffected. Logs are ANSI-stripped;
  non-interactive runs record fettle's own output only.
- **New `[reports]` config:** `keep` (retention per host+type, default 5), `dir`
  (base-dir override, default `~/.fettle`), `log` (set `false` to disable the
  run-log).

## [0.10.0] — scored, ranked hardening audit

- **`hardening-audit` output is now scored and ranked.** Each binary gets a risk
  score — `Σ weight(missing protection) × 3 when it's a privilege boundary
  (setuid/setgid or a configured `sensitive_packages`) — mapped to **Critical /
  High / Medium / Low** bands, and packages are sorted worst-first by their most
  vulnerable binary. So the outlier that matters (e.g. a setuid helper missing a
  stack canary) rises to the top instead of drowning under big, harmless packages.
- **Focused terminal, full detail on disk.** The on-screen table shows only the
  **Critical** and **High** packages (`BAND · SCORE · P · PACKAGE · BINS ·
  MISSING`), collapses Medium/Low into a one-line tally, and writes the complete
  per-criterion **matrix** (a column per protection) to `~/hardening-audit.txt`.
  The summary still reports every band's count.
- **New `[hardening]` scoring keys** (all optional): `sensitive_packages` (globs
  — mark network daemons as privilege boundaries; setuid/setgid is automatic),
  `priv_multiplier`, and `weights` (per-criterion). Band thresholds are calibrated
  constants.

## [0.9.0] — binary hardening audit

- **New `hardening-audit` check (`-H` / `--hardening-audit`).** Runs `checksec`
  over your installed executables and flags packages whose binaries were **not**
  built with the hardening the distro says it uses — an upstream Makefile
  clobbering `CFLAGS`, a vendored prebuilt binary, or a sloppy AUR build. It's a
  supply-chain question, not a generic lint. Read-only, rootless, cross-distro,
  and **opt-in** (not in the default `-a` set). Findings roll up per package and
  save to `~/hardening-audit.txt`.
  - The baseline is **derived from the distro's own build policy** — Arch's
    `makepkg.conf` *plus* GCC's compiled-in `--enable-default-pie/ssp` (where PIE
    and the stack canary actually come from), or Debian's `dpkg-buildflags` — so
    a deviation means the package genuinely departed from how everything else was
    built.
  - Four always-on accuracy corrections keep it honest: non-ELF files are skipped
    (checksec otherwise "fails" every check on a script), static Go/Rust binaries
    are skipped, `_FORTIFY_SOURCE=No` is ignored when nothing was fortifiable, and
    `stack_clash` is never treated as pass/fail. Detectable vs. not is documented
    in the README.
  - Prune the (deliberately long) default list with `[hardening]`
    `exclude_checks` / `exclude_packages` / `exclude_paths` globs in your config;
    fettle reports how many findings your exclude lists hid. Needs `checksec`
    (skipped with a note if absent).

## [0.8.0] — auto-updates posture check

- **New `auto-updates` check (`-x` / `--auto-updates`).** A read-only,
  informational report of whether the system is configured to update itself
  unattended. Runs by default in `-a`; needs no root; cross-distro.
  - **Debian/Ubuntu:** reads `apt-config dump` (the authoritative
    `APT::Periodic::Unattended-Upgrade` / `Update-Package-Lists` values, honoring
    the full `apt.conf.d/` layering), whether `unattended-upgrades` is installed,
    and `systemctl is-enabled apt-daily-upgrade.timer`.
  - **Arch/Manjaro:** checks a curated list of known community auto-updater
    systemd timers (`arch-update.timer`, `pacman-auto-update.timer`,
    `yay-auto-update.timer`, `topgrade.timer`, …) via `systemctl is-enabled`;
    none enabled = "manual updates — the Arch default". A custom-named timer
    isn't recognized (the tradeoff of name-matching).
  - It only reports the fact and offers no opinion either way.

## [0.7.0] — AUR pre-upgrade IoC gate

- **Flagged AUR packages are caught *before* they're built.** Before `yay -Sua`,
  `fettle -u` / `-a` now pre-checks the AUR packages it's about to upgrade against
  the IoC feeds (known-compromise names, malicious maintainers, orphan/out-of-date/
  stale) and **prompts to continue or abort** on any finding (default abort). A
  clean set just prints a one-line "no indicators". Previously the only AUR
  security check ran *after* the update.
- Applies to **`fettle remote <host> -u/-a`** too (same code runs on the host; the
  prompt comes over `ssh -t`). Under `--yes`, a **CRITICAL** finding aborts
  unattended unless you pass `--force-aur`. `--no-aur-precheck` (or
  `aur_precheck_on_update = false`) disables the gate.
- Covers the `yay -Qua` upgrade set; `--devel`/`-git` rebuilds that don't bump a
  version stay covered by the yay hook and the post-update `aur-ioc-scan`.

## [0.6.0] — clearer output; security audits in the default run

- **External-tool output is now framed.** When fettle hands off to yay/pacman/apt,
  it brackets that tool's live output in a labeled banner (`──── yay ──── output
  below is yay's, not fettle's ────`) so fettle's own messages are never mistaken
  for the package manager's. No capture, so PKGBUILD-review and sudo prompts still
  work.
- **`fettle` / `-a` now runs the security audits too.** The default set gained
  `pkg-audit` and `aur-ioc-scan` (appended, read-only), so a full run also reports
  package provenance and checks installed AUR packages against known-compromise
  feeds. Previously neither ran under `-a`.
- **Quieter cross-distro default runs.** A "skipping <action>" note now only prints
  for actions you *named* — default-set actions a distro can't do (e.g.
  `aur-ioc-scan` on Debian) are skipped silently.
- The bundled yay hook (`~/.config/yay/init.lua`) now prefers `fettle aur-precheck`
  over the legacy `aur-precheck.sh` when fettle is on `PATH`.

## [0.5.0] — remote AI upgrade-check

- **`fettle remote HOST upgrade-check`** — the experimental AI pre-upgrade advisor
  now works against a remote host. fettle collects a redacted snapshot **on the
  host** (read-only, no sudo, no API key) and runs the Claude analysis **on your
  machine** with your local key. Your key never leaves your machine, only your
  machine needs internet to Anthropic, and the report is saved locally as
  `~/upgrade-check-<host>.txt`. (Replaces the old behaviour, which ran the whole
  thing on the remote and wanted your key set there.) Missing `inxi` on the host
  degrades gracefully; on Debian the pending list reflects the host's cached apt
  data (Arch uses a fresh rootless sync).

## [0.4.5] — correctness & safety review fixes

_All items below were flagged and fixed during a Claude Fable 5 review of the
whole codebase._

- **User config is honoured on elevated runs.** `--config` is now carried across
  the `sudo` re-exec. Previously `sudo` reset `HOME=/root`, so system-changing
  runs re-resolved the config path to `/root`'s (usually absent) and silently used
  built-in defaults — ignoring your `keep_orphans`, `exclude_foreign`, and
  `[updaters]` exactly when they matter (e.g. orphan removal).
- **A missing external tool no longer crashes the run.** `command.run` returns a
  clean non-zero result instead of raising `FileNotFoundError`.
- **No spurious sudo prompt in read-only/dry-run queries.** `sudo -u <user>` is
  only used when actually running as root (it can't drop privileges you don't
  hold), so unprivileged queries like the `yay -Qua` preview run directly.
- **Vanilla Arch / EndeavourOS `update` no longer fails** on the Manjaro-only
  `pacman-mirrors` — it's now skipped when absent.
- **Root-owned cache/state no longer crashes a later user run.** The AUR IOC cache
  and maintainer snapshots degrade gracefully if unreadable, and are chowned back
  to the invoking user after a root run writes them.
- **Security: the remote zipapp** is uploaded to the remote user's `$HOME` under a
  random name (was a predictable world-writable `/tmp` path run under `sudo`).
- **`aur-precheck` never silently drops a package name** — everything after `--`
  is taken literally.

## [0.4.4] — Python rebuild check no longer flags Python itself

- **`-y` / `python-rebuild-check` ignores Python interpreter packages.** It used
  to list packages like `python312` (a separate, deliberately-installed Python
  interpreter) as "needing rebuild" just because they own `/usr/lib/python3.12`.
  Now the interpreter that owns an old Python dir is excluded (via its stdlib
  owner + a name-pattern fallback), so only genuinely **stranded modules** are
  flagged. Old Python dirs owned by *no* package are reported separately as
  removable leftover cruft, and skipped interpreters are named for transparency.

## [0.4.3] — kernel-removal safety fix

- **Debian/Ubuntu: never offer to remove the *newest* kernel.** Kernel management
  protected only the *running* kernel, so after a kernel upgrade before reboot
  (running the old kernel, newer one installed) it offered to purge the newer,
  next-boot kernel — a potential rollback. It now protects the running kernel
  **and** the newest installed one(s), compared numerically (a string sort ranks
  `6.8.0-99` above `6.8.0-124`), and nudges you to reboot when a newer kernel is
  installed but not yet active. Arch/Manjaro was audited and is unaffected
  (removal is user-named; the running series is refused).

## [0.4.2] — fixes

- **`fettle upgrade` now works** as a synonym for `update` (install package
  upgrades). The `--upgrade` flag already worked; the bare word didn't.

## [0.4.1] — fixes

- **Fixed the post-update AUR hint.** The Arch update summary pointed at
  `fettle -A -S`, a pre-v0.4.0 combo — since `-S` is now sys-audit, running it
  errored. It now correctly suggests `fettle -A -I` (AUR audit + IoC scan).
- **Clearer error for clashing shortcuts.** Combining a dispatch shortcut with an
  action flag (e.g. `fettle -A -S`) now prints a clear message instead of a
  cryptic sub-parser error; sub-options like `-S --list` still pass through.
- **`fettle sys-audit` with no arguments runs all checks** (was a "nothing to
  check" no-op) — matching `fettle -S`. Named categories and `--list` unchanged;
  the `remote` form still requires explicit categories/`--all`.
- **Debian/Ubuntu: autoremove previews first.** `apt-get autoremove` now lists the
  exact packages it would drop **before** asking, instead of confirming blind.

## [0.4.0] — CLI rework (breaking)

A **hard break** that reorganizes the command-line surface. Update any scripts,
aliases, or config files that used the old names.

**Switches — renamed / moved:**

| What | Old | New |
|---|---|---|
| config-file drift | `-p` / `--pacnew` | `-d` / `--config-drift` |
| AUR IoC scan | `-S` / `--aur-ioc-scan` | `-I` / `--aur-ioc-scan` |
| rebuild check | `--rebuilds` | `-r` / `--rebuild-check` |
| python rebuild check | `--python-rebuild` | `-y` / `--python-rebuild-check` |
| firmware check | `--firmware` (action `firmware`) | `-f` / `--firmware` (action `firmware-check`) |
| kernel | action `kernels` | `-k` / action `kernel` |
| package audit | `fettle pkg-audit` (word only) | `-P` / `--pkg-audit` (+ word) |
| upgrade | `-u` | `-u` / `--update` / `--upgrade` |

**New:**
- `-O` / `--only-update` — **safe metadata refresh + "what's upgradable" report**,
  no upgrade. Arch previews from a private cache (never `pacman -Sy`, so no
  partial-upgrade risk); Debian runs `apt update` + flatpak metadata.
- **Dispatch shortcuts** for the subcommand-style actions (subcommand forms stay
  for their options): `-S` → `sys-audit --all`, `-U` → `upgrade-check`, `-p` →
  `aur-precheck`.
- **`clean` now asks once** before deleting caches (`--yes` skips).
- **`aur-precheck` with no package** now scans *all* installed AUR packages (bare
  `fettle aur-precheck` / `-p` used to print nothing).

**`fettle remote` reworked** — `fettle remote [--ssh-arg X]... HOST <any
action/flags…>`. Everything after `HOST` is forwarded verbatim, so the whole CLI
works remotely. With no action named it still runs only the safe set
(`clean update firmware-check`), even under `--yes`.

**Config:**
- `default_actions` renamed to the new action names (`rebuild-check`,
  `python-rebuild-check`, `config-drift`, `firmware-check`). Old names are dropped
  with a warning pointing at the new spelling; hyphens and underscores both work.
- Removed the redundant `source_audit` action; `integrity` is now solely the
  `sys-audit` *packages* module.

**Removed:** old switches/long-options above no longer exist (they error rather
than silently doing something else).
