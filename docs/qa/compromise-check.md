# QA — `compromise-check` (`-M`)

**The question a user is really asking:** *"something feels wrong with this box — can
this tell me whether I have been got, without wasting my afternoon on things that are
fine?"*

That is a harder bar than the other audits. This is the one action a person reaches for
when they are already worried, so a false alarm costs more than usual and a false
all-clear costs far more. It is also the action most likely to be read in a hurry.

Status: **COMPLETE** — C1 through C8. Five defects found, five fixed.

Swept at v1.6.1 against the local Manjaro workstation (Arch backend, 4431 binaries, 487
unit files, 1046 processes) and Debian 13 containers as root and as an ordinary user.

---

## The three axes

| axis | verdict |
|---|---|
| **Correct** | PASS — every check has a planted positive control, and all fire |
| **Truthful** | **3 defects**, all fixed: a misleading `--only` message, `--quiet` inverted, and coverage claimed where the reader could not verify it |
| **Clear** | **2 defects**, both fixed: the table broke on long subjects, and four repeated headers |

---

## C1 — does each check actually fire? *(Correct)*

Every check was run against a planted artifact, on a machine where the artifact was the
only thing wrong. Not mocks — real files, and for the fileless case a real
`memfd_create` + `execve`.

| check | control | result |
|---|---|---|
| unowned unit | `Restart=always` unit in `/etc/systemd/system`, payload in `/var/lib` | **High**, names the AUR wave |
| unowned cron | `@reboot root /var/lib/x/agent` in `/etc/cron.d` | **High** |
| user crontab | `*/5 * * * * /dev/shm/.x/beacon` | **High** |
| user unit | `~/.config/systemd/user/` with a `/var/lib` target | **High** |
| `ld.so.preload` | one line naming a `.so` | **High** — the dynamic linker complained too, independently confirming the artifact |
| unsigned module | `/sys/module/<m>/taint` = `E` | **High** with enforcement on, **Medium** with it off |
| unexplained taint | `tainted=12288`, no module accounts for it | **Low** |
| hidden process | PID in `cgroup.procs`, absent from `/proc` | **Critical** |
| eBPF IoC pin | `hidden_pids` in `/sys/fs/bpf` | **Critical** |
| memfd exec | **real** memfd holding an interpreter, exec'd | **Critical** |
| deleted from `/tmp` | unlinked after start | **High** |
| unowned listener | listening socket, unowned binary | **Medium** / **High** from `/tmp` |
| promiscuous iface | `IFF_PROMISC` without `brport` | **Medium** |
| `/dev` regular file | a plain file under `/dev` | **Medium** |
| boot config | `LD_PRELOAD` in `grub.cfg`; `init=/tmp/x` in a systemd-boot entry | **High** |

**PASS.** A detection that has never detected anything is not a detection.

## C2 — what does it say on a machine where nothing is wrong? *(Correct)*

The number that decides whether this feature is usable. Four findings on the reference
desktop, and **every one is explicable in a sentence**:

| finding | what it actually is |
|---|---|
| `etc/cron.d/timeshift-hourly` — Medium | timeshift writes it at runtime when you enable snapshots |
| `rumble-agent-4b7a…f6.service` — Medium | runZero Explorer, installed on purpose |
| `rumble-agent-e87f…7d.service` — Low | the same, pointing at a binary runZero renamed |
| `pid 50020` — Low | a self-updating AppImage |
| kernel taint — Low | a DKMS or VMware module built and unloaded during an update |

**PASS**, and the six rejected rules that got it there are recorded in
`~/.claude/…/feedback_measure_the_false_positive_floor.md`. The naive versions produced
41, 27, 6272, 2 and 9 hits respectively.

## C3 — `--only compromise-check` blamed the backend *(Truthful — DEFECT, fixed)*

```
$ fettle -a --only compromise-check
! nothing to do — none of the default actions are implemented by the arch backend.
$ echo $?
0
```

Both halves are false. The arch backend implements it perfectly well, and the run exited
**0** having done nothing. The real cause: `--only` *narrows the set being run*, that set
is the default one, and `compromise-check` is not in it.

**Not specific to this action** — `--only hardening-audit`, `--only kernel` and
`--only only-update` all produced the identical false sentence. A message that names the
wrong cause sends the reader to check the wrong thing, which is worse than no message.

**Fixed**: the `--only`-matched-nothing case is now its own message, names what was
asked for, says that `--only` narrows rather than adds, gives the command that does work,
and exits **1**.

## C4 — `--quiet` was inverted *(Truthful — DEFECT, fixed)*

`-M -q` suppressed the headers and the summary and printed **the entire findings table**.
The body was going through a bare `print()` that never consulted `Output`, so the one
flag whose whole job is "less output" removed the labels and kept the wall of text.

This is one instance of the `--quiet` defect recorded in the outstanding-issues file
(17 bare `print()` calls repo-wide). **Fixed for both audits** by adding `Output.detail()`
— the channel for an action's body output — and routing the axes table and the binary
axis through it. `-M -q` and `-H -q` are now silent, and both halves of `-H` obey the
flag rather than one of them.

## C5 — the table broke on the subjects it actually has *(Clear — DEFECT, fixed)*

A 56-character unit name against a 30-character column: the subject took a row of its
own and the finding landed on the next one, indented into the middle of the screen with
nothing to its left. Two of the reference machine's four findings looked like that.

Three fixes, all in the shared renderer so `-H` gets them too:

- **Width follows the terminal**, capped at 120, fixed at 80 when output is not a TTY so
  a run-log does not change shape with the window that produced it.
- **Middle-truncation keeping both ends.** Head-truncation renders
  `rumble-agent-4b7a89f3-…` and `rumble-agent-e87f42e9-…` identically, which turns two
  findings into one indistinguishable pair. The untruncated name is in the saved report.
- **Column widths from the data**, with the subject column never narrower than its own
  header — found while testing: with subjects like `/tmp` and `/var` the computed width
  was 6 and the header rendered as `SUBJECTFINDING`.

## C6 — four repeated column headers *(Clear — DEFECT, fixed)*

With four check groups the screen carried four `SEVERITY / SUBJECT / FINDING` rows and
four separate tables, so the worst thing on the machine could be anywhere in the middle.

**Fixed**: one table with a GROUP column, ranked worst-first across the whole action. The
per-group coverage lines survive above it — they carry the `(487 checked)` number, which
a findings table cannot. The GROUP column drops itself when every finding came from one
group, which is the common case for `-H`.

## C7 — does it ever claim coverage it did not have? *(Truthful — DEFECT, fixed)*

Three separate ways it could have, each fixed as it was found:

1. **A fully blind run summarised as "nothing to report"** — `actions.run` fills an empty
   summary with exactly that, and the action added no line of its own. The screen said
   "not checked"; the summary said the opposite.
2. **A partially blind run reported its findings and not its blindness.** The summary now
   carries both: `2 Medium, 3 Low; 4 check(s) could not look`.
3. **A sub-check could mark its whole group not-applicable.** `na` is a group property,
   so the hidden-process check setting it on a cgroup-less host would have hidden an
   `/etc/ld.so.preload` finding sitting beside it behind one "not applicable" line.

**PASS after fixes.** Verified by running with an empty `--root`, in a container without
cgroups, and unprivileged where `/sys/fs/bpf` cannot be read.

## C8 — privilege and the flags *(Correct)*

| case | result |
|---|---|
| `--dry-run` writes no report | **PASS** — report count unchanged across a run |
| classified read-only **and** needs-root | **PASS** — asserted both ways |
| `fettle remote HOST -M` elevates | **PASS** — `_forwarded_needs_root` returns True |
| unprivileged degrades rather than refuses | **PASS** — system-scope checks run; each blind check names its own directory |
| exit `0` with Medium/Low, `1` at High | **PASS** — verified on two distros |

---

## Left open, deliberately

- **`bpftool` is not installed on the reference machine**, so only *pinned* BPF objects
  are examined there. Reported as blindness with the install command, which is the
  correct behaviour; the coverage gap is real and is the user's to close.
- **The eBPF check cannot see an implant that hooks `bpf()`.** Stated in the output
  rather than papered over. Closing it needs a memory capture, which is out of scope.
- **No `--root` sweep against the six lab VMs.** This action reads `/proc`, `/sys` and
  the cgroup hierarchy, none of which a `--root` scratch tree can simulate honestly, so
  the live verification is the workstation plus containers rather than the usual matrix.
